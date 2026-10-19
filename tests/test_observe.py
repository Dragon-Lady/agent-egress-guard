"""Offline fixtures only: loopback servers and synthetic canaries."""
import asyncio
import json
import os
from pathlib import Path
import socket
import signal
import ssl
import stat
import subprocess
import sys
import time

import pytest

from agent_egress_guard.classify import host_class
from agent_egress_guard.cli import main
from agent_egress_guard.doctor import proxy_child_probe, namespace_probe
from agent_egress_guard.ledger import Ledger, StateError
from agent_egress_guard.proxy import Proxy, ProxyError, authority, public_addresses, client_hello_sni, dial_public
from agent_egress_guard.session import proxy_environment, run, systemd_available


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    value = Ledger()
    yield value
    value.close()


@pytest.mark.parametrize("host", ["storage.googleapis.com", "bucket.storage.googleapis.com",
    "s3.amazonaws.com", "s3.us-east-1.amazonaws.com", "bucket.s3.amazonaws.com",
    "bucket.s3.us-east-1.amazonaws.com", "a.b.s3.us-east-1.amazonaws.com",
    "bucket.s3-accelerate.amazonaws.com", "account.blob.core.windows.net",
    "account.dfs.core.windows.net", "account.r2.cloudflarestorage.com",
    "bucket.backblazeb2.com", "bucket.digitaloceanspaces.com"])
def test_storage_class(host):
    assert host_class(host) == "storage"


@pytest.mark.parametrize("host", ["notstorage.googleapis.com", "storage.googleapis.com.evil.invalid",
    "amazonaws.com", "s3.fake.amazonaws.com.evil.invalid", "blob.core.windows.net",
    "www.googleapis.com", "example.invalid"])
def test_label_boundaries(host):
    assert host_class(host) == "other"


def test_private_state_and_drift(tmp_path):
    root = tmp_path / "state"
    value = Ledger(root)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "ledger.sqlite3").stat().st_mode) == 0o600
    value.close()
    root.chmod(0o755)
    with pytest.raises(StateError):
        Ledger(root)


def test_refuses_database_symlink(tmp_path):
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    target = tmp_path / "outside"
    target.write_text("preserve")
    (root / "ledger.sqlite3").symlink_to(target)
    with pytest.raises(OSError):
        Ledger(root)
    assert target.read_text() == "preserve"


@pytest.mark.parametrize("target", ["user:pass@example.invalid:443", "example.invalid:0",
    "example.invalid:99999", "example.invalid:443/path", "bad\r\nhost:443",
    "host_with_underscore:443"])
def test_reject_bad_authority(target):
    with pytest.raises((ValueError, ProxyError)):
        authority(target)


def test_explicit_zero_port_does_not_use_default():
    with pytest.raises(ProxyError):
        authority("target.invalid:0", 80)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.0.1",
    "::1", "::ffff:127.0.0.1", "fe80::1", "0.0.0.0", "224.0.0.1"])
def test_private_destinations_rejected(address, monkeypatch):
    async def check():
        async def resolve(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
        with pytest.raises(ProxyError):
            await public_addresses("target.invalid", 443)
    asyncio.run(check())


def test_mixed_dns_answer_rejected(monkeypatch):
    async def check():
        async def resolve(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
                    for address in ("8.8.8.8", "127.0.0.1")]
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
        with pytest.raises(ProxyError):
            await public_addresses("target.invalid", 443)
    asyncio.run(check())


def test_dial_pins_validated_numeric_address(monkeypatch):
    async def check():
        async def resolve(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        async def connect(host, port, **kwargs):
            assert host == "8.8.8.8" and port == 443
            return "reader", "writer"
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
        monkeypatch.setattr(asyncio, "open_connection", connect)
        assert await dial_public("target.invalid", 443) == ("reader", "writer")
    asyncio.run(check())


async def fixture_proxy(ledger, handler):
    upstream = await asyncio.start_server(handler, "127.0.0.1", 0)
    async def fixture_dial(host, port):
        assert host == "target.invalid"
        return await asyncio.open_connection("127.0.0.1", upstream.sockets[0].getsockname()[1])
    session = ledger.start("fixture", 0)
    proxy = Proxy(ledger, session, "CANARY-AEG-PROXY", dial=fixture_dial)
    port = await proxy.start()
    return upstream, proxy, port, session


def test_proxy_counts_and_auth(ledger):
    async def check():
        async def echo(reader, writer):
            while data := await reader.read(4096):
                writer.write(data)
                await writer.drain()
            writer.close()
            await writer.wait_closed()
        upstream, proxy, port, session = await fixture_proxy(ledger, echo)
        for authenticated in (False, True):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            auth = "Proxy-Authorization: " + proxy.auth + "\r\n" if authenticated else ""
            writer.write(("CONNECT target.invalid:443 HTTP/1.1\r\n" + auth + "\r\n").encode())
            header = await reader.readuntil(b"\r\n\r\n")
            if authenticated:
                assert b"200" in header
                writer.write(b"CANARY-AEG-BODY")
                await writer.drain()
                assert await reader.readexactly(15) == b"CANARY-AEG-BODY"
            else:
                assert b"407" in header
            writer.close()
            await writer.wait_closed()
        await proxy.close()
        upstream.close()
        await upstream.wait_closed()
        rows = ledger.db.execute("SELECT bytes_up,bytes_down,status FROM connections WHERE session=?", (session,)).fetchall()
        assert (15, 15, "sni_unavailable") in rows
        assert (0, 0, "unauthenticated") in rows
        for path in ledger.root.iterdir():
            assert b"CANARY-AEG-BODY" not in path.read_bytes()
            assert b"CANARY-AEG-PROXY" not in path.read_bytes()
    asyncio.run(check())


def test_http_query_path_headers_and_body_not_persisted(ledger):
    async def check():
        captured = []
        async def server(reader, writer):
            header = await reader.readuntil(b"\r\n\r\n")
            captured.append(header + await reader.readexactly(15))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
        upstream, proxy, port, session = await fixture_proxy(ledger, server)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(("POST http://target.invalid/CANARY-AEG-PATH?sig=CANARY-AEG-QUERY HTTP/1.1\r\n"
                      "Host: target.invalid\r\nContent-Length: 15\r\n"
                      "Authorization: Bearer CANARY-AEG-HEADER\r\nProxy-Authorization: " + proxy.auth +
                      "\r\n\r\nCANARY-AEG-BODY").encode())
        await writer.drain()
        assert b"200 OK" in await reader.read()
        writer.close()
        await proxy.close()
        upstream.close()
        await upstream.wait_closed()
        assert b"Proxy-Authorization" not in captured[0]
        assert b"Authorization: Bearer CANARY-AEG-HEADER" in captured[0]
        assert ledger.db.execute("SELECT path_template FROM connections").fetchone()[0] == "/<path>"
        for path in ledger.root.iterdir():
            assert b"CANARY-AEG" not in path.read_bytes()
    asyncio.run(check())


def test_sni_parser_and_fragment_limit():
    context = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_hostname="target.invalid")
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()
    hello = outgoing.read()
    assert client_hello_sni(hello) == "target.invalid"
    for partial in (b"", b"random", hello[:30], hello[:6]):
        assert client_hello_sni(partial) is None


def test_proxy_environment_no_uncontrolled_bypass(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "CANARY-AEG-PRIVATE")
    env = proxy_environment(12345, "CANARY-AEG-CREDENTIAL")
    for name in ("http_proxy", "https_proxy", "all_proxy"):
        assert env[name] == env[name.upper()]
        assert "127.0.0.1:12345" in env[name]
    assert env["no_proxy"] == env["NO_PROXY"] == "localhost,127.0.0.1,::1"
    assert env["NODE_USE_ENV_PROXY"] == "1"


def test_agent_exit_code(ledger):
    session, code = asyncio.run(run([sys.executable, "-c", "raise SystemExit(17)"], ledger, use_scope=False))
    assert code == 17
    assert ledger.report(session)["exit_code"] == 17


def test_signal_forwarding_preserves_exit_status(tmp_path):
    marker = tmp_path / "ready"
    env = dict(os.environ, XDG_STATE_HOME=str(tmp_path / "state"))
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    child_code = "import pathlib,time; pathlib.Path(" + repr(str(marker)) + ").touch(); time.sleep(30)"
    proc = subprocess.Popen([sys.executable, "-m", "agent_egress_guard", "run", "--",
                             sys.executable, "-c", child_code], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.02)
        assert marker.exists()
        proc.send_signal(signal.SIGTERM)
        _, error = proc.communicate(timeout=5)
        assert proc.returncode == 143
        assert b"observe mode is best-effort" in error
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()


@pytest.mark.parametrize("double_fork", [False, True])
@pytest.mark.parametrize("scope", [False, True])
def test_post_exit_descendant_upload(ledger, tmp_path, double_fork, scope):
    if scope and not systemd_available():
        pytest.skip("user systemd manager unavailable; subreaper case remains required")
    async def check():
        async def echo(reader, writer):
            while data := await reader.read(4096):
                writer.write(data)
                await writer.drain()
            writer.close()
        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        async def fixture_dial(host, port):
            return await asyncio.open_connection("127.0.0.1", upstream.sockets[0].getsockname()[1])
        def factory(*args):
            return Proxy(*args, dial=fixture_dial)
        script = tmp_path / "descendant.py"
        script.write_text('''import os, time, socket, base64
from urllib.parse import urlsplit
if os.fork(): os._exit(0)
os.setsid()
''' + ("if os.fork(): os._exit(0)\n" if double_fork else "") + '''time.sleep(0.25)
p = urlsplit(os.environ['https_proxy'])
auth = base64.b64encode((p.username + ':' + p.password).encode()).decode()
with socket.create_connection((p.hostname,p.port)) as sock:
    sock.sendall(('CONNECT target.invalid:443 HTTP/1.1\\r\\nProxy-Authorization: Basic '+auth+'\\r\\n\\r\\n').encode())
    assert b'200' in sock.recv(4096)
    sock.sendall(b'late-upload')
    assert sock.recv(4096) == b'late-upload'
''')
        started = time.monotonic()
        session, code = await asyncio.wait_for(run([sys.executable, str(script)], ledger,
                                                  use_scope=scope, proxy_type=factory), 8)
        assert code == 0 and time.monotonic() - started >= 0.25
        row = ledger.db.execute("SELECT bytes_up,pid,exe FROM connections WHERE session=?", (session,)).fetchone()
        assert row[0] == 11
        assert row[1] is not None and row[2].startswith("python")
        upstream.close()
        await upstream.wait_closed()
    asyncio.run(check())


def test_nonrun_paths_do_not_connect(ledger, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    session = ledger.start("fixture", 0)
    assert main(["report", session, "--json"]) == 0
    assert "best-effort" in capsys.readouterr().out
    assert host_class("target.invalid") == "other"


@pytest.mark.parametrize("mode", ["--inspect", "--block", "--confine"])
def test_unavailable_mode_never_launches(mode, tmp_path, capsys):
    marker = tmp_path / "launched"
    assert main(["run", mode, "--", sys.executable, "-c", f"open({str(marker)!r}, 'w').close() "]) == 3
    assert not marker.exists()
    assert "not implemented" in capsys.readouterr().err


def test_argument_errors_dont_echo_credentials(capsys):
    with pytest.raises(SystemExit):
        main(["CANARY-AEG-SECRET"])
    assert "CANARY-AEG-SECRET" not in capsys.readouterr().err


def test_doctor_child_proxy_probe():
    assert proxy_child_probe()


def test_namespace_probe_is_read_only(monkeypatch):
    calls = []
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/bwrap")
    def fake(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 1, "", "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted\n")
    monkeypatch.setattr(subprocess, "run", fake)
    result = namespace_probe()
    assert result["reason"] == "user_namespace_restricted"
    assert len(calls) == 1 and calls[0][0] == "bwrap"
    assert "sysctl" not in calls[0]


@pytest.mark.parametrize("kind", ["proj", "svcacct", "admin", "ant-api03", "ant-admin01", "ant-oat01", "ant-ort01"])
def test_extended_provider_labels_are_redacted(ledger, kind):
    from push_guard import scan_text_for_secrets
    value = "s" + "k-" + kind + "-" + "Ab3dE5fG7hJ9kL2mN4pQ6rS8" + ".invalid"
    if not any(f.rule_id.startswith("secret.") for f in scan_text_for_secrets(value)):
        pytest.skip("draft dependency lacks provider shapes; publish gate requires reviewed 0.4.3")
    session = ledger.start("fixture", 0)
    ledger.connection(session, started=0, duration=0, host=value, port=443,
                      method="CONNECT", path_template="/", bytes_up=0, bytes_down=0,
                      pid=None, exe=value, status="ok", sni=value)
    assert ledger.db.execute("SELECT host,exe,sni FROM connections").fetchone() == ("<redacted>",) * 3
    assert value.encode() not in (ledger.root / "ledger.sqlite3").read_bytes()
