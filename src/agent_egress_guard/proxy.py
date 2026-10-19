"""Authenticated loopback proxy: relay bytes, never retain request/response bodies."""
import asyncio
import base64
import hmac
import ipaddress
import re
import socket
import time
from urllib.parse import urlsplit

from .ledger import Ledger

HEADER_CAP = 32768
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT"}


class ProxyError(ValueError):
    pass


def authority(value: str, default: int | None = None) -> tuple[str, int]:
    if any(c in value for c in "@/?#\\") or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ProxyError("invalid authority")
    parsed = urlsplit("//" + value)
    try:
        host, port = parsed.hostname, parsed.port
        if port is None:
            port = default
    except ValueError as exc:
        raise ProxyError("invalid port") from exc
    if not host or port is None or not 1 <= port <= 65535:
        raise ProxyError("invalid authority")
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
            raise ProxyError("invalid hostname")
    return host, port


async def public_addresses(host: str, port: int) -> list[tuple]:
    addresses = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise ProxyError("no destination")
    # Validate every answer, then connect only to a validated numeric address.
    # This also excludes mapped loopback, unspecified, multicast and link-local.
    for _, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise ProxyError("non-public destination")
    return addresses


async def dial_public(host: str, port: int):
    addresses = await public_addresses(host, port)
    for family, _, _, _, address in addresses:
        try:
            return await asyncio.wait_for(asyncio.open_connection(address[0], port, family=family), 10)
        except OSError:
            continue
    raise ProxyError("destination unavailable")


def client_hello_sni(data: bytes) -> str | None:
    """Best-effort single-record ClientHello parser; no TLS interception."""
    try:
        if len(data) < 9 or data[0] != 22 or data[5] != 1:
            return None
        size = int.from_bytes(data[3:5], "big") + 5
        if size > len(data):
            return None
        body = memoryview(data)[9:size]
        pos = 34
        pos += 1 + body[pos]
        count = int.from_bytes(body[pos:pos+2], "big")
        pos += 2 + count
        pos += 1 + body[pos]
        end = pos + 2 + int.from_bytes(body[pos:pos+2], "big")
        pos += 2
        while pos + 4 <= min(end, len(body)):
            kind = int.from_bytes(body[pos:pos+2], "big")
            length = int.from_bytes(body[pos+2:pos+4], "big")
            pos += 4
            if pos + length > len(body):
                return None
            if kind == 0 and length >= 5 and body[pos+2] == 0:
                name_length = int.from_bytes(body[pos+3:pos+5], "big")
                if 5 + name_length > length:
                    return None
                name = bytes(body[pos+5:pos+5+name_length]).decode("ascii")
                return authority(name, 443)[0]
            pos += length
    except (IndexError, ValueError, UnicodeError):
        pass
    return None


class Proxy:
    def __init__(self, ledger: Ledger, session: str, credential: str, attribute=None, *, dial=dial_public):
        self.ledger, self.session = ledger, session
        self.auth = "Basic " + base64.b64encode(("aeg:" + credential).encode()).decode()
        self.attribute = attribute or (lambda port: (None, None))
        self.dial = dial
        self.tasks = set()
        self.server = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.accept, "127.0.0.1", 0, limit=HEADER_CAP)
        return self.server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        # Allow completed peers a bounded drain; never leave handler tasks using
        # a closed ledger. Session tracking keeps this proxy alive for descendants.
        if self.tasks:
            _, pending = await asyncio.wait(self.tasks, timeout=2)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    async def accept(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        host, port, method, template = "<unknown>", 0, "UNKNOWN", ""
        up = down = 0
        started, tick = time.time(), time.monotonic()
        status, sni, upstream = "invalid_request", None, None
        pid, exe = None, None
        pumps = []

        async def response(code: int, reason: str):
            writer.write(f"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()

        try:
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            if len(header) > HEADER_CAP:
                raise ProxyError("header too large")
            lines = header.decode("latin-1").split("\r\n")
            method, target, version = lines[0].split(" ")
            if method not in METHODS or version not in {"HTTP/1.0", "HTTP/1.1"}:
                method = "UNKNOWN"
                raise ProxyError("unsupported request")
            headers = []
            for line in lines[1:-2]:
                name, separator, value = line.partition(":")
                if not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any(ord(c) < 32 and c != "\t" for c in value):
                    raise ProxyError("invalid header")
                headers.append((name, value.strip()))
            credentials = [v for k, v in headers if k.lower() == "proxy-authorization"]
            if len(credentials) != 1 or not hmac.compare_digest(credentials[0].encode("latin-1"), self.auth.encode()):
                status = "unauthenticated"
                await response(407, "Proxy Authentication Required")
                return
            if method == "CONNECT":
                host, port = authority(target)
            else:
                parsed = urlsplit(target)
                if parsed.scheme != "http" or parsed.fragment:
                    raise ProxyError("absolute HTTP URL required")
                host, port = authority(parsed.netloc, 80)
                # Record a template only. The raw path can contain credentials
                # too; no query string or path segment ever enters the ledger.
                template = "/" if parsed.path in {"", "/"} else "/<path>"
            pid, exe = self.attribute(writer.get_extra_info("peername")[1])
            try:
                remote, upstream = await self.dial(host, port)
            except (ProxyError, OSError, asyncio.TimeoutError):
                status = "destination_refused"
                await response(502, "Destination Unavailable")
                return
            status = "ok"
            if method == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                status = "sni_unavailable"
            else:
                # Forward exactly one upstream connection. Proxy credentials and
                # hop headers are never sent to the destination.
                route = parsed.path or "/"
                if parsed.query:
                    route += "?" + parsed.query
                hosts = [v for k, v in headers if k.lower() == "host"]
                if len(hosts) != 1 or authority(hosts[0], 80) != (host, port):
                    raise ProxyError("host mismatch")
                lengths = [v for k, v in headers if k.lower() == "content-length"]
                encodings = [v for k, v in headers if k.lower() == "transfer-encoding"]
                if len(lengths) > 1 or len(encodings) > 1 or (lengths and encodings):
                    raise ProxyError("ambiguous framing")
                if lengths and not lengths[0].isdigit():
                    raise ProxyError("invalid length")
                if encodings and encodings[0].lower() != "chunked":
                    raise ProxyError("unsupported transfer encoding")
                hop = {"proxy-authorization", "proxy-connection", "connection", "keep-alive"}
                cleaned = [(k, v) for k, v in headers if k.lower() not in hop]
                wire = f"{method} {route} {version}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in cleaned) + "Connection: close\r\n\r\n"
                payload = wire.encode("latin-1")
                upstream.write(payload)
                await upstream.drain()
                up += len(payload)

            async def upload():
                nonlocal up, sni, status
                first = True
                while data := await reader.read(65536):
                    if first and method == "CONNECT":
                        sni = client_hello_sni(data)
                        if sni:
                            status = "ok" if sni == host else "sni_mismatch"
                    first = False
                    upstream.write(data)
                    await upstream.drain()
                    up += len(data)
                if upstream.can_write_eof():
                    upstream.write_eof()

            async def download():
                nonlocal down
                while data := await remote.read(65536):
                    writer.write(data)
                    await writer.drain()
                    down += len(data)

            pumps = [asyncio.create_task(upload()), asyncio.create_task(download())]
            # Upstream closure ends the transaction; upload EOF permits an
            # upstream response. Half-close does not discard response bytes.
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for done_task in done:
                done_task.result()
            if pumps[0] in done and pumps[1] not in done:
                await pumps[1]
        except (ValueError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            status = "invalid_request" if upstream is None else "connection_error"
            # Never copy an exception, URL, header, or payload into diagnostics.
        except asyncio.CancelledError:
            status = "session_closed"
            raise
        finally:
            for pump in pumps:
                if not pump.done():
                    pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            for stream in (upstream, writer):
                if stream is not None:
                    stream.close()
                    try:
                        await stream.wait_closed()
                    except OSError:
                        pass
            self.ledger.connection(self.session, started=started, duration=time.monotonic()-tick,
                                   host=host, port=port, method=method, path_template=template,
                                   bytes_up=up, bytes_down=down, pid=pid, exe=exe, status=status, sni=sni)
            self.tasks.discard(task)
