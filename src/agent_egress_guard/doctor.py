"""Read-only environment checks and a loopback-only proxy probe."""
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import threading

from .session import proxy_environment, systemd_available

INSPECT_HELP = (
    "inspect mode needs Python 3.12+ and mitmproxy; install with "
    "`sfw pipx install --python python3.12 'agent-egress-guard[inspect]'`"
)
RESTRICTIONS = (
    "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted",
    "bwrap: setting up uid map: Permission denied",
    "No permissions to create new namespace",
)
SYSCTLS = ("kernel/apparmor_restrict_unprivileged_userns", "kernel/unprivileged_userns_clone",
           "user/max_user_namespaces")


def namespace_probe() -> dict:
    values = {}
    for name in SYSCTLS:
        try:
            text = (Path("/proc/sys") / name).read_text().strip()
            values[name] = int(text)
        except (OSError, ValueError):
            values[name] = None
    result = {"sysctls": values, "available": False, "reason": "bwrap_missing"}
    if not shutil.which("bwrap"):
        return result
    try:
        probe = subprocess.run(["bwrap", "--unshare-user", "--unshare-net", "--ro-bind", "/", "/",
                                "--proc", "/proc", "--dev", "/dev", "--", "/bin/true"],
                               capture_output=True, text=True, timeout=5)
        result["available"] = probe.returncode == 0
        result["reason"] = "ok" if probe.returncode == 0 else "probe_failed"
        if any(line in RESTRICTIONS for line in probe.stderr.splitlines()):
            result["reason"] = "user_namespace_restricted"
    except (OSError, subprocess.TimeoutExpired):
        result["reason"] = "probe_unavailable"
    return result


def proxy_child_probe() -> bool:
    # An actual urllib child request goes only to this loopback listener.
    # The .invalid hostname is never resolved or contacted by the server.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(4)
        received = []

        def serve():
            try:
                with listener.accept()[0] as client:
                    client.settimeout(3)
                    header = client.recv(4096)
                    received.append(header.startswith(b"GET http://probe.invalid/ HTTP/1.1\r\n"))
                    client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            result = subprocess.run([sys.executable, "-I", "-c",
                                     "import urllib.request; urllib.request.urlopen('http://probe.invalid/', timeout=3).close()"],
                                    env=proxy_environment(listener.getsockname()[1], "probe"),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
            passed = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            passed = False
        thread.join(timeout=4)
        return passed and received == [True]


def inspect_available() -> bool:
    if sys.version_info < (3, 12):
        return False
    try:
        version("mitmproxy")
        return True
    except PackageNotFoundError:
        return False


def inspect_environment() -> dict:
    alias = shutil.which("aeg")
    expected = Path(sys.executable).parent / "aeg"
    return {"platform": sys.platform, "kernel": platform.release(),
            "python": platform.python_version(), "systemd_user_scope": systemd_available(),
            "namespace": namespace_probe(), "proxy_probe_python_urllib": proxy_child_probe(),
            "inspect_dependency_available": inspect_available(), "inspect_implemented": False,
            "alias_shadowed": bool(alias and Path(alias).absolute() != expected.absolute())}


def print_doctor() -> int:
    result = inspect_environment()
    print(json.dumps(result, indent=2))
    if not result["namespace"]["available"]:
        print("Block/confine requires user namespaces with network setup. Check the targeted bwrap "
              "AppArmor profile with an administrator (see docs/sandbox.md), or use observe mode. "
              "aeg never changes system settings.")
    if not result["inspect_dependency_available"]:
        print(INSPECT_HELP)
    print("Inspect and enforcement are not implemented in this draft. The probe tests Python urllib only.")
    return 0 if (result["platform"] == "linux" and result["proxy_probe_python_urllib"]
                 and result["namespace"]["available"] and result["inspect_dependency_available"]) else 3
