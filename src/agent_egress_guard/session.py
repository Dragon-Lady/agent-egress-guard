"""Supervise launched descendants without retaining command lines or environments."""
import asyncio
import ctypes
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time

import psutil

from . import BANNER
from .ledger import Ledger, StateError
from .proxy import Proxy


def proxy_environment(port: int, credential: str) -> dict[str, str]:
    env = dict(os.environ)
    url = f"http://aeg:{credential}@127.0.0.1:{port}"
    for name in ("http_proxy", "https_proxy", "all_proxy"):
        env[name] = env[name.upper()] = url
    env["grpc_proxy"] = url
    env["NO_PROXY"] = env["no_proxy"] = "localhost,127.0.0.1,::1"
    env["NODE_USE_ENV_PROXY"] = "1"
    return env


class Subreaper:
    def __enter__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.previous = ctypes.c_int()
        if self.libc.prctl(37, ctypes.byref(self.previous), 0, 0, 0) != 0 or self.libc.prctl(36, 1, 0, 0, 0) != 0:
            raise StateError("Linux child-subreaper setup failed")
        return self

    def __exit__(self, *args):
        self.libc.prctl(36, self.previous.value, 0, 0, 0)


def systemd_available() -> bool:
    if not shutil.which("systemd-run") or not shutil.which("systemctl"):
        return False
    try:
        return subprocess.run(["systemctl", "--user", "show", "--property=Version", "--value"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def preexisting(command: str) -> bool:
    executable = shutil.which(command) or command
    resolved = os.path.realpath(executable)
    for proc in psutil.process_iter(["pid", "exe"]):
        try:
            if proc.pid != os.getpid() and proc.info["exe"] and os.path.realpath(proc.info["exe"]) == resolved:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


class Tracker:
    def __init__(self):
        self.scope_path = None

    def members(self) -> list[psutil.Process]:
        processes = {p.pid: p for p in psutil.Process().children(recursive=True)}
        if self.scope_path:
            try:
                for value in self.scope_path.read_text().split():
                    pid = int(value)
                    processes[pid] = psutil.Process(pid)
            except (FileNotFoundError, ProcessLookupError, psutil.NoSuchProcess):
                pass
        result = []
        for proc in processes.values():
            try:
                if proc.status() != psutil.STATUS_ZOMBIE:
                    result.append(proc)
            except psutil.NoSuchProcess:
                pass
        return result

    def attribute(self, port: int):
        for proc in self.members():
            try:
                for conn in proc.net_connections(kind="tcp"):
                    if conn.laddr and conn.laddr.port == port:
                        return proc.pid, Path(proc.exe()).name
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None, None

    def scope(self, unit: str) -> bool:
        try:
            result = subprocess.run(["systemctl", "--user", "show", unit, "--property=ControlGroup", "--value"],
                                    capture_output=True, text=True, timeout=3)
            value = result.stdout.strip()
            if result.returncode == 0 and value.startswith("/") and ".." not in value.split("/"):
                self.scope_path = Path("/sys/fs/cgroup") / value.lstrip("/") / "cgroup.procs"
                return True
        except (OSError, subprocess.TimeoutExpired):
            pass
        return False


def reap_orphans() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                return
        except ChildProcessError:
            return


async def run(command: list[str], ledger: Ledger, *, use_scope: bool | None = None,
              fail_on_alert: bool = False, warning_after: float = 30,
              proxy_type=Proxy) -> tuple[str, int]:
    if sys.platform != "linux":
        raise StateError("only Linux is supported")
    if not command:
        raise StateError("a command is required after --")
    scoped = systemd_available() if use_scope is None else use_scope
    tracker = Tracker()
    session = ledger.start("systemd-scope+subreaper" if scoped else "subreaper-only",
                           max(len(os.environ.get("NO_PROXY", "")), len(os.environ.get("no_proxy", ""))))
    credential = secrets.token_urlsafe(32)
    proxy = proxy_type(ledger, session, credential, tracker.attribute)
    port = await proxy.start()
    unit = "aeg-" + session
    argv = ["systemd-run", "--user", "--scope", "--quiet", "--unit=" + unit, "--", *command] if scoped else command
    notes = []
    if preexisting(command[0]):
        notes.append("pre-existing agent daemon; its traffic is not attributed")
    if not scoped:
        notes.append("user systemd scope unavailable; subreaper tracking is best-effort")
    old_handlers = {}
    process = None
    code = 3
    loop = asyncio.get_running_loop()

    def forward(signum):
        # Terminal input/output remains inherited. Forward to tracked children
        # for direct signals as well as interactive interrupts; never other PIDs.
        for child in tracker.members():
            try:
                child.send_signal(signum)
            except psutil.NoSuchProcess:
                pass

    try:
        with Subreaper():
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGWINCH):
                old_handlers[signum] = signal.getsignal(signum)
                loop.add_signal_handler(signum, forward, signum)
            # Inherit stdio and the foreground process group: no PTY emulation,
            # command echoing, shell invocation or credential-bearing argv.
            process = await asyncio.create_subprocess_exec(*argv, env=proxy_environment(port, credential))
            next_warning = time.monotonic() + warning_after
            attempts = 0
            while True:
                if scoped and tracker.scope_path is None and attempts < 10:
                    await asyncio.to_thread(tracker.scope, unit)
                    attempts += 1
                if process.returncode is not None:
                    await process.wait()
                    reap_orphans()
                    members = tracker.members()
                    if not members:
                        break
                    if time.monotonic() >= next_warning:
                        print(f"{len(members)} descendants still running; proxy remains active", file=sys.stderr)
                        next_warning = time.monotonic() + warning_after
                await asyncio.sleep(0.05)
            code = process.returncode
            if code < 0:
                code = 128 - code
            if scoped and tracker.scope_path is None:
                notes.append("scope membership was unavailable; descendant tracking used the subreaper")
    except OSError:
        raise StateError("agent launch failed; check executable availability") from None
    finally:
        for signum, old in old_handlers.items():
            loop.remove_signal_handler(signum)
            signal.signal(signum, old)
        await proxy.close()
        ledger.finish(session, code)
        for note in notes:
            print(note, file=sys.stderr)
        print(BANNER, file=sys.stderr)
        print("session: " + session, file=sys.stderr)
    warnings = ledger.report(session)["connection_warnings"]
    return session, (1 if fail_on_alert and warnings else code)
