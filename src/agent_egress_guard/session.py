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


def controlling_terminal() -> int | None:
    # stdin may be a pipe and both output streams may be redirected. /dev/tty
    # refers to this session's controlling terminal independently of all three.
    try:
        return os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    except OSError:
        return None


def foreground_group(fd: int | None) -> int | None:
    if fd is None:
        return None
    try:
        group = os.tcgetpgrp(fd)
        return group if group == os.getpgrp() else None
    except OSError:
        return None


def set_foreground(fd: int, group: int) -> None:
    # A background wrapper must be able to reclaim the terminal after exit.
    previous = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    try:
        os.tcsetpgrp(fd, group)
    finally:
        signal.signal(signal.SIGTTOU, previous)


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
        notes.append("same executable already running; processes outside this session are not attributed")
    if not scoped:
        notes.append("user systemd scope unavailable; subreaper tracking is best-effort")
    old_handlers = {}
    process = None
    code = 3
    loop = asyncio.get_running_loop()
    terminal_fd = controlling_terminal()
    terminal_group = foreground_group(terminal_fd)
    terminal_transferred = False

    def forward(signum):
        # Terminal-generated signals go directly to the foreground agent group.
        # Direct signals to the wrapper reach each tracked group once, including
        # detached descendants. Never signal the wrapper's own group recursively.
        groups = set()
        for child in tracker.members():
            try:
                group = os.getpgid(child.pid)
                if group == os.getpgrp():
                    child.send_signal(signum)
                    if signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGQUIT):
                        child.send_signal(signal.SIGCONT)
                elif group not in groups:
                    groups.add(group)
                    os.killpg(group, signum)
                    if signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGQUIT):
                        os.killpg(group, signal.SIGCONT)
            except (ProcessLookupError, psutil.NoSuchProcess):
                pass

    def reclaim_terminal():
        nonlocal terminal_transferred
        if terminal_transferred:
            try:
                set_foreground(terminal_fd, terminal_group)
            except OSError:
                notes.append("terminal no longer available; foreground could not be restored")
            finally:
                terminal_transferred = False

    def relay_job_stop():
        nonlocal terminal_transferred
        if terminal_group is None or process is None:
            return
        # asyncio owns exit reaping. Inspect group state without stealing an
        # exit status from its child watcher. A single paused worker must not
        # suspend an otherwise running foreground job.
        states = []
        for member in tracker.members():
            try:
                if os.getpgid(member.pid) == process.pid:
                    states.append(member.status())
            except (ProcessLookupError, psutil.NoSuchProcess):
                pass
        if not states or any(state != psutil.STATUS_STOPPED for state in states):
            return
        reclaim_terminal()
        # Tell the shell its foreground job stopped. Execution resumes here
        # after fg/bg (SIGCONT). Only fg gives us ownership of the terminal.
        os.kill(os.getpid(), signal.SIGSTOP)
        try:
            if foreground_group(terminal_fd) == terminal_group:
                set_foreground(terminal_fd, process.pid)
                terminal_transferred = True
            os.killpg(process.pid, signal.SIGCONT)
        except ProcessLookupError:
            pass

    try:
        with Subreaper():
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH):
                old_handlers[signum] = signal.getsignal(signum)
                loop.add_signal_handler(signum, forward, signum)
            # Use a distinct group while inheriting stdio. For a real terminal,
            # handshake before exec prevents a read/SIGTTIN race at startup.
            ready_read = ready_write = None
            try:
                launch = argv
                if terminal_group is not None:
                    ready_read, ready_write = os.pipe()
                    launch = [sys.executable, str(Path(__file__).with_name("_launch.py")), str(ready_read), *argv]
                process = await asyncio.create_subprocess_exec(
                    *launch, env=proxy_environment(port, credential),
                    process_group=0, umask=ledger.agent_umask,
                    pass_fds=(() if ready_read is None else (ready_read,)),
                )
                if terminal_group is not None:
                    set_foreground(terminal_fd, process.pid)
                    terminal_transferred = True
                    os.write(ready_write, b"1")
            finally:
                for fd in (ready_read, ready_write):
                    if fd is not None:
                        os.close(fd)
            next_warning = time.monotonic() + warning_after
            attempts = 0
            while True:
                relay_job_stop()
                if scoped and tracker.scope_path is None and attempts < 10:
                    await asyncio.to_thread(tracker.scope, unit)
                    attempts += 1
                if process.returncode is not None:
                    await process.wait()
                    reclaim_terminal()
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
        reclaim_terminal()
        if terminal_fd is not None:
            os.close(terminal_fd)
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
