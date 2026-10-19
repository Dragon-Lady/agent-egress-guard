"""Real process groups, controlling terminals, and agent file permissions."""
import asyncio
import os
from pathlib import Path
import pty
import signal
import stat
import subprocess
import sys
import time

import psutil
import pytest

from agent_egress_guard.ledger import Ledger, StateError
from agent_egress_guard.session import run, systemd_available
from agent_egress_guard.doctor import namespace_probe, print_doctor


@pytest.mark.parametrize('mask', [0o022, 0o002, 0o077])
@pytest.mark.parametrize('scope', [False, True])
def test_agent_keeps_caller_umask(tmp_path, mask, scope):
    if scope and not systemd_available():
        pytest.skip('user systemd manager unavailable')
    original = os.umask(mask)
    ledger = None
    try:
        ledger = Ledger(tmp_path / 'state')
        target = tmp_path / 'agent-output'
        code = ('import pathlib; p=pathlib.Path(' + repr(str(target)) + '); '
                'p.mkdir(); (p/"file").touch()')
        _, status = asyncio.run(run([sys.executable, '-c', code], ledger, use_scope=scope))
        assert status == 0
        assert stat.S_IMODE(target.stat().st_mode) == 0o777 & ~mask
        assert stat.S_IMODE((target / 'file').stat().st_mode) == 0o666 & ~mask
        ledger.db.execute('PRAGMA journal_mode=WAL')
        ledger.start('fixture', 0)
        assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in ledger.root.iterdir())
        ledger.close()
        assert os.umask(mask) == mask
        ledger = None
        (tmp_path / 'state').chmod(0o755)
        with pytest.raises(StateError):
            Ledger(tmp_path / 'state')
        assert os.umask(mask) == mask
    finally:
        if ledger is not None:
            ledger.close()
        os.umask(original)


def wait_for(check, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.02)
    pytest.fail('process control fixture timed out')


@pytest.mark.parametrize('scope', [False, True])
@pytest.mark.parametrize('delivery', ['terminal', 'wrapper'])
def test_single_sigint_with_terminal_input_and_restore(tmp_path, scope, delivery):
    if scope and not systemd_available():
        pytest.skip('user systemd manager unavailable')
    ready, stop, result, restored = [tmp_path / name for name in ('ready', 'stop', 'result', 'restored')]
    agent = tmp_path / 'agent.py'
    agent.write_text('''import pathlib, signal, subprocess, sys, time
count = 0
def caught(*args):
    global count
    count += 1
signal.signal(signal.SIGINT, caught)
sibling = None
if len(sys.argv) == 4:
    sibling = subprocess.Popen([sys.executable, __file__, sys.argv[1] + '.child',
                                sys.argv[2], sys.argv[3] + '.child', 'sibling'])
    assert sys.stdin.readline().strip() == "terminal-input"
    while not pathlib.Path(sys.argv[1] + '.child').exists(): time.sleep(0.02)
pathlib.Path(sys.argv[1]).touch()
while not pathlib.Path(sys.argv[2]).exists(): time.sleep(0.02)
pathlib.Path(sys.argv[3]).write_text(str(count))
if sibling is not None: assert sibling.wait(timeout=3) == 0
''')
    driver = tmp_path / 'driver.py'
    driver.write_text('''import asyncio, os, pathlib, sys
from agent_egress_guard.ledger import Ledger
from agent_egress_guard.session import run
ledger = Ledger(pathlib.Path(sys.argv[1]))
try:
    _, code = asyncio.run(run([sys.executable, *sys.argv[4:]], ledger, use_scope=sys.argv[2] == "True"))
    assert code == 0
    assert os.tcgetpgrp(0) == os.getpgrp()
    pathlib.Path(sys.argv[3]).touch()
finally:
    ledger.close()
''')
    pid, master = pty.fork()
    if pid == 0:
        try:
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'))
            os.execve(sys.executable, [sys.executable, str(driver), str(tmp_path / 'state'),
                      str(scope), str(restored), str(agent), str(ready), str(stop), str(result)], env)
        finally:
            os._exit(99)
    reaped = False
    try:
        os.write(master, b'terminal-input\n')
        wait_for(ready.exists)
        if delivery == 'terminal':
            os.write(master, b'\x03')
        else:
            os.kill(pid, signal.SIGINT)
        time.sleep(0.3)
        stop.touch()
        wait_for(restored.exists)
        _, status = os.waitpid(pid, 0)
        reaped = True
        assert os.waitstatus_to_exitcode(status) == 0
        assert result.read_text() == '1'
        assert Path(str(result) + '.child').read_text() == '1'
    finally:
        if not reaped:
            try:
                children = psutil.Process(pid).children(recursive=True)
                for child in reversed(children):
                    try:
                        child.kill()
                    except psutil.NoSuchProcess:
                        pass
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError, psutil.NoSuchProcess):
                pass
        os.close(master)


@pytest.mark.parametrize('message', [
    'bwrap: No permissions to create a new namespace, likely because the kernel does not allow it',
    'bwrap: loopback: Failed RTM_NEWLINK: Operation not permitted',
    'bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted',
    'bwrap: setting up uid map: Permission denied',
])
def test_real_namespace_error_shapes(message, monkeypatch):
    monkeypatch.setattr('shutil.which', lambda _: '/usr/bin/bwrap')
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: subprocess.CompletedProcess(argv, 1, '', message))
    assert namespace_probe()['reason'] == 'user_namespace_restricted'


@pytest.mark.parametrize('proxy_ok', [True, False])
def test_doctor_exit_tracks_observe_capability(proxy_ok, monkeypatch, capsys):
    monkeypatch.setattr('agent_egress_guard.doctor.inspect_environment', lambda: {
        'platform': 'linux', 'namespace': {'available': False},
        'inspect_dependency_available': False, 'proxy_probe_python_urllib': proxy_ok})
    assert print_doctor() == (0 if proxy_ok else 3)
    assert 'Private intranet' in capsys.readouterr().out
