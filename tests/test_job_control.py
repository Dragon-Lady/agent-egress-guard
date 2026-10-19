"""Interactive-shell job control and termination of stopped process groups."""
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import subprocess
import sys
import time

import psutil
import pytest

from agent_egress_guard.session import systemd_available


DRIVER = '''import asyncio, pathlib, sys
from agent_egress_guard.ledger import Ledger
from agent_egress_guard.session import run
ledger = Ledger(pathlib.Path(sys.argv[1]))
try:
    _, status = asyncio.run(run([sys.executable, *sys.argv[3:]], ledger, use_scope=sys.argv[2] == 'True'))
finally:
    ledger.close()
raise SystemExit(status)
'''


def environment(tmp_path):
    return dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'),
                PS1='FIXTURE-PROMPT> ', PROMPT_COMMAND='', HISTFILE='/dev/null',
                XDG_STATE_HOME=str(tmp_path / 'state'))


def cleanup(pid):
    try:
        for child in reversed(psutil.Process(pid).children(recursive=True)):
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, psutil.NoSuchProcess):
        pass


def read_until(fd, marker, timeout=8):
    output = b''
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker in output:
            return output
        if select.select([fd], [], [], 0.05)[0]:
            try:
                chunk = os.read(fd, 8192)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
    pytest.fail('terminal fixture timed out: ' + repr(output))


@pytest.mark.parametrize('scope', [False, True])
def test_ctrl_z_returns_shell_and_fg_resumes_agent(tmp_path, scope):
    if scope and not systemd_available():
        pytest.skip('user systemd manager unavailable')
    driver, agent = tmp_path / 'driver.py', tmp_path / 'agent.py'
    driver.write_text(DRIVER)
    agent.write_text('''import signal, sys
signal.signal(signal.SIGCONT, lambda *args: print('AGENT-RESUMED', flush=True))
print('AGENT-READY', flush=True)
assert sys.stdin.readline().strip() == 'finish'
raise SystemExit(17)
''')
    pid, master = pty.fork()
    if pid == 0:
        os.execve('/bin/bash', ['bash', '--noprofile', '--norc', '-i'], environment(tmp_path))
    try:
        read_until(master, b'FIXTURE-PROMPT> ')
        command = shlex.join([sys.executable, str(driver), str(tmp_path / 'ledger'), str(scope), str(agent)])
        os.write(master, (command + "\n").encode())
        read_until(master, b'AGENT-READY\r\n')
        for cycle in range(2):
            os.write(master, b'\x1a')
            output = read_until(master, b'FIXTURE-PROMPT> ')
            assert b'Stopped' in output
            # The shell really executes commands after the stop.
            os.write(master, b"printf 'SHELL-%s\\n' 'READY'\n")
            output = read_until(master, b'FIXTURE-PROMPT> ')
            assert b'SHELL-READY\r\n' in output
            os.write(master, b'fg; printf "AEG_EXIT=%s\\n" "$?"\n' if cycle == 1 else b'fg\n')
            read_until(master, b'AGENT-RESUMED\r\n')
        os.write(master, b'finish\n')
        output = read_until(master, b'FIXTURE-PROMPT> ')
        assert b'AEG_EXIT=17\r\n' in output
    finally:
        cleanup(pid)
        os.waitpid(pid, 0)
        os.close(master)


@pytest.mark.parametrize('scope', [False, True])
@pytest.mark.parametrize('signum', [signal.SIGTERM, signal.SIGHUP])
@pytest.mark.parametrize('detached', [False, True])
def test_termination_wakes_stopped_agent_group(tmp_path, scope, signum, detached):
    if scope and not systemd_available():
        pytest.skip('user systemd manager unavailable')
    driver, agent, ready = [tmp_path / name for name in ('driver.py', 'agent.py', 'ready')]
    driver.write_text(DRIVER)
    agent.write_text('''import os, pathlib, sys, time
''' + ('if os.fork(): os._exit(0)\nos.setsid()\n' if detached else '') + '''pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
time.sleep(30)
''')
    proc = subprocess.Popen([sys.executable, str(driver), str(tmp_path / 'ledger'),
                             str(scope), str(agent), str(ready)], env=environment(tmp_path),
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)
    try:
        deadline = time.monotonic() + 8
        while not ready.exists() and time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.02)
        assert ready.exists()
        child_pid = int(ready.read_text())
        if detached:
            time.sleep(0.2)  # Let the original command exit and the child reparent.
        os.killpg(os.getpgid(child_pid), signal.SIGSTOP)
        deadline = time.monotonic() + 3
        while psutil.Process(child_pid).status() != psutil.STATUS_STOPPED and time.monotonic() < deadline:
            time.sleep(0.02)
        assert psutil.Process(child_pid).status() == psutil.STATUS_STOPPED
        proc.send_signal(signum)
        proc.communicate(timeout=8)
        assert proc.returncode == (0 if detached else 128 + signum)
    finally:
        if proc.poll() is None:
            cleanup(proc.pid)
            proc.wait()


@pytest.mark.parametrize('scope', [False, True])
@pytest.mark.parametrize('redirect_outputs', [False, True])
@pytest.mark.parametrize('finish', ['input', 'ctrl-c'])
def test_piped_stdin_retains_controlling_terminal(tmp_path, scope, redirect_outputs, finish):
    if scope and not systemd_available():
        pytest.skip('user systemd manager unavailable')
    driver, agent = tmp_path / 'driver.py', tmp_path / 'agent.py'
    driver.write_text(DRIVER)
    agent.write_text('''import os, signal, sys
assert sys.stdin.read() == 'piped-input\\n'
def interrupted(*args):
    raise SystemExit(23)
signal.signal(signal.SIGINT, interrupted)
fd = os.open('/dev/tty', os.O_RDWR)
os.write(fd, b'PIPE-AGENT-READY\\n')
assert os.read(fd, 4096).strip() == b'finish'
os.close(fd)
raise SystemExit(17)
''')
    pid, master = pty.fork()
    if pid == 0:
        os.execve('/bin/bash', ['bash', '--noprofile', '--norc', '-i'], environment(tmp_path))
    try:
        read_until(master, b'FIXTURE-PROMPT> ')
        command = "printf 'piped-input\\n' | " + shlex.join([
            sys.executable, str(driver), str(tmp_path / 'ledger'), str(scope), str(agent)])
        if redirect_outputs:
            command += ' >' + shlex.quote(str(tmp_path / 'stdout')) + ' 2>' + shlex.quote(str(tmp_path / 'stderr'))
        os.write(master, (command + '; printf "PIPE_EXIT=%s\\n" "$?"\n').encode())
        read_until(master, b'PIPE-AGENT-READY\r\n')
        os.write(master, b'finish\n' if finish == 'input' else b'\x03')
        output = read_until(master, b'FIXTURE-PROMPT> ')
        assert (b'PIPE_EXIT=17\r\n' if finish == 'input' else b'PIPE_EXIT=23\r\n') in output
    finally:
        cleanup(pid)
        os.waitpid(pid, 0)
        os.close(master)
