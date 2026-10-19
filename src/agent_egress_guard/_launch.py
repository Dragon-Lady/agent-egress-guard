"""Wait for terminal ownership before executing an interactive command.

The helper reads only its inherited readiness pipe; it never reads the terminal
while its process group is in the background. No shell or command logging.
"""
import os
import sys


def main():
    fd = int(sys.argv[1])
    try:
        ready = os.read(fd, 1)
    finally:
        os.close(fd)
    if ready != b"1":
        return 3
    try:
        os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
    except OSError:
        print("aeg: agent executable could not be started", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
