"""One private SQLite store. Payloads, command lines and credentials never enter it."""
import os
from pathlib import Path
import sqlite3
import stat
import time
import uuid

from push_guard import scan_text_for_secrets

from .classify import host_class


class StateError(RuntimeError):
    pass


def safe_label(value: str | None) -> str | None:
    if value is None:
        return None
    if any(f.rule_id.startswith("secret.") for f in scan_text_for_secrets(value)):
        return "<redacted>"
    return "".join(c if c.isascii() and c.isprintable() else "?" for c in value)[:253]


def state_root() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "agent-egress-guard"


def check_private(path: Path, directory: bool = False) -> None:
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    mode = 0o700 if directory else 0o600
    if not expected(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode:
        raise StateError("state ownership, permissions or symlink check failed")


class Ledger:
    def __init__(self, root: Path | None = None):
        self.root = root if root is not None else state_root()
        # Process-wide private umask also protects SQLite journal/temporary files.
        os.umask(0o077)
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        check_private(self.root, directory=True)
        path = self.root / "ledger.sqlite3"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        for candidate in (path, Path(str(path) + "-journal"), Path(str(path) + "-wal"), Path(str(path) + "-shm")):
            if candidate.exists() or candidate.is_symlink():
                check_private(candidate)
        self.db = sqlite3.connect(path)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, started REAL, ended REAL, exit_code INTEGER,
                tracking TEXT, old_no_proxy_length INTEGER);
            CREATE TABLE IF NOT EXISTS connections (
                session TEXT, started REAL, duration REAL, host TEXT, port INTEGER,
                method TEXT, path_template TEXT, bytes_up INTEGER, bytes_down INTEGER,
                pid INTEGER, exe TEXT, class TEXT, status TEXT, sni TEXT);
        """)

    def start(self, tracking: str, old_no_proxy_length: int) -> str:
        session = uuid.uuid4().hex
        self.db.execute("INSERT INTO sessions VALUES (?, ?, NULL, NULL, ?, ?)",
                        (session, time.time(), tracking, old_no_proxy_length))
        self.db.commit()
        return session

    def finish(self, session: str, code: int) -> None:
        self.db.execute("UPDATE sessions SET ended=?, exit_code=? WHERE id=?", (time.time(), code, session))
        self.db.commit()

    def connection(self, session: str, *, started: float, duration: float, host: str,
                   port: int, method: str, path_template: str, bytes_up: int,
                   bytes_down: int, pid: int | None, exe: str | None,
                   status: str, sni: str | None = None) -> None:
        # Fixed schema; never accept arbitrary event dictionaries or exception text.
        self.db.execute("INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (session, started, duration, safe_label(host), port, method,
                         path_template, bytes_up, bytes_down, pid, safe_label(exe),
                         host_class(host), status, safe_label(sni)))
        self.db.commit()

    def report(self, session: str = "last") -> dict:
        if session == "last":
            row = self.db.execute("SELECT id FROM sessions ORDER BY started DESC LIMIT 1").fetchone()
            if row is None:
                raise StateError("no recorded sessions")
            session = row[0]
        row = self.db.execute("SELECT id, started, ended, exit_code, tracking FROM sessions WHERE id=?", (session,)).fetchone()
        if row is None:
            raise StateError("session not found")
        hosts = self.db.execute("""SELECT host, class, SUM(bytes_up), SUM(bytes_down), COUNT(*)
            FROM connections WHERE session=? GROUP BY host, class ORDER BY host""", (session,)).fetchall()
        problems = self.db.execute("SELECT COUNT(*) FROM connections WHERE session=? AND status NOT IN ('ok', 'sni_unavailable')", (session,)).fetchone()[0]
        return {"session": row[0], "started": row[1], "ended": row[2], "exit_code": row[3],
                "tracking": row[4], "mode": "observe-best-effort", "connection_warnings": problems,
                "hosts": [dict(zip(("host", "class", "bytes_up", "bytes_down", "connections"), h)) for h in hosts]}

    def sessions(self, limit: int = 20) -> list[dict]:
        return [dict(zip(("session", "started", "ended", "exit_code"), row)) for row in
                self.db.execute("SELECT id, started, ended, exit_code FROM sessions ORDER BY started DESC LIMIT ?", (limit,))]

    def close(self) -> None:
        self.db.close()
