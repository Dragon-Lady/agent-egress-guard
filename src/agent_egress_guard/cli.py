"""Literal CLI controls; unsupported modes fail before launching an agent."""
import argparse
import asyncio
import json
import sqlite3
import sys

from . import BANNER, __version__
from .doctor import INSPECT_HELP, inspect_available, print_doctor
from .ledger import Ledger, StateError
from .session import run


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default echoes untrusted argv, which can contain credentials.
        self.print_usage(sys.stderr)
        self.exit(2, "aeg: invalid arguments; use --help for supported controls\n")


def main(argv=None) -> int:
    parser = Parser(prog="aeg", description="Best-effort, local egress observation for a launched CLI.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="action", required=True, parser_class=Parser)
    runner = commands.add_parser("run")
    runner.add_argument("--fail-on-alert", action="store_true", help="exit 1 for observed connection warnings")
    for flag in ("inspect", "block", "confine"):
        runner.add_argument("--" + flag, action="store_true", help="reserved; unavailable in this draft")
    runner.add_argument("command", nargs=argparse.REMAINDER)
    reporter = commands.add_parser("report")
    reporter.add_argument("session", nargs="?", default="last")
    reporter.add_argument("--json", action="store_true")
    listing = commands.add_parser("sessions")
    listing.add_argument("--limit", type=int, default=20)
    commands.add_parser("doctor")
    args = parser.parse_args(argv)
    if args.action == "doctor":
        return print_doctor()
    if args.action == "run":
        if args.inspect or args.block or args.confine:
            if args.inspect and not inspect_available():
                print(INSPECT_HELP, file=sys.stderr)
            print("Requested mode is not implemented; no agent was launched.", file=sys.stderr)
            return 3
        if args.command[:1] == ["--"]:
            args.command = args.command[1:]
        if not args.command:
            parser.error("command missing")
    ledger = None
    try:
        ledger = Ledger()
        if args.action == "run":
            _, code = asyncio.run(run(args.command, ledger, fail_on_alert=args.fail_on_alert))
            return code
        if args.action == "sessions":
            if not 1 <= args.limit <= 1000:
                parser.error("limit out of range")
            print(json.dumps(ledger.sessions(args.limit), indent=2))
            return 0
        report = ledger.report(args.session)
        report["coverage"] = BANNER
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(BANNER)
            print("Session:", report["session"], "tracking:", report["tracking"])
            print("HOST\tCLASS\tBYTES UP\tBYTES DOWN\tCONNECTIONS")
            for host in report["hosts"]:
                print("\t".join(str(host[key]) for key in ("host", "class", "bytes_up", "bytes_down", "connections")))
            print("Connection warnings:", report["connection_warnings"])
            print("No recorded connections does not establish that no data left the machine.")
        return 1 if report["connection_warnings"] else 0
    except (StateError, OSError, ValueError, sqlite3.Error):
        print("aeg could not complete the operation; check command availability and private state permissions.", file=sys.stderr)
        return 3
    finally:
        if ledger:
            ledger.close()
