# Agent Egress Guard

A local, Linux-first egress ledger for coding-agent sessions.

Development is in draft pull requests. No release is available yet. This first
draft records connections through an authenticated loopback proxy. It does not
decrypt TLS, inspect bodies, detect proxy bypasses, or enforce an egress policy.

**Observe mode is best-effort:** traffic that ignores proxy settings can be
missed. Observed bytes are not total egress. No recorded connections is not
proof that no data left the machine. Enforcement is a later stage, not a
working `--block` switch in this draft.

## Development install

From a reviewed checkout, using Python 3.11 or newer:

```sh
sfw pipx install .
aeg doctor
aeg run -- your-agent-command
aeg report last
aeg report last --json
aeg sessions
```

Both `aeg` and `agent-egress-guard` are installed. The `inspect` extra is reserved
for a later implementation; installing it does not enable inspection today.

## What the first draft records

One private SQLite store contains session times, destination hostname and port,
connection byte counts, best-effort PID/executable basename, and storage-host
classification. HTTP paths are reduced to a template and queries are removed.
Command arguments, environment values, headers, bodies and body fingerprints
are not written to the store. TLS byte counts include protocol overhead, not
just application payload. A complete first-record TLS ClientHello can provide
SNI; fragmented ClientHello or encrypted SNI may leave it unknown.

State lives under `$XDG_STATE_HOME/agent-egress-guard`, or
`~/.local/state/agent-egress-guard`. The directory is mode 0700; SQLite files are
mode 0600. Unsafe ownership, permissions and symlinks are rejected. Reports are
local; there is no telemetry, update check or remote report destination.

The proxy resolves and relays only requests from clients with its per-session
credential. It refuses private, loopback, link-local and other non-public
destinations, including mixed public/private DNS answers. Unauthenticated
attempts are refused and counted as connection warnings. The credential is
passed through proxy environment variables, never command arguments.

## Session lifetime and controls

The wrapper becomes a Linux child subreaper and uses a user-systemd scope when
available. It waits for remaining descendants, keeping the proxy alive after
the top-level command exits. Without a user manager, it falls back to subreaper
tracking and says so. Existing daemons outside the session remain outside its
coverage. A same-executable process check warns about possible existing daemons.

Stdio stays attached to the original terminal. SIGINT, SIGTERM and SIGWINCH are
forwarded to tracked processes. End-of-session output avoids interrupting the
agent UI; long-lived descendants produce a periodic liveness message.

`run` returns the agent's exit status by default. `--fail-on-alert` returns 1 on
recorded connection warnings. `report` returns 1 for these warnings, 0 otherwise;
neither result means the session was safe or contained. Environment/state errors
return 3. `doctor` returns 3 when any optional capability is missing; observe
mode can still work. The proxy probe checks Python urllib only, not every client.

## Coverage limits

- Both cases of HTTP/HTTPS/ALL proxy variables are set, plus `grpc_proxy` and
  `NODE_USE_ENV_PROXY=1`. Inherited `NO_PROXY` is replaced with
  `localhost,127.0.0.1,::1`; only its old length is recorded.
- Node's supported versions need environment-proxy support; older releases can
  bypass. curl needs lowercase `http_proxy`. Rust reqwest can disable proxies;
  tungstenite does not automatically use these variables. Custom Go transports
  and gRPC clients may behave differently.
- QUIC/HTTP3, raw sockets, direct DNS and SSH are outside this proxy's coverage.
  DoH via a compliant HTTP proxy appears as encrypted traffic; direct DoH can
  bypass. Loopback traffic intentionally bypasses and is not treated as an alert.
- PID attribution races with short connections. Processes launched through an
  existing daemon or D-Bus may leave the tracked scope. Same-user adversarial
  processes can read inherited credentials; this is not a sandbox.
- Proxy bypass polling, volume/new-host alerts and settings comparisons are
  the next draft. TLS inspection, CAs and confinement are later stages.

See [threat model](docs/threat-model.md), [sandbox checks](docs/sandbox.md) and
[review checklist](docs/review-checklist.md). All changes remain draft until
reviewed and approved. Publication is disabled and separately gated.
