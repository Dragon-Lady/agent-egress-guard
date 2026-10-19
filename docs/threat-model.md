# Threat model

The user explicitly launches a CLI under an observe-only wrapper. The intended
benefit is visibility into cooperating clients' proxied connections, including
descendants that outlive the top-level CLI. The proxy does not break TLS.

Observation is best-effort. Traffic that ignores proxy variables can be missed;
this draft does not include bypass polling or enforcement. Later polling also
misses short-lived connections. An untrusted same-user agent can read proxy
credentials, use another daemon, manipulate its cgroup or bypass the proxy.
An authenticated local proxy is not containment. Future confinement must be
evaluated separately; it must not promise universal coverage without evidence.

Proxy destinations are DNS-resolved, every answer is checked, then a validated
numeric address is used for connection. Non-public targets and unauthenticated
clients are refused. HTTP supports absolute-form requests; HTTPS uses CONNECT.
The TCP relay keeps payloads in transient bounded chunks and writes no bodies,
headers or query strings to the ledger. HTTP paths are templates because paths
can themselves contain sensitive identifiers. Hostnames and executable basenames
are still sensitive metadata; keep local reports private. Known secret-shaped
labels are redacted using Push Guard's public API, which is heuristic and does
not cover arbitrary encoded secrets.

SNI parsing is opportunistic and limited to the first complete record. Encrypted
or fragmented ClientHello can leave it unavailable. A mismatch is an observation,
not proof of malicious traffic. Byte counts describe tunneled or forwarded wire
bytes, including TLS/HTTP overhead; CONNECT setup bytes are excluded.

No network calls originate from reports, classification, storage or imports.
The proxy performs DNS and connections requested by authenticated clients.
Doctor's proxy probe uses loopback only and never resolves its fixture hostname.
There is no remote telemetry or update check.

Later inspection must use a protected per-user CA directory (0700), an exclusive
0600 key, separate child certificate and combined trust bundle. It must never
use a system-wide CA or expose the key to children. Pinning/rustls-webpki,
Electron/NSS and JVM clients require explicit coverage warnings. No CA is
generated in this draft. The published Push Guard dependency does not yet
include the separate provider-pattern repair; no secret-blocking claim is made.
