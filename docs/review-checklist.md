# First draft review scope

Implemented: Python 3.11 core, reserved 3.12 inspection extra, argparse and both
entry points; explicit observation limits; subreaper and optional systemd scope;
private SQLite as the sole store; authenticated proxy; public-address validation;
best-effort attribution; SNI mismatch reporting; storage-host label boundaries;
agent exit status; signals; read-only namespace and local proxy probes; pinned
CI actions, guarded installs, Git and distribution scans.

Intentional refinements to the design:

- Unauthenticated proxy clients receive 407 rather than being relayed. Their
  attempts remain visible as metadata warnings.
- The banner does not recommend an unavailable enforcement switch or promise
  complete coverage. Reserved unsupported switches fail before agent launch.
- HTTP paths are reduced to templates, stricter than merely dropping queries.
- Namespace failures do not claim AppArmor was the cause without evidence.
- No source fixtures require a Push Guard exception; the allow list has no
  entries. Any future exception must name its exact fixture path and rule.

Deferred to draft two: bypass polling (loopback excluded and SSH classified),
upload thresholds, new destinations and settings expectations.

Deferred to inspection/enforcement drafts: bounded JSON value scanning using
only Push Guard's public API; secret-rule filtering; no auth-header scanning;
alert/hold/block policy; compression caps and storage fail-closed rules; bundle
classification; CA ownership/key safety, combined trust and pinning passthrough;
network namespace relay, confinement and nested sandbox tests. Exact-span
redaction needs a separately reviewed public Push Guard API and release.

Release gate: the publish workflow is disabled by default. Before an approved
release, verify the pypi environment's required reviewer, configure Trusted
Publishing and private terms, review the stable-version diff and enable the
release variable explicitly. No release is part of this draft.

Dependency release preparation: the runtime minimum is now stable Push Guard
0.4.3 and CI installs the published package. Provider-label canaries run against
the installed dependency. Private terms are required for every CI distribution
scan. Publishing remains disabled; environment approval and Trusted Publishing
must be verified before the owner authorizes a release.
