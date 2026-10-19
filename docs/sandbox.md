# Namespace capability checks

Doctor reads relevant user-namespace sysctls when present and runs this
capability probe without changing settings:

```sh
bwrap --unshare-user --unshare-net --ro-bind / / --proc /proc --dev /dev -- /bin/true
```

A failed probe does not by itself prove AppArmor was responsible. Known uid-map,
loopback and namespace-denied messages are classified; unknown failures remain
unknown. Missing sysctl files are not interpreted as a zero or a one.

On Ubuntu-derived systems with AppArmor restrictions, an administrator can review
the distribution's targeted bwrap profile in the apparmor-profiles package and
its applicability to the installed distribution. This is an administrator action
requiring sudo, not an action performed by aeg. Do not disable the system-wide
user-namespace restriction as a routine fix. Observe mode remains an option.

Enforcement is not implemented here. The later confinement draft must test the
real network relay and nested bwrap workloads on supported hosts, skip capability
tests explicitly when unavailable, and fail before launching if confinement
cannot be established. aeg never changes system settings.

Reference: https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces
