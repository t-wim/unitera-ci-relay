# Scope: disposable offline VM preparation and synthetic qualification

Owner: relay repository; base and allowed files are in publication-policy.json. Changes are
limited to free local VM lifecycle code, synthetic probes/tests and sanitized operating docs.
The existing quarantined workflows are unchanged. Shared core, Source, Registry, credentials,
runner registration, status reporting, merge and production state are not modified.

Decision: a fresh verified RAM-only VM per synthetic job, Docker only in the VM, no personal
mounts/agents/credentials and no host/LAN/metadata network path. A dedicated rootless QEMU
process is confined by user/network/PID namespaces, a minimal host filesystem view, QEMU
seccomp and hard user-scope resource limits. The virtual NIC remains live; host services are
positively tested on the host and denied in the guest. This is more than a NAT assumption.

Contract: vm/guest-init.sh and the reviewed image/controller digest must match private live
evidence for success, deliberate failure, timeout, SIGTERM cancellation and a fresh successor.
All twenty named guest checks, real cgroup limits, preserved input hashes and absence of
process/scope/job-directory leftovers are mandatory. Failed or incomplete ledgers deny
VM_ISOLATION_QUALIFIED. Every source-derived or image/host-specific artifact remains private.

This offline synthetic VM profile is not an admitted runner or general-purpose online lane.
Network access is denied entirely, including external dependencies. Full real CI resource
needs and gate parity are not measured here. Future source/dependency ingestion and online
egress require their own bounded review and negative tests.

CI_PARITY, SOURCE_CI and WRITEBACK remain open; no source merge eligibility or activation is
created. Next gate for this slice is exact-head code/evidence and publication review. No
push, merge, tokens or qualification variables are authorized by this preparation task.
