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

## Scope: independent source-CI executor (CI-EXECUTOR-01 candidate, 2026-10-27)

Additive to the quarantined relay: a source-CI lane that executes real Unitera_Systems checks
on an exactly pinned commit inside a disposable VM. Trusted pure-Python controller modules
(prep/image/monitor/manifest/verify), a mechanical shell launcher, a guest executor that never
evaluates shell strings, and an independent evidence verifier with run-id replay protection.
Source bound via git blob object ids plus a full sha256 inventory (re-verified inside the
guest); toolchain node v24.19.0 / pnpm 10.5.2 digest-pinned and guest-verified; offline
dependency store built on the host with lifecycle scripts disabled; ext4 workspace image with
qcow2 per-run overlays; per-run isolation canaries gate the overall verdict. The synthetic
five-run profile and its qualified implementation remain untouched; the source-CI profile is
qualified by its own battery (host regression tests plus live qualification runs). First
live run at 5b4d9f0c executed checks c1-c8 with authentic exit codes: c1-c6 and c8 PASS,
c7 (vitest unit baseline) FAIL with 8 mock-based test failures in the journal-custody area —
a real candidate regression signal at the pinned release SHA, since GitHub Actions has been
startup-blocked since 2026-10-21 and could not gate the affected merges. No workflow
enablement, status writeback, merge, push, token or production effect is part of this
candidate; publication stays unauthorized until the battery and review close.
