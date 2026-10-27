# Operation log (append-only)

## 2026-10-27 — fetch.py SSRF hardening, hardened-base requalification, C7 source-CI PASS, publication

Owner/scope: owner order 2026-10-27 items 2+3 ("Relay-Sicherheit schließen: vm/fetch.py
härten und die betroffene Isolation erneut qualifizieren"; "CI-Evidence integrieren:
C7-Commit und Relay über die kontrollierten Veröffentlichungs- und Review-Gates
übernehmen"). The pre-existing write-time scanner finding `vm/fetch.py:21 [high] SSRF`
(urllib follows redirects without per-hop validation) was remediated in code — not
bypassed: `download()` now uses `ci_util.guarded_urlopen` (https-only, pinned-host
allowlist covering both Alpine publishers, getaddrinfo/is_global resolution check for
both address families, redirects rejected outright); the lock-file publisher checks in
`fetch()` remain as defense in depth. New `GuardedDownloadTests` (7 cases: non-https,
non-allowlisted host, private and loopback resolution, redirect-handler rejection,
global-IP happy path, static fetch.py source assertion); host regression battery
98/98 PASS. Because fetch.py is part of the qualified synthetic implementation
identity, a fresh five-run synthetic requalification was executed on the hardened
implementation (private task root requal-hardening-20261027: 5/5 runs PASS across the
success/failure/timeout/cancel outcome matrix, all in-guest isolation checks PASS per
run, VM_ISOLATION_QUALIFIED=true, 18 implementation files bound by digest including
fetch.py 8ec2843cbe0f8608). Source-CI evidence on the repaired Systems commit:
run e843f434d05a4b6290486a4c3e75f30a pinned to d297a165cd4d5b06c044bfa7b0c9e45859898030,
production plan c1-c8, overall PASS, isolation PASS, 26/26 checks PASS (c7: 1321
passed / 191 skipped / 0 failed), independent verifier ACCEPT, executor file digests
byte-identical to the previously qualified runs. publication-policy.json updated to
MERGE_ELIGIBLE with the owner order as authorization provenance; push + PR executed
under that order. No workflow enablement, runner registration or status writeback.

## 2026-10-21T12:49:06.354550+00:00 — Publication sanitation

Agent: Codex. Scope: fresh relay quarantine candidate with synthetic fixtures only.
The previous local state is preserved outside this publication tree. No rejected local commit
is carried into the new history. Copied source fixtures and derived command mapping inherited
from the remote base are removed from the final tree. No source content or real source digest
is reintroduced in a new commit. Test data and temporary test histories are invented.

Added a read-only publication auditor for full new history, object, tree and added-diff scans;
reports remain in the separate local review packet. Reference disclosure is restricted by
publication-policy.json. Existing remote ancestors and foreign repositories are untouched.
Risk: publication checks do not establish a VM boundary, complete real CI, credential safety,
status writeback or merge eligibility. Tests, exact head and outcomes are supplied in the
local packet; no success is asserted here before execution. No push or workflow run occurred.
Rollback: abandon the new branch while preserving the disabled lane and prior private archive.

## 2026-10-22T03:45:02.569182+00:00 — Offline disposable VM preparation and synthetic qualification

Owner/scope: relay-local VM lifecycle, invented isolation cases and sanitized operations.
Added a public-image lock, private asset verification/builder, bounded QEMU/user-scope
controller and synthetic host-file/TCP/Unix/credential and state-isolation probes.
Images, host details and all evidence stay outside the publication tree. No runner
registration, workflow enablement, source execution, token, status or merge occurred.
Local tests cover input/image/path/resource/qualification boundaries; live cases and
exact code digests are recorded privately. Earlier failed smoke evidence is preserved.
Risk/limits: this is an offline, single-VM RAM-only synthetic profile, not full CI or
credentialed runner admission. Installed OS/package database remains part of the trust base.
Rollback: stop only task-owned scopes and reconcile their inputs; preserve evidence and
keep the legacy runner stopped and dispatch workflows disabled. See VM_LANE.md.

## 2026-10-22 — Bounded cleanup and qualification exit-code repair

Scope: two review findings only. Cleanup steps independently record exceptions and continue
with owned-scope termination, launcher kill/reap, job removal and final inventories. Unknown
scope state, leftover files/processes or cleanup errors deny qualification. Handler and lock
restoration run even if final receipt generation fails. Full qualification CLI exits from the
final VM_ISOLATION_QUALIFIED decision; smoke separately requires one passing case.
Regression tests inject systemctl timeouts, process wait/removal failures and implementation
drift. Earlier live VM evidence remains bound to its earlier implementation; this repair does
not inherit that qualification. Runner and workflows remain disabled. No push or merge.

## 2026-10-27 — Source-CI executor candidate (CI-EXECUTOR-01)

Owner/scope: relay-local source-CI execution lane on the quarantined relay. New trusted
controller modules (pure Python, write-time scanned), mechanical shell launcher, guest
executor and independent evidence verifier. Prepared, validated and digest-bound private
artifacts: source snapshot of Systems 5b4d9f0c7c0748c223cf2f5fe3a9acacd245e294 bound via
git blob object ids and a full sha256 inventory; pinned node v24.19.0 and pnpm 10.5.2
(digest-verified vendor tarballs); offline dependency store built with lifecycle scripts
disabled on the host; ext4 workspace image; CI guest initrd. Real checks c1-c8 executed in
the disposable VM on the pinned commit with authentic exit codes, per-run isolation
canaries and fail-closed aggregation. Two host-side near-miss incidents during preparation
(unauthorized pnpm prompt answered by default in the workspace root; staging node_modules
leak into the workspace image) were caught by the controller's own fail-closed checks or
were no-ops; both root causes are fixed in code. No workflow enablement, runner
registration, status writeback, source merge, push or token use occurred. Private assets,
ledgers and run evidence stay outside the publication tree.
