# Operation log (append-only)

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
