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
