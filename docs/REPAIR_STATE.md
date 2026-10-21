# Scope: publication sanitation only

Decision: make a bounded quarantine candidate independently reviewable without exporting
private source snapshots, source-derived command inventories or host/credential evidence.
Owner: the relay repository identified by publication-policy.json. No shared-core, source,
Registry or personal credential change is included.

Implementation: a fresh clone starts from the destination's current main commit. The old
local repository remains preserved separately. The new publication branch does not descend
from that rejected local candidate and carries no private backup refs, alternate object store,
archive or copied evidence. Existing remote history is retained; final-tree inherited source
fixtures are removed. Rewriting already-published remote history is outside this task.

Contract: all proposed commit trees must match the strict file allowlist; tests use only
invented fixtures. Real bindings here are limited to the destination repository, local branch
name and the base already present at that destination. Source bindings remain execution-time
inputs rather than embedded private information. Synthetic fixture digests disclose no real
source binding. The separate local review packet records exact head, complete file inventory,
new commit/object inventory, full diff digest and validation results.

Gate: run test_candidate.py; inspect every new commit/tree/object and full diff; scan the
resulting tree and added content against known private corpus, private-reference deny-list
and credential patterns. A clean scan is not automatic approval or an exhaustive privacy proof.
No push is performed by these tools. Publication review and authorization remain separate.

Lifecycle state:

- ISOLATION_QUALIFIED: NOT_QUALIFIED
- CI_PARITY_QUALIFIED: NOT_QUALIFIED
- EXACT_SOURCE_CI_PASS: NOT_RUN
- STATUS_WRITEBACK_VERIFIED: NOT_VERIFIED
- MERGE_ELIGIBLE: false
- MERGED: false

No VM was created or qualified. Full CI execution mapping, credential custody, trusted
producer integration, independent live qualification and merge/deployment gates remain open.
The existing runner/workflow shutdown posture is preserved. No source status, merge or
production/pilot activation follows from this sanitation.

Next gate: review the exact local publication packet for this head and destination.
Do not push before that review succeeds. Preserve the previous candidate locally even if
this branch is abandoned. A later code change requires renewed tests and publication review.
