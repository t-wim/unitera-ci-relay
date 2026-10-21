# Relay quarantine publication candidate

This candidate contains original containment logic, invented test fixtures and sanitized
operating documentation. It is ready for a separate publication review only after the
local review packet has been checked. It does not authorize a push, dispatch or merge.

Both dispatch entrypoints validate the relay/source/base input formats and relay SHA,
then fail unconditionally before source, credential or Docker operations. They remain
manual-only. The legacy runner must stay stopped and both workflows must stay disabled.

`MERGE_CONTROL = PROCESS_ENFORCED`. Platform enforcement is not claimed.
Isolation, real CI parity, source CI, writeback and merge eligibility remain unqualified.

## Files and disclosure

`publication-policy.json` contains the exact allowed file inventory and only the necessary
real destination, branch and already-published relay base reference. No real source-repository
identity, source commit, source workflow digest, source command inventory, host inventory or
private source snapshot is embedded. Fixture content and its digests are entirely synthetic.
Standard Git author/committer and signing provenance require review as commit metadata.

The inherited application fixtures and mapping are removed from the resulting tree. Existing
destination ancestors are not rewritten. No rejected local commit is an ancestor of the new
candidate. The prior local repository and its private backup are outside this publication path.

## Checks

Prerequisites: Python 3, PyYAML, Git and Bash already available locally. No source install,
network access or source command execution is required for these checks.

```sh
python3 test_candidate.py
python3 inventory.py
git diff --check
```

The inventory example validates invented file hashes and preserves matrix, condition and
step data. It does not model an application's real gates. Expressions remain inert data.
Tests also construct temporary synthetic Git histories to verify that private content in an
intermediate commit is detected even when removed from the final tree.

`audit_publication.py` reads every proposed commit tree, new Git object, added diff line and
commit identity against a strict file allowlist, credential patterns and an external private
corpus/deny-list. Its report contains paths, digests and rule names, never matched contents.
Private corpora, deny-lists and real review evidence must stay outside this repository.
Pattern/corpus checks have limits and cannot prove the absence of all unknown private data.

See [repair state](docs/REPAIR_STATE.md) and [operation log](docs/VORGAENGE_LOG.md).
Rollback: abandon this unmerged candidate while retaining the disabled execution lane.
Never re-enable the old workflows as a fallback. No VM, credential, provider or source
repository changes are part of this sanitation slice.
