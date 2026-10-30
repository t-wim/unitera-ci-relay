# MAWS full-CI relay profile — admission candidate (NOT EXECUTABLE)

**Owner gate:** t-wim. Class: candidate, separate from Unitera_Systems, baum-os W2 and Marketing qualification. State: DRAFT / VM NOT QUALIFIED / NO RUNNER ADMISSION / NO STATUS WRITER / NO CI PARITY CLAIM.

## Purpose

Design a future pinned MAWS source-CI VM profile that will replace every check in baum777/model-agnostic-workflow-system's hosted .github/workflows/loop-repo-ci.yml, plus all applicable MAWS governance/skill promotion checks. The MAWS source-side proposal is PR #128 (review/maws-sovereign-ci-parity-20261030). Its required-gates.json contains 23 exact hosted steps (2 infrastructure, 21 command groups) and 20 additional MAWS policy gates.

The candidate module vm/maws_gate_contract.py accepts a supplied data-only MAWS source inventory, rejects incomplete or forged self-admission and computes a gate-set SHA-256. It CANNOT call the VM/runner, execute an npm/script, trust source content, publish a status or authorize removal of hosted CI. Current tool scripts and quarantine workflows remain unchanged.

## Existing relay constraints verified

- Main is hard-bound to baum777/Unitera_Systems in vm/ci_prep.py and vm/ci_manifest.py; production plan c1–c8 in vm/ci_plan.py covers only a small Unitera subset.
- Existing vm/ci-lock.json is Node 24.19.0 + pnpm 10.5.2, not the Node24/npm source profile of MAWS.
- The baum-os profile is on open PR #9 and explicitly partial (1/4 jobs, 5/17 steps); neither it nor the synthetic five-run qualification proves MAWS parity.
- Source relay actions workflow_dispatch jobs fail closed under quarantine; there is no incoming MAWS PR trigger or admitted source-SHA status publisher.
- Relay publication-policy.json on main does NOT allow these new files; this draft requires separate t-wim approval of an allowlist extension and any future runtime implementation.
- Existing source branch ruleset lacks required_status_checks: a passing relay must be enforced in MAWS's source repository, not inferred from VM evidence.

## Required MAWS implementation slices

W0 **Source inventory admission:** verify actual MAWS source commit/tree, source manifest bytes and exact legacy workflow Git blob before accepting the 23+20 gate inventory. Independent source-side parity validation must agree. This module alone is not that evidence.

W1 **VM/toolchain:** new MAWS-scoped source origin and source-custody verifier; complete Git history for merge:audit; pinned Node24/npm/Python3/git/sh/find/xargs/npm cache. No untrusted source on t-wim host; VM has no tokens, private files, host sockets or network egress by default.

W2 **Execute exact all-gate plan:** realize actions/checkout and setup-node with isolated equivalent; execute each hosted multiline run body as digest-bound file in guest only; include all applicable supplemental security/skill frontdoor/instruction/registry gates. Do not skip or reduce a command. SkillSpector and SkillEvaluator exact-target scanner packages require their own external-extension risk admission and pinned dependency/toolchain closure.

W3 **Independent qualification:** negative inputs, tampered digest, missing/extra/duplicate gate, unknown conditional applicability, fake PASS, timeout, cancellation, cleanup, source mismatch, no full ancestry, denial of access to runner host/secrets, fresh successor. Independent verifier rederives raw exit/timeout/evidence and gate-set digest, records immutable run ledger and cannot elevate a missing receipt to PASS. Requalify the final changed VM image five-run battery and prove two fully reconciled green MAWS source runs (candidate cutover rule).

W4 **Dispatch/status authority:** reviewed event dispatcher delivering source PR/push exact SHAs to t-wim workflow_dispatch, plus separate least-privileged SHA-bound status writer operating only after verifier. Security of signature/replay, source head/merge-base, rate limits and writeback must be negatively tested.

W5 **Enforcement and removal:** require the relay status in MAWS main ruleset, show failed/replayed/missing check blocks merges, obtain independent t-wim and MAWS owner approvals, then remove the old hosted source workflow in a separate PR. Rollback requires a merge freeze and owner-reviewed restoration, not lowering the status requirement.

## Acceptance

FULL_CI_PARITY requires one-to-one coverage of legacy step IDs 01..23, explicit policy for supplemental gates 01..20 with exact change applicability, independent execution evidence and zero unknown/skip for mandatory checks. Runner availability alone is insufficient.

At present: inventory candidate only. No VM, runner, status, trusted GitHub App dispatch, hosted CI deletion, merge or authority changes were made.

Local offline candidate test to execute independently (NOT claimed executed here):

    python3 -m unittest -v test_maws_gate_contract

Publication: t-wim owner must reconcile publication-policy.json and other branch changes before any merge. CI parity and isolation gate outcomes are BLOCKED until actual qualification evidence exists.
