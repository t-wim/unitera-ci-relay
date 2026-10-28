# UNITERA Marketing Agent Team — t-wim relay admission proposal

**State: QUARANTINED / REVIEW ONLY / NOT ACTIVE SOURCE CI.**

Target source repository: `baum777/unitera_marketing_agent-team`.
Relay: `t-wim/unitera-ci-relay`; runner labels:
`self-hosted, Linux, X64, unitera-ci, relay`.

The marketing repository's existing hosted `validate.yml` uses `ubuntu-latest` and
its Actions runs have ended with `startup_failure`. Changing that source workflow's
`runs-on` field alone would not grant it access to a separately repo-scoped t-wim runner.

This proposal adds **only a quarantined, exact-pin workflow_dispatch admission entrypoint**.
It validates source and relay commit syntax, verifies the actual relay commit is pinned,
and deliberately exits nonzero. It never executes untrusted source on the runner host,
downloads or checks out code, sends a source status, grants approval, or calls an AI provider.

## Proposed Python test parity (isolated VM only)

```bash
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts tests
```

The fixed, non-executing test plan is in `vm/marketing_ci_contract.py`, with
offline checks in `test_marketing_ci_contract.py`. It does not replace the
source repository's own workflow or its future successful CI evidence.

## Separate admission gates before real source tests

1. **t-wim relay-owner review and authorization.** Current `publication-policy.json`
   explicitly allowlists only the previous source-CI files/scope; do not silently
   expand that policy or treat publication of this branch as authority to activate.
2. **Python3 + stdlib guest runtime, pinned by digest**, with all dependencies and
   binaries verified. The existing source-CI VM profile is hard-bound to
   `baum777/Unitera_Systems`, Node and pnpm; it cannot be treated as an already
   qualified Python marketing executor.
3. **Exact-source custody**: reviewed 40-character source commit, Git archive/blob
   identities, independent SHA-256 file inventory, and in-guest re-verification
   before source code runs. No untrusted source script on the self-hosted host.
4. **New guest-profile qualification** covering host files, Unix sockets, LAN and
   metadata access denial, credentials/agent isolation, resource limits, timeout,
   SIGTERM cleanup and fresh successor. Prior synthetic qualification is not
   automatically qualification for this new profile.
5. **Independent evidence verifier** checks actual exit codes, timeouts, digests,
   isolation results and anti-replay; no success from log strings alone.
6. **Commit-status writeback** (optional, separately gated) must be SHA-bound,
   least-privileged, audited and negatively tested before activation.
7. **Explicit operator/owner release** is required for changing the quarantine
   workflow. No branch policy, merge eligibility or deployment is implied.

## Source and security exclusions

Do not import `.env`, `OPENROUTER_API_KEY`, `ZAI_API_KEY`, `private/`, `runs/`
or GitHub account credentials into the VM. All marketing CI tests run offline
with external egress denied, and use mocked model/provider interfaces.
Do not enable model calls, publishing, external outreach, self-modification,
paid fallback, runner registration or host-wide cleanup.

## Candidate regression only

```bash
python3 -m unittest -v test_marketing_ci_contract
```

A passing candidate test does **not** prove source CI passed. Until independent
isolation/parity/owner gates close, the workflow ends at
`MARKETING_CI_QUARANTINED` by design.
