# Unitera CI relay

The repair candidate binds execution to `expected_relay_sha` before source
checkout or credential use. Source PR identity/reviews are checked in a separate
job without executing candidate code. Canonical jobs consume no source API token.

## Candidate state

`CANDIDATE_NOT_LIVE_QUALIFIED`. This change is not pilot activation, merge
authorization, platform branch protection, or completed CI parity.

Required inputs: `source_sha`, `base_sha`, `expected_relay_sha`, `source_pr`.
Source workflow SHA-256 pins prevent unreviewed source CI changes from inheriting
this mapping. The added commands cover consumed-vendor integrity, Mimosa,
hosted Web/BFF, governance validation, all 17 governance matrix commands, and
the RLS gate. Execution is serial and fail-closed; aggregate CI job dependencies
are represented by sequential successful steps. Artifact uploads and the source
trusted-evidence producer are not replicated by this candidate.

`UNITERA_SOURCE_READ_TOKEN` is a proposed read-only credential for source PR and
review reads, referenced only in the trusted review job. It is NOT created,
installed or verified by this patch. The workflow refuses credential use unless
`UNITERA_RELAY_CREDENTIAL_ISOLATION_QUALIFIED` is explicitly `true`.
That variable is an admission switch, never proof: independent host/SSH/Docker/
credential-isolation assessment must precede setting it. The persistent runner
and Docker socket can expose host credentials to untrusted source code; separate
jobs alone do not establish isolation. Do not dispatch this candidate before
that qualification. No existing secret is read by this implementation run.

## Validation

`python3 test_candidate.py` verifies the pin dependency, wrong-pin rejection,
17-command inventory, source-workflow hash bindings, mandatory security steps,
shell syntax, self-hosted labels and separation of source code from API tokens.
These are local structural and shell-contract tests, not a live runner proof.

The two `source-*.yml` files are exact, dated test fixtures from
`baum777/Unitera_Systems@3fc6a0914a341138ee547599d2044e2f6f0992be`;
they do not execute as GitHub workflows. `gate-mapping.json` records their pins.

## Remaining closure gates

1. Independent review of this exact relay head and source PR head.
2. Independently verified credential/host isolation and bounded read-token custody.
3. Live wrong-relay-SHA negative test, then exact-source full run.
4. Honest exact-source pending/final status writeback from a separate trusted
   reporter; no write token may be exposed to source code.
5. Artifact/producer integration and complete parity review; fresh source refs.
6. Owner-controlled process-mode merge with preserved deployment dispositions.

No automatic PR triggering, status writeback, relay merge, source merge,
secret creation, runner registration, billing or source workflows changed.
Rollback: abandon the repair branch; after separately authorized adoption,
revert the repair commit. Never fall back silently to a paid runner.
