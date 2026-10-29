# baum-os W2 qualification candidate

Base: t-wim/unitera-ci-relay `37d3edd38e736f3a05070c80bdf5a875ae9dc7cf`.
Candidate only; not committed, adopted, admitted or VM-qualified.

- Reuses the existing VM lane; no second execution architecture or workflow changes.
- Carries the pre-existing local launcher/independent-caller-pin repair from local
  `3297386e724ec5fd76a0870e1105fea29d09d8ee`, reconciled onto the current remote base.
- Hardens `ci_verify.py`: mandatory independent pins and caller-selected plan, structural
  schema and mandatory envelope set, path/link checks, duplicate raw protocol detection,
  mandatory EXIT/TMO, and explicit INDETERMINATE on inaccessible raw evidence. No ledger
  append is requested by this W2 run on historical evidence.
- Adds data-only `baum_ci_custody.py`: exact origin/commit/tree/blob inventory, streaming
  SHA-256 verification without working-tree inputs or source execution; full three-workflow,
  four-job, 17-run-step plan retaining actions, if/env/needs/summary context. Symlinks and
  gitlinks are inventoried as Git data, never materialized or followed. Source preparation
  code changes are detected. Unsupported guest requirements remain blockers.
- Adds `baum_status_candidate.py`: validates a blocked NOT_SENT payload; no HTTP writer,
  tokens, status publication or locally fabricated authority.
- Focused synthetic tests cover pins, nested repository launcher identity, schema/protocol/
  envelope manipulation, omitted EXIT/TMO, replay, cleanup, source archive/ref/origin/path/
  symlink handling and forbidden status-success/self-authorization.

Actual baum-os Source CI has not run. The current guest is Systems-specific, pnpm 10.5.2,
without the required Bash/Git/pnpm 11.9 closure and authenticated fresh Git-history/gitlink
basis. Guest source currently runs as root; supervisor/plan/console privilege separation and
complete independently preserved job logs must be qualified before accepting untrusted PRs.
Never equate `--ignore-scripts` alone with denial of all source-controlled package-manager
configuration/hooks during host preparation. No host package preparation was executed here.

KVM API availability is capability evidence only. t-wim custody, host execution authority,
source/review/status authority and current-image five-run qualification remain separate.
Historical five-run data and signed image provenance cannot admit this changed candidate.

Status of this document: the paragraphs above describe the candidate **as authored**
(historical snapshot at `0f10225c`, before any publication review). Since then the W2.2
owner order of 2026-10-29 authorized publication review, and `publication-policy.json`
was reconciled accordingly — first to base `37d3edd`, then, after marketing PR #8 merged,
replaced verbatim with the owner-provided combined version for base `58ecbb7d`
(review 5696470035: baum-os files inside the reviewed allowlist, `MERGE_ELIGIBLE=false`,
combined publication review requiring explicit owner approval). The qualification and
readiness statements in this file remain revision-scoped to the evidence recorded in
`docs/SOURCE_CI.md`, `docs/VORGAENGE_LOG.md` and the private ledgers; they are not
activation, admission or merge claims.

Source/VM manifest integration, full image/toolchain/plan trust anchors, non-root guest
supervision, complete raw job logs, actual cleanup/failure battery and independently held
anti-replay custody still require work. The existing source manifest remains Systems-only;
the baum-os inventory is preparation evidence, not a forged source execution receipt.
W1's 15 migration patches remain untouched. No Systems/Registry/Marketing wave is started.
