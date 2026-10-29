# Source-CI executor: custody contract, profile and parity

## Scope of this candidate

Extends the quarantined offline relay with an independent source-CI execution lane for
Unitera_Systems at an exactly pinned commit. No workflow enablement, runner registration,
status writeback, merge or deployment is part of this candidate. The synthetic five-run
isolation profile remains untouched and separately qualified.

## Trust boundaries

```text
trusted controller (host python, scanned, no process execution of its own)
  -> vm/ci_prep.py    validated source snapshot bound to the commit via git blob ids + sha256
  -> vm/ci_image.py   guest image assembled from digest-verified artifacts only
  -> vm/ci_monitor.py run planning, protocol parsing, aggregation, cleanup, manifest
mechanical lane (shell, dumb by design, reviewed like code)
  -> vm/ci_start.sh   qcow2 overlay + exec of the exact validated argv
  -> prep/steps*.sh   git archive / offline store build / mkfs, emitted by the controller
untrusted execution
  -> vm/ci_guest.sh   boots, proves isolation, verifies source+toolchain, exec's plan argv
evidence verification (separate process, separate decision logic)
  -> vm/ci_verify.py  re-derives the verdict from console+digests+manifest, replay-protected
```

The guest never evaluates a shell string from data: plan commands cross the boundary as
unit-separator argv fields (validated charset) and are exec'd via `timeout "$tmo" "$@"`.

## Pinned execution profile (source-CI lane)

- Guest: 2816 MiB RAM, 2 vCPU, virtio disk overlay (qcow2, backing = prepared ext4 image),
  user networking restrict=on/ipv6=off, no host shares, /dev/kvm only, sandboxed QEMU.
- Scope: MemoryMax 3816M, MemorySwapMax=0, CPUQuota=200%, TasksMax=512; read back and required.
- Budgets: >=5120 MiB MemAvailable to start, abort below 2560 MiB, 64 MiB console budget,
  global deadline 5400 s, per-check timeouts in the plan.
- Toolchain: node v24.19.0 (nodejs.org tarball, sha256-pinned in ci-lock.json),
  pnpm 10.5.2 + worker.js (registry.npmjs.org tarball, sha512-pinned), glibc libs from
  dpkg-verified host files; identical digests verified inside the guest (check c2).
- Dependencies: offline store built on the trusted host with --ignore-scripts from the
  pinned lockfile; package lifecycle scripts run only inside the VM (check c3).
- Source: `git archive` of the exact commit; the controller re-derives every git blob object
  id from the tar and requires a full sha256 inventory match; the guest re-verifies all
  3011 file digests plus the file count (check c1) before anything executes.

## Qualification-relevant deltas vs the qualified synthetic profile

- Larger guest RAM/smp, longer deadlines, virtio-blk disk overlay (new device, same
  no-host-share posture), console budget raised. The synthetic lane and its qualification
  are untouched; the source-CI profile is qualified separately by its own battery
  (isolation checks run inside every source-CI run and gate the overall verdict).
- Shell files are part of the reviewed candidate surface; the write-time security scanner
  does not cover shell, so ci_start.sh is kept deliberately mechanical (no logic, no
  network, fixed command allowlist asserted by test_ci.py).

## CI parity matrix (first slice, Systems @5b4d9f0c)

| REQUIRED_CONTEXT | SOURCE_WORKFLOW | RELAY_CHECK | ENVIRONMENT | TEST_COMMAND | PARITY_STATUS |
|---|---|---|---|---|---|
| Lint & Build (partial) | ci.yml / lint-and-build | c4_build_packages, c5_api_typecheck, c6_lint_ts | VM, node 24.19.0, pnpm 10.5.2 | `pnpm -r --if-present --filter ./packages/* run build`; `--filter ./apps/api exec tsc --noEmit`; `run lint:ts` | PARTIAL (api/packages side; web build/next lint missing) |
| Unit Tests + Coverage | ci.yml / test | c7_api_unit_baseline | VM | `--filter ./apps/api run test:unit-baseline -- --maxWorkers=2` | PARTIAL (no coverage artifact; worker bound is a resource adaptation) |
| Governance | governance-guardrails.yml | c8_governance_check | VM | `run governance:check` | PARTIAL (matrix not fully mirrored) |
| hosted-pilot-required | ci.yml aggregator | - | - | - | MISSING (needs PG/docker testcontainers lane) |
| PostgreSQL integration family | governance-guardrails matrix | - | - | - | MISSING (no PG in guest) |
| RLS Runtime Required | governance-guardrails | - | - | - | MISSING |
| Migration / drift | ci matrix migrate/drift-check | - | - | - | MISSING (needs PG) |
| Append-only / vendor integrity / secret scan | ci.yml security-gates | - | - | - | MISSING (follow-up slice: pure-node scripts feasible offline) |
| Native Qt/QML gates | native-ui.yml, qml-correlation | - | - | - | MISSING (Qt toolchain not in guest) |
| Container build smoke | ci.yml container-build-smoke | - | - | - | MISSING (guest docker is deliberately absent in this profile) |
| Hosted web/auth runtime | ci.yml hosted-* | - | - | - | MISSING |
| Source integrity / supply chain (new, relay-side) | - | c1, c2, c3 | VM | digest verification + frozen offline install | FULL (executor-side) |
| Isolation regression (relay-side) | - | 18 guest checks per run | VM | canaries + denials | FULL (executor-side) |

Overall: CI_PARITY = PARTIAL for the offline-capable TypeScript toolchain family; the
PostgreSQL-, Docker-, Qt- and hosted-runtime families remain MISSING and each need their own
bounded profile extension (identified dependency: postgres service or testcontainers-in-guest,
Qt 6.10 toolchain image, docker-in-guest re-qualification).

## baum-os lane (W2.1 qualification 2026-10-28)

Second source lane for `baum777/baum-os`, reusing the same controller / launcher / guest /
verifier split with a dedicated profile:

- Source pin: commit `d8f96217b121325ef1f4d46a8c3e5743e31fc0cb`, tree
  `0aa6204a90375277e93f8d5e2394d88b1dbe21df`, 19874 files, 3 tracked symlinks, 17 gitlinks
  (submodules carried as data; guest check c1b re-derives the tree identity in-guest via
  `git update-index --add --cacheinfo 160000,<sha>,<path>`).
- Toolchain: node 24.19.0 (same as the Systems lane), pnpm 11.9.0 (`vm/baum-lock.json`,
  ESM layout with bin/dist entries plus worker.js), bash and git with 171 dpkg-verified
  git-core files.
- Dependencies: offline store plus the pnpm 11 metadata/verification cache shipped inside the
  workspace image (HOME=/ws/work); a pure-exec shim binds `--offline --store-dir /ws/store`
  to install commands only.
- Plan `baum_governance`: five verbatim governance step scripts (g4-g8) copied from the
  source commit (run_sha256-bound) and executed from /plan/…; guest native checks c1, c2, c1b.
- Qualification: five-run synthetic requalification on this implementation (bundle
  `7c867f6e…`, 2026-10-28, superseding six earlier defect-bound intermediates) and one
  reference source-CI run `5028322e7d4846b5ac506d359f999c50` (26/26 checks PASS, vm_exit 33,
  verifier ACCEPT). CI parity for baum-os is PARTIAL: 1 of 4 jobs, 5 of 17 run steps
  (governance only); validate/reachability/gate-test families and the PG/Docker/Qt/hosted
  families remain unsupported in this profile.

## Evidence

Every run produces: console transcript, per-check exit codes/timeouts/log digests, cleanup
record, cgroup readback, result.json, manifest.json (strict schema) and a digest envelope;
`ci_verify.py` re-derives the verdict independently and maintains an append-only run-id
ledger (replay-rejected). A local hash chain is consistency evidence, not a cryptographic
attestation.
