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

## Evidence

Every run produces: console transcript, per-check exit codes/timeouts/log digests, cleanup
record, cgroup readback, result.json, manifest.json (strict schema) and a digest envelope;
`ci_verify.py` re-derives the verdict independently and maintains an append-only run-id
ledger (replay-rejected). A local hash chain is consistency evidence, not a cryptographic
attestation.

## Execution identity readback repair (2026-10-28, local candidate)

The launcher resolved `vm/../..`, recording the enclosing workspace commit instead of
its own relay commit in nested repositories. It now resolves `vm/..`.
A nested-Git regression executes the launcher with a harmless `/usr/bin/true` payload
and existing fixture overlay, without starting QEMU or materializing an image.

The verifier CLI now requires `--relay-pin` and `--source-pin`. These are supplied by
the trusted caller policy and dispatch custody, never copied from the evidence manifest.
`verify()` requires the same keyword arguments and rejects mismatches before ledger append.
Existing caller commands must supply both pins; the workflow input contract is unchanged.
The trusted caller must also verify that the checkout and executed implementation match
its reviewed pin; this repair does not make a mutable checkout trusted.

The previously reported run e843f434d05a4b6290486a4c3e75f30a has authentic source test
results but records an enclosing-workspace SHA. It must not be admitted as exact-relay
execution evidence. This local candidate has only host regression evidence, not fresh
VM qualification or a released commit. Both workflows remain quarantined.
