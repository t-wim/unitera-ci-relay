# UNITERA MARKETING PYTHON VM QUALIFICATION — 2026-10-28

> **Security closure update (same day, PR #8 review):** all seven Codex review
> findings are fixed and negatively tested; the five-run qualification was
> re-executed live on the hardened implementation. See the
> `SECURITY CLOSURE (PR #8 REVIEW)` section at the end for the finding/fix/test
> matrix and the new evidence bindings (runs `9805827e…`…`54bbcd59…`, chained
> controller-evidence ledger entry #2, Mimosa deep-scan seal
> `sha256:366472cb…`). The qualification below was superseded by that
> requalification; earlier runs remain in the private store as history.

## REPOSITORY

```text
Relay repository:      t-wim/unitera-ci-relay
Branch:                feat/marketing-python-vm-implementation-20261028 (stacked on merged PR #6 / main)
Initial SHA (main):    37d3edd38e736f3a05070c80bdf5a875ae9dc7cf
Implementation SHA:    cf50323558394ff7b3a19a0d68134e2df38141fa (qualification host binding)
Final SHA:             see PR head (report-only commits after the qualification do not touch vm/)
Source repository:     baum777/unitera_marketing_agent-team
Pinned source SHA:     1eb696ac361ea44dce1deeb3799e3110077f85a6 (independently confirmed = current main HEAD)
```

## IMPLEMENTATION

```text
Python image:          vm/marketing_image.py + vm/marketing-runtime-lock.json
                       CPython 3.14.4 from dpkg-verified Ubuntu packages
                       (python3.14-minimal / libpython3.14-minimal / libpython3.14-stdlib
                       3.14.4-1ubuntu0.2); 710 runtime files incl. complete stdlib and
                       lib-dynload DT_NEEDED closure (816 initrd members after closure).
                       Signed Alpine kernel/initrd members reused from image-lock.json;
                       ELF interpreter placed at guest /lib64 as in the qualified lane.
                       guest initrd sha256 3e24d2f1dba8c409… (bound in prep manifest).
Runtime provenance:    every file dpkg-owned and md5-verified (image.verified_system_file);
                       package versions pinned in the committed lock; full per-file
                       SHA-256 manifest (toolchain.sha256) inside the initrd; digests
                       re-verified on the host before every launch (verify_prepared)
                       and inside the guest (check c2) before any source test runs.
Source custody:        vm/marketing_source_custody.py + vm/marketing_prep.py — exact commit
                       resolution, origin check, git ls-tree capture, git archive export,
                       per-file git-blob re-derivation, SHA-256 inventory (46 files,
                       409064 bytes), symlink/submodule/private-path/.env denial,
                       safe extraction, ext4 workspace image (512 MiB, sha256
                       e79fd76bcf9ba48a…), inventory bound into each per-job initrd overlay.
Guest workspace:       /ws/src from the custody-verified ext4 disk; guest re-verifies all
                       46 file digests + count (check c1) before executing anything.
VM controller:         vm/marketing_monitor.py + vm/marketing_start.sh (mechanical) —
                       profile marketing-python-vm-v1: QEMU/KVM q35, 1 vCPU, 1024 MiB RAM,
                       user-net restrict=on/ipv6=off, virtio qcow2 overlay (no host shares),
                       isa-debug-exit, QEMU -sandbox on; bwrap --unshare-all wrapper;
                       systemd user scope MemoryMax=1408M, MemorySwapMax=0, CPUQuota=100%,
                       TasksMax=256 (read back and required per run); lane lock (max 1 VM);
                       console budget 16 MiB; start gate 2560 MiB MemAvailable /
                       8 GiB disk; abort floor 1280 MiB.
Isolation profile:     17 guest checks per run (canary files incl. socket canary,
                       credential env, docker socket, host mounts, host TCP service, LAN,
                       metadata IPv4/IPv6, agent forwarding, predecessor state, live
                       virtual link, synthetic process/file creation) gated by host
                       positive controls (loopback 127.0.0.1, LAN 172.17.0.1 and synthetic
                       Unix socket service all proven reachable on the host, denied in guest).
Independent verifier:  vm/marketing_verify.py — re-derives verdict from raw console +
                       envelope digests + manifest + prep manifest; actual exit codes
                       mandatory for passed plan commands; timeout/exit-family checks;
                       cancelled-run semantics; positive-control gate; fail-closed for
                       unknown outcomes; append-only run-id ledger (replay rejected).
Status adapter:        vm/marketing_status_writeback.py + readback() — SHA-bound POST and
                       independent GET readback implemented and negatively tested;
                       sending requires owner approval + source-scoped credential and
                       remains INACTIVE (no credential exists on this lane).
```

## TESTS

```text
Offline tests:         137/137 PASS (python3 -m unittest discover -p 'test_*.py')
                       incl. test_marketing_vm_lane.py adversarial battery: plan binding,
                       manifest schema, unknown plan, stubbed commands, missing exit
                       codes, wrong timeout flags, tampered console/cleanup, unknown
                       outcomes, missing positive controls, replay ledger, runtime-lock
                       version binding, stdlib/python-digest tamper, readback spoofing.
Adversarial tests:     custody: wrong origin/commit, unsafe/secret-like paths, archive↔tree
                       mismatch; verifier: 23 negative classes (see Phase I list);
                       qualification gate: consistent receipts without host binding stay
                       unqualified, wrong executor digests rejected, duplicate run ids
                       rejected.
Guest test execution:  the three fixed commands ran ONLY inside the VM at the pinned
                       source SHA (runs 787a96fc… and 3cac0597…): 
                       python3 scripts/validate.py (exit 0),
                       python3 -m unittest discover -s tests -v (exit 0),
                       python3 -m compileall -q scripts tests (exit 0);
                       full log transcripts digest-bound in receipts (LOGDIGEST lines).
Five-run qualification: Q1 success 787a96fc53ff… (22/22 checks PASS, vm_exit 33, ~20 s)
                       Q2 failure 6db83d614317… (fixture exit 1 observed, vm_exit 35, ~15 s)
                       Q3 timeout  ec944c6aaf3c… (per-command timeout at 25 s: SIGTERM-
                       terminated hold fixture, TMO=1/EXIT=143, vm_exit 35, ~41 s)
                       Q4 cancel   0f29b1be27f5… (real SIGTERM to the live controller
                       while the VM held after SRC_READY; scope SIGKILLed, vm_exit -9,
                       ~7 s, no leftover scope/pids/job dir)
                       Q5 success  3cac0597cc13… (fresh successor, 22/22 PASS, vm_exit 33,
                       fresh_successor_verified=true, ~20 s)
                       All five independently verified (verifier ACCEPT in fresh
                       processes); VM_ISOLATION_QUALIFIED=true computed only from these
                       five real cases + host binding to the committed implementation
                       digests (10 executor files) at relay SHA cf503235….
Source CI parity:      Level 4 = production plan at exact SHA 1eb696ac… (Q1/Q5 above);
                       hosted validate.yml remains startup_failed; this lane covers the
                       three offline Python commands only (no provider/network family).
Independent readback:  Level 5 NOT EXECUTED — status delivery is owner-gated and
                       no source-repository credential exists on this lane; readback
                       implementation is negatively tested offline.
```

## SECURITY

```text
Host source execution: none. Marketing code executes only inside the disposable VM;
                       host-side steps are git data operations and file assembly
                       (verified by module design + test assertions).
Network isolation:     user-net restrict=on, IPv6 off, no forwarding; guest proves
                       host service/LAN/metadata denial while host positive controls
                       prove the targets are live (127.0.0.1, 172.17.0.1, unix socket).
Credentials in guest:  none — no tokens, no SSH agent, no .env; canary contents never
                       crossed the boundary (verified absent from all consoles).
Resource limits:       scope limits read back from cgroup per run and required
                       (memory.max 1474836480, swap 0); host RAM floor enforced.
Cleanup:               every run: scope not-found, zero owned PIDs, job directory
                       (qcow2 overlay + per-job initrd) removed; evidence retained.
Anti-replay:           append-only ledger; duplicate run-id append raises
                       REPLAY_REJECTED (demonstrated); qualification gate rejects
                       duplicate ids and stale executor digests.
Outstanding findings:  - QEMU exit for cancelled runs is the launcher's -9 (SIGKILL of
                         the owned scope), not a guest exit code — receipt records it
                         as vm_exit_code=-9 (documented, fail-closed semantics).
                       - busybox timeout terminates with SIGTERM (143); the contract
                         accepts the 124/137/143 exit family as the timeout outcome.
                       - The publication-policy allowlist extension and base_sha
                         rebinding in this PR require explicit owner review.
```

## GITHUB

```text
PR:                    feat/marketing-python-vm-implementation-20261028 → main
                       (stacked successor of merged PR #6; no force push).
Relay workflow:        .github/workflows/marketing-ci-relay.yml unchanged: admission-only,
                       validates exact source/relay pins, then deliberately exits 1 with
                       MARKETING_CI_QUARANTINED. State on GitHub: active (dispatch-only),
                       fail-closed. unitera-ci-relay.yml and unitera-relay-preflight.yml
                       remain disabled_manually.
Runner execution:      the live lane ran on the t-wim self-hosted runner host
                       (QEMU/KVM, systemd user scopes, bwrap); GitHub-side runner
                       admission is NOT activated.
Source commit status:  NOT SENT (owner-gated; adapter + readback implemented and
                       negatively tested only).
Independent status readback: NOT EXECUTED (follows status delivery).
Owner admission:       REQUIRED for: merging this PR, activating any workflow change,
                       installing a source-scoped status credential, and any future
                       marketing test admission. This report creates no such authority.
```

## FINAL STATUS

```text
IMPLEMENTATION:            COMPLETE (Python VM lane, custody, controller, verifier)
VM_QUALIFICATION:          VM_ISOLATION_QUALIFIED=true (five real verified cases,
                            live host, this branch's implementation digests)
SOURCE_TEST_EXECUTION:     PASS in guest at 1eb696ac… (validate.py, unittest, compileall)
STATUS_WRITEBACK:          NOT ACTIVATED (owner-gated; implemented + negatively tested)
INTEGRATION:               QUARANTINED (admission workflow stays fail-closed by design)
```

## REMAINING BLOCKERS

- t-wim owner review/admission of this PR (includes the publication-policy allowlist
  extension and base rebinding shown in the diff).
- Source-repository owner must separately install/approve a least-privilege commit-status
  credential before any writeback; readback is implemented but unexercised end-to-end.
- No automated merge, workflow activation or runner registration is authorized here.

## NEXT SAFE ACTION

t-wim owner reviews the PR diff (especially publication-policy.json), re-runs
`python3 -m unittest discover -p 'test_*.py'` on the exact PR head, and — if admitting —
merges with the quarantine posture unchanged; status writeback stays disabled until the
source-scoped credential and its negative tests are separately approved.

## SECURITY CLOSURE (PR #8 REVIEW) — 2026-10-28

All seven Codex review findings fixed, each with a reproducible negative test
(`test_marketing_vm_lane.py`, classes `SecurityClosureTests` /
`QualificationGateTests` / extended asset-tamper test); offline battery
143/143 PASS at the requalified head.

| # | Sev | Finding | Fix | Negative test |
|---|-----|---------|-----|---------------|
| 1 | P1 | kernel digest unbound at launch | three-way binding file ↔ image record ↔ prep manifest in `verify_prepared`; kernel re-check in the final `inputs_unchanged` gate; `vm_kernel_digest` carried through run.json, manifest schema and verifier prep binding | substituted-kernel and unbound-manifest variants must raise before launch |
| 2 | P1 | self-declared `host_observation` JSON could qualify (Codex reproduced `qualified=true`) | qualification requires a hash-chained append-only controller-evidence ledger entry (written only by `marketing_qualify` after the five live runs) binding run ids, relay commit, **current** executor digests and per-case evidence-manifest digests, plus full independent evidence re-verification (`marketing_verify.reasons_from`) of every case directory | exact Codex repro (synthetic receipts + crafted binding/ledger) stays unqualified; forged chain, wrong digests and missing evidence manifests all rejected |
| 3 | P2 | positive-control failure left the launched VM running | host preflight moved inside the cleanup-protected region; **any** non-`exited` outcome (incl. `controller_error:*`) kills and stops the scope | stubbed-lane test: occupied port → `controller_error:OSError`, scope kill + cleanup invoked, fail-closed result.json written |
| 4 | P2 | lane lock acquired only after QEMU start | exclusive lock acquired in the driver **before** the launcher and handed to `watch()` (single-owner close) | second acquire raises `BLOCKED_LANE_LOCK`; external lock is passed through, not re-acquired |
| 5 | P2 | fixed RAM gate regardless of `--guest-mib` | `scaled_resource_profile()`: start/floor thresholds derive from guest size (only ever above defaults), persisted in the run profile; guest range 512–4096 validated | 2048 MiB guest with 3000 MiB available must raise; out-of-range sizes rejected |
| 6 | P2 | ledger read-modify-write race could lose run ids | flock-serialized mutation + atomic `os.replace` publication (`_locked_ledger_write`) | 8 concurrent appends all present afterwards; duplicate still `REPLAY_REJECTED` |
| 7 | P2 | only memory limits verified | `limits_match()` requires memory.max, memory.swap.max, cpu.max (N% → `N*1000 100000`) and pids.max to match the configured scope | each missing/wrong metric (cpu, pids, swap) fails the gate |

### Requalification evidence (hardened implementation)

```text
Implementation SHA:   391245c… (all seven fixes; executor digests bound below)
Source SHA:           1eb696ac361ea44dce1deeb3799e3110077f85a6 (unchanged pin)
Q1 success            9805827edde1452194913600a0cdc82e  vm_exit 33  ACCEPT
Q2 failure            1f4f3e75716545d7963affd7a59cec95  vm_exit 35  ACCEPT
Q3 timeout            93ae1a863aaa471591766755be6cf268  vm_exit 35  ACCEPT
Q4 cancel (real SIGTERM while holding) 182aec508b0748df962412cad3958582  vm_exit -9  ACCEPT
Q5 fresh successor    54bbcd59779744bb949ac2120cc2089a  vm_exit 33  ACCEPT
Controller evidence:  marketing-qualification-ledger.json entry #2
                      (chain-verified; binds run ids, relay SHA 391245c…,
                       current executor digests, per-case manifest digests)
                      — entry #1 records an earlier attempt whose record key
                      mismatched the verifier; it was left untouched in the
                      append-only ledger and superseded, never edited.
Kernel binding:       vm_kernel_digest 40f620bc… in every manifest, three-way
                      verified pre-launch and at the final input check.
Replay protection:    duplicate append of 9805827e… → REPLAY_REJECTED.
Mimosa deep scan:     0 findings, seal sha256:366472cbb5725060d8329b1af6b9ff518f4fe05fa397e2d2f531af60afa378f2
VM_ISOLATION_QUALIFIED: true (only from the five runs above + ledger entry #2)
```

Verdict after closure: **PASS** for the seven findings and the requalification.
Owner admission, merge, workflow activation, runner registration and source
status writeback remain separately gated and unchanged.
