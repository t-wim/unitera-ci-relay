# Marketing Python VM — implementation boundary (2026-10-28)

**Status: PARTIAL / QUARANTINED / NO LIVE PYTHON VM QUALIFICATION.**

This extension is staged in a separate candidate branch off the existing Draft PR #5.
It does not change the quarantined workflow, existing Systems/Node VM profile,
publication-policy.json, runner configuration or source-repository status.

## Implemented candidate modules

- `vm/marketing_source_custody.py`: exact source-commit custody from an already
  existing Git checkout of `baum777/unitera_marketing_agent-team`. It verifies
  the remote and full commit, exports only committed regular Git files, re-derives
  Git blob IDs and a SHA-256 file inventory, denies private/symlink/submodule
  inputs and never executes marketing code on the host.
- `vm/marketing_vm_contract.py`: fixed Python3 offline commands; source/relay
  bindings, required isolation/cleanup records and independently recomputed
  per-check log hashes. A matching receipt is consistency evidence only.
- `vm/marketing_vm_qualification.py`: five-case validation contract for
  success, deliberate failure, timeout, cancellation and fresh successor.
  It **always returns qualified=false** pending real t-wim host observation,
  owner review and independently checked raw VM/cgroup evidence. Synthetic
  receipts cannot activate a runner.
- `vm/marketing_status_writeback.py`: disabled commit-status adapter pinned
  to the marketing repository, exact source SHA and a fixed context. It requires
  separate owner approval, VM qualification and writer qualification. A scoped
  credential belonging to the **source** repository is essential. The relay
  token alone cannot write source-repository commit statuses. Actual status
  delivery requires a separate independent GET readback.
- `test_marketing_vm_candidate.py`: offline-only behavioral/negative tests.
  Synthetic fixtures never constitute execution of marketing code in a VM.

## Required actual VM implementation before activation

The existing source-CI VM is fixed to `baum777/Unitera_Systems` and Node/pnpm.
No existing code path safely launches the marketing Python source in a qualified
guest. These remaining requirements must be completed and run on the t-wim host:

1. Build a separate Python 3 + stdlib guest image from verified/pinned distro
   artifacts, reusing the signed Alpine kernel and no-host-share QEMU wrapper.
   Pin and revalidate the Python executable, extension modules and shared libs.
2. Build an ext4 VM input image from the digest-verified source archive, with a
   complete inside-guest SHA-256 inventory. Host may prepare data but cannot
   execute source scripts or install dependencies from the source checkout.
3. Add a new guest test executor with exact argv, Python environment isolation,
   no network, fixed timeouts and isolation probes, and controller monitor
   preserving raw console, actual return codes, resource ceilings and cleanup.
4. Run five real independent VM qualification cases, host positive controls,
   failure/timeout/SIGTERM teardown and fresh-successor validation. Bind
   images, source/relay SHAs, toolchain digests and implementation files.
5. Independent verifier must parse raw guest console and host receipts, enforce
   anti-replay, distinguish unknown from success, verify exactly three checks,
   and inspect cleanup even when VM launch fails.
6. t-wim owner must review and explicitly authorize this new VM profile.
   Source-repository owner separately installs/approves least-privilege
   commit-status writeback credential. No token enters a guest.
7. Only after qualification amend the Draft workflow and run fixed commands
   for an exact pinned marketing source commit. Independently read back
   the source commit status after any accepted status POST.

### Fixed commands (VM only)

```bash
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts tests
```

No provider calls, external marketing actions, publishing, paid fallback,
runtime activation or modifications to the original Systems VM are permitted.

### State and acceptance

- Contract/custody/status-adapter code: candidate only.
- Code review and offline tests: require execution on exact branch head.
- Physical Python VM execution: **NOT RUN**.
- Five-case Python VM isolation qualification: **NOT RUN**.
- Marketing source tests on t-wim runner: **NOT RUN**.
- Source-repository commit status: **NOT SENT**.
- Draft PR #5 remains quarantined, unmerged and not runner-admitted.

**Do not change these facts to PASS solely because unit tests or mock receipts pass.**
