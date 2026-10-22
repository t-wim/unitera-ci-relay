# Quarantined relay and offline synthetic VM candidate

The relay entrypoints remain quarantined. This candidate adds a standalone, RAM-only
QEMU/KVM VM profile for synthetic qualification, with no runner registration or Source CI.
VM state is fresh on each boot. Docker runs only in the guest; no host Docker API is used.

Images, derived binaries, host probes and all test ledgers live in a private workspace
location outside this repository. The publication allowlist includes only implementation,
invented fixtures, public distribution image provenance and sanitized documentation.

See [VM operations and resource limits](docs/VM_LANE.md), [current scope](docs/REPAIR_STATE.md)
and [operation log](docs/VORGAENGE_LOG.md). Offline regression tests:

```sh
python3 -m unittest discover -p 'test_*.py' -v
python3 inventory.py
git diff --check
```

Live VM qualification is separate from these offline tests. A complete private five-run
ledger is required; labels, configuration or an echoed success string alone cannot qualify
it. The public-image fetch/build steps use existing installed distribution tools and verify
image signature/digest plus package ownership/checksums of guest tools.

`MERGE_CONTROL = PROCESS_ENFORCED`. No platform enforcement is claimed. VM-profile proof
does not qualify real CI parity, exact-source CI, status writeback, source merge or deployment.
Keep both workflows disabled and the legacy relay runner stopped. This local candidate is
for publication review; no push or merge is performed by the VM tools.
