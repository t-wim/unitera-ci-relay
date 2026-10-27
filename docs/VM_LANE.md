# Offline synthetic VM operations

## Boundary and trust

The guest boots a SHA-256- and publisher-signature-verified public Alpine virtual image,
then switches to its own new tmpfs root. Kernel/initramfs members come from that signed ISO.
Allowlisted installed OS binaries and libraries used for guest Docker are checked against
package ownership/checksums. Their exact versions/hashes and the derived initrd stay private.
Trust base: the local OS, package database, KVM/QEMU and installed confinement tooling.

QEMU runs without host privileges inside new user, PID and network namespaces. Its host
filesystem view includes read-only OS executables/libraries and one kernel file, and its own
private job input. These host sandbox mounts are **not guest filesystem shares**. The guest
has no 9p/virtiofs, disk passthrough, host socket, SSH agent or credential. QEMU configuration
is fixed; no arbitrary forwarding, SMB/TFTP, extra drives or runtime arguments are accepted.
The outer user-bus address is used only to create/stop the transient scope; Bubblewrap clears
it before QEMU. No GitHub credential is read or placed in the image.

User networking has restrict=on and IPv6 off; an independent network namespace adds a second
boundary with no host/LAN routes. The synthetic virtual-link positive control must pass.
Offline means all external dependencies are denied too. There is no online-egress claim.
The guest starts its own Docker socket, imports an invented BusyBox root and runs a local
container with network=none and the normal guest Docker seccomp profile.

## Resources and host preservation

- One VM at a time, 768 MiB guest RAM, one vCPU.
- Kernel-enforced user scope: 1 GiB memory maximum, zero host swap, 100% single-CPU quota,
  128 host tasks. Actual cgroup values are read back and required by qualification.
- Start requires 3.25 GiB MemAvailable; abort if available RAM falls below 2 GiB.
- Start requires 32 GiB free disk, retaining 30 GiB for personal use. Private lane assets,
  evidence and next job input must fit a 2 GiB budget; guest writable state stays in RAM.
- A lock prevents concurrent runs. No host-wide firewall, Docker or process cleanup is used.
These budgets qualify only the synthetic profile, not the later application CI workload.

## Reproduction

Prerequisites: Linux KVM access for the operator, unprivileged user/network namespaces,
Bubblewrap, systemd user scope with memory/CPU controllers, QEMU, Python/PyYAML, 7z, C compiler,
GPG, cpio and the allowlisted distribution Docker/runtime binaries already installed.
No privileged system service or GitHub runner is installed. The canonical owning workspace
path guard must exist. Set PRIVATE_DIR to a fresh private directory in that workspace,
outside the Git checkout. Fetch/build assets and every run directory share that private root.

```sh
python3 vm/fetch.py "$PRIVATE_DIR/assets"
python3 vm/image.py "$PRIVATE_DIR/assets"
python3 vm/qualify.py --assets "$PRIVATE_DIR/assets" --private "$PRIVATE_DIR/run-01"
```

The fetcher is pinned to public vendor URLs, digest and signing fingerprint. It does not use
a personal keyring. Existing partial downloads must be reconciled, not silently overwritten.
The builder never extracts the image to the host filesystem; only verified members enter the
private initramfs. It compiles the tiny guest-only debug-exit helper without running it on
the host. Both image integrity and guest source digest are rechecked before each launch.

## Actual qualification and evidence

The driver creates synthetic protected file/review/status canaries, a synthetic Unix socket
and a short-lived host TCP service. Host loopback/LAN/Unix positive controls must succeed.
Canary contents are never passed to the guest. Only synthetic probe paths/port are serialized
with shell quoting; no untrusted source package or executable is imported.

Five sequential VMs: success, deliberate failure, timeout while running, actual SIGTERM
cancellation while running, then success in a fresh successor. Every guest proves host file,
socket, agent, TCP/LAN/IPv6/metadata denial, freshness, actual creation of a lingering synthetic
process/file, guest Docker readiness and container success. The controller also requires real
exit codes, cgroup limits, unchanged images, and zero remaining own PIDs/scopes/job directories.
A bounded reap wait verifies exit completion; it does not waive zombie or running leftovers.

Raw console, command/limit/PID receipts, source/image hashes and ledgers are private. Guest
output is parsed only as a fixed synthetic record schema, never eval/source/executable data.
The controller combines it with host-positive, image, cgroup, exit and teardown evidence.
`VM_ISOLATION_QUALIFIED` is computed only for the complete unchanged five-run implementation.
It is not a GitHub variable, credential-isolation approval, runner admission or CI result.

## Rollback and limits

Normal success/error/timeout/SIGTERM all discard the RAM-only VM and its private job input.
Scope/PID ownership is recorded. Stop/kill is restricted to that exact random task scope;
no foreign scope, network, VM, image or container is touched. A controller hard crash/power loss
is not claimed as the tested SIGTERM case: retain its receipt and reconcile only its owned
scope/input before resuming. Fresh random job identities never reuse prior guest state.

To roll back, keep the legacy runner/workflows off, stop any positively identified active
scope for this task, verify no owned QEMU process remains and archive the private evidence.
Remove only positively owned job inputs/assets if separately desired; never global Docker or
network cleanup. Cached base images and evidence are retained by default, outside publication.

Public references: https://www.qemu.org/docs/master/system/qemu-manpage.html (restrict)
and https://www.alpinelinux.org/downloads/ (publisher image hashes/signatures).
