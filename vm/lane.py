"""Offline synthetic VM controller. No runner registration or host Docker API."""
import argparse
import fcntl
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import signal
import subprocess
import time
import uuid

from image import cpio
from paths import private_path

REPO = Path(__file__).resolve().parents[1]
GIB = 1024 ** 3
REQUIRED_CHECKS = {'live_virtual_link', 'protected_host_canary', 'review_canary', 'status_canary',
                   'docker_canary', 'credential_environment_absent', 'synthetic_process_created', 'synthetic_file_created',
                   'host_docker_socket_absent', 'no_host_mounts', 'host_service_denied', 'lan_denied',
                   'metadata_denied', 'ipv6_host_denied', 'ipv6_metadata_denied', 'previous_file_absent',
                   'previous_process_absent', 'no_agent_forwarding', 'guest_docker_ready', 'guest_container'}


class Cancelled(Exception):
    pass


def budget(private):
    memory = {line.split(':')[0]: int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()}
    free = shutil.disk_usage(private).free
    if memory['MemAvailable'] < int(3.25 * GIB):
        raise RuntimeError('BLOCKED_RESOURCES: need 3.25 GiB MemAvailable (1 GiB scope + host/controller reserve)')
    if free < 32 * GIB:
        raise RuntimeError('BLOCKED_RESOURCES: need 32 GiB free (30 GiB personal reserve + 2 GiB lane budget)')
    return {'available_bytes': memory['MemAvailable'], 'disk_free_bytes': free,
            'guest_mib': 768, 'scope_memory_max_bytes': GIB, 'scope_swap_max': 0,
            'cpu_quota_percent': 100, 'tasks_max': 128, 'concurrency': 1}


def systemctl(*args):
    return subprocess.run(['systemctl', '--user', *args], capture_output=True, text=True, timeout=15)


def scope_pids(unit):
    r = systemctl('show', unit, '-p', 'ControlGroup', '--value')
    group = r.stdout.strip()
    if r.returncode or not group.startswith('/'):
        return []
    path = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.procs'
    try:
        return [int(pid) for pid in path.read_text().split()]
    except FileNotFoundError:
        return []


def scope_metrics(unit):
    group = systemctl('show', unit, '-p', 'ControlGroup', '--value').stdout.strip()
    if not group.startswith('/'):
        return {}
    directory = Path('/sys/fs/cgroup') / group.lstrip('/')
    metrics = {}
    for name in ['memory.max', 'memory.swap.max', 'memory.peak', 'cpu.max', 'pids.max']:
        try:
            metrics[name] = (directory / name).read_text().strip()
        except FileNotFoundError:
            pass
    return metrics


def command(assets, job, unit):
    # No arbitrary extra arguments, network forwarding, filesystem shares or disks.
    qemu = ['/usr/bin/qemu-system-x86_64', '-no-user-config', '-nodefaults',
            '-machine', 'q35,accel=kvm', '-cpu', 'host', '-smp', '1', '-m', '768',
            '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot',
            '-kernel', '/assets/kernel', '-initrd', '/job/initrd',
            '-append', 'console=ttyS0 quiet panic=-1 rdinit=/init',
            '-netdev', 'user,id=isolated,restrict=on,ipv6=off', '-device', 'virtio-net-pci,netdev=isolated',
            '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
            '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']
    wrapped = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session',
               '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib',
               '--symlink', 'usr/lib64', '/lib64', '--symlink', 'usr/bin', '/bin',
               '--symlink', 'usr/sbin', '/sbin', '--proc', '/proc', '--dev', '/dev',
               '--dev-bind', '/dev/kvm', '/dev/kvm', '--tmpfs', '/tmp', '--tmpfs', '/run',
               '--dir', '/assets', '--ro-bind', str(assets / 'kernel'), '/assets/kernel',
               '--bind', str(job), '/job', '--clearenv', '--setenv', 'PATH', '/usr/bin',
               '--setenv', 'HOME', '/empty', *qemu]
    return ['systemd-run', '--user', '--scope', '--collect', '--quiet', '--unit=' + unit,
            '-p', 'MemoryMax=1G', '-p', 'MemorySwapMax=0', '-p', 'CPUQuota=100%',
            '-p', 'TasksMax=128', *wrapped]


def cleanup(unit, owned_scope, proc, observed_pids, job, evidence, log):
    """Attempt every owned-resource teardown even when another step fails."""
    errors = []
    def attempt(step, action, default=None):
        try:
            return action()
        except Exception as error:
            errors.append({'step': step, 'error': type(error).__name__})
            return default

    if owned_scope:
        observed_pids.update(attempt('initial_scope_pids', lambda: scope_pids(unit), []))
        # Ownership, not a fallible LoadState query, authorizes these exact-scope actions.
        killed = attempt('scope_kill', lambda: systemctl('kill', '--signal=SIGKILL', unit))
        stopped = attempt('scope_stop', lambda: systemctl('stop', unit))
    else:
        killed = stopped = None
    if proc is not None:
        attempt('process_wait', lambda: proc.wait(timeout=10))
        if attempt('process_poll', proc.poll) is None:
            attempt('process_kill', proc.kill)
            attempt('process_reap', lambda: proc.wait(timeout=5))
    attempt('console_write', lambda: (evidence / 'console.log').write_bytes(log))
    attempt('job_remove', lambda: shutil.rmtree(job))
    def reap_observed():
        deadline = time.monotonic() + 5
        while any(Path('/proc', str(pid)).exists() for pid in observed_pids) and time.monotonic() < deadline:
            time.sleep(0.05)
    attempt('observed_reap', reap_observed)
    remaining = attempt('final_scope_pids', lambda: scope_pids(unit))
    final = attempt('final_scope_state', lambda: systemctl('show', unit, '-p', 'LoadState', '--value'))
    state = final.stdout.strip() if final is not None and final.returncode == 0 else 'UNKNOWN'
    live = attempt('observed_pid_inventory', lambda: [pid for pid in observed_pids if Path('/proc', str(pid)).exists()])
    removed = attempt('job_inventory', lambda: not job.exists(), False)
    files = attempt('job_file_inventory', lambda: sorted(str(path.relative_to(job)) for path in job.rglob('*')) if job.exists() else [])
    exited = proc is None or attempt('final_process_poll', proc.poll) is not None
    record = {'cleanup_errors': errors, 'scope_ownership_verified': owned_scope,
              'final_scope_load_state': state, 'observed_pids_still_exist': live,
              'observed_pids': sorted(observed_pids), 'scope_remaining_pids': remaining,
              'job_directory_removed': removed, 'job_files_remaining': files,
              'cleanup_verified': (not errors and remaining == [] and live == []
                                   and removed and state == 'not-found' and exited)}
    if proc is not None:
        record['process_returncode'] = proc.returncode
    for name, result in [('scope_kill_exit', killed), ('scope_stop_exit', stopped)]:
        if result is not None:
            record[name] = result.returncode
    return record


def acquire_slot(assets, private):
    if assets.parent != private.parent:
        raise ValueError('assets and run evidence must share the same private task root')
    lock = (assets.parent / 'lane.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        lock.close()
        raise
    return lock


def run(assets, private, mode, probe, outcome='success'):
    if mode not in {'success', 'failure', 'hold'} or outcome not in {'success', 'failure', 'timeout', 'cancel'}:
        raise ValueError('unsupported synthetic mode/outcome')
    assets, private = private_path(assets), private_path(private)
    if assets.parent != private.parent:
        raise ValueError('assets and run evidence must share the same private task root')
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = acquire_slot(assets, private)
    resource = budget(private)
    runtime_bytes = sum(path.stat().st_size for path in assets.parent.rglob('*')
                        if path.is_file() and not path.is_symlink())
    if runtime_bytes + (assets / 'synthetic-initrd').stat().st_size + 2 * 1024 ** 2 > 2 * GIB:
        raise RuntimeError('BLOCKED_RESOURCES: private lane storage budget would exceed 2 GiB')
    resource['private_runtime_bytes_before_job'] = runtime_bytes
    manifest = json.loads((assets / 'derived-image.json').read_text())
    for name, field in [('kernel', 'kernel_sha256'), ('synthetic-initrd', 'initrd_sha256')]:
        if hashlib.sha256((assets / name).read_bytes()).hexdigest() != manifest[field]:
            raise ValueError('derived image integrity mismatch')
    if manifest['guest_init_sha256'] != hashlib.sha256((Path(__file__).parent / 'guest-init.sh').read_bytes()).hexdigest():
        raise ValueError('guest code differs from derived image')
    ipaddress.ip_address(probe['LAN_PROBE'])
    if not 1 <= int(probe['HOST_PORT']) <= 65535:
        raise ValueError('invalid canary port')
    config = {**probe, 'MODE': mode}
    if set(config) != {'LAN_PROBE', 'HOST_PORT', 'HOST_CANARY_PATH', 'REVIEW_CANARY_PATH', 'STATUS_CANARY_PATH', 'DOCKER_CANARY_PATH', 'MODE'}:
        raise ValueError('unexpected probe configuration')
    overlay = '\n'.join(name + '=' + shlex.quote(str(value)) for name, value in config.items()) + '\n'
    job_id = uuid.uuid4().hex
    unit = 'relay-synthetic-vm-' + job_id + '.scope'
    if systemctl('show', unit, '-p', 'LoadState', '--value').stdout.strip() != 'not-found':
        raise RuntimeError('refuse an existing or unverifiable scope identity')
    job = private / ('job-' + job_id)
    job.mkdir(mode=0o700)
    evidence = private / ('evidence-' + job_id)
    evidence.mkdir(mode=0o700)
    (job / 'initrd').write_bytes((assets / 'synthetic-initrd').read_bytes() + gzip.compress(cpio({'probe-config': (overlay.encode(), 0o600)}), mtime=0))
    argv = command(assets, job, unit)
    record = {'job_id': job_id, 'unit': unit, 'mode': mode, 'expected_outcome': outcome,
              'resource_budget': resource, 'argv': argv, 'image_sha256': manifest['initrd_sha256'],
              'checks': {}, 'ready_seen': False, 'outcome': 'UNKNOWN', 'cleanup_verified': False}
    proc = None
    log = bytearray()
    pending = b''
    old_handler = signal.getsignal(signal.SIGTERM)
    def cancel(signum, frame):
        raise Cancelled('SIGTERM')
    signal.signal(signal.SIGTERM, cancel)
    started, ready_at = time.monotonic(), None
    observed_pids = set()
    owned_scope = False
    try:
        runtime = '/run/user/' + str(os.getuid())
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env={'PATH': '/usr/bin:/bin', 'HOME': str(private),
                                     'XDG_RUNTIME_DIR': runtime, 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + runtime + '/bus'},
                                start_new_session=True)
        while True:
            current_pids = scope_pids(unit)
            if proc.pid in current_pids:
                owned_scope = True
            if owned_scope:
                observed_pids.update(current_pids)
            metrics = scope_metrics(unit)
            if metrics.get('memory.max') == str(GIB):
                record['observed_cgroup_limits'] = metrics
            available = next(int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                             if line.startswith('MemAvailable:'))
            if available < 2 * GIB:
                raise RuntimeError('host RAM reserve lost; stopping only this synthetic VM')
            readable, _, _ = select.select([proc.stdout], [], [], 0.1)
            if readable:
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk and proc.poll() is not None:
                    break
                log.extend(chunk)
                if len(log) > 2 * 1024 * 1024:
                    raise RuntimeError('guest output budget exceeded')
                pending += chunk
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    line = line.rstrip(b'\r')
                    if line.startswith(b'CHECK '):
                        fields = line.decode('ascii', errors='replace').split()
                        if len(fields) == 3 and fields[1] in REQUIRED_CHECKS:
                            if fields[1] in record['checks']:
                                raise RuntimeError('duplicate synthetic check result')
                            record['checks'][fields[1]] = fields[2]
                    if line == b'SYNTHETIC_READY':
                        ready_at = time.monotonic()
                        record['ready_seen'] = True
                        (evidence / 'ready.json').write_text(json.dumps({'controller_pid': os.getpid(), 'job_id': job_id}))
            if ready_at and outcome == 'cancel' and time.monotonic() - ready_at > 1:
                os.kill(os.getpid(), signal.SIGTERM)
            if ready_at and outcome == 'timeout' and time.monotonic() - ready_at > 2:
                record['outcome'] = 'timeout'
                record['termination_requested_while_running'] = proc.poll() is None
                record['ready_to_timeout_seconds'] = time.monotonic() - ready_at
                break
            if time.monotonic() - started > 90:
                raise RuntimeError('boot/qualification deadline exceeded')
            if proc.poll() is not None and not readable:
                break
        if record['outcome'] == 'UNKNOWN':
            rc = proc.wait(timeout=5)
            record['process_returncode'] = rc
            record['outcome'] = 'success' if rc == 33 else 'failure' if rc == 35 else 'unexpected_exit'
    except Cancelled:
        record['outcome'] = 'cancel'
        record['cancel_signal_received'] = signal.SIGTERM
        record['termination_requested_while_running'] = proc is not None and proc.poll() is None
    except BaseException as error:
        record['outcome'] = 'controller_error'
        record['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            record.update(cleanup(unit, owned_scope, proc, observed_pids, job, evidence, log))
            record['duration_seconds'] = round(time.monotonic() - started, 3)
            record['inputs_unchanged'] = all(hashlib.sha256((assets / name).read_bytes()).hexdigest() == manifest[field]
                                            for name, field in [('kernel', 'kernel_sha256'), ('synthetic-initrd', 'initrd_sha256')])
            limits = record.get('observed_cgroup_limits', {})
            cpu = limits.get('cpu.max', '').split()
            record['limits_verified'] = (limits.get('memory.max') == str(GIB) and limits.get('memory.swap.max') == '0'
                                         and limits.get('pids.max') == '128' and len(cpu) == 2 and cpu[0].isdigit()
                                         and int(cpu[0]) <= int(cpu[1]))
            record['qualification_pass'] = (record['outcome'] == outcome and record['ready_seen']
                                            and set(record['checks']) == REQUIRED_CHECKS
                                            and all(value == 'PASS' for value in record['checks'].values())
                                            and owned_scope and record['cleanup_verified'] and record['inputs_unchanged'] and record['limits_verified'])
            (evidence / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
        finally:
            signal.signal(signal.SIGTERM, old_handler)
            lock.close()
    return record, evidence


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--assets', required=True, type=Path)
    parser.add_argument('--private', required=True, type=Path)
    parser.add_argument('--probe', required=True, type=Path)
    parser.add_argument('--outcome', choices=['success', 'failure', 'timeout', 'cancel'], required=True)
    args = parser.parse_args()
    mode = args.outcome if args.outcome in {'success', 'failure'} else 'hold'
    result, evidence = run(args.assets, args.private, mode, json.loads(args.probe.read_text()), args.outcome)
    print(json.dumps({'qualification_pass': result['qualification_pass'], 'outcome': result['outcome'],
                      'checks': result['checks'], 'cleanup_verified': result['cleanup_verified'], 'evidence': str(evidence)}, indent=2))
    raise SystemExit(0 if result['qualification_pass'] else 1)
