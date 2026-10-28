"""Marketing Python VM run controller: launch planning and watch/cleanup.

launch - validates the prepared artifacts (custody receipt, ext4 workspace image,
         digest-checked Python guest initrd), creates an isolated run directory with
         synthetic host canaries, writes the trusted per-job initrd overlay
         (ci-config + plan), the overlay spec and the exact validated VM argv.
         The VM itself is started by vm/marketing_start.sh from the operator lane.
watch  - runs the synthetic host positive controls, observes the console protocol,
         enforces deadline, memory floor and abort modes, performs owned-scope
         cleanup via the qualified lane helpers, aggregates fail-closed and writes
         manifest + evidence envelope. Marketing source never runs on this host.

The console protocol parser is shared with the qualified source-CI lane
(ci_monitor.parse_protocol_line) so the guest contract stays byte-identical."""
import argparse
import datetime
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import socketserver
import threading
import time
import uuid
from pathlib import Path

import marketing_manifest
import marketing_plan
from ci_monitor import parse_protocol_line
from ci_util import load_json, sha256_file, write_args_file
from marketing_vm_contract import ISOLATION_CHECKS
from paths import private_path

PROFILE = {'plan': 'production', 'guest_mib': 1024, 'smp': 1, 'scope_memory_max': '1408M',
           'cpu_quota_percent': 100, 'tasks_max': 256, 'deadline_s': 1800,
           'console_budget_bytes': 16 * 1024 * 1024, 'mem_min_mib': 2560, 'mem_floor_mib': 1280,
           'disk_min_bytes': 8 * 1024 ** 3}
PROTOCOL_NAME = re.compile(r'[a-z0-9][a-z0-9_-]*')
CONFIG_KEYS = {'MODE', 'HOST_PORT', 'LAN_PROBE', 'HOST_CANARY_PATH', 'REVIEW_CANARY_PATH',
               'STATUS_CANARY_PATH', 'SOCKET_CANARY_PATH', 'EXPECTED_FILE_COUNT', 'PYTHON_VERSION'}
EXECUTOR_FILES = ['marketing_monitor.py', 'marketing_guest.sh', 'marketing_plan.py',
                  'marketing_image.py', 'marketing_start.sh', 'marketing_prep.py',
                  'marketing_manifest.py', 'marketing_source_custody.py',
                  'marketing-runtime-lock.json']


def assets(private):
    return private_path(private) / 'marketing-assets'


def local_lan_address(text=None):
    text = text if text is not None else Path('/proc/net/fib_trie').read_text()
    candidates = []
    for address in dict.fromkeys(re.findall(r'\b(\d+\.\d+\.\d+\.\d+)\b', text)):
        if address.startswith('127.') or address in ('0.0.0.0', '255.255.255.255'):
            continue
        if address.endswith('.0') or address.endswith('.255'):
            continue
        candidates.append(address)
    if not candidates:
        raise RuntimeError('no non-loopback local address for the LAN denial probe')
    return candidates[0]


def budget_check(profile, meminfo_text=None, free_bytes=None):
    source = meminfo_text if meminfo_text is not None else Path('/proc/meminfo').read_text()
    memory = {line.split(':')[0]: int(line.split()[1]) for line in source.splitlines()}
    import shutil as _shutil
    free = free_bytes if free_bytes is not None else _shutil.disk_usage('/').free
    if memory['MemAvailable'] < profile['mem_min_mib'] * 1024:
        raise RuntimeError('BLOCKED_RESOURCES: need %d MiB MemAvailable for the marketing profile'
                           % profile['mem_min_mib'])
    if free < profile['disk_min_bytes']:
        raise RuntimeError('BLOCKED_RESOURCES: need %d GiB free disk for overlay and logs'
                           % (profile['disk_min_bytes'] // 1024 ** 3))


def verify_prepared(assets_dir):
    """Re-verify every prepared digest before a VM may launch (lock binding, DoD B4)."""
    prep = load_json(assets_dir / 'marketing-prep-manifest.json')
    image_record = load_json(assets_dir / 'ws-image.json')
    if sha256_file(assets_dir / 'ws-base.img') != image_record['sha256']:
        raise ValueError('workspace base image digest mismatch')
    if image_record['sha256'] != prep['workspace_image']['sha256']:
        raise ValueError('workspace image not bound to the prep manifest')
    mkt_record = load_json(assets_dir / 'marketing-image.json')
    if sha256_file(assets_dir / 'marketing-initrd') != mkt_record['initrd_sha256']:
        raise ValueError('marketing initrd digest mismatch')
    if prep['python_runtime']['initrd_sha256'] != mkt_record['initrd_sha256']:
        raise ValueError('prep manifest not bound to the verified python runtime image')
    if prep['python_runtime']['python_bin_sha256'] != mkt_record['python_bin_sha256']:
        raise ValueError('python binary digest not bound to the verified runtime image')
    if prep['source']['commit'] is None:
        raise ValueError('prep manifest has no source commit')
    return prep, image_record, mkt_record


def build_argv(kernel, base_image, job_dir, unit, profile):
    qemu = ['/usr/bin/qemu-system-x86_64', '-no-user-config', '-nodefaults',
            '-machine', 'q35,accel=kvm', '-cpu', 'host', '-smp', str(profile['smp']),
            '-m', str(profile['guest_mib']), '-display', 'none', '-monitor', 'none',
            '-serial', 'stdio', '-no-reboot', '-kernel', '/assets/kernel',
            '-initrd', '/job/initrd',
            '-append', 'console=ttyS0 quiet panic=-1 rdinit=/init',
            '-netdev', 'user,id=isolated,restrict=on,ipv6=off', '-device', 'virtio-net-pci,netdev=isolated',
            '-drive', 'file=/job/ws.qcow2,if=virtio,format=qcow2,cache=writethrough',
            '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
            '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']
    wrapped = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session',
               '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib',
               '--symlink', 'usr/lib64', '/lib64', '--symlink', 'usr/bin', '/bin',
               '--symlink', 'usr/sbin', '/sbin', '--proc', '/proc', '--dev', '/dev',
               '--dev-bind', '/dev/kvm', '/dev/kvm', '--tmpfs', '/tmp', '--tmpfs', '/run',
               '--ro-bind', str(kernel), '/assets/kernel',
               '--ro-bind', str(base_image), str(base_image),
               '--bind', str(job_dir), '/job', '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin',
               *qemu]
    return ['systemd-run', '--user', '--scope', '--collect', '--quiet', '--unit=' + unit,
            '-p', 'MemoryMax=' + profile['scope_memory_max'], '-p', 'MemorySwapMax=0',
            '-p', 'CPUQuota=' + str(profile['cpu_quota_percent']) + '%',
            '-p', 'TasksMax=' + str(profile['tasks_max']), *wrapped]


def append_job_overlay(initrd_path, config, plan, assets_dir=None):
    import gzip
    import shlex
    from image import cpio
    lines = []
    for key, value in config.items():
        text = str(value)
        validate_config_value(key, text)
        lines.append(key + '=' + shlex.quote(text))
    plan_text = marketing_plan.serialize_plan(plan)
    data = {'ci-config': ('\n'.join(lines).encode(), 0o600), 'plan': (plan_text.encode(), 0o600)}
    if assets_dir is not None:
        # The custody inventory travels with the per-job initrd overlay, binding
        # every launch to the exact prepared source inventory.
        data['inventory.sha256'] = ((assets_dir / 'inventory.sha256').read_bytes(), 0o644)
    return initrd_path.read_bytes() + gzip.compress(cpio(data), mtime=0)


def validate_config_value(key, value):
    if key not in CONFIG_KEYS:
        raise ValueError('ci-config key rejected: ' + str(key))
    if not re.fullmatch(r'[A-Za-z0-9_./:=, -]+', value) or len(value) > 200:
        raise ValueError('ci-config value charset rejected: ' + key)


def launch(private, plan_name, mode, abort_delay_s=None, deadline_s=None, guest_mib=None,
           guest_mode=None):
    private = private_path(private)
    assets_dir = assets(private)
    prep, image_record, mkt_record = verify_prepared(assets_dir)
    profile = dict(PROFILE)
    profile['plan'] = plan_name
    if deadline_s:
        profile['deadline_s'] = deadline_s
    if guest_mib:
        profile['guest_mib'] = guest_mib
        profile['scope_memory_max'] = str(int(guest_mib * 1.375)) + 'M'
    budget_check(profile)
    plan = marketing_plan.plan_by_name(plan_name)
    marketing_plan.expected_check_set(plan_name)
    runs = private / 'runs'
    runs.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex
    run_dir = runs / run_id
    run_dir.mkdir(mode=0o700)
    (run_dir / 'launch').mkdir()
    (run_dir / 'evidence').mkdir(mode=0o700)
    job_dir = run_dir / 'job'
    job_dir.mkdir(mode=0o700)
    canaries = {}
    for label in ['host', 'review', 'status']:
        path = run_dir / (label + '.canary')
        value = ('SYNTHETIC_ONLY_' + secrets.token_hex(24)).encode()
        path.write_bytes(value)
        path.chmod(0o600)
        canaries[label] = (path, value)
    unix_path = private / ('d-' + run_id[:8] + '.sock')
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
    probe.close()
    config = {'MODE': guest_mode or mode, 'HOST_PORT': port, 'LAN_PROBE': local_lan_address(),
              'HOST_CANARY_PATH': canaries['host'][0], 'REVIEW_CANARY_PATH': canaries['review'][0],
              'STATUS_CANARY_PATH': canaries['status'][0], 'SOCKET_CANARY_PATH': unix_path,
              'EXPECTED_FILE_COUNT': prep['source']['file_count'],
              'PYTHON_VERSION': prep['python_runtime']['version']}
    (job_dir / 'initrd').write_bytes(append_job_overlay(assets_dir / 'marketing-initrd',
                                                        config, plan, assets_dir))
    unit = 'unitera-marketing-vm-' + run_id + '.scope'
    write_args_file(run_dir / 'launch' / 'argv.args',
                    build_argv(assets_dir / 'kernel', assets_dir / 'ws-base.img', job_dir, unit, profile))
    (run_dir / 'launch' / 'overlay.txt').write_text(str(assets_dir / 'ws-base.img') + '\n' + str(job_dir / 'ws.qcow2') + '\n')
    run = {'run_id': run_id, 'run_dir': str(run_dir), 'unit': unit, 'mode': mode,
           'abort_delay_s': abort_delay_s, 'profile': profile, 'plan_name': plan_name,
           '_config': {key: str(value) for key, value in config.items()},
           'source_commit_sha': prep['source']['commit'],
           'source_artifact_digest': prep['source']['archive_sha256'],
           'source_inventory_digest': prep['source']['inventory_sha256'],
           'vm_image_digest': mkt_record['initrd_sha256'],
           'base_image_digest': image_record['sha256'],
           'python_runtime_sha256': mkt_record['python_bin_sha256'],
           'python_version': prep['python_runtime']['version'],
           'toolchain_versions': {'python': prep['python_runtime']['version']},
           'expected_checks': sorted(marketing_plan.expected_check_set(plan_name) | set(ISOLATION_CHECKS)),
           'canary_digests': {k: hashlib.sha256(v).hexdigest() for k, (p, v) in canaries.items()}}
    (run_dir / 'run.json').write_text(json.dumps(run, indent=2) + '\n')
    return run


class Cancelled(Exception):
    pass


def aggregate(run, state, cleanup_record, limits_verified, inputs_ok, vm_exit):
    expected = state['expected']
    check_records = []
    plan_entries = marketing_plan.plan_by_name(run['plan_name'])
    for name in sorted(expected):
        command = 'guest-native'
        for entry in plan_entries:
            if entry['name'] == name:
                command = ' '.join(entry['argv'])
        check_line = state['check_lines'].get(name)
        exit_code = state['exit_codes'].get(name)
        timeout = state['timeouts'].get(name, 0)
        log_digest = state['log_digests'].get(name, 'guest-native')
        if check_line is None:
            result = 'BLOCKED' if name in (e['name'] for e in plan_entries) and not state['ready_at'] else 'FAIL'
            check_records.append({'name': name, 'command': command, 'exit_code': exit_code if exit_code is not None else 126,
                                  'timeout': timeout, 'result': result, 'log_digest': 'guest-native'})
            continue
        if name in (entry['name'] for entry in plan_entries):
            if exit_code is None:
                result = 'FAIL'
            elif check_line == 'PASS' and exit_code == 0 and timeout == 0:
                result = 'PASS'
            else:
                result = 'FAIL'
        else:
            result = 'PASS' if check_line == 'PASS' else 'FAIL'
            if exit_code is None:
                exit_code = 0 if result == 'PASS' else 1
        check_records.append({'name': name, 'command': command,
                              'exit_code': exit_code if exit_code is not None else 126,
                              'timeout': timeout, 'result': result, 'log_digest': log_digest})
    isolation_ok = all(state['check_lines'].get(name) == 'PASS' for name in ISOLATION_CHECKS)
    cleanup_ok = bool(cleanup_record and cleanup_record.get('cleanup_verified'))
    protocol_ok = not state['protocol_errors']
    all_pass = all(record['result'] == 'PASS' for record in check_records)
    exit_consistent = (vm_exit == 33) if all_pass else (vm_exit is None or vm_exit != 33)
    overall = 'PASS' if (all_pass and isolation_ok and cleanup_ok and limits_verified
                         and inputs_ok and protocol_ok and exit_consistent
                         and state['ready_at'] is not None) else 'FAIL'
    return check_records, isolation_ok, cleanup_ok, overall


def acquire_lane_lock(private):
    import fcntl
    lock_path = private_path(private) / 'marketing-lane.lock'
    handle = lock_path.open('a')
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        handle.close()
        raise RuntimeError('BLOCKED_LANE_LOCK: another marketing VM run holds the lane')
    return handle


def watch(run_dir_path, deadline_override=None):
    import lane
    run_dir = Path(run_dir_path)
    run = load_json(run_dir / 'run.json')
    lane_lock = acquire_lane_lock(run_dir.parents[1])
    assets_dir = assets(run_dir.parents[1])
    prep, image_record, mkt_record = verify_prepared(assets_dir)
    profile = run['profile']
    deadline = time.monotonic() + (deadline_override or profile['deadline_s'])
    response = ('SYNTHETIC_SERVICE_' + secrets.token_hex(16) + '\n').encode()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(response)

    class ReuseTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    port = _port_from_run(run)
    server = ReuseTCPServer(('0.0.0.0', port), Handler)
    server.timeout = 1
    threading.Thread(target=server.serve_forever, daemon=True).start()
    unix_path = Path(_unix_from_run(run))
    unix_server = socketserver.UnixStreamServer(str(unix_path), Handler)
    threading.Thread(target=unix_server.serve_forever, daemon=True).start()
    positive = {}
    for address in ['127.0.0.1', _lan_from_run(run)]:
        with socket.create_connection((address, port), timeout=2) as sock:
            positive[address] = sock.recv(1024) == response
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect(str(unix_path))
        positive['synthetic_unix_socket'] = sock.recv(1024) == response
    if not all(positive.values()):
        raise RuntimeError('host synthetic service positive control failed')

    state = {'expected': set(run['expected_checks']), 'check_lines': {}, 'exit_codes': {},
             'timeouts': {}, 'log_digests': {}, 'protocol_errors': [], 'markers': [],
             'ready_at': None, 'log_tail': '', 'noise_lines': 0}
    console = bytearray()
    console_path = run_dir / 'console.log'
    offset = 0
    rc_seen_at = None
    unit = run['unit']
    observed_pids = set()
    owned_scope = False
    limits_verified = False
    observed_limits = {}
    outcome = 'UNKNOWN'
    scope_active_last = False
    termination_signal = None
    old_handler = signal.getsignal(signal.SIGTERM)

    def cancel(signum, frame):
        nonlocal termination_signal
        termination_signal = signum
        raise Cancelled('SIGTERM')

    signal.signal(signal.SIGTERM, cancel)
    started = time.monotonic()
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        while True:
            try:
                text = console_path.read_text(errors='replace') if console_path.exists() else ''
            except OSError:
                text = ''
            fresh = text[offset:]
            offset = len(text)
            console.extend(fresh.encode(errors='replace'))
            if len(console) > profile['console_budget_bytes']:
                outcome = 'console_budget_exceeded'
                break
            for raw in fresh.splitlines():
                parse_protocol_line(raw.rstrip('\r'), state)
            show = lane.systemctl('show', unit, '-p', 'LoadState', '-p', 'ActiveState', '--value')
            states = [line.strip() for line in show.stdout.splitlines() if line.strip()]
            load_state = states[0] if states else 'unknown'
            active_state = states[1] if len(states) > 1 else 'unknown'
            active = show.returncode == 0 and active_state in ('active', 'activating',
                                                               'reloading')
            scope_active_last = active
            if active:
                pids = lane.scope_pids(unit)
                if pids:
                    owned_scope = True
                    observed_pids.update(pids)
                metrics = lane.scope_metrics(unit)
                if metrics.get('memory.max') == str(int(int(profile['scope_memory_max'][:-1]) * 1024 * 1024)):
                    observed_limits = metrics
            available = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                             if line.startswith('MemAvailable:'))
            if available < profile['mem_floor_mib'] * 1024:
                outcome = 'host_reserve_lost'
                break
            if state['ready_at'] is not None and run.get('mode') == 'abort_after_ready':
                if time.monotonic() - state['ready_at'] > (run.get('abort_delay_s') or 30):
                    # Deliver a genuine SIGTERM to this controller process; the
                    # installed handler performs the cancellation path.
                    os.kill(os.getpid(), signal.SIGTERM)
            if time.monotonic() > deadline:
                outcome = 'timeout'
                break
            exit_rc = run_dir / 'vm-exit.rc'
            if exit_rc.exists() and not active:
                outcome = 'exited'
                break
            if exit_rc.exists():
                if rc_seen_at is None:
                    rc_seen_at = time.monotonic()
                elif time.monotonic() - rc_seen_at > 10:
                    outcome = 'exited'
                    break
            if not active and (run_dir / 'started-at.txt').exists() and time.monotonic() - started > 30:
                outcome = 'scope_lost'
                break
            time.sleep(0.5)
    except Cancelled:
        outcome = 'cancelled'
    except BaseException as error:
        outcome = 'controller_error:' + type(error).__name__
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            if outcome in ('timeout', 'cancelled', 'controller_error:Cancelled', 'host_reserve_lost',
                           'console_budget_exceeded') or (outcome == 'UNKNOWN'):
                try:
                    lane.systemctl('kill', '--signal=SIGKILL', unit)
                    lane.systemctl('stop', unit)
                except BaseException:
                    pass
            time.sleep(1)
            for _attempt in range(3):
                load_state_now = lane.systemctl('show', unit, '-p', 'LoadState', '--value').stdout.strip()
                if load_state_now == 'not-found':
                    break
                lane.systemctl('stop', unit)
                time.sleep(2)
            vm_exit = None
            exit_rc = run_dir / 'vm-exit.rc'
            if exit_rc.exists():
                try:
                    vm_exit = int(exit_rc.read_text().strip())
                except ValueError:
                    vm_exit = None
            cleanup_record = lane.cleanup(unit, owned_scope, None, observed_pids,
                                          run_dir / 'job', run_dir / 'evidence', bytes(console))
            limits_verified = (observed_limits.get('memory.max') ==
                               str(int(int(profile['scope_memory_max'][:-1]) * 1024 * 1024)) and
                               observed_limits.get('memory.swap.max') == '0')
            inputs_ok = (sha256_file(assets_dir / 'ws-base.img') == image_record['sha256'] and
                         sha256_file(assets_dir / 'marketing-initrd') == mkt_record['initrd_sha256'])
            check_records, isolation_ok, cleanup_ok, overall = aggregate(
                run, state, cleanup_record, limits_verified, inputs_ok, vm_exit)
            server.shutdown(); server.server_close()
            unix_server.shutdown(); unix_server.server_close()
            unix_path.unlink(missing_ok=True)
            finished_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            result = {'schema': 'relay.marketing-run-result.v1', 'run_id': run['run_id'], 'outcome': outcome,
                      'vm_exit': vm_exit, 'started_at': started_at, 'finished_at': finished_at,
                      'termination_signal': termination_signal,
                      'terminated_while_running': (outcome in ('timeout', 'cancelled')
                                                   and scope_active_last),
                      'host_service_positive_controls': positive,
                      'protocol_errors': state['protocol_errors'][:50],
                      'markers': state['markers'], 'cleanup': cleanup_record,
                      'limits_verified': limits_verified, 'inputs_unchanged': inputs_ok,
                      'overall_result': overall, 'isolation_result': 'PASS' if isolation_ok else 'FAIL'}
            (run_dir / 'evidence' / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            vm_root = Path(__file__).parent
            executor_version = {name: sha256_file(vm_root / name) for name in EXECUTOR_FILES}
            relay_head = (run_dir / 'relay-head.txt')
            manifest_run = dict(run)
            manifest_run.update({
                'executor_version': executor_version,
                'relay_commit_sha': relay_head.read_text().strip() if relay_head.exists() else '0' * 40,
                'started_at': started_at, 'finished_at': finished_at,
                'check_records': check_records, 'overall_result': overall,
                'cleanup_result': 'PASS' if cleanup_ok else 'FAIL',
                'isolation_result': 'PASS' if isolation_ok else 'FAIL',
                'evidence': {}, 'toolchain_versions': run['toolchain_versions'],
                'profile': profile})
            manifest_run['evidence'] = {
                'result.json': sha256_file(run_dir / 'evidence' / 'result.json')}
            manifest = marketing_manifest.build_manifest(manifest_run)
            (run_dir / 'evidence' / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            manifest_run['evidence'] = {
                'result.json': sha256_file(run_dir / 'evidence' / 'result.json'),
                'manifest.json': sha256_file(run_dir / 'evidence' / 'manifest.json'),
                'console.log': sha256_file(run_dir / 'evidence' / 'console.log')}
            envelope = {'schema': 'relay.marketing-evidence-envelope.v1', 'run_id': run['run_id'],
                        'files': manifest_run['evidence'],
                        'run_json_sha256': sha256_file(run_dir / 'run.json')}
            (run_dir / 'evidence' / 'envelope.json').write_text(json.dumps(envelope, indent=2) + '\n')
            print(json.dumps({'run_id': run['run_id'], 'outcome': outcome, 'overall': overall,
                              'isolation': result['isolation_result'],
                              'cleanup': 'PASS' if cleanup_ok else 'FAIL',
                              'checks': {r['name']: r['result'] for r in check_records}}))
        finally:
            try:
                lane_lock.close()
            except BaseException:
                pass
            signal.signal(signal.SIGTERM, old_handler)
    return outcome


def _port_from_run(run):
    return int(_config_value(run, 'HOST_PORT'))


def _lan_from_run(run):
    return _config_value(run, 'LAN_PROBE')


def _unix_from_run(run):
    return _config_value(run, 'SOCKET_CANARY_PATH')


def _config_value(run, key):
    return run['_config'][key]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['launch', 'watch'])
    parser.add_argument('--private', type=Path)
    parser.add_argument('--plan', default='production')
    parser.add_argument('--mode', default='run', choices=['run', 'hold', 'abort_after_ready'])
    parser.add_argument('--abort-delay', type=int)
    parser.add_argument('--deadline', type=int)
    parser.add_argument('--guest-mib', type=int)
    parser.add_argument('--run', type=Path)
    args = parser.parse_args()
    if args.phase == 'launch':
        print(json.dumps(launch(args.private, args.plan, args.mode, args.abort_delay,
                                args.deadline, args.guest_mib), indent=2))
    else:
        raise SystemExit(0 if watch(args.run, args.deadline) in ('exited',) else 0)
