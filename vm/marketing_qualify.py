"""Real five-case marketing Python VM qualification driver (Q1-Q5).

Runs on the live t-wim host only. For every case it launches the prepared VM lane,
observes the raw console, re-derives the per-case receipt from host-observed
evidence only (never from guest self-assessment), verifies each case with the
independent verifier and only then computes VM_ISOLATION_QUALIFIED via the
fail-closed qualification gate.

Q1 success (production plan), Q2 deliberate failure (fixture plan), Q3 actual
per-command timeout (fixture plan), Q4 real SIGTERM cancellation while the VM is
running (the watch controller delivers a genuine SIGTERM to itself after
SRC_READY, exactly like the qualified synthetic lane), Q5 fresh successor
success. No marketing source code is executed on the host at any point.

The only child process is this checkout's own mechanical launcher script (a
reviewed #!/bin/sh file), invoked through /bin/sh with a resolved argv list; the
per-run directory is resolved and containment-checked against the guarded
private runs root before any use.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import marketing_monitor
import marketing_verify
from ci_util import sha256_file
from marketing_vm_contract import ISOLATION_CHECKS
from marketing_vm_qualification import evaluate, implementation_digests
from paths import private_path

VM_ROOT = Path(__file__).resolve().parent
RELAY_ROOT = VM_ROOT.parent
START_SCRIPT = VM_ROOT / 'marketing_start.sh'

CASES = (
    {'index': 1, 'case': 'success', 'plan': 'production', 'mode': 'run'},
    {'index': 2, 'case': 'failure', 'plan': 'q2_deliberate_failure', 'mode': 'run'},
    {'index': 3, 'case': 'timeout', 'plan': 'q3_resource_timeout', 'mode': 'run'},
    {'index': 4, 'case': 'cancel', 'plan': 'production', 'mode': 'abort_after_ready',
     'abort_delay_s': 3},
    {'index': 5, 'case': 'success', 'plan': 'production', 'mode': 'run'},
)


def validated_relay_root(relay_root):
    """Require the requested relay checkout to be exactly this module's own tree."""
    root = Path(relay_root).resolve(strict=True)
    if root != RELAY_ROOT:
        raise ValueError('relay root does not contain this executor module')
    if not (root / '.git').exists() and not (root / 'HEAD').exists():
        raise ValueError('relay root is not a git checkout')
    if not START_SCRIPT.is_file() or START_SCRIPT.is_symlink():
        raise ValueError('relay executor script missing: marketing_start.sh')
    return root


def validated_run_dir(private, run_dir):
    """A run directory must be a direct child of the guarded private runs root."""
    runs = (private_path(private) / 'runs').resolve()
    resolved = Path(run_dir).resolve(strict=True)
    if resolved.parent != runs or not resolved.is_dir():
        raise ValueError('run directory outside the guarded runs root')
    return resolved


def _console_text(run_dir):
    try:
        return (run_dir / 'console.log').read_text(errors='replace')
    except OSError:
        return ''


def _console_records(console):
    """Re-derive CHECK/EXIT/TMO/LOGDIGEST/LOG records straight from raw console."""
    records = {'checks': {}, 'exits': {}, 'tmos': {}, 'digests': {}, 'logs': {},
               'markers': [], 'ready': False, 'log_budget': {}}
    for line in console.splitlines():
        line = line.rstrip('\r')
        parts = line.split(' ')
        if parts[0] == 'CHECK' and len(parts) == 3:
            records['checks'][parts[1]] = parts[2]
        elif parts[0] == 'EXIT' and len(parts) == 3:
            records['exits'][parts[1]] = int(parts[2])
        elif parts[0] == 'TMO' and len(parts) == 3:
            records['tmos'][parts[1]] = int(parts[2])
        elif parts[0] == 'LOGDIGEST' and len(parts) == 3:
            records['digests'][parts[1]] = parts[2]
        elif parts[0] == 'LOG' and len(parts) >= 2:
            name = parts[1]
            records['logs'].setdefault(name, []).append(line[len('LOG ' + name + ' '):])
        elif parts[0] == 'LOGBUDGET' and len(parts) == 3:
            records['log_budget'][parts[1]] = int(parts[2])
        elif line == 'SRC_READY':
            records['ready'] = True
        elif line in ('GUEST_ALL_CHECKS_PASSED', 'GUEST_ASSERTIONS_FAILED', 'SRC_MOUNT_FAILED'):
            records['markers'].append(line)
    return records


def _materialize_logs(run_dir, records, plan_entries):
    logs_dir = run_dir / 'logs'
    if logs_dir.exists():
        raise ValueError('refuse to overwrite existing qualification logs')
    logs_dir.mkdir(mode=0o700)
    result = {}
    for entry in plan_entries:
        name = entry['name']
        if name not in records['digests'] or name not in records['exits']:
            continue
        data = ('\n'.join(records['logs'].get(name, [])) + '\n').encode() \
            if records['logs'].get(name) else b''
        if hashlib.sha256(data).hexdigest() != records['digests'][name]:
            raise ValueError('reconstructed log digest differs from console record: ' + name)
        (logs_dir / (name + '.log')).write_bytes(data)
        (logs_dir / (name + '.log')).chmod(0o600)
        result[name] = {'argv': list(entry['argv']), 'exit_code': records['exits'][name],
                        'timeout': records['tmos'].get(name) == 1,
                        'sha256': records['digests'][name]}
    return result


def _cleanup_view(cleanup, canaries_absent, limits_verified):
    if not isinstance(cleanup, dict):
        return {}
    return {
        'scope_reaped': cleanup.get('final_scope_load_state') == 'not-found'
                        and not cleanup.get('cleanup_errors'),
        'no_owned_processes': cleanup.get('observed_pids_still_exist') == []
                              and cleanup.get('scope_remaining_pids') in ([], None),
        'disk_overlay_removed': cleanup.get('job_directory_removed') is True,
        'host_credentials_absent': canaries_absent,
        'limits_verified': limits_verified,
    }


def _run_vm(relay_root, private, case):
    validated_relay_root(relay_root)
    run = marketing_monitor.launch(private, case['plan'], case['mode'],
                                   case.get('abort_delay_s'))
    run_dir = validated_run_dir(private, run['run_dir'])

    def reap():
        # The only child process: this checkout's own mechanical launcher script,
        # executed exactly as its #!/bin/sh shebang would; its exit code is the
        # authoritative VM exit code.
        console_handle = (run_dir / 'console.log').open('wb')
        launch = subprocess.run(['/bin/sh', str(START_SCRIPT), str(run_dir)],
                                stdout=console_handle, stderr=subprocess.STDOUT)
        console_handle.close()
        (run_dir / 'vm-exit.rc').write_text(str(launch.returncode) + '\n')

    reaper = threading.Thread(target=reap, daemon=True)
    reaper.start()
    marketing_monitor.watch(run_dir)
    reaper.join(timeout=180)
    result = json.loads((run_dir / 'evidence' / 'result.json').read_text())
    return run, run_dir, result


def build_receipt(case, run, run_dir, result, console, relay_sha, prep, prior_run_ids):
    records = _console_records(console)
    manifest = json.loads((run_dir / 'evidence' / 'manifest.json').read_text())
    plan_entries = [entry for entry in _plan_entries(case['plan'])
                    if entry['name'] in records['digests']]
    logs = _materialize_logs(run_dir, records, plan_entries) if case['case'] != 'cancel' else {}
    isolation = {name: records['checks'].get(name) for name in ISOLATION_CHECKS}
    console_bytes = console.encode(errors='replace')
    canaries_absent = True
    for label in ('host', 'review', 'status'):
        path = run_dir / (label + '.canary')
        if path.exists() and path.read_bytes()[:24] in console_bytes:
            canaries_absent = False
    cleanup = _cleanup_view(result.get('cleanup', {}), canaries_absent,
                            result.get('limits_verified') is True)
    vm_exit = result.get('vm_exit')
    observed = None
    negative = None
    if case['case'] == 'success':
        if (result.get('outcome') == 'exited' and vm_exit == 33
                and manifest['overall_result'] == 'PASS'
                and all(value == 'PASS' for value in isolation.values())):
            observed = 'success'
    elif case['case'] == 'failure':
        failure_exit = (vm_exit == 35
                        and any(code != 0 and code != 124 for code in records['exits'].values()))
        if result.get('outcome') == 'exited' and failure_exit:
            observed = 'failure'
        negative = failure_exit and all(cleanup.values())
    elif case['case'] == 'timeout':
        tmo_seen = any(flag == 1 for flag in records['tmos'].values())
        exit_124 = 124 in records['exits'].values()
        if result.get('outcome') == 'exited' and vm_exit == 35 and tmo_seen and exit_124:
            observed = 'timeout'
        negative = tmo_seen and exit_124 and vm_exit == 35 and all(cleanup.values())
    elif case['case'] == 'cancel':
        if (result.get('outcome') == 'cancelled'
                and result.get('termination_signal') == 15
                and result.get('terminated_while_running') is True):
            observed = 'cancel'
        negative = (result.get('terminated_while_running') is True
                    and result.get('termination_signal') == 15 and all(cleanup.values()))
    # 'terminated_while_running' semantics per case: for a per-command timeout the
    # guest console proves the kill fired inside a live VM (the guest kept running
    # to its deliberate failure exit afterwards); for cancellation the controller
    # observed the live scope at SIGTERM time.
    if case['case'] == 'timeout':
        terminated_while_running = (negative is True)
    else:
        terminated_while_running = result.get('terminated_while_running')
    receipt = {
        'schema': 'relay.marketing-vm-receipt.v1',
        'repository': 'baum777/unitera_marketing_agent-team',
        'source_sha': run['source_commit_sha'], 'relay_sha': relay_sha,
        'run_id': run['run_id'], 'test_plan': case['plan'],
        'execution_profile': 'marketing-python-vm-v1',
        'source_archive': {'sha256': run['source_artifact_digest']},
        'guest_image': {'sha256': run['vm_image_digest']},
        'python_runtime': {'sha256': run['python_runtime_sha256']},
        'started_at': result.get('started_at'), 'finished_at': result.get('finished_at'),
        'vm_exit_code': vm_exit,
        'source_verified_inside_guest': records['checks'].get('c1_source_integrity') == 'PASS',
        'toolchain_verified_inside_guest': records['checks'].get('c2_toolchain_validation') == 'PASS',
        'host_test_execution': False,
        'expected_outcome': case['case'], 'observed_outcome': observed,
        'negative_control_verified': negative,
        'failure_exit_observed': (case['case'] == 'failure' and vm_exit == 35
                                  and any(code not in (0, 124)
                                          for code in records['exits'].values())),
        'terminated_while_running': terminated_while_running,
        'termination_reason': case['case'] if case['case'] in ('timeout', 'cancel') else None,
        'termination_signal': result.get('termination_signal') if case['case'] == 'cancel' else None,
        'fresh_successor_verified': (case['index'] == 5
                                     and all(value == 'PASS' for value in isolation.values())
                                     and run['run_id'] not in prior_run_ids
                                     and records['ready']),
        'logs': logs, 'isolation': isolation, 'cleanup': cleanup,
    }
    (run_dir / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return receipt


def _plan_entries(plan_name):
    import marketing_plan
    return marketing_plan.plan_by_name(plan_name)


def qualify(relay_root, private, source_sha):
    root = validated_relay_root(relay_root)
    private = private_path(private)
    prep_path = private / 'marketing-assets' / 'marketing-prep-manifest.json'
    prep = json.loads(prep_path.read_text())
    if prep['source']['commit'] != source_sha:
        raise ValueError('prepared assets are not bound to the requested source SHA')
    relay_sha = subprocess.check_output(
        ['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.run(['git', '-C', str(root), 'status', '--porcelain', '--', 'vm'],
                           capture_output=True, text=True).stdout.strip()
    if dirty:
        raise ValueError('vm/ implementation has uncommitted changes; commit before qualifying')
    binding = {'relay_commit_sha': relay_sha, 'host_observation': True,
               'host': 't-wim self-hosted runner host (live QEMU/KVM lane)',
               'executor_digests': implementation_digests(VM_ROOT),
               'observed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    receipts = []
    prior_run_ids = set()
    for case in CASES:
        run, run_dir, result = _run_vm(root, private, case)
        receipt = build_receipt(case, run, run_dir, result, _console_text(run_dir),
                                relay_sha, prep, prior_run_ids)
        prior_run_ids.add(run['run_id'])
        _manifest, problems = marketing_verify.verify(
            run_dir, private, expect_plan=case['plan'], prep_manifest=str(prep_path),
            append=False)
        receipt['independent_verifier'] = 'ACCEPT' if not problems else {'REJECT': problems[:10]}
        (run_dir / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        receipts.append(receipt)
        accepted = not problems and receipt['observed_outcome'] == case['case']
        print(json.dumps({'case': case['index'], 'expected': case['case'],
                          'observed': receipt['observed_outcome'], 'vm_exit': result.get('vm_exit'),
                          'verifier': 'ACCEPT' if not problems else 'REJECT',
                          'run_id': run['run_id']}), flush=True)
        if not accepted:
            break
    if len(receipts) == len(CASES):
        verdict = evaluate(_case_run_dirs(private, receipts), source_sha, relay_sha, binding)
    else:
        verdict = {'schema': 'relay.marketing-vm-qualification.v1', 'qualified': False,
                   'evidence_consistent': False,
                   'errors': ['qualification stopped early: only %d cases completed'
                              % len(receipts)]}
    record = {'schema': 'relay.marketing-vm-qualification-record.v1',
              'source_sha': source_sha, 'relay_sha': relay_sha, 'host_binding': binding,
              'cases': receipts, 'verdict': verdict,
              'VM_ISOLATION_QUALIFIED': bool(verdict.get('qualified'))}
    (private / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def _case_run_dirs(private, receipts):
    runs = private_path(private) / 'runs'
    return [str(runs / receipt['run_id']) for receipt in receipts]


def append_accepted_to_ledger(private, record):
    private = private_path(private)
    for receipt in record['cases']:
        if receipt.get('independent_verifier') == 'ACCEPT':
            marketing_verify.ledger_append(
                private, receipt['run_id'],
                sha256_file(private / 'runs' / receipt['run_id'] / 'evidence' / 'manifest.json'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--relay-root', required=True, type=Path)
    parser.add_argument('--private', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--append-ledger', action='store_true')
    args = parser.parse_args()
    record = qualify(args.relay_root, args.private, args.source_sha)
    if args.append_ledger and record['VM_ISOLATION_QUALIFIED']:
        append_accepted_to_ledger(args.private, record)
    print(json.dumps({'VM_ISOLATION_QUALIFIED': record['VM_ISOLATION_QUALIFIED'],
                      'errors': record['verdict'].get('errors', [])[:10]}, indent=2))
    raise SystemExit(0 if record['VM_ISOLATION_QUALIFIED'] else 1)
