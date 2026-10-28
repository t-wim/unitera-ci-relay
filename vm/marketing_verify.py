"""Independent evidence verifier for marketing Python VM runs. Separate process,
separate decision logic.

Re-derives the verdict from raw artifacts (console transcript, envelope digests,
manifest, run.json, prep manifest) without trusting the monitor's aggregation:
schema validation, digest recomputation, completeness of the mandatory check set,
per-check exit/timeout consistency, isolation/positive-control/cleanup gates,
exact source/relay/runtime binding, unknown-outcome fail-closed handling and
run-id replay protection against the append-only run ledger.

A local hash chain is NOT a cryptographic attestation; this verifier establishes
consistency with locally recorded digests only. No guest self-assessment is ever
accepted as attested truth: only host-observed console records count."""
import argparse
import json
import re
from pathlib import Path

import marketing_manifest
import marketing_plan
from ci_util import sha256_file
from marketing_vm_contract import ISOLATION_CHECKS

LEDGER_SCHEMA = 'relay.marketing-run-ledger.v1'


def reasons_from(run_dir, expect_plan=None, prep_manifest=None):
    run_dir = Path(run_dir)
    problems = []
    envelope = json.loads((run_dir / 'evidence' / 'envelope.json').read_text())
    if envelope.get('schema') != 'relay.marketing-evidence-envelope.v1':
        problems.append('envelope schema mismatch')
    for name, digest in envelope.get('files', {}).items():
        path = run_dir / 'evidence' / name
        if not path.exists():
            problems.append('evidence file missing: ' + name)
        elif sha256_file(path) != digest:
            problems.append('evidence digest mismatch: ' + name)
    if sha256_file(run_dir / 'run.json') != envelope.get('run_json_sha256'):
        problems.append('run.json digest mismatch against envelope')
    manifest = json.loads((run_dir / 'evidence' / 'manifest.json').read_text())
    if manifest.get('schema') != marketing_manifest.SCHEMA:
        problems.append('manifest schema mismatch')
    try:
        marketing_manifest.validate_manifest(manifest)
    except ValueError as exc:
        problems.append('manifest invalid: ' + str(exc))
    run = json.loads((run_dir / 'run.json').read_text())
    console = (run_dir / 'evidence' / 'console.log').read_text(errors='replace')
    result = json.loads((run_dir / 'evidence' / 'result.json').read_text())

    # Unknown or ambiguous controller outcomes can never produce a positive verdict.
    if result.get('outcome') not in ('exited', 'timeout', 'cancelled'):
        problems.append('fail-closed outcome: ' + str(result.get('outcome')))
    if result.get('vm_exit') is None and result.get('outcome') == 'exited':
        problems.append('exited run without authoritative VM exit code')

    # Independent console re-derivation (mirrors guest protocol, not monitor internals).
    checks_seen, exits_seen, tmos_seen, digests_seen, ready = {}, {}, {}, {}, False
    for line in console.splitlines():
        line = line.rstrip('\r')
        parts = line.split(' ')
        if parts[0] == 'CHECK' and len(parts) == 3 and re.fullmatch(r'[a-z0-9][a-z0-9_-]*', parts[1]):
            checks_seen[parts[1]] = parts[2]
        elif parts[0] == 'EXIT' and len(parts) == 3 and re.fullmatch(r'-?\d+', parts[2]):
            exits_seen[parts[1]] = int(parts[2])
        elif parts[0] == 'TMO' and len(parts) == 3 and parts[2] in ('0', '1'):
            tmos_seen[parts[1]] = int(parts[2])
        elif parts[0] == 'LOGDIGEST' and len(parts) == 3 and re.fullmatch(r'[0-9a-f]{64}', parts[2]):
            digests_seen[parts[1]] = parts[2]
        elif line == 'SRC_READY':
            ready = True
    if not ready:
        problems.append('SRC_READY not present in console')
    expected = set(run['expected_checks'])
    if expect_plan:
        expected = set(marketing_plan.expected_check_set(expect_plan)) | set(ISOLATION_CHECKS)
    missing = expected - set(checks_seen)
    if missing:
        problems.append('console missing checks: ' + ','.join(sorted(missing))[:200])
    unexpected = set(checks_seen) - expected
    if unexpected:
        problems.append('console has unexpected checks: ' + ','.join(sorted(unexpected))[:200])
    manifest_checks = {entry['check_name']: entry for entry in manifest['checks']}
    if set(manifest_checks) != expected:
        problems.append('manifest check set differs from expected mandatory set')
    plan_name = expect_plan or manifest.get('test_plan') or run.get('plan_name')
    try:
        plan_checks = {entry['name'] for entry in marketing_plan.plan_by_name(plan_name)}
    except ValueError:
        plan_checks = set()
        problems.append('unknown test plan binding in evidence')
    if expect_plan and manifest.get('test_plan') != expect_plan:
        problems.append('manifest test plan differs from expected plan')
    for name, entry in manifest_checks.items():
        observed = checks_seen.get(name)
        recorded_exit = exits_seen.get(name)
        recorded_tmo = tmos_seen.get(name, 0)
        recorded_digest = digests_seen.get(name)
        if observed is None:
            problems.append('manifest check absent from console: ' + name)
            continue
        if entry['result'] == 'PASS':
            if observed != 'PASS' or entry['exit_code'] != 0 or entry['timeout'] != 0:
                problems.append('PASS inconsistent for ' + name)
            if name in plan_checks:
                # A passed plan command must carry its actual console exit code.
                if recorded_exit is None:
                    problems.append('missing actual exit code for ' + name)
                elif recorded_exit != entry['exit_code']:
                    problems.append('exit code mismatch for ' + name)
            if recorded_tmo != entry['timeout']:
                problems.append('timeout flag mismatch for ' + name)
            if recorded_digest is not None and entry['log_digest'] != 'guest-native' \
                    and recorded_digest != entry['log_digest']:
                problems.append('log digest mismatch for ' + name)
        elif entry['result'] == 'FAIL':
            if observed != 'FAIL':
                problems.append('FAIL inconsistent for ' + name)
            if recorded_exit is None:
                problems.append('missing actual exit code for failed ' + name)
            if recorded_tmo != entry['timeout']:
                problems.append('timeout flag mismatch for ' + name)
        else:
            if observed == 'PASS':
                problems.append('BLOCKED/SKIPPED but console shows PASS: ' + name)
    isolation_ok = all(checks_seen.get(name) == 'PASS' for name in ISOLATION_CHECKS)
    if manifest['isolation_result'] != ('PASS' if isolation_ok else 'FAIL'):
        problems.append('isolation_result inconsistent with console')
    if manifest['isolation_result'] != 'PASS':
        problems.append('isolation_result not PASS')
    if manifest['cleanup_result'] != 'PASS':
        problems.append('cleanup_result not PASS')
    positive = result.get('host_service_positive_controls')
    if not isinstance(positive, dict) or len(positive) < 3 or not all(positive.values()):
        problems.append('host positive controls missing or failed')
    recomputed_overall = 'PASS' if (isolation_ok and manifest['cleanup_result'] == 'PASS'
                                    and all(e['result'] == 'PASS' for e in manifest['checks'])
                                    and ready and not unexpected
                                    and result.get('outcome') == 'exited'
                                    and result.get('vm_exit') == 33) else 'FAIL'
    if manifest['overall_result'] != recomputed_overall:
        problems.append('overall_result inconsistent: manifest=' + manifest['overall_result']
                        + ' recomputed=' + recomputed_overall)
    if result.get('overall_result') != manifest['overall_result']:
        problems.append('result.json/manifest overall mismatch')
    # Timeout, interruption and cleanup must stay distinguishable.
    if result.get('outcome') == 'timeout' and result.get('terminated_while_running') is not True:
        problems.append('timeout without live termination evidence')
    if result.get('outcome') == 'cancelled':
        if result.get('terminated_while_running') is not True:
            problems.append('cancellation without live termination evidence')
        if result.get('termination_signal') != 15:
            problems.append('cancellation without observed SIGTERM')
    if prep_manifest:
        prep = json.loads(Path(prep_manifest).read_text())
        if manifest['source_commit_sha'] != prep['source']['commit']:
            problems.append('source commit not bound to prep manifest')
        if manifest['source_artifact_digest'] != prep['source']['archive_sha256']:
            problems.append('source archive digest not bound to prep manifest')
        if manifest['source_inventory_digest'] != prep['source']['inventory_sha256']:
            problems.append('source inventory digest not bound to prep manifest')
        if manifest['python_runtime_sha256'] != prep['python_runtime']['python_bin_sha256']:
            problems.append('python runtime digest not bound to prep manifest')
        if manifest['vm_image_digest'] != prep['python_runtime']['initrd_sha256']:
            problems.append('guest image digest not bound to prep manifest')
    return manifest, problems


def ledger_path(private):
    return Path(private) / 'marketing-run-ledger.json'


def ledger_append(private, run_id, manifest_digest):
    path = ledger_path(private)
    if path.exists():
        ledger = json.loads(path.read_text())
    else:
        ledger = {'schema': LEDGER_SCHEMA, 'runs': {}}
    if ledger.get('schema') != LEDGER_SCHEMA:
        raise ValueError('ledger schema mismatch')
    if run_id in ledger['runs']:
        raise ValueError('REPLAY_REJECTED: run_id already in ledger: ' + run_id)
    ledger['runs'][run_id] = {'manifest_sha256': manifest_digest}
    ledger['collisions'] = ledger.get('collisions', 0)
    path.write_text(json.dumps(ledger, indent=2) + '\n')
    return True


def verify(run_dir, private, expect_plan=None, prep_manifest=None, append=False):
    manifest, problems = reasons_from(run_dir, expect_plan, prep_manifest)
    if append:
        if problems:
            problems.append('ledger append refused: run not accepted')
        else:
            ledger_append(private, manifest['run_id'],
                          sha256_file(Path(run_dir) / 'evidence' / 'manifest.json'))
    return manifest, problems


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True, type=Path)
    parser.add_argument('--private', required=True, type=Path)
    parser.add_argument('--expect-plan')
    parser.add_argument('--prep-manifest', type=Path)
    parser.add_argument('--append-ledger', action='store_true')
    args = parser.parse_args()
    manifest, problems = verify(args.run, args.private, args.expect_plan,
                                args.prep_manifest, args.append_ledger)
    print(json.dumps({'run_id': manifest['run_id'], 'overall_result': manifest['overall_result'],
                      'verdict': 'ACCEPT' if not problems else 'REJECT',
                      'problems': problems}, indent=2))
    raise SystemExit(0 if not problems else 1)
