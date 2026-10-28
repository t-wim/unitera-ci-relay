"""Independent evidence verifier for source-CI runs. Separate process, separate decision logic.

Re-derives the verdict from the raw artifacts (console transcript, envelope digests, manifest)
without trusting the monitor's aggregation: schema validation, digest recomputation, completeness
of the mandatory check set, per-check exit/timeout consistency, isolation and cleanup gates,
and run-id replay protection against the append-only run ledger.

A local hash chain is NOT a cryptographic attestation; this verifier establishes consistency
with locally recorded digests only.
"""
import argparse
import json
import re
from pathlib import Path

from ci_manifest import SCHEMA
from ci_util import sha256_file

import ci_plan
import ci_monitor

LEDGER_SCHEMA = 'relay.ci-run-ledger.v1'


def reasons_from(run_dir, expect_plan=None, prep_manifest=None):
    run_dir = Path(run_dir)
    problems = []
    envelope = json.loads((run_dir / 'evidence' / 'envelope.json').read_text())
    if envelope.get('schema') != 'relay.ci-evidence-envelope.v1':
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
    if manifest.get('schema') != SCHEMA:
        problems.append('manifest schema mismatch')
    run = json.loads((run_dir / 'run.json').read_text())
    console = (run_dir / 'evidence' / 'console.log').read_text(errors='replace')

    # Independent console re-derivation (mirrors guest protocol, not monitor internals).
    checks_seen, exits_seen, tmos_seen, ready = {}, {}, {}, False
    for line in console.splitlines():
        line = line.rstrip('\r')
        parts = line.split(' ')
        if parts[0] == 'CHECK' and len(parts) == 3 and re.fullmatch(r'[a-z0-9][a-z0-9_-]*', parts[1]):
            checks_seen[parts[1]] = parts[2]
        elif parts[0] == 'EXIT' and len(parts) == 3 and re.fullmatch(r'-?\d+', parts[2]):
            exits_seen[parts[1]] = int(parts[2])
        elif parts[0] == 'TMO' and len(parts) == 3 and parts[2] in ('0', '1'):
            tmos_seen[parts[1]] = int(parts[2])
        elif line == 'SRC_READY':
            ready = True
    if not ready:
        problems.append('SRC_READY not present in console')
    expected = set(run['expected_checks'])
    if expect_plan:
        expected = set(ci_plan.expected_check_set(expect_plan)) | set(ci_monitor.ISOLATION_CHECKS)
    missing = expected - set(checks_seen)
    if missing:
        problems.append('console missing checks: ' + ','.join(sorted(missing))[:200])
    unexpected = set(checks_seen) - expected
    if unexpected:
        problems.append('console has unexpected checks: ' + ','.join(sorted(unexpected))[:200])
    manifest_checks = {entry['check_name']: entry for entry in manifest['checks']}
    if set(manifest_checks) != expected:
        problems.append('manifest check set differs from expected mandatory set')
    for name, entry in manifest_checks.items():
        observed = checks_seen.get(name)
        recorded_exit = exits_seen.get(name)
        recorded_tmo = tmos_seen.get(name, 0)
        if observed is None:
            problems.append('manifest check absent from console: ' + name)
            continue
        if entry['result'] == 'PASS':
            if observed != 'PASS' or entry['exit_code'] != 0 or entry['timeout'] != 0:
                problems.append('PASS inconsistent for ' + name)
            if recorded_exit is not None and recorded_exit != entry['exit_code']:
                problems.append('exit code mismatch for ' + name)
            if recorded_tmo != entry['timeout']:
                problems.append('timeout flag mismatch for ' + name)
        elif entry['result'] == 'FAIL':
            if observed != 'FAIL':
                problems.append('FAIL inconsistent for ' + name)
        else:
            if observed == 'PASS':
                problems.append('BLOCKED/SKIPPED but console shows PASS: ' + name)
    isolation_ok = all(checks_seen.get(name) == 'PASS' for name in ci_monitor.ISOLATION_CHECKS)
    if manifest['isolation_result'] != ('PASS' if isolation_ok else 'FAIL'):
        problems.append('isolation_result inconsistent with console')
    if manifest['isolation_result'] != 'PASS':
        problems.append('isolation_result not PASS')
    if manifest['cleanup_result'] != 'PASS':
        problems.append('cleanup_result not PASS')
    recomputed_overall = 'PASS' if (isolation_ok and manifest['cleanup_result'] == 'PASS'
                                    and all(e['result'] == 'PASS' for e in manifest['checks'])
                                    and ready and not unexpected) else 'FAIL'
    if manifest['overall_result'] != recomputed_overall:
        problems.append('overall_result inconsistent: manifest=' + manifest['overall_result']
                        + ' recomputed=' + recomputed_overall)
    result_json = json.loads((run_dir / 'evidence' / 'result.json').read_text())
    if result_json.get('overall_result') != manifest['overall_result']:
        problems.append('result.json/manifest overall mismatch')
    if prep_manifest:
        prep = json.loads(Path(prep_manifest).read_text())
        if manifest['source_commit_sha'] != prep['source']['commit']:
            problems.append('source commit not bound to prep manifest')
        if manifest['dependency_lock_digest'] != prep['source']['lockfile_sha256']:
            problems.append('lockfile digest not bound to prep manifest')
    return manifest, problems


def ledger_path(private):
    return Path(private) / 'ci-run-ledger.json'


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


def execution_pin_problems(manifest, run, relay_pin, source_pin):
    """Pins come from the trusted caller, never from the run being verified."""
    for pin in (relay_pin, source_pin):
        if not isinstance(pin, str) or not re.fullmatch(r'[0-9a-f]{40}', pin) or pin == '0' * 40:
            raise ValueError('execution pins must be nonzero full commit SHAs')
    problems = []
    if manifest.get('relay_commit_sha') != relay_pin:
        problems.append('relay commit differs from trusted dispatch pin')
    if manifest.get('source_commit_sha') != source_pin or run.get('source_commit_sha') != source_pin:
        problems.append('source commit differs from trusted dispatch source')
    return problems


def verify(run_dir, private, expect_plan=None, prep_manifest=None, append=False,
           *, relay_pin, source_pin):
    manifest, problems = reasons_from(run_dir, expect_plan, prep_manifest)
    run = json.loads((Path(run_dir) / 'run.json').read_text())
    problems.extend(execution_pin_problems(manifest, run, relay_pin, source_pin))
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
    parser.add_argument('--relay-pin', required=True,
                        help='Full reviewed relay SHA from the trusted caller policy')
    parser.add_argument('--source-pin', required=True,
                        help='Full source SHA from the trusted dispatch request')
    args = parser.parse_args()
    manifest, problems = verify(args.run, args.private, args.expect_plan,
                                args.prep_manifest, args.append_ledger,
                                relay_pin=args.relay_pin, source_pin=args.source_pin)
    print(json.dumps({'run_id': manifest['run_id'], 'overall_result': manifest['overall_result'],
                      'verdict': 'ACCEPT' if not problems else 'REJECT',
                      'problems': problems}, indent=2))
    raise SystemExit(0 if not problems else 1)
