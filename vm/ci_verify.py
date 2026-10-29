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

from ci_manifest import SCHEMA, validate_manifest
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
    if set(envelope.get('files', {})) != {'manifest.json', 'console.log', 'result.json'}:
        problems.append('evidence envelope mandatory file set mismatch')
    for name, digest in envelope.get('files', {}).items():
        if name not in {'manifest.json', 'console.log', 'result.json'}:
            problems.append('unsafe/unexpected evidence name: ' + str(name))
            continue
        path = run_dir / 'evidence' / name
        if path.is_symlink():
            problems.append('linked evidence rejected: ' + name)
        elif not path.exists():
            problems.append('evidence file missing: ' + name)
        elif sha256_file(path) != digest:
            problems.append('evidence digest mismatch: ' + name)
    if sha256_file(run_dir / 'run.json') != envelope.get('run_json_sha256'):
        problems.append('run.json digest mismatch against envelope')
    manifest = json.loads((run_dir / 'evidence' / 'manifest.json').read_text())
    if manifest.get('schema') != SCHEMA:
        problems.append('manifest schema mismatch')
    try:
        validate_manifest(manifest)
    except (ValueError, TypeError, KeyError) as error:
        problems.append('manifest schema validation failed: ' + str(error))
    run = json.loads((run_dir / 'run.json').read_text())
    console = (run_dir / 'evidence' / 'console.log').read_text(errors='replace')

    # Independent console re-derivation (mirrors guest protocol, not monitor internals).
    checks_seen, exits_seen, tmos_seen, ready = {}, {}, {}, False
    for line in console.splitlines():
        line = line.rstrip('\r')
        parts = line.split(' ')
        if parts[0] == 'CHECK' and len(parts) == 3 and re.fullmatch(r'[a-z0-9][a-z0-9_-]*', parts[1]):
            if parts[1] in checks_seen:
                problems.append('duplicate console CHECK: ' + parts[1])
            checks_seen[parts[1]] = parts[2]
        elif parts[0] == 'EXIT' and len(parts) == 3 and re.fullmatch(r'-?\d+', parts[2]):
            if parts[1] in exits_seen:
                problems.append('duplicate console EXIT: ' + parts[1])
            exits_seen[parts[1]] = int(parts[2])
        elif parts[0] == 'TMO' and len(parts) == 3 and parts[2] in ('0', '1'):
            if parts[1] in tmos_seen:
                problems.append('duplicate console TMO: ' + parts[1])
            tmos_seen[parts[1]] = int(parts[2])
        elif line == 'SRC_READY':
            if ready:
                problems.append('duplicate SRC_READY')
            ready = True
    if not ready:
        problems.append('SRC_READY not present in console')
    expected = set(run['expected_checks'])
    if expect_plan:
        expected = set(ci_plan.expected_check_set(expect_plan)) | set(ci_monitor.ISOLATION_CHECKS)
        for entry in ci_plan.plan_by_name(expect_plan):
            if entry['name'] not in exits_seen or entry['name'] not in tmos_seen:
                problems.append('missing mandatory EXIT/TMO: ' + entry['name'])
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
    problems.extend(raw_result_problems(result_json, manifest))
    if prep_manifest:
        prep = json.loads(Path(prep_manifest).read_text())
        if manifest['source_commit_sha'] != prep['source']['commit']:
            problems.append('source commit not bound to prep manifest')
        if manifest['dependency_lock_digest'] != prep['source']['lockfile_sha256']:
            problems.append('lockfile digest not bound to prep manifest')
    return manifest, problems


def raw_result_problems(result_json, manifest):
    """Cross-check the raw monitor result a PASS verdict silently relies on:
    enforced cgroup limits, unchanged inputs, host positive controls and the raw
    cleanup record. A monitor that merely claims PASS cannot pass these."""
    problems = []
    if manifest['overall_result'] != 'PASS':
        return problems
    for field in ('limits_verified', 'inputs_unchanged'):
        if result_json.get(field) is not True:
            problems.append('result.json lacks ' + field + ' for a PASS run')
    # The guest contract is exit 33 == GUEST_ALL_CHECKS_PASSED; the monitor's own
    # aggregation requires it for an all-PASS run. Re-derive it independently so a
    # PASS claim over inconsistent failure-exit evidence (or a missing exit code)
    # cannot be accepted even if every other raw field looks right.
    if result_json.get('vm_exit') != 33:
        problems.append('PASS run does not record the all-checks-passed VM exit code 33'
                        ' (got ' + repr(result_json.get('vm_exit')) + ')')
    positives = result_json.get('host_service_positive_controls')
    if not isinstance(positives, dict) or not positives or not all(positives.values()):
        problems.append('host positive controls not all true')
    cleanup = result_json.get('cleanup')
    if not isinstance(cleanup, dict) or not cleanup.get('cleanup_verified'):
        problems.append('raw cleanup record not verified')
    elif cleanup.get('scope_remaining_pids') or cleanup.get('observed_pids_still_exist'):
        problems.append('cleanup left scope/process residue')
    return problems


def asset_binding_problems(private, manifest):
    """Independently re-derive the prepared asset digests from the private root.
    Missing assets stay pin-bound only (legacy fixtures); present assets must match."""
    problems = []
    assets = Path(private) / 'ci-assets'
    if not assets.is_dir():
        return problems
    for name in ('ci-image.json', 'ws-image.json', 'ci-prep-manifest.json'):
        if not (assets / name).is_file():
            problems.append('prepared asset record missing: ' + name)
            return problems
    ci_image = json.loads((assets / 'ci-image.json').read_text())
    ws_image = json.loads((assets / 'ws-image.json').read_text())
    prep = json.loads((assets / 'ci-prep-manifest.json').read_text())
    if not (assets / 'ci-initrd').is_file() or sha256_file(assets / 'ci-initrd') != ci_image.get('initrd_sha256'):
        problems.append('ci initrd digest mismatch against image record')
    if not (assets / 'ws-base.img').is_file() or sha256_file(assets / 'ws-base.img') != ws_image.get('sha256'):
        problems.append('workspace base image digest mismatch against image record')
    if manifest.get('vm_image_digest') != ci_image.get('initrd_sha256'):
        problems.append('manifest vm image digest differs from prepared ci image')
    if manifest.get('source_commit_sha') != prep.get('source', {}).get('commit'):
        problems.append('source commit differs from prepared assets')
    if manifest.get('dependency_lock_digest') != prep.get('source', {}).get('lockfile_sha256'):
        problems.append('lockfile digest differs from prepared assets')
    if manifest.get('repository') != prep.get('repository'):
        problems.append('repository differs from prepared assets')
    return problems


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
    if expect_plan is None:
        raise ValueError('trusted caller --expect-plan required; evidence cannot choose mandatory checks')
    manifest, problems = reasons_from(run_dir, expect_plan, prep_manifest)
    run = json.loads((Path(run_dir) / 'run.json').read_text())
    problems.extend(execution_pin_problems(manifest, run, relay_pin, source_pin))
    problems.extend(asset_binding_problems(private, manifest))
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
    parser.add_argument('--expect-plan', required=True)
    parser.add_argument('--prep-manifest', type=Path)
    parser.add_argument('--append-ledger', action='store_true')
    parser.add_argument('--relay-pin', required=True,
                        help='Full reviewed relay SHA from the trusted caller policy')
    parser.add_argument('--source-pin', required=True,
                        help='Full source SHA from the trusted dispatch request')
    args = parser.parse_args()
    try:
        manifest, problems = verify(args.run, args.private, args.expect_plan,
                                    args.prep_manifest, args.append_ledger,
                                    relay_pin=args.relay_pin, source_pin=args.source_pin)
    except (OSError, ValueError, TypeError, KeyError) as error:
        verdict = 'INDETERMINATE' if isinstance(error, OSError) else 'REJECT'
        print(json.dumps({'run_id': None, 'overall_result': 'UNKNOWN', 'verdict': verdict,
                          'problems': [type(error).__name__ + ': ' + str(error)]}, indent=2))
        raise SystemExit(2 if verdict == 'INDETERMINATE' else 1)
    print(json.dumps({'run_id': manifest['run_id'], 'overall_result': manifest['overall_result'],
                      'verdict': 'ACCEPT' if not problems else 'REJECT',
                      'verifier_revision': sha256_file(Path(__file__)),
                      'problems': problems}, indent=2))
    raise SystemExit(0 if not problems else 1)
