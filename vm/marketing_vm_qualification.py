"""Fail-closed five-case evidence gate for the distinct marketing Python VM.

Consistency alone never qualifies, and neither does a caller-supplied JSON flag:
`qualified` can only become true when

  1. the five case receipts (Q1 success, Q2 deliberate failure, Q3 actual
     timeout, Q4 SIGTERM cancellation, Q5 fresh successor) verify against the
     independently recomputed receipt contract,
  2. a controller-maintained, hash-chained, append-only qualification ledger on
     the host contains an entry binding exactly these five run ids, the relay
     commit, the CURRENT executor file digests and the per-case evidence
     manifest digests (chain integrity recomputed entry by entry), and
  3. every case directory passes full independent evidence re-verification
     (raw console, envelope digests, cleanup, positive controls) by
     marketing_verify — evidence a synthetic receipt tree cannot produce.

A hand-written binding (formerly `host_observation: true`) can no longer
produce qualification; the ledger entry itself is written only by
marketing_qualify after the five live runs.

Owner admission for status writeback / runner activation is a SEPARATE gate
(marketing_vm_contract.prepare_status_payload) and is never implied here.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

import marketing_verify
from marketing_vm_contract import QUALIFICATION_CASES, verify_receipt, ISOLATION_CHECKS

EXECUTOR_FILES = ('marketing_monitor.py', 'marketing_guest.sh', 'marketing_plan.py',
                  'marketing_image.py', 'marketing_start.sh', 'marketing_prep.py',
                  'marketing_manifest.py', 'marketing_verify.py',
                  'marketing_source_custody.py', 'marketing_vm_contract.py')
QUALIFICATION_LEDGER_SCHEMA = 'relay.marketing-qualification-ledger.v1'
GENESIS = '0' * 64


def implementation_digests(vm_root=None):
    root = Path(vm_root) if vm_root else Path(__file__).parent
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in EXECUTOR_FILES}


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def qualification_ledger_path(private):
    return Path(private) / 'marketing-qualification-ledger.json'


def _entry_digest(entry):
    payload = {key: entry[key] for key in ('index', 'prev_sha256', 'record')}
    return hashlib.sha256(_canonical(payload)).hexdigest()


def append_qualification_entry(private, record):
    """Append a chained controller-evidence entry; flock-serialized and atomic."""
    path = qualification_ledger_path(private)

    def mutate(ledger):
        if ledger.get('schema') != QUALIFICATION_LEDGER_SCHEMA:
            raise ValueError('qualification ledger schema mismatch')
        entries = ledger.setdefault('entries', [])
        entry = {'index': len(entries) + 1,
                 'prev_sha256': entries[-1]['entry_sha256'] if entries else GENESIS,
                 'record': record}
        entry['entry_sha256'] = _entry_digest(entry)
        entries.append(entry)
        return entry['index']

    return marketing_verify._locked_ledger_write(
        path, mutate, {'schema': QUALIFICATION_LEDGER_SCHEMA, 'entries': []})


def verify_qualification_ledger(path, expected):
    """Recompute the whole chain and match the newest binding-compatible entry.

    expected: {'source_sha', 'relay_sha', 'run_ids', 'executor_digests'}
    Returns (entry, None) on success or (None, reason) fail-closed."""
    path = Path(path)
    if not path.is_file():
        return None, 'qualification ledger missing'
    try:
        ledger = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        return None, 'qualification ledger unreadable: ' + type(exc).__name__
    if ledger.get('schema') != QUALIFICATION_LEDGER_SCHEMA:
        return None, 'qualification ledger schema mismatch'
    entries = ledger.get('entries')
    if not isinstance(entries, list) or not entries:
        return None, 'qualification ledger empty'
    previous = GENESIS
    seen_indexes = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'index', 'prev_sha256',
                                                         'record', 'entry_sha256'}:
            return None, 'ledger entry has unexpected shape'
        if entry['prev_sha256'] != previous or entry['index'] in seen_indexes:
            return None, 'ledger chain broken'
        if _entry_digest(entry) != entry['entry_sha256']:
            return None, 'ledger entry digest mismatch'
        previous = entry['entry_sha256']
        seen_indexes.add(entry['index'])
    for entry in reversed(entries):
        record = entry['record']
        if (record.get('source_sha') == expected['source_sha']
                and record.get('relay_sha') == expected['relay_sha']
                and record.get('run_ids') == expected['run_ids']
                and record.get('executor_digests') == expected['executor_digests']):
            return entry, None
    return None, 'no ledger entry binds these runs, commits and implementation digests'


def controller_evidence_valid(case_dirs, receipts, source_sha, relay_sha, evidence):
    """The only path to qualification: a chained ledger entry written by the live
    controller PLUS full independent evidence re-verification of every case."""
    if not isinstance(evidence, dict) or 'ledger_path' not in evidence:
        return False, 'controller evidence (qualification ledger) not provided'
    expected = {'source_sha': source_sha, 'relay_sha': relay_sha,
                'run_ids': [receipt['run_id'] for receipt in receipts],
                'executor_digests': implementation_digests()}
    entry, error = verify_qualification_ledger(evidence['ledger_path'], expected)
    if error:
        return False, 'qualification ledger: ' + error
    recorded_digests = entry['record'].get('case_manifest_digests', {})
    for receipt, directory in zip(receipts, case_dirs):
        manifest_path = Path(directory) / 'evidence' / 'manifest.json'
        if not manifest_path.is_file():
            return False, 'case evidence manifest missing: ' + receipt['run_id']
        if recorded_digests.get(receipt['run_id']) != hashlib.sha256(
                manifest_path.read_bytes()).hexdigest():
            return False, 'ledger does not bind the case evidence manifest: ' + receipt['run_id']
        _manifest, problems = marketing_verify.reasons_from(
            directory, expect_plan=receipt.get('test_plan'))
        if problems:
            return False, ('independent evidence re-verification failed for '
                           + receipt['run_id'] + ': ' + problems[0])
    return True, None


def evaluate(case_dirs, source_sha, relay_sha, controller_evidence=None):
    if len(case_dirs) != len(QUALIFICATION_CASES):
        return {"schema":"relay.marketing-vm-qualification.v1",
                "qualified":False,"evidence_consistent":False,
                "errors":["five VM cases required"]}
    errors, seen = [], set()
    receipts = []
    for index, (expected, directory) in enumerate(zip(QUALIFICATION_CASES, case_dirs), 1):
        try:
            receipt, issues = verify_receipt(directory, source_sha, relay_sha)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"case {index}: missing/unreadable evidence ({type(exc).__name__})")
            receipts.append(None)
            continue
        receipts.append(receipt)
        run_id = receipt["run_id"]
        if run_id in seen:
            errors.append(f"case {index}: duplicate run id")
        seen.add(run_id)
        if (receipt.get("expected_outcome"),receipt.get("observed_outcome")) != (expected,expected):
            errors.append(f"case {index}: wrong outcome")
        if receipt.get("test_plan") not in (None, "production", "q2_deliberate_failure",
                                            "q3_resource_timeout"):
            errors.append(f"case {index}: unbound test plan")
        if expected == "success":
            errors.extend(f"case {index}: {issue}" for issue in issues)
            if index == 5 and receipt.get("fresh_successor_verified") is not True:
                errors.append(f"case {index}: successor freshness unproven")
        else:
            # A deliberate failure/timeout/cancel cannot have all test checks
            # succeed. The independent host controller must separately verify
            # its real exit/signal/deadline and unchanged isolation boundaries.
            negative = receipt.get("negative_control_verified") is True
            cleanup = receipt.get("cleanup",{})
            if not negative or not isinstance(cleanup,dict) or not all(
                cleanup.get(k) is True for k in ("scope_reaped","no_owned_processes",
                    "disk_overlay_removed","host_credentials_absent","limits_verified")
            ):
                errors.append(f"case {index}: negative control or cleanup not proven")
            if not isinstance(receipt.get("isolation"),dict) or not all(
                receipt["isolation"].get(k)=="PASS" for k in ISOLATION_CHECKS
            ):
                errors.append(f"case {index}: isolation failure")
            if receipt.get("host_test_execution") is not False:
                errors.append(f"case {index}: host execution forbidden")
            if receipt.get("source_sha") != source_sha or receipt.get("relay_sha") != relay_sha:
                errors.append(f"case {index}: commit binding mismatch")
            if expected == "failure":
                if receipt.get("vm_exit_code") == 33 or receipt.get("failure_exit_observed") is not True:
                    errors.append(f"case {index}: deliberate failure exit unproven")
            elif expected in ("timeout", "cancel"):
                if receipt.get("terminated_while_running") is not True:
                    errors.append(f"case {index}: live termination unproven")
                if receipt.get("termination_reason") != expected:
                    errors.append(f"case {index}: wrong termination reason")
                if expected == "cancel" and receipt.get("termination_signal") != 15:
                    errors.append(f"case {index}: SIGTERM not observed")
    consistent = not errors and len(seen)==len(QUALIFICATION_CASES)
    binding_ok = False
    binding_error = 'controller evidence pending'
    if consistent:
        binding_ok, binding_error = controller_evidence_valid(
            case_dirs, receipts, source_sha, relay_sha, controller_evidence)
        if not binding_ok:
            errors.append('controller evidence: ' + str(binding_error))
    qualified = consistent and binding_ok
    result = {"schema":"relay.marketing-vm-qualification.v1",
              "qualified":qualified,
              "evidence_consistent":consistent,
              "case_count":len(seen),"errors":errors}
    if not qualified:
        result["blocker"] = ("CONTROLLER_EVIDENCE_LEDGER_REQUIRED"
                             if consistent else "FIVE_VERIFIED_CASES_REQUIRED")
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source-sha",required=True)
    p.add_argument("--relay-sha",required=True)
    p.add_argument("--case",action="append",required=True)
    p.add_argument("--controller-evidence",type=Path,
                   help="JSON file naming the qualification ledger path")
    args=p.parse_args()
    evidence = None
    if args.controller_evidence:
        evidence = json.loads(args.controller_evidence.read_text())
    result=evaluate(args.case,args.source_sha,args.relay_sha,evidence)
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if result["qualified"] else 2)
