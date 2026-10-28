"""Fail-closed five-case evidence gate for the distinct marketing Python VM.

Consistency alone never qualifies: `qualified` can only become true when the five
real VM cases (Q1 success, Q2 deliberate failure, Q3 actual timeout, Q4 SIGTERM
cancellation, Q5 fresh successor) are all verified against independently
recomputed evidence AND a real host binding is present that was recorded by the
live t-wim host controller on this machine, binding relay commit, executor file
digests and the exact implementation under which the runs were observed.

Owner admission for status writeback / runner activation is a SEPARATE gate
(marketing_vm_contract.prepare_status_payload) and is never implied here.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from marketing_vm_contract import QUALIFICATION_CASES, verify_receipt, ISOLATION_CHECKS

EXECUTOR_FILES = ('marketing_monitor.py', 'marketing_guest.sh', 'marketing_plan.py',
                  'marketing_image.py', 'marketing_start.sh', 'marketing_prep.py',
                  'marketing_manifest.py', 'marketing_verify.py',
                  'marketing_source_custody.py', 'marketing_vm_contract.py')


def implementation_digests(vm_root=None):
    root = Path(vm_root) if vm_root else Path(__file__).parent
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in EXECUTOR_FILES}


def host_binding_valid(binding, relay_sha):
    """A binding is real only if it names this exact implementation and commit."""
    if not isinstance(binding, dict):
        return False, 'host binding missing'
    if binding.get('relay_commit_sha') != relay_sha:
        return False, 'host binding relay commit mismatch'
    if binding.get('host_observation') is not True:
        return False, 'host observation flag missing'
    recorded = binding.get('executor_digests')
    if not isinstance(recorded, dict) or set(recorded) != set(EXECUTOR_FILES):
        return False, 'executor digest set mismatch'
    if recorded != implementation_digests():
        return False, 'executor digests differ from the current implementation'
    return True, None


def evaluate(case_dirs, source_sha, relay_sha, host_binding=None):
    if len(case_dirs) != len(QUALIFICATION_CASES):
        return {"schema":"relay.marketing-vm-qualification.v1",
                "qualified":False,"evidence_consistent":False,
                "errors":["five VM cases required"]}
    errors, seen = [], set()
    for index, (expected, directory) in enumerate(zip(QUALIFICATION_CASES, case_dirs), 1):
        try:
            receipt, issues = verify_receipt(directory, source_sha, relay_sha)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"case {index}: missing/unreadable evidence ({type(exc).__name__})")
            continue
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
    binding_ok, binding_error = host_binding_valid(host_binding, relay_sha)
    if consistent and not binding_ok:
        errors.append('host binding: ' + str(binding_error))
    qualified = consistent and binding_ok
    result = {"schema":"relay.marketing-vm-qualification.v1",
              "qualified":qualified,
              "evidence_consistent":consistent,
              "case_count":len(seen),"errors":errors}
    if not qualified:
        result["blocker"] = ("VM_HOST_ATTESTATION_AND_OWNER_ADMISSION_REQUIRED"
                             if not binding_ok else "OWNER_ADMISSION_REQUIRED_FOR_ACTIVATION")
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source-sha",required=True)
    p.add_argument("--relay-sha",required=True)
    p.add_argument("--case",action="append",required=True)
    p.add_argument("--host-binding",type=Path)
    args=p.parse_args()
    binding = json.loads(args.host_binding.read_text()) if args.host_binding else None
    result=evaluate(args.case,args.source_sha,args.relay_sha,binding)
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if result["qualified"] else 2)
