"""Fail-closed five-case evidence gate for a distinct marketing Python VM.

This is a *candidate verifier*, not a VM launcher. Its verdict can only
identify evidence consistency; it cannot qualify a host or authorize runner
admission. Genuine VM qualification requires the live t-wim host controller,
independent raw-console/cgroup readback and owner-signed review.
"""
from __future__ import annotations
import argparse
import json
from marketing_vm_contract import QUALIFICATION_CASES, verify_receipt, ISOLATION_CHECKS

def evaluate(case_dirs, source_sha, relay_sha):
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
    return {"schema":"relay.marketing-vm-qualification.v1",
            "qualified":False,
            "evidence_consistent":consistent,
            "case_count":len(seen),"errors":errors,
            "blocker":"VM_HOST_ATTESTATION_AND_OWNER_ADMISSION_REQUIRED"}

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source-sha",required=True)
    p.add_argument("--relay-sha",required=True)
    p.add_argument("--case",action="append",required=True)
    args=p.parse_args()
    result=evaluate(args.case,args.source_sha,args.relay_sha)
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(2)
