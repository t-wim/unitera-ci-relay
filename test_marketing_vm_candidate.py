"""Offline contract tests only. No VM, model, runner or GitHub network calls."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "vm"))
from marketing_source_custody import prepare, _safe_name
from marketing_vm_contract import (PLAN, ISOLATION_CHECKS, plan, verify_receipt,
                                   prepare_status_payload)
from marketing_vm_qualification import evaluate
from marketing_status_writeback import payload, send

SOURCE = "a" * 40
RELAY = "b" * 40

def fixture(root, outcome="success", run_id="1" * 32):
    root.mkdir(parents=True, exist_ok=True)
    logs_dir = root / "logs"
    logs_dir.mkdir(exist_ok=True)
    logs = {}
    for name, _, argv in PLAN:
        data = (name + "\n").encode()
        (logs_dir / (name + ".log")).write_bytes(data)
        logs[name] = {"argv": list(argv), "exit_code": 0,
                      "timeout": False, "sha256": hashlib.sha256(data).hexdigest()}
    record = {
        "schema": "relay.marketing-vm-receipt.v1",
        "repository": "baum777/unitera_marketing_agent-team",
        "source_sha": SOURCE, "relay_sha": RELAY, "run_id": run_id,
        "execution_profile": "marketing-python-vm-v1",
        "source_archive": {"sha256": "c"*64},
        "guest_image": {"sha256": "d"*64},
        "python_runtime": {"sha256": "e"*64},
        "vm_exit_code": 35 if outcome == "failure" else (None if outcome in ("timeout","cancel") else 33),
        "source_verified_inside_guest": True,
        "toolchain_verified_inside_guest": True, "host_test_execution": False,
        "expected_outcome": outcome, "observed_outcome": outcome,
        "negative_control_verified": outcome != "success",
        "failure_exit_observed": outcome == "failure",
        "terminated_while_running": outcome in ("timeout", "cancel"),
        "termination_reason": outcome if outcome in ("timeout", "cancel") else None,
        "termination_signal": 15 if outcome == "cancel" else None,
        "fresh_successor_verified": outcome == "success",
        "logs": logs, "isolation": {k: "PASS" for k in ISOLATION_CHECKS},
        "cleanup": {k: True for k in ("scope_reaped", "no_owned_processes",
                                     "disk_overlay_removed", "host_credentials_absent",
                                     "limits_verified")},
    }
    (root / "receipt.json").write_text(json.dumps(record))
    return record

class MarketingCandidateTests(unittest.TestCase):
    def test_plan_is_fixed(self):
        self.assertEqual(len(plan()), 3)
        self.assertEqual(plan()[1]["argv"],
                         ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"])

    def test_fixture_consistency_is_not_host_qualification(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture(Path(tmp))
            _, errors = verify_receipt(tmp, SOURCE, RELAY)
            self.assertEqual(errors, [])
            self.assertFalse(evaluate([], SOURCE, RELAY)["qualified"])

    def test_tampered_test_log_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture(Path(tmp))
            (Path(tmp) / "logs" / "marketing_stdlib_tests.log").write_text("tampered")
            _, errors = verify_receipt(tmp, SOURCE, RELAY)
            self.assertTrue(any("tampered" in x for x in errors))

    def test_pin_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture(Path(tmp))
            _, errors = verify_receipt(tmp, "f"*40, RELAY)
            self.assertIn("pinned commit mismatch", errors)

    def test_missing_isolation_or_cleanup_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = fixture(Path(tmp))
            record["isolation"]["metadata_denied"] = "FAIL"
            record["cleanup"]["scope_reaped"] = False
            (Path(tmp)/"receipt.json").write_text(json.dumps(record))
            _, errors = verify_receipt(tmp, SOURCE, RELAY)
            self.assertIn("isolation checks incomplete", errors)
            self.assertIn("cleanup or resource proof incomplete", errors)

    def test_host_source_execution_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = fixture(Path(tmp))
            record["host_test_execution"] = True
            (Path(tmp)/"receipt.json").write_text(json.dumps(record))
            _, errors = verify_receipt(tmp, SOURCE, RELAY)
            self.assertTrue(any("host" in x for x in errors))

    def test_five_case_records_cannot_prove_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = [Path(tmp) / str(n) for n in range(5)]
            outcomes = ("success", "failure", "timeout", "cancel", "success")
            for i, dest in enumerate(paths):
                fixture(dest, outcome=outcomes[i], run_id=str(i+1)*32)
            result = evaluate(paths, SOURCE, RELAY)
            # Passing locally manufactured records never qualifies a real VM.
            self.assertFalse(result["qualified"])
            self.assertTrue(result["evidence_consistent"])
            data = json.loads((paths[-1]/"receipt.json").read_text())
            data["run_id"] = "1"*32
            (paths[-1]/"receipt.json").write_text(json.dumps(data))
            self.assertFalse(evaluate(paths, SOURCE, RELAY)["evidence_consistent"])
            data["run_id"] = "5" * 32
            data["fresh_successor_verified"] = False
            (paths[4] / "receipt.json").write_text(json.dumps(data))
            self.assertFalse(evaluate(paths, SOURCE, RELAY)["evidence_consistent"])

    def test_status_denied_without_separate_gates(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = fixture(Path(tmp))
            for options in ({}, {"owner_approved":True},
                            {"owner_approved":True, "vm_qualified":True}):
                with self.assertRaises(PermissionError):
                    prepare_status_payload(record, [], **options)
            candidate = payload(record, [], owner_approved=True,
                                vm_qualified=True, writer_qualified=True)
            self.assertEqual(candidate["sha"], SOURCE)
            self.assertEqual(candidate["state"], "success")

    def test_status_uses_exact_sha_and_one_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = fixture(Path(tmp))
            candidate = payload(record, [], owner_approved=True,
                                vm_qualified=True, writer_qualified=True)
            seen = []
            class Response:
                status = 201
                def __enter__(self):return self
                def __exit__(self, *args):return False
                def read(self, n):return b"{}"
            def post(req, timeout):
                seen.append(req)
                return Response()
            result = send(candidate, "DUMMY_APPROVAL_TOKEN_123456789123", post=post)
            self.assertTrue(result["independent_readback_required"])
            self.assertEqual(len(seen), 1)
            self.assertTrue(seen[0].full_url.endswith("/"+SOURCE))

    def test_private_paths_and_traversal_blocked(self):
        for path in ("/etc/passwd", "../escape", "src/../escape",
                     "private/data.txt", "runs/old.json", ".env"):
            with self.assertRaises(ValueError):
                _safe_name(path)

    def test_source_export_bound_to_exact_git_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp)/"source"
            checkout.mkdir()
            def git(*cmd):
                return subprocess.check_output(
                    ["git", "-C", str(checkout), *cmd], stderr=subprocess.DEVNULL
                ).decode().strip()
            git("init", "-q")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("remote", "add", "origin",
                "https://github.com/baum777/unitera_marketing_agent-team.git")
            (checkout/"scripts").mkdir()
            (checkout/"scripts"/"validate.py").write_text("print('fixture')\n")
            git("add", ".")
            git("commit", "-qm", "fixture")
            sha = git("rev-parse", "HEAD")
            receipt = prepare(checkout, sha, Path(tmp)/"private")
            self.assertEqual(receipt["file_count"], 1)
            self.assertEqual(receipt["commit"], sha)
            git("remote", "set-url", "origin", "https://example.invalid/other.git")
            with self.assertRaises(ValueError):
                prepare(checkout, sha, Path(tmp)/"other")

if __name__ == "__main__":
    unittest.main()
