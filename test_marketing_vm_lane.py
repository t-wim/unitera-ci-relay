"""Offline adversarial tests for the marketing Python VM lane modules.

Level-1 battery only: no VM launch, no network, no runner. Builds synthetic
evidence directories (same shapes the live lane writes) and verifies that the
independent verifier, the manifest schema, the plan binding, the runtime lock
checks, the custody export and the status readback fail closed on every
manipulation. Synthetic fixtures never constitute VM execution.
"""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "vm"))

import marketing_manifest
import marketing_plan
import marketing_verify
from ci_util import sha256_file
from marketing_image import _runtime_files
from marketing_monitor import verify_prepared
from marketing_status_writeback import readback, send
from marketing_vm_contract import ISOLATION_CHECKS, verify_receipt
from marketing_vm_qualification import evaluate, host_binding_valid

SOURCE = "1" * 40
RELAY = "2" * 40


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (dict, list)):
        path.write_text(json.dumps(data, indent=2) + "\n")
    else:
        path.write_text(data)
    return path


def build_evidence(root, *, plan_name="production", outcome="exited", vm_exit=33,
                   overall="PASS", drop_exit=None, flip_timeout=False,
                   missing_positive=False, cleanup_fail=False, fail_check=None,
                   tamper_console=None):
    """Synthesize a complete run directory shaped exactly like the live lane's."""
    plan = marketing_plan.plan_by_name(plan_name)
    expected = marketing_plan.expected_check_set(plan_name) | set(ISOLATION_CHECKS)
    run = {"run_id": "a" * 32, "expected_checks": sorted(expected),
           "plan_name": plan_name, "source_commit_sha": SOURCE,
           "source_artifact_digest": "3" * 64, "source_inventory_digest": "4" * 64,
           "vm_image_digest": "5" * 64, "python_runtime_sha256": "6" * 64,
           "python_version": "3.14.4", "toolchain_versions": {"python": "3.14.4"},
           "relay_commit_sha": RELAY, "executor_version": {"m": "7" * 64},
           "profile": {"guest_mib": 1024, "deadline_s": 1800}, "mode": "run"}
    _write(root / "run.json", run)
    lines = []
    for name in sorted(expected):
        lines.append("CHECK %s %s" % (name, "FAIL" if name == fail_check else "PASS"))
    console = list(lines)
    if plan_name != "__none__":
        for entry in plan:
            exit_code = 0
            if plan_name == "q2_deliberate_failure":
                exit_code = 1
            if plan_name == "q3_resource_timeout":
                exit_code = 124
            if drop_exit != entry["name"]:
                console.append("EXIT %s %d" % (entry["name"], exit_code))
            tmo = 1 if (plan_name == "q3_resource_timeout" and not flip_timeout) else 0
            if flip_timeout and plan_name == "q3_resource_timeout":
                tmo = 0
            console.append("TMO %s %d" % (entry["name"], tmo))
            console.append("LOGDIGEST %s %s" % (entry["name"], "8" * 64))
    console.append("SRC_READY")
    if vm_exit == 33:
        console.append("GUEST_ALL_CHECKS_PASSED")
    console_text = "\n".join(console) + "\n"
    if tamper_console:
        console_text = tamper_console(console_text)
    _write(root / "evidence" / "console.log", console_text)
    checks = []
    for name in sorted(expected):
        entry = next((e for e in plan if e["name"] == name), None)
        if entry is None:
            checks.append({"check_name": name, "command_identifier": "guest-native",
                           "exit_code": 0, "timeout": 0,
                           "result": "FAIL" if name == fail_check else "PASS",
                           "log_digest": "guest-native"})
            continue
        exit_code = {"production": 0, "q2_deliberate_failure": 1,
                     "q3_resource_timeout": 124}[plan_name]
        result = "PASS" if (exit_code == 0 and name != fail_check) else "FAIL"
        checks.append({"check_name": name, "command_identifier": " ".join(entry["argv"]),
                       "exit_code": exit_code, "timeout": 1 if plan_name == "q3_resource_timeout" else 0,
                       "result": result, "log_digest": "8" * 64})
    positive = {"127.0.0.1": True, "192.0.2.10": True, "synthetic_unix_socket": True}
    if missing_positive:
        positive["127.0.0.1"] = False
    result_json = {
        "schema": "relay.marketing-run-result.v1", "run_id": "a" * 32, "outcome": outcome,
        "vm_exit": vm_exit, "started_at": "2026-10-28T12:00:00+00:00",
        "finished_at": "2026-10-28T12:01:00+00:00", "termination_signal": None,
        "terminated_while_running": False,
        "host_service_positive_controls": positive, "protocol_errors": [], "markers": [],
        "cleanup": {"cleanup_errors": [], "final_scope_load_state": "not-found",
                    "observed_pids_still_exist": [], "scope_remaining_pids": [],
                    "job_directory_removed": True, "cleanup_verified": not cleanup_fail},
        "limits_verified": True, "inputs_unchanged": True,
        "overall_result": overall, "isolation_result": "PASS" if not fail_check else "FAIL"}
    _write(root / "evidence" / "result.json", result_json)
    manifest = {
        "schema": marketing_manifest.SCHEMA, "run_id": "a" * 32,
        "repository": marketing_manifest.REPOSITORY, "source_commit_sha": SOURCE,
        "source_artifact_digest": "3" * 64, "source_inventory_digest": "4" * 64,
        "relay_commit_sha": RELAY, "executor_version": {"m": "7" * 64},
        "vm_image_digest": "5" * 64, "python_runtime_sha256": "6" * 64,
        "python_version": "3.14.4", "test_plan": plan_name,
        "toolchain_versions": {"python": "3.14.4"},
        "execution_profile_name": marketing_manifest.EXECUTION_PROFILE,
        "profile": {"guest_mib": 1024, "deadline_s": 1800},
        "started_at": "2026-10-28T12:00:00+00:00", "finished_at": "2026-10-28T12:01:00+00:00",
        "checks": checks, "overall_result": overall,
        "cleanup_result": "FAIL" if cleanup_fail else "PASS",
        "isolation_result": "PASS" if not fail_check else "FAIL",
        "evidence": {}}
    if plan_name == "q2_deliberate_failure" and overall == "PASS":
        manifest["overall_result"] = overall = "FAIL"
        result_json["overall_result"] = "FAIL"
        _write(root / "evidence" / "result.json", result_json)
    _write(root / "evidence" / "manifest.json", manifest)
    files = {"result.json": sha256_file(root / "evidence" / "result.json"),
             "manifest.json": sha256_file(root / "evidence" / "manifest.json"),
             "console.log": sha256_file(root / "evidence" / "console.log")}
    manifest["evidence"] = files
    _write(root / "evidence" / "manifest.json", manifest)
    files["manifest.json"] = sha256_file(root / "evidence" / "manifest.json")
    _write(root / "evidence" / "envelope.json",
           {"schema": "relay.marketing-evidence-envelope.v1", "run_id": "a" * 32,
            "files": files, "run_json_sha256": sha256_file(root / "run.json")})
    return root


PREP = {
    "schema": "relay.marketing-prep.v1",
    "source_repository": marketing_manifest.REPOSITORY,
    "source": {"commit": SOURCE, "file_count": 46, "archive_sha256": "3" * 64,
               "inventory_sha256": "4" * 64, "source_bytes": 123},
    "python_runtime": {"version": "3.14.4", "python_bin_sha256": "6" * 64,
                       "runtime_file_count": 700, "initrd_sha256": "5" * 64,
                       "toolchain_manifest_sha256": "9" * 64},
    "workspace_image": {"bytes": 1, "sha256": "b" * 64, "label": "UNITERA_MKT_WS",
                        "content": {}}}


class PlanBindingTests(unittest.TestCase):
    def test_production_plan_is_the_fixed_three_command_battery(self):
        plan = marketing_plan.plan_by_name("production")
        self.assertEqual([e["argv"] for e in plan],
                         [["python3", "scripts/validate.py"],
                          ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"],
                          ["python3", "-m", "compileall", "-q", "scripts", "tests"]])

    def test_fixture_plans_are_controller_authored(self):
        self.assertEqual(marketing_plan.plan_by_name("q2_deliberate_failure")[0]["argv"],
                         ["python3", "/fixtures/exit-one.py"])
        self.assertEqual(marketing_plan.plan_by_name("q3_resource_timeout")[0]["timeout_s"], 25)
        with self.assertRaises(ValueError):
            marketing_plan.plan_by_name("unknown-plan")

    def test_serialized_plan_never_contains_shell_metacharacters_in_fields(self):
        for name in ("production", "q2_deliberate_failure", "q3_resource_timeout"):
            text = marketing_plan.serialize_plan(marketing_plan.plan_by_name(name))
            for line in text.splitlines():
                name_field, tmo, cwd, argv_text = line.split("|", 3)
                self.assertTrue(name_field.replace("_", "a").replace("-", "a").isalnum())
                self.assertTrue(tmo.isdigit())
                self.assertNotIn(";", argv_text)
                self.assertNotIn("`", argv_text)
                self.assertNotIn("$", argv_text)


class ManifestSchemaTests(unittest.TestCase):
    def valid(self):
        return {"schema": marketing_manifest.SCHEMA, "run_id": "a" * 32,
                "repository": marketing_manifest.REPOSITORY, "source_commit_sha": SOURCE,
                "source_artifact_digest": "3" * 64, "source_inventory_digest": "4" * 64,
                "relay_commit_sha": RELAY, "executor_version": {}, "vm_image_digest": "5" * 64,
                "python_runtime_sha256": "6" * 64, "python_version": "3.14.4",
                "test_plan": "production", "toolchain_versions": {"python": "3.14.4"},
                "execution_profile_name": marketing_manifest.EXECUTION_PROFILE,
                "profile": {"guest_mib": 1024}, "started_at": "2026-10-28T12:00:00+00:00",
                "finished_at": "2026-10-28T12:01:00+00:00",
                "checks": [{"check_name": "c1_source_integrity",
                            "command_identifier": "guest-native", "exit_code": 0,
                            "timeout": 0, "result": "PASS", "log_digest": "guest-native"}],
                "overall_result": "PASS", "cleanup_result": "PASS",
                "isolation_result": "PASS", "evidence": {"x": "0" * 64}}

    def test_valid_manifest_passes(self):
        self.assertTrue(marketing_manifest.validate_manifest(self.valid()))

    def test_wrong_repository_rejected(self):
        manifest = self.valid()
        manifest["repository"] = "baum777/Unitera_Systems"
        with self.assertRaises(ValueError):
            marketing_manifest.validate_manifest(manifest)

    def test_unknown_keys_and_bad_digests_rejected(self):
        manifest = self.valid()
        manifest["surprise"] = 1
        with self.assertRaises(ValueError):
            marketing_manifest.validate_manifest(manifest)
        manifest = self.valid()
        manifest["python_runtime_sha256"] = "zz"
        with self.assertRaises(ValueError):
            marketing_manifest.validate_manifest(manifest)

    def test_pass_check_with_failing_exit_rejected(self):
        manifest = self.valid()
        manifest["checks"][0]["exit_code"] = 1
        with self.assertRaises(ValueError):
            marketing_manifest.validate_manifest(manifest)


class VerifierAdversarialTests(unittest.TestCase):
    def prep(self, tmp):
        return str(_write(Path(tmp) / "prep.json", PREP))

    def test_clean_success_evidence_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_evidence(Path(tmp) / "run")
            _manifest, problems = marketing_verify.reasons_from(root, "production", self.prep(tmp))
            self.assertEqual(problems, [])

    def test_missing_actual_exit_code_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_evidence(Path(tmp) / "run", drop_exit="marketing_stdlib_tests")
            _manifest, problems = marketing_verify.reasons_from(root, "production", self.prep(tmp))
            self.assertTrue(any("missing actual exit code" in p for p in problems))

    def test_wrong_timeout_flag_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_evidence(Path(tmp) / "run", plan_name="q3_resource_timeout",
                                  overall="FAIL", vm_exit=35, flip_timeout=True)
            _manifest, problems = marketing_verify.reasons_from(
                root, "q3_resource_timeout", self.prep(tmp))
            self.assertTrue(any("timeout flag mismatch" in p for p in problems))

    def test_unknown_outcome_and_missing_positive_control_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_evidence(Path(tmp) / "run", outcome="controller_error:X")
            _manifest, problems = marketing_verify.reasons_from(root, "production", self.prep(tmp))
            self.assertTrue(any("fail-closed outcome" in p for p in problems))
        with tempfile.TemporaryDirectory() as tmp:
            root = build_evidence(Path(tmp) / "run", missing_positive=True)
            _manifest, problems = marketing_verify.reasons_from(root, "production", self.prep(tmp))
            self.assertTrue(any("positive controls" in p for p in problems))

    def test_tampered_console_and_cleanup_fail_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_evidence(Path(tmp) / "run",
                                  tamper_console=lambda t: t.replace("CHECK live_virtual_link PASS",
                                                                     "CHECK live_virtual_link FAIL"))
            _manifest, problems = marketing_verify.reasons_from(root, "production", self.prep(tmp))
            self.assertTrue(any("isolation" in p for p in problems))
        with tempfile.TemporaryDirectory() as tmp:
            root = build_evidence(Path(tmp) / "run", cleanup_fail=True)
            _manifest, problems = marketing_verify.reasons_from(root, "production", self.prep(tmp))
            self.assertTrue(any("cleanup" in p for p in problems))

    def test_incomplete_plan_and_leftover_processes_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_evidence(Path(tmp) / "run", fail_check="marketing_compileall")
            _manifest, problems = marketing_verify.reasons_from(root, "production", self.prep(tmp))
            self.assertTrue(problems)
        with tempfile.TemporaryDirectory() as tmp:
            root = build_evidence(Path(tmp) / "run")
            result = json.loads((root / "evidence" / "result.json").read_text())
            result["cleanup"]["observed_pids_still_exist"] = [4242]
            result["cleanup"]["cleanup_verified"] = False
            _write(root / "evidence" / "result.json", result)
            manifest = json.loads((root / "evidence" / "manifest.json").read_text())
            manifest["cleanup_result"] = "FAIL"
            manifest["overall_result"] = "FAIL"
            _write(root / "evidence" / "manifest.json", manifest)
            _manifest, problems = marketing_verify.reasons_from(root, "production", self.prep(tmp))
            self.assertTrue(any("cleanup" in p for p in problems))

    def test_binding_against_prep_manifest_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_evidence(Path(tmp) / "run")
            prep = dict(PREP)
            prep["source"] = dict(PREP["source"], commit="9" * 40)
            _manifest, problems = marketing_verify.reasons_from(root, "production",
                                                                str(_write(Path(tmp) / "p2.json", prep)))
            self.assertTrue(any("source commit not bound" in p for p in problems))

    def test_ledger_rejects_replayed_run_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            marketing_verify.ledger_append(tmp, "a" * 32, "0" * 64)
            with self.assertRaises(ValueError):
                marketing_verify.ledger_append(tmp, "a" * 32, "1" * 64)


class ReceiptPlanBindingTests(unittest.TestCase):
    def receipt_root(self, tmp, plan, logs, outcome="success", vm_exit=33):
        root = Path(tmp) / ("r-" + plan)
        root.mkdir(parents=True)
        (root / "logs").mkdir()
        record = {
            "schema": "relay.marketing-vm-receipt.v1",
            "repository": marketing_manifest.REPOSITORY,
            "source_sha": SOURCE, "relay_sha": RELAY, "run_id": "c" * 32,
            "test_plan": plan, "execution_profile": "marketing-python-vm-v1",
            "source_archive": {"sha256": "3" * 64}, "guest_image": {"sha256": "5" * 64},
            "python_runtime": {"sha256": "6" * 64}, "vm_exit_code": vm_exit,
            "source_verified_inside_guest": True, "toolchain_verified_inside_guest": True,
            "host_test_execution": False, "expected_outcome": outcome,
            "observed_outcome": outcome, "negative_control_verified": outcome != "success",
            "failure_exit_observed": outcome == "failure",
            "terminated_while_running": outcome in ("timeout", "cancel"),
            "termination_reason": outcome if outcome in ("timeout", "cancel") else None,
            "termination_signal": 15 if outcome == "cancel" else None,
            "fresh_successor_verified": outcome == "success",
            "logs": {}, "isolation": {k: "PASS" for k in ISOLATION_CHECKS},
            "cleanup": {k: True for k in ("scope_reaped", "no_owned_processes",
                                          "disk_overlay_removed", "host_credentials_absent",
                                          "limits_verified")}}
        for name, argv, exit_code, timeout in logs:
            data = name.encode() + b"\n"
            (root / "logs" / (name + ".log")).write_bytes(data)
            record["logs"][name] = {"argv": argv, "exit_code": exit_code,
                                    "timeout": timeout,
                                    "sha256": hashlib.sha256(data).hexdigest()}
        _write(root / "receipt.json", record)
        return root

    def test_production_receipt_requires_exactly_three_bound_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.receipt_root(tmp, "production", [
                ("marketing_manifest_validation", ["python3", "scripts/validate.py"], 0, False),
                ("marketing_stdlib_tests",
                 ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"], 0, False),
                ("marketing_compileall",
                 ["python3", "-m", "compileall", "-q", "scripts", "tests"], 0, False)])
            _receipt, issues = verify_receipt(root, SOURCE, RELAY)
            self.assertEqual(issues, [])
            incomplete = self.receipt_root(tmp + "x", "production", [
                ("marketing_manifest_validation", ["python3", "scripts/validate.py"], 0, False)])
            _receipt, issues = verify_receipt(incomplete, SOURCE, RELAY)
            self.assertTrue(any("missing or extra test logs" in i for i in issues))

    def test_unknown_plan_and_stub_stdlib_receipt_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.receipt_root(tmp, "mystery-plan", [])
            _receipt, issues = verify_receipt(root, SOURCE, RELAY)
            self.assertTrue(any("test plan" in i for i in issues))
            stubbed = self.receipt_root(tmp + "y", "production", [
                ("marketing_manifest_validation", ["python3", "scripts/validate.py"], 0, False),
                ("marketing_stdlib_tests",
                 ["python3", "-c", "print('ok')"], 0, False),
                ("marketing_compileall",
                 ["python3", "-m", "compileall", "-q", "scripts", "tests"], 0, False)])
            _receipt, issues = verify_receipt(stubbed, SOURCE, RELAY)
            self.assertTrue(any("invalid command/exit" in i for i in issues))

    def test_python_digest_and_stdlib_tamper_fail_image_checks(self):
        # A manipulated standard library or missing binary digest must break the
        # prepared-asset binding before any launch (lock re-verification).
        with tempfile.TemporaryDirectory() as tmp:
            assets = Path(tmp) / "assets"
            assets.mkdir(parents=True)
            (assets / "ws-base.img").write_bytes(b"img")
            _write(assets / "ws-image.json",
                   {"bytes": 3, "sha256": sha256_file(assets / "ws-base.img"),
                    "label": "L", "content": {}})
            (assets / "marketing-initrd").write_bytes(b"initrd")
            image = {"schema": "relay.marketing-image.v1",
                     "initrd_sha256": sha256_file(assets / "marketing-initrd"),
                     "guest_init_sha256": "0" * 64, "kernel_sha256": "0" * 64,
                     "base_initrd_sha256": "0" * 64, "python_version": "3.14.4",
                     "python_bin_sha256": "6" * 64, "runtime_file_count": 700,
                     "entry_count": 900, "toolchain_manifest_sha256": "9" * 64}
            _write(assets / "marketing-image.json", image)
            prep = dict(PREP, workspace_image=json.loads((assets / "ws-image.json").read_text()))
            prep["python_runtime"] = dict(PREP["python_runtime"],
                                          initrd_sha256=image["initrd_sha256"])
            _write(assets / "marketing-prep-manifest.json", prep)
            verify_prepared(assets)  # clean binding passes
            tampered = dict(prep, python_runtime=dict(prep["python_runtime"],
                                                      python_bin_sha256="e" * 64))
            _write(assets / "marketing-prep-manifest.json", tampered)
            with self.assertRaises(ValueError):
                verify_prepared(assets)
            (assets / "marketing-initrd").write_bytes(b"manipulated-stdlib")
            _write(assets / "marketing-prep-manifest.json", prep)
            with self.assertRaises(ValueError):
                verify_prepared(assets)

    def test_runtime_lock_binds_installed_distribution_versions(self):
        files = _runtime_files(json.loads(
            (Path(__file__).parent / "vm" / "marketing-runtime-lock.json").read_text()))
        self.assertGreaterEqual(len(files), 500)
        self.assertIn("usr/bin/python3", files)
        self.assertTrue(all(str(path).startswith(("/usr/", "/lib"))
                            for path in files.values()))
        lock = json.loads(
            (Path(__file__).parent / "vm" / "marketing-runtime-lock.json").read_text())
        lock["packages"]["python3.14-minimal"] = "9.9.9-1fake"
        with self.assertRaises(ValueError):
            _runtime_files(lock)


class QualificationGateTests(unittest.TestCase):
    def test_consistent_receipts_without_host_binding_stay_unqualified(self):
        with tempfile.TemporaryDirectory() as tmp:
            sys.path.insert(0, str(Path(__file__).parent / "vm"))
            import test_marketing_vm_candidate as candidate
            paths = []
            outcomes = ("success", "failure", "timeout", "cancel", "success")
            for index, outcome in enumerate(outcomes, 1):
                case = Path(tmp) / str(index)
                candidate.fixture(case, outcome=outcome, run_id=str(index) * 32)
                data = json.loads((case / "receipt.json").read_text())
                data["vm_exit_code"] = {"success": 33, "failure": 35,
                                        "timeout": 35, "cancel": None}[outcome]
                data["terminated_while_running"] = outcome in ("timeout", "cancel")
                _write(case / "receipt.json", data)
                paths.append(case)
            result = evaluate(paths, candidate.SOURCE, candidate.RELAY)
            self.assertFalse(result["qualified"])
            self.assertTrue(result["evidence_consistent"])
            binding = {"relay_commit_sha": candidate.RELAY, "host_observation": True,
                       "executor_digests": {"wrong.py": "0" * 64}}
            self.assertFalse(evaluate(paths, candidate.SOURCE, candidate.RELAY, binding)["qualified"])

    def test_host_binding_requires_exact_implementation_digests(self):
        ok, _error = host_binding_valid({"relay_commit_sha": RELAY, "host_observation": True,
                                         "executor_digests": {}}, RELAY)
        self.assertFalse(ok)


class StatusReadbackTests(unittest.TestCase):
    def candidate(self):
        return {"repository": marketing_manifest.REPOSITORY, "sha": SOURCE,
                "context": "unitera/marketing-python-vm", "state": "success",
                "description": "Isolated Python VM tests verified; no runtime activation"}

    def test_readback_binds_exact_sha_and_context(self):
        class Response:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, n):
                return json.dumps({"sha": SOURCE, "statuses": [
                    {"context": "unitera/marketing-python-vm", "state": "success"}]}).encode()
        seen = []
        def get(req, timeout):
            seen.append(req.full_url)
            return Response()
        result = readback(SOURCE, "DUMMY_READBACK_TOKEN_123456789", get=get)
        self.assertTrue(result["readback_verified"])
        self.assertTrue(seen[0].endswith("/commits/" + SOURCE + "/status"))

    def test_readback_rejects_wrong_sha_missing_context_and_unknown_network(self):
        class WrongSha:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, n):
                return json.dumps({"sha": "9" * 40, "statuses": []}).encode()
        with self.assertRaises(RuntimeError):
            readback(SOURCE, "DUMMY_READBACK_TOKEN_123456789", get=lambda req, timeout: WrongSha())
        from urllib.error import URLError
        def broken(req, timeout):
            raise URLError("unreachable")
        with self.assertRaises(RuntimeError):
            readback(SOURCE, "DUMMY_READBACK_TOKEN_123456789", get=broken)

    def test_send_without_credential_and_unknown_result_never_retry(self):
        with self.assertRaises(PermissionError):
            send(self.candidate(), "")
        from urllib.error import URLError
        def unknown(req, timeout):
            raise URLError("blackhole")
        with self.assertRaises(RuntimeError):
            send(self.candidate(), "DUMMY_APPROVAL_TOKEN_123456789123", post=unknown)


if __name__ == "__main__":
    unittest.main()
