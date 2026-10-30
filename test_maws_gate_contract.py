"""Pure local tests of a non-executing MAWS gate inventory classifier."""
import json
import unittest

from vm.maws_gate_contract import classify_manifest, AdmissionBlocked

def example():
    steps = []
    for i in range(1, 24):
        item = {"id": f"legacy-{i:02d}", "order": i, "name": f"step-{i}",
                "required": True, "execution_boundary": "isolated-vm"}
        if i <= 2:
            item["type"] = "action"
            item["action"] = "actions/checkout@v4" if i == 1 else "actions/setup-node@v4"
            item["with"] = {"fetch-depth": "0"} if i == 1 else {"node-version": "'24'"}
        else:
            item["type"] = "run"
            item["run"] = "echo synthetic"
        steps.append(item)
    extra = [{"id": f"supp-{i:02d}", "command": "npm run validate", "condition": "always",
              "evidence_required": True} for i in range(1, 21)]
    extra[14]["command"] = "npm run skill:frontdoor -- --target <exact>"
    extra[14]["condition"] = "when-skill-candidate-changes"
    return {
        "schema": "maws.selfhosted-ci-parity-candidate.v1",
        "source_repository": "baum777/model-agnostic-workflow-system",
        "source_baseline_commit": "a" * 40,
        "legacy_workflow_path": ".github/workflows/loop-repo-ci.yml",
        "legacy_workflow_git_blob_sha": "18f8256b787a5e46c3c49e4004877793ef69ff91",
        "legacy_step_count": 23, "legacy_steps": steps,
        "supplemental_policy_gates": extra,
        "relay_state": "NOT_IMPLEMENTED_NOT_QUALIFIED",
        "cutover_state": "BLOCKED"
    }

class CandidateTests(unittest.TestCase):
    def test_inventory_not_execution(self):
        result = classify_manifest(example())
        self.assertEqual(result["legacy_gate_count"], 23)
        self.assertEqual(result["supplemental_gate_count"], 20)
        self.assertEqual(result["execution"], "BLOCKED")
        self.assertEqual(result["ci_parity"], "NOT_RUN")
        self.assertEqual(result["cutover"], "BLOCKED")

    def test_missing_legacy_step_blocks(self):
        data = example()
        data["legacy_steps"].pop()
        with self.assertRaises(AdmissionBlocked):
            classify_manifest(data)

    def test_missing_git_history_blocks(self):
        data = example()
        data["legacy_steps"][0]["with"]["fetch-depth"] = "1"
        with self.assertRaises(AdmissionBlocked):
            classify_manifest(data)

    def test_missing_skill_frontdoor_blocks(self):
        data = example()
        data["supplemental_policy_gates"][14]["command"] = "echo PASS"
        with self.assertRaises(AdmissionBlocked):
            classify_manifest(data)

    def test_fake_cutover_blocks(self):
        data = example()
        data["cutover_state"] = "PASS"
        with self.assertRaises(AdmissionBlocked):
            classify_manifest(data)

    def test_duplicate_gate_blocks(self):
        data = example()
        data["supplemental_policy_gates"][1]["id"] = "supp-01"
        with self.assertRaises(AdmissionBlocked):
            classify_manifest(data)

    def test_unknown_condition_blocks(self):
        data = example()
        data["supplemental_policy_gates"][0]["condition"] = "waived"
        with self.assertRaises(AdmissionBlocked):
            classify_manifest(data)

    def test_wrong_source_blob_blocks(self):
        data = example()
        data["legacy_workflow_git_blob_sha"] = "0" * 40
        with self.assertRaises(AdmissionBlocked):
            classify_manifest(data)

if __name__ == "__main__":
    unittest.main()
