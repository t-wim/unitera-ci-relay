"""Non-executing MAWS CI parity manifest admission candidate.

This does NOT run source code, register a runner, produce PASS, or write status.
A verified exact-source manifest is prerequisite INPUT for a future approved VM
profile. Never pass derived scripts to shell/runner host from this module.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

MAWS_SOURCE_REPO = "baum777/model-agnostic-workflow-system"
SCHEMA = "maws.selfhosted-ci-parity-candidate.v1"
EXPECTED_LEGACY_BLOB = "18f8256b787a5e46c3c49e4004877793ef69ff91"
LEGACY_STEPS = 23
SUPPLEMENTARY_GATES = 20

class AdmissionBlocked(ValueError):
    pass

def require(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionBlocked(message)

def classify_manifest(document: dict) -> dict:
    """Return an explicit BLOCKED inventory classification, never executable authority."""
    require(isinstance(document, dict), "manifest must be an object")
    require(document.get("schema") == SCHEMA, "manifest schema mismatch")
    require(document.get("source_repository") == MAWS_SOURCE_REPO, "source repository mismatch")
    require(document.get("legacy_workflow_path") == ".github/workflows/loop-repo-ci.yml",
            "source workflow mismatch")
    require(document.get("legacy_workflow_git_blob_sha") == EXPECTED_LEGACY_BLOB,
            "legacy workflow blob drift: new source review needed")
    require(re.fullmatch(r"[0-9a-f]{40}", document.get("source_baseline_commit", "")) is not None,
            "missing immutable source baseline")
    require(document.get("legacy_step_count") == LEGACY_STEPS, "declared legacy gate count mismatch")
    require(document.get("cutover_state") == "BLOCKED", "inventory cannot authorize CI cutover")
    require(document.get("relay_state") == "NOT_IMPLEMENTED_NOT_QUALIFIED",
            "inventory cannot assert VM qualification")

    steps = document.get("legacy_steps")
    require(isinstance(steps, list) and len(steps) == LEGACY_STEPS,
            "incomplete legacy gate inventory")
    seen = set()
    for position, step in enumerate(steps, start=1):
        require(isinstance(step, dict), "legacy gate is not an object")
        expected = "legacy-" + str(position).zfill(2)
        gate_id = step.get("id")
        require(gate_id == expected and step.get("order") == position, "legacy gate order mismatch")
        require(gate_id not in seen, "duplicate legacy gate")
        seen.add(gate_id)
        require(isinstance(step.get("name"), str) and bool(step["name"].strip()),
                "legacy gate missing name")
        require(step.get("required") is True, "legacy gate became optional")
        if position in (1, 2):
            require(step.get("type") == "action" and isinstance(step.get("action"), str)
                    and step.get("action"), "source/toolchain action missing")
        else:
            require(step.get("type") == "run" and isinstance(step.get("run"), str)
                    and bool(step["run"].strip()), "missing original source run body")
        require(step.get("execution_boundary") in (
            "isolated-vm", "equivalent-source-custody-or-pinned-toolchain-in-vm"),
            "unqualified execution boundary")

    require(steps[0].get("action") == "actions/checkout@v4", "checkout action changed")
    require(steps[0].get("with", {}).get("fetch-depth") == "0",
            "full Git ancestry requirement missing")
    require(steps[1].get("action") == "actions/setup-node@v4", "toolchain action changed")
    require(steps[1].get("with", {}).get("node-version") == "'24'",
            "Node 24 requirement missing")

    extra = document.get("supplemental_policy_gates")
    require(isinstance(extra, list) and len(extra) == SUPPLEMENTARY_GATES,
            "supplemental policy gate inventory incomplete")
    for gate in extra:
        require(isinstance(gate, dict), "supplemental gate is not an object")
        gate_id = gate.get("id")
        require(re.fullmatch(r"supp-[0-9]{2}", str(gate_id)) is not None and gate_id not in seen,
                "supplemental gate identity invalid/duplicate")
        seen.add(gate_id)
        require(gate.get("evidence_required") is True and isinstance(gate.get("command"), str)
                and bool(gate["command"].strip()), "supplemental gate lacks evidence/command")
        require(gate.get("condition") in (
            "always", "after-skill-admission-only", "when-skill-candidate-changes",
            "when-registry-relevant-change", "when-provider-export-changes",
            "when-runtime-activation-changes", "when-context-assembly-changes",
            "when-merge-authority-changes"), "unrecognized supplemental condition")
    require(any(g.get("condition") == "when-skill-candidate-changes" and
                g.get("command", "").startswith("npm run skill:frontdoor")
                for g in extra), "required candidate admission missing")

    gate_digest = hashlib.sha256(json.dumps(
        {"legacy": steps, "supplementary": extra}, sort_keys=True,
        separators=(",", ":")).encode("utf8")).hexdigest()
    return {
        "schema": "relay.maws-gate-inventory-classification.v1",
        "source_repository": MAWS_SOURCE_REPO,
        "source_baseline_commit": document["source_baseline_commit"],
        "gate_set_sha256": gate_digest,
        "legacy_gate_count": LEGACY_STEPS,
        "supplemental_gate_count": SUPPLEMENTARY_GATES,
        "legacy_command_groups": LEGACY_STEPS - 2,
        "analysis": "INVENTORY_ACCEPTED_ONLY",
        "execution": "BLOCKED",
        "runner_admission": "BLOCKED",
        "ci_parity": "NOT_RUN",
        "status_writeback": "NOT_AUTHORIZED",
        "cutover": "BLOCKED",
        "missing_evidence": [
            "verified source commit/tree/history/manifest custody",
            "current-image VM qualification and isolation/cleanup",
            "Node24/npm/Python/Git toolchain and dependencies",
            "23 legacy execution results plus supplemental gate evidence",
            "independent raw-log and exit/timeout verifier",
            "GitHub status writeback and effective required check",
            "t-wim and source owner release"
        ]
    }

def inspect_file(path: str | Path) -> dict:
    return classify_manifest(json.loads(Path(path).read_text(encoding="utf8")))
