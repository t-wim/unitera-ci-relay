"""Independent, fail-closed contract for the proposed isolated Python VM lane.

The existing t-wim Node/Systems lane MUST NOT be treated as qualified for this
distinct workload. This module makes no host VM launches or GitHub mutations.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

SOURCE_REPO = "baum777/unitera_marketing_agent-team"
RELAY_REPO = "t-wim/unitera-ci-relay"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
PLAN = (
    ("marketing_manifest_validation", 120, ("python3", "scripts/validate.py")),
    ("marketing_stdlib_tests", 900, ("python3", "-m", "unittest", "discover", "-s", "tests", "-v")),
    ("marketing_compileall", 120, ("python3", "-m", "compileall", "-q", "scripts", "tests")),
)
ISOLATION_CHECKS = frozenset((
    "protected_host_canary", "review_canary", "status_canary",
    "credential_environment_absent", "host_docker_socket_absent",
    "no_host_mounts", "host_service_denied", "lan_denied",
    "metadata_denied", "ipv6_host_denied", "ipv6_metadata_denied",
    "no_agent_forwarding", "previous_file_absent", "previous_process_absent",
    "synthetic_process_created", "synthetic_file_created", "live_virtual_link",
))
QUALIFICATION_CASES = ("success", "failure", "timeout", "cancel", "success")
STATUS_CONTEXT = "unitera/marketing-python-vm"
GUARD_STATE = "QUARANTINED"

def plan():
    return [{"name": name, "timeout_s": seconds, "cwd": "/ws/src", "argv": list(argv)}
            for name, seconds, argv in PLAN]

def validate_identity(repository, source_sha, relay_sha, run_id):
    if repository != SOURCE_REPO:
        raise ValueError("wrong source repository")
    if not all(isinstance(x, str) and SHA.fullmatch(x) for x in (source_sha, relay_sha)):
        raise ValueError("invalid exact source/relay commit")
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ValueError("invalid run identifier")
    return True

def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def verify_receipt(run_dir, expected_source_sha, expected_relay_sha):
    """Verify independent on-disk evidence; no PASS from summary text alone.

    This is a consistency verifier, not cryptographic attestation of a
    remote machine. A trusted host observation and actual guest VM are still
    required for qualification.
    """
    root = Path(run_dir)
    receipt = json.loads((root / "receipt.json").read_text())
    validate_identity(receipt.get("repository"), receipt.get("source_sha"),
                      receipt.get("relay_sha"), receipt.get("run_id"))
    issues = []
    if receipt["source_sha"] != expected_source_sha or receipt["relay_sha"] != expected_relay_sha:
        issues.append("pinned commit mismatch")
    if receipt.get("schema") != "relay.marketing-vm-receipt.v1":
        issues.append("receipt schema mismatch")
    for name in ("source_archive", "guest_image", "python_runtime"):
        value = receipt.get(name, {})
        if not isinstance(value, dict) or not DIGEST.fullmatch(str(value.get("sha256", ""))):
            issues.append("missing digest: " + name)
    logs = receipt.get("logs")
    if not isinstance(logs, dict) or set(logs) != {row[0] for row in PLAN}:
        issues.append("missing or extra test logs")
        logs = {}
    for name, _seconds, argv in PLAN:
        record = logs.get(name, {})
        if record.get("argv") != list(argv) or type(record.get("exit_code")) is not int:
            issues.append("invalid command/exit: " + name)
            continue
        if type(record.get("timeout")) is not bool:
            issues.append("invalid timeout: " + name)
            continue
        if not DIGEST.fullmatch(str(record.get("sha256", ""))):
            issues.append("invalid log digest: " + name)
            continue
        path = root / "logs" / (name + ".log")
        if not path.is_file() or path.is_symlink() or sha256(path) != record["sha256"]:
            issues.append("log tampered/missing: " + name)
        if record["exit_code"] or record["timeout"]:
            issues.append("test failed: " + name)
    checks = receipt.get("isolation", {})
    if not isinstance(checks, dict) or set(checks) != ISOLATION_CHECKS or any(
        checks.get(name) != "PASS" for name in ISOLATION_CHECKS
    ):
        issues.append("isolation checks incomplete")
    cleanup = receipt.get("cleanup", {})
    if not isinstance(cleanup, dict) or not all(
        cleanup.get(k) is True for k in (
            "scope_reaped", "no_owned_processes", "disk_overlay_removed",
            "host_credentials_absent", "limits_verified",
        )
    ):
        issues.append("cleanup or resource proof incomplete")
    if receipt.get("vm_exit_code") != 33:
        issues.append("VM did not report successful exit")
    if receipt.get("execution_profile") != "marketing-python-vm-v1":
        issues.append("wrong VM profile")
    if receipt.get("source_verified_inside_guest") is not True:
        issues.append("guest source custody unverified")
    if receipt.get("toolchain_verified_inside_guest") is not True:
        issues.append("guest Python toolchain unverified")
    if receipt.get("host_test_execution") is not False:
        issues.append("test execution on host forbidden")
    return receipt, issues

def prepare_status_payload(receipt, issues, *, owner_approved=False, vm_qualified=False,
                           status_writer_qualified=False):
    """Read-only, non-sending candidate for a SHA-bound commit status.

    Explicit owner and independent VM/writeback qualification must be true.
    Never accepts a commit SHA supplied by model/guest output alone; caller
    must pass independently verified receipt and expected pins.
    """
    if issues or not (owner_approved and vm_qualified and status_writer_qualified):
        raise PermissionError("MARKETING_STATUS_WRITEBACK_QUARANTINED")
    if receipt.get("repository") != SOURCE_REPO:
        raise ValueError("wrong status destination")
    return {
        "repository": SOURCE_REPO, "sha": receipt["source_sha"],
        "context": STATUS_CONTEXT, "state": "success",
        "description": "Isolated Python VM tests verified; no runtime activation",
    }
