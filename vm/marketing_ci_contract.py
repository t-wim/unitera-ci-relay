"""Inert, review-only UNITERA marketing relay integration contract.

No checkout, execution, network access, runner registration or status writeback.
Source code may run only after a separately qualified isolated Python VM guest
has been authorized by the relay owner. Admission is deliberately fail-closed.
"""
from __future__ import annotations
import re

SOURCE_REPOSITORY = "baum777/unitera_marketing_agent-team"
RUNNER_LABELS = ("self-hosted", "Linux", "X64", "unitera-ci", "relay")
ADMISSION_STATE = "QUARANTINED"
SHA_RE = re.compile(r"[0-9a-f]{40}\\Z")

# Exact offline acceptance commands, permitted only in qualified disposable VM.
PYTHON_VM_PLAN = (
    ("marketing_manifest_validation", 120, ("python3", "scripts/validate.py")),
    ("marketing_stdlib_tests", 900, ("python3", "-m", "unittest", "discover", "-s", "tests", "-v")),
    ("marketing_compileall", 120, ("python3", "-m", "compileall", "-q", "scripts", "tests")),
)

def validate_pins(source_sha: str, expected_relay_sha: str, actual_relay_sha: str, source_pr: str):
    if not all(isinstance(x, str) and SHA_RE.fullmatch(x) for x in
               (source_sha, expected_relay_sha, actual_relay_sha)):
        raise ValueError("invalid source or relay commit SHA")
    if expected_relay_sha != actual_relay_sha:
        raise ValueError("relay head differs from reviewed pin")
    if not isinstance(source_pr, str) or not re.fullmatch(r"[1-9][0-9]*", source_pr):
        raise ValueError("invalid source PR identifier")
    return True

def reviewed_python_plan():
    return tuple((name, timeout, tuple(argv)) for name, timeout, argv in PYTHON_VM_PLAN)

def authorize_execution(*_args, **_kwargs):
    raise PermissionError("MARKETING_CI_QUARANTINED: Python VM isolation not qualified")
