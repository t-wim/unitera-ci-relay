"""Reuse the owning workspace's canonical write-path mediation."""
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[1]


def private_path(value):
    path = Path(value).resolve()
    if path.is_relative_to(REPO):
        raise ValueError('images/evidence must remain outside the relay repository')
    guard = next((parent / 'scripts/workspace-path-guard.sh' for parent in REPO.parents
                  if (parent / 'AGENTS.md').is_file() and (parent / 'scripts/workspace-path-guard.sh').is_file()), None)
    if guard is None:
        raise ValueError('owning workspace path guard unavailable')
    result = subprocess.run(['bash', str(guard), '--check', str(path)],
                            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True)
    if result.returncode:
        raise ValueError('private path rejected by owning workspace guard')
    return path
