"""Pinned Git source custody for the MARKETING Python VM candidate.

Host-side preparation may invoke only Git's data-export operations. It never
imports, runs, sources, installs or evaluates code from the marketing checkout.
No network operation is implemented; the checkout must already exist.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path

SOURCE_REPO = "baum777/unitera_marketing_agent-team"
SOURCE_REMOTES = frozenset((
    "https://github.com/baum777/unitera_marketing_agent-team.git",
    "git@github.com:baum777/unitera_marketing_agent-team.git",
))
SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_FILES = 10000
MAX_BYTES = 64 * 1024 * 1024

def _git(checkout, *args):
    return subprocess.run(("git", "-C", str(checkout), *args),
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

def _git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()

def _safe_name(name):
    if not name or name.startswith("/") or "\\" in name or any(
        part in ("", ".", "..") for part in name.split("/")
    ):
        raise ValueError("unsafe committed path")
    parts = name.split("/")
    if parts[0] in (".git", "private", "runs", ".mimosa"):
        raise ValueError("private or execution state in committed source")
    if name in (".env", ".env.local") or parts[-1].startswith(".env.") and not parts[-1].endswith(".example"):
        raise ValueError("secret-like path in source")
    return name

def _tree_entries(raw):
    result = {}
    for line in raw.split(b"\0"):
        if not line:
            continue
        meta, delim, filename = line.partition(b"\t")
        if not delim:
            raise ValueError("invalid Git tree entry")
        mode, kind, blob = meta.decode("ascii").split()
        name = _safe_name(filename.decode("utf-8", errors="strict"))
        if mode not in ("100644", "100755") or kind != "blob" or not SHA.fullmatch(blob):
            raise ValueError("non-regular Git entry (symlink/submodule rejected)")
        if name in result:
            raise ValueError("duplicate Git entry")
        result[name] = blob
    if not result or len(result) > MAX_FILES:
        raise ValueError("source file count outside bounds")
    return result

def prepare(checkout, commit, destination):
    checkout, destination = Path(checkout).resolve(), Path(destination).resolve()
    if not SHA.fullmatch(commit):
        raise ValueError("source commit must be a full lowercase SHA")
    if destination.is_relative_to(checkout) or checkout.is_relative_to(destination):
        raise ValueError("private destination cannot overlap source checkout")
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("destination must be empty; no implicit overwrite")
    remote = _git(checkout, "remote", "get-url", "origin").decode().strip()
    if remote not in SOURCE_REMOTES:
        raise ValueError("wrong source repository origin")
    resolved = _git(checkout, "rev-parse", "--verify", commit + "^{commit}").decode().strip()
    if resolved != commit:
        raise ValueError("commit identity mismatch")
    tree = _tree_entries(_git(checkout, "ls-tree", "-r", "-z", commit))
    destination.mkdir(mode=0o700, parents=True, exist_ok=False if not destination.exists() else True)
    archive = destination / "source.tar"
    # git archive is a data operation. No user-controlled command string or shell.
    with archive.open("xb") as output:
        subprocess.run(("git", "-C", str(checkout), "archive", "--format=tar", commit),
                       stdout=output, stderr=subprocess.PIPE, check=True)
    if archive.stat().st_size > MAX_BYTES:
        raise ValueError("source archive exceeds size limit")
    inventory, total = {}, 0
    with tarfile.open(archive, "r:") as tf:
        seen = set()
        for member in tf:
            name = _safe_name(member.name.rstrip("/"))
            if member.isdir():
                continue
            if not member.isfile() or name in seen or name not in tree:
                raise ValueError("unsafe/duplicate/unexpected archive member")
            seen.add(name)
            data = tf.extractfile(member).read(MAX_BYTES + 1)
            total += len(data)
            if total > MAX_BYTES or len(data) != member.size:
                raise ValueError("source bytes exceed limit")
            if _git_blob(data) != tree[name]:
                raise ValueError("archive content differs from Git blob")
            inventory[name] = hashlib.sha256(data).hexdigest()
    if set(inventory) != set(tree):
        raise ValueError("archive/tree file set mismatch")
    receipt = {
        "schema": "relay.marketing-source-custody.v1",
        "repository": SOURCE_REPO, "commit": commit,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "file_count": len(inventory), "source_bytes": total,
        "inventory": inventory,
    }
    path = destination / "source-receipt.json"
    with path.open("x", encoding="utf-8") as out:
        json.dump(receipt, out, sort_keys=True, indent=2)
        out.write("\n")
    path.chmod(0o600)
    archive.chmod(0o600)
    return receipt

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--private-destination", required=True)
    args = parser.parse_args()
    result = prepare(args.checkout, args.source_sha, args.private_destination)
    print(json.dumps({k: v for k, v in result.items() if k != "inventory"}, sort_keys=True))
