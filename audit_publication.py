"""Read-only review of a proposed Git publication; never pushes or prints matches."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

RULES = {
    'private_key': re.compile(rb'-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----'),
    'github_credential': re.compile(rb'\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{25,}'),
    'aws_access_key': re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'bearer_literal': re.compile(rb'Authorization:\s*Bearer\s+[A-Za-z0-9_./+=-]{20,}', re.I),
    'credential_url': re.compile(rb'https?://[^\s/@:]+:[^\s/@]+@', re.I),
}


def scan_bytes(data, forbidden=(), corpus=()):
    """Bounded detector: credentials, local deny-list and long private-text overlap."""
    findings = [name for name, pattern in RULES.items() if pattern.search(data)]
    if b'\0' in data:
        findings.append('binary_payload_requires_manual_review')
    if any(item and item in data for item in forbidden):
        findings.append('forbidden_private_reference')
    normalized = b' '.join(data.split())
    for private in corpus:
        if data and data == private:
            findings.append('exact_private_copy')
            break
        text = b' '.join(private.split())
        # Avoid treating short, common workflow syntax as application source.
        if any(text[i:i + 160] in normalized for i in range(0, max(0, len(text) - 159), 80)):
            findings.append('long_private_text_overlap')
            break
    return sorted(set(findings))


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def review(repo, base, head, corpus, forbidden):
    repo = repo.resolve()
    policy = json.loads(git(repo, 'show', head + ':publication-policy.json'))
    if base != policy['base_sha']:
        raise ValueError('base differs from publication policy')
    ancestor = subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', base, head], capture_output=True)
    if ancestor.returncode:
        raise ValueError('base is not an ancestor')
    target = policy['target_repository']
    origin = git(repo, 'remote', 'get-url', 'origin').decode().strip()
    if origin not in {f'https://github.com/{target}.git', f'https://github.com/{target}', f'git@github.com:{target}.git'}:
        raise ValueError('unexpected destination or credential-bearing origin')
    if (repo / '.git/objects/info/alternates').exists():
        raise ValueError('alternate object store requires separate review')
    if git(repo, 'replace', '-l').strip() or (repo / '.git/info/grafts').exists():
        raise ValueError('history replacement or graft requires separate review')
    expected = set(policy['allowed_files'])
    if len(expected) != len(policy['allowed_files']):
        raise ValueError('duplicate allowlist entry')
    commits = git(repo, 'rev-list', '--reverse', head, '^' + base).decode().splitlines()
    if not commits:
        raise ValueError('no publication candidate commits')
    findings, trees = [], []
    for commit in commits:
        entries = []
        for raw in git(repo, 'ls-tree', '-rz', '--long', commit).split(b'\0'):
            if not raw:
                continue
            metadata, name = raw.split(b'\t', 1)
            mode, kind, oid, size = metadata.decode().split()
            path = name.decode()
            if mode != '100644' or kind != 'blob':
                findings.append({'commit': commit, 'path': path, 'rule': 'non_regular_file'})
                continue
            data = git(repo, 'cat-file', 'blob', oid)
            entries.append({'path': path, 'blob': oid, 'bytes': int(size), 'sha256': hashlib.sha256(data).hexdigest()})
            for rule in scan_bytes(data, forbidden, corpus):
                findings.append({'commit': commit, 'path': path, 'rule': rule})
        if {entry['path'] for entry in entries} != expected:
            findings.append({'commit': commit, 'rule': 'entire_commit_tree_differs_from_allowlist'})
        trees.append({'commit': commit, 'files': sorted(entries, key=lambda row: row['path'])})
    objects = []
    for oid in git(repo, 'rev-list', '--objects', '--no-object-names', head, '^' + base).decode().splitlines():
        kind = git(repo, 'cat-file', '-t', oid).decode().strip()
        data = git(repo, 'cat-file', kind, oid)
        objects.append({'oid': oid, 'type': kind, 'bytes': len(data)})
        if kind in {'blob', 'commit'}:
            for rule in scan_bytes(data, forbidden, corpus):
                findings.append({'object': oid, 'rule': rule})
    # A full local diff is reviewed separately. Scan all added content here without
    # reproducing deleted baseline content that the destination already possesses.
    diff = git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames', '--unified=0', base, head)
    added = b'\n'.join(line[1:] for line in diff.splitlines() if line.startswith(b'+') and not line.startswith(b'+++'))
    for rule in scan_bytes(added, forbidden, corpus):
        findings.append({'scope': 'all_added_diff_lines', 'rule': rule})
    base_emails = set(git(repo, 'log', base, '--format=%ae%n%ce').decode().splitlines())
    new_emails = set(git(repo, 'log', base + '..' + head, '--format=%ae%n%ce').decode().splitlines())
    if not new_emails.issubset(base_emails):
        findings.append({'scope': 'commit_metadata', 'rule': 'new_identity_requires_disclosure_review'})
    return {'target_repository': target, 'base_sha': base, 'head_sha': head,
            'new_commits': commits, 'commit_trees': trees, 'new_objects': objects,
            'diff_sha256': hashlib.sha256(diff).hexdigest(),
            'diff_name_status': git(repo, 'diff', '--name-status', base, head).decode().splitlines(),
            'private_corpus_files_checked': len(corpus), 'deny_list_entries_checked': len(forbidden),
            'git_identities_already_in_destination_history': new_emails.issubset(base_emails),
            'findings': findings, 'scan_result': 'NO_DETECTED_MATCHES' if not findings else 'REVIEW_BLOCKED',
            'publication_authorized': False, 'push_performed': False,
            'limits': 'Pattern/corpus checks are bounded, not proof that arbitrary unknown private data cannot exist.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--base', required=True)
    parser.add_argument('--head', default='HEAD')
    parser.add_argument('--private-corpus', required=True, type=Path)
    parser.add_argument('--deny-list', required=True, type=Path)
    args = parser.parse_args()
    if not args.private_corpus.is_dir():
        raise ValueError('private corpus missing')
    corpus = [p.read_bytes() for p in sorted(args.private_corpus.rglob('*')) if p.is_file()]
    forbidden = [value.encode() for value in json.loads(args.deny_list.read_text())]
    if not corpus or not forbidden:
        raise ValueError('private corpus or deny-list empty')
    head = git(args.repo, 'rev-parse', args.head).decode().strip()
    result = review(args.repo, args.base, head, corpus, forbidden)
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if result['findings'] else 0)


if __name__ == '__main__':
    main()
