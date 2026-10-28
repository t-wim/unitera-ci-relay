"""Trusted baum-os source/toolchain preparation for the existing VM lane.

Mirrors vm/ci_prep.py phases (plan/verify/disk/finalize) for the baum-os profile:
typed tree custody (regular files, symlinks, gitlinks), pinned node 24 + pnpm 11.9.0
(bound to the committed packageManager pin), dpkg-verified bash/git and their
library closure, and the offline pnpm-11 store built with lifecycle scripts
disabled on the host. Pure logic; mechanical steps are emitted for the shell lane.
This module never executes anything itself. Git blob object ids are re-derived with
the reviewed ci_prep.git_blob_sha helper (git's own content addressing); every
security digest in this pipeline is SHA-256.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import shlex
import shutil
import tarfile
from pathlib import Path

from ci_prep import git_blob_sha
from ci_util import (MAX_ARCHIVE_BYTES, extract_member, load_json, sha256_file,
                     store_manifest_digest, verify_download)
from paths import private_path

REPOSITORY = 'baum777/baum-os'
REMOTES = {'https://github.com/baum777/baum-os.git', 'git@github.com:baum777/baum-os.git'}
SHA_RE = re.compile(r'[0-9a-f]{40}')
MAX_SYMLINK_TARGET_BYTES = 4096
# The shim is executor surface (same trust class as the Systems-lane argv translation):
# pnpm 11 ignores the npm_config_store_dir/offline environment exports, so the offline
# store is bound for install commands exactly like the proven probe form
# `install --frozen-lockfile --offline --store-dir /ws/store`; all other commands
# (run/exec of the repository scripts) stay untouched. Script bodies remain verbatim.
PNPM_SHIM = ('#!/bin/sh\ncase "$1" in\n'
             '  install) exec /usr/bin/node /pnpm/bin/pnpm.mjs "$@" --offline'
             ' --store-dir /ws/store ;;\n'
             '  *) exec /usr/bin/node /pnpm/bin/pnpm.mjs "$@" ;;\n'
             'esac\n')


def validate_path(path):
    if not path or path.startswith('/') or any(p in ('', '.', '..') or p.lower() == '.git' for p in path.split('/')):
        raise ValueError('unsafe source path')
    if any(ch in path for ch in ('\0', '\n', '\r', '\t')):
        raise ValueError('unrepresentable source path')


def assets_dir(private):
    return private_path(private) / 'ci-assets'


def write_script(path, lines):
    path.write_text('\n'.join(['#!/bin/sh', 'set -eu'] + lines) + '\n')
    path.chmod(0o700)


def parse_typed_ls_tree(text):
    """Parse `git ls-tree -r -z <commit>` keeping typed modes; gitlinks stay data."""
    regular, symlinks, gitlinks = {}, [], []
    for record in text.split(b'\0'):
        if not record:
            continue
        metadata, name = record.split(b'\t', 1)
        mode, kind, oid = metadata.decode().split()
        path = name.decode('utf8')
        validate_path(path)
        if not SHA_RE.fullmatch(oid):
            raise ValueError('bad object id in ls-tree for ' + path)
        if mode in ('100644', '100755'):
            regular[path] = [oid, mode]
        elif mode == '120000':
            symlinks.append({'path': path, 'git_object': oid})
        elif mode == '160000':
            gitlinks.append({'path': path, 'commit': oid})
        else:
            raise ValueError('unsupported git mode ' + mode + ' for ' + path)
    return regular, symlinks, gitlinks


def plan(repo, private, commit):
    private = private_path(private)
    repo = Path(repo).resolve()
    if not repo.is_dir() or not ((repo / '.git').exists() or (repo / 'HEAD').exists()):
        raise ValueError('baum-os repository directory required: ' + str(repo))
    if not SHA_RE.fullmatch(commit) or commit == '0' * 40:
        raise ValueError('commit must be a full nonzero 40-hex sha')
    assets = assets_dir(private)
    assets.mkdir(mode=0o700, parents=True, exist_ok=True)
    prep = private / 'prep'
    prep.mkdir(mode=0o700, exist_ok=True)
    lock = load_json(Path(__file__).parent / 'baum-lock.json')
    existing = assets / 'ci-prep-manifest.json'
    if existing.exists():
        recorded = load_json(existing).get('source', {}).get('commit')
        if recorded == commit:
            return {'status': 'reconciled', 'manifest': str(existing)}
        raise ValueError('assets exist for a different commit; reconcile explicitly before re-preparing')
    # staging-home, store, pnpm-pkg and node-dist are retained inputs whose digests
    # verify/finalize re-bind on every re-preparation; only staging trees are stale.
    for stale in ['staging-src']:
        if (assets / stale).exists():
            raise ValueError('stale preparation state exists: ' + stale + '; reconcile explicitly')
    import fetch as vendor_fetch
    vendor_fetch.fetch(assets)
    verify_download(lock['node'], assets / 'node.tar.xz')
    verify_download(lock['pnpm'], assets / 'pnpm.tgz')
    node_bin = assets / 'node-dist' / 'node'
    if not node_bin.exists():
        member = 'node-v' + lock['node']['version'] + '-linux-x64/bin/node'
        node_bin.parent.mkdir(parents=True, exist_ok=True)
        node_bin.write_bytes(extract_member(assets / 'node.tar.xz', member))
        node_bin.chmod(0o755)
    pnpm_pkg = assets / 'pnpm-pkg'
    if not pnpm_pkg.exists():
        for member, destination in [(lock['pnpm']['bin_entry'], 'bin/pnpm.mjs'),
                                    (lock['pnpm']['bundle_entry'], 'dist/pnpm.mjs'),
                                    (lock['pnpm']['worker_entry'], 'dist/worker.js')]:
            target = pnpm_pkg / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(extract_member(assets / 'pnpm.tgz', member))
    q = shlex.quote
    write_script(prep / 'steps1.sh', [
        'cd ' + q(str(private)),
        'git -C ' + q(str(repo)) + ' remote get-url origin > prep/origin.txt',
        'git -C ' + q(str(repo)) + ' rev-parse --verify ' + commit + '^{commit} > prep/resolved.txt',
        'git -C ' + q(str(repo)) + ' rev-parse ' + commit + '^{tree} > prep/tree.txt',
        'git -C ' + q(str(repo)) + ' ls-tree -r -z ' + commit + ' > prep/tree-entries.txt',
        'git -C ' + q(str(repo)) + ' archive --format=tar ' + commit + ' > prep/source.tar',
        'ldd ' + q(str(node_bin)) + ' > prep/node-ldd.txt',
        'ldd /usr/bin/bash > prep/bash-ldd.txt',
        'ldd /usr/bin/git > prep/git-ldd.txt',
    ])
    return {'status': 'planned', 'steps1': str(prep / 'steps1.sh'), 'private': str(private),
            'commit': commit}


def validate_symlink_target(path, target):
    if target.startswith('/'):
        # Frozen incident-archive entry: absolute, host-shaped, guaranteed dangling
        # inside the guest (no /home/... exists there). Recorded, never resolved.
        return 'absolute-frozen'
    parts = [component for component in Path(path).parent.parts if component not in ('', '.')]
    for component in Path(target).parts:
        if component in ('', '.'):
            continue
        if component == '..':
            if not parts:
                raise ValueError('symlink escapes repository root: ' + path)
            parts.pop()
        else:
            parts.append(component)
    if not parts:
        raise ValueError('symlink resolves to repository root: ' + path)
    return 'relative-in-tree'


def _verify_archive(archive_path, regular, symlinks):
    """Verify every archive member against the commit tree (git blob identity), then
    materialize the exact typed tree (files, exec bits, symlinks) into staging."""
    destination = archive_path.parent / 'staging-src'
    if destination.exists():
        raise ValueError('staging tree exists; reconcile explicitly')
    expected_symlinks = {entry['path']: entry for entry in symlinks}
    inventory = {}
    verified_symlinks = {}
    with tarfile.open(archive_path, 'r:') as tar:
        for member in tar:
            name = member.name
            if name.startswith('/') or name == '' or '..' in Path(name).parts:
                raise ValueError('unsafe archive member: ' + name)
            if member.isdir():
                continue
            if member.issym():
                if name not in expected_symlinks:
                    raise ValueError('unexpected archive symlink: ' + name)
                data = member.linkname.encode('utf8')
                if len(data) > MAX_SYMLINK_TARGET_BYTES:
                    raise ValueError('symlink target budget exceeded: ' + name)
                if git_blob_sha(data) != expected_symlinks[name]['git_object']:
                    raise ValueError('symlink target disagrees with its git blob: ' + name)
                verified_symlinks[name] = member.linkname
                continue
            if not member.isfile():
                raise ValueError('non-regular archive member rejected: ' + name)
            if name not in regular:
                raise ValueError('archive file missing from tree: ' + name)
            data = tar.extractfile(member).read()
            if git_blob_sha(data) != regular[name][0]:
                raise ValueError('git blob object id mismatch for ' + name)
            inventory[name] = [hashlib.sha256(data).hexdigest(), len(data), regular[name][1]]
    if set(verified_symlinks) != set(expected_symlinks):
        raise ValueError('archive symlink set differs from tree symlink set')
    if set(inventory) != set(regular):
        raise ValueError('archive file set differs from tree file set')
    with tarfile.open(archive_path, 'r:') as tar:
        for member in tar:
            name = member.name
            if member.isdir():
                (destination / name).mkdir(parents=True, exist_ok=True)
                continue
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                if target.exists() or target.is_symlink():
                    raise ValueError('duplicate archive entry: ' + name)
                os.symlink(member.linkname, target)
                continue
            data = tar.extractfile(member).read()
            target.write_bytes(data)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    return destination, inventory, verified_symlinks


def verify(private, commit):
    private = private_path(private)
    prep = private / 'prep'
    assets = assets_dir(private)
    origin = (prep / 'origin.txt').read_text().strip()
    if origin not in REMOTES:
        raise ValueError('unexpected baum-os remote: ' + origin)
    resolved = (prep / 'resolved.txt').read_text().strip()
    if resolved != commit:
        raise ValueError('resolved commit differs from requested commit')
    expected_tree = (prep / 'tree.txt').read_text().strip()
    if not SHA_RE.fullmatch(expected_tree):
        raise ValueError('tree sha malformed')
    archive_path = prep / 'source.tar'
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError('source archive exceeds size budget')
    regular, symlinks, gitlinks = parse_typed_ls_tree((prep / 'tree-entries.txt').read_bytes())
    staging_src, inventory, targets = _verify_archive(archive_path, regular, symlinks)
    for entry in symlinks:
        entry['target'] = targets[entry['path']]
        entry['kind'] = validate_symlink_target(entry['path'], entry['target'])
    shutil.rmtree(staging_src / 'node_modules', ignore_errors=True)
    lines = [inventory[name][0] + '  ' + name for name in sorted(inventory)]
    (assets / 'inventory.sha256').write_text('\n'.join(lines) + '\n')
    (assets / 'symlinks.txt').write_text(
        ''.join(entry['path'] + '\t' + entry['target'] + '\n' for entry in symlinks))
    (assets / 'gitlinks.txt').write_text(
        ''.join(entry['commit'] + '\t' + entry['path'] + '\n' for entry in gitlinks))
    (assets / 'expected-tree.txt').write_text(expected_tree + '\n')
    lock = load_json(Path(__file__).parent / 'baum-lock.json')
    package_json = json.loads((staging_src / 'package.json').read_text())
    package_manager = package_json.get('packageManager', '')
    if not package_manager.startswith(lock['pnpm']['matches_package_manager_pin'] + '+sha512.'):
        raise ValueError('packageManager pin does not match the pinned pnpm version: ' + package_manager)
    pinned_hex = package_manager.split('+sha512.', 1)[1]
    lock_hex = base64.b64decode(lock['pnpm']['tar_sha512'].split('-', 1)[1]).hex()
    if pinned_hex != lock_hex or pinned_hex != lock['pnpm']['tar_sha512_hex_from_package_manager']:
        raise ValueError('pnpm digest provenance chain broken (packageManager vs baum-lock)')
    import image
    node_bin = assets / 'node-dist' / 'node'
    shim = assets / 'pnpm-shim'
    if not shim.exists():
        shim.write_text(PNPM_SHIM)
        shim.chmod(0o755)
    toolchain_expected = {
        '/usr/bin/node': node_bin, '/usr/bin/pnpm': shim,
        '/pnpm/bin/pnpm.mjs': assets / 'pnpm-pkg' / 'bin' / 'pnpm.mjs',
        '/pnpm/dist/pnpm.mjs': assets / 'pnpm-pkg' / 'dist' / 'pnpm.mjs',
        '/pnpm/dist/worker.js': assets / 'pnpm-pkg' / 'dist' / 'worker.js',
        '/usr/bin/bash': Path('/usr/bin/bash'), '/usr/bin/git': Path('/usr/bin/git'),
    }
    records = {}
    libs = []
    for name in ('node-ldd.txt', 'bash-ldd.txt', 'git-ldd.txt'):
        for path in sorted(set(re.findall(r'(/[A-Za-z0-9_./+-]+)', (prep / name).read_text()))):
            if Path(path).is_file():
                _data, record = image.verified_system_file(path)
                libs.append(record)
    git_core = []
    for path in sorted(Path('/usr/lib/git-core').iterdir()):
        if path.is_file():
            _data, record = image.verified_system_file(path)
            git_core.append(record)
    (assets / 'git-core-files.json').write_text(json.dumps({'records': git_core}, indent=2) + '\n')
    for guest_path, source in toolchain_expected.items():
        if guest_path in ('/usr/bin/bash', '/usr/bin/git'):
            data, record = image.verified_system_file(source)
            records[guest_path] = {'sha256': hashlib.sha256(data).hexdigest(), 'record': record}
        else:
            records[guest_path] = {'sha256': sha256_file(source), 'record': None}
    (assets / 'toolchain.sha256').write_text(
        ''.join(records[name]['sha256'] + '  ' + name + '\n' for name in sorted(records)))
    home = assets / 'staging-home'
    (home / '.local' / 'share').mkdir(parents=True, exist_ok=True)
    # pnpm 11's supply-chain/lockfile verification needs registry metadata even with
    # --offline (proven live: ENOTFOUND retries inside the isolated guest). The trusted
    # host store build populated pnpm's own metadata cache; it ships with the workspace
    # image (guest HOME=/ws/work) and is bound by digest here.
    _cache = store_manifest_digest(home / '.cache' / 'pnpm')
    pnpm_cache = {'file_count': _cache['file_count'], 'manifest_sha256': _cache['manifest_sha256']}
    q = shlex.quote
    write_script(prep / 'steps2.sh', [
        'cd ' + q(str(staging_src)),
        'rc=0',
        '# manage-package-manager-versions stays off: the executor must run exactly the',
        '# repository-pinned pnpm 11.9.0 vendored above, never an ambient one.',
        'env -i PATH=/usr/bin:/bin HOME=' + q(str(home)) + ' XDG_DATA_HOME=' + q(str(home / '.local/share')) +
        ' npm_config_manage_package_manager_versions=false' +
        ' ' + q(str(node_bin)) + ' ' + q(str(assets / 'pnpm-pkg' / 'bin' / 'pnpm.mjs')) +
        ' install --frozen-lockfile --ignore-scripts --store-dir ' + q(str(assets / 'store')) +
        ' > ' + q(str(prep / 'store-build.log')) + ' 2>&1 || rc=$?',
        'echo "$rc" > ' + q(str(prep / 'store-build.rc')),
        'exit "$rc"',
    ])
    toolchain = {'node': {'url': lock['node']['url'], 'tar_sha256': lock['node']['tar_sha256'],
                          'bin_sha256': sha256_file(node_bin), 'version': lock['node']['version']},
                 'pnpm': {'url': lock['pnpm']['url'], 'tar_sha512': lock['pnpm']['tar_sha512'],
                          'tar_sha512_hex_from_package_manager': lock['pnpm']['tar_sha512_hex_from_package_manager'],
                          'bin_sha256': sha256_file(assets / 'pnpm-pkg' / 'bin' / 'pnpm.mjs'),
                          'bundle_sha256': sha256_file(assets / 'pnpm-pkg' / 'dist' / 'pnpm.mjs'),
                          'worker_sha256': sha256_file(assets / 'pnpm-pkg' / 'dist' / 'worker.js'),
                          'version': lock['pnpm']['version']},
                 'pnpm_shim_sha256': sha256_file(shim),
                 'bash': records['/usr/bin/bash']['record'], 'git': records['/usr/bin/git']['record'],
                 'git_core_file_count': len(git_core), 'libs': libs}
    return {'status': 'verified', 'commit': commit, 'git_tree_sha': expected_tree,
            'file_count': len(inventory), 'archive_sha256': sha256_file(archive_path),
            'lockfile_sha256': sha256_file(staging_src / 'pnpm-lock.yaml'),
            'package_json_sha256': sha256_file(staging_src / 'package.json'),
            'package_manager': package_manager, 'pnpm_cache': pnpm_cache,
            'symlinks': symlinks, 'gitlinks': gitlinks, 'toolchain': toolchain}


def disk(private, commit, verified):
    private = private_path(private)
    prep = private / 'prep'
    assets = assets_dir(private)
    rc = (prep / 'store-build.rc').read_text().strip()
    if rc != '0':
        raise ValueError('offline store build failed with rc=' + rc + '; see prep/store-build.log')
    import ci_util
    import image
    native = ci_util.native_lib_records(assets / 'store', image.verified_system_file)
    (assets / 'native-libs.json').write_text(json.dumps(native, indent=2) + '\n')
    disk_root = prep / 'disk'
    if disk_root.exists():
        raise ValueError('staging disk exists; reconcile explicitly')
    (disk_root / 'work').mkdir(parents=True)
    # The guest must receive the exact committed tree (no .git); its own c1b check
    # re-derives the tree identity from this materialized content. Copy verbatim
    # (symlinks included — the tracked .quarantine node_modules link must survive),
    # then drop only the real root node_modules the host store build created.
    shutil.copytree(prep / 'staging-src', disk_root / 'src', symlinks=True)
    shutil.rmtree(disk_root / 'src' / 'node_modules', ignore_errors=True)
    shutil.copytree(assets / 'store', disk_root / 'store')
    # pnpm metadata/verification cache under the guest HOME so the offline supply-chain
    # verification resolves without any network (guest is restrict=on by design).
    shutil.copytree(assets / 'staging-home' / '.cache', disk_root / 'work' / '.cache',
                    dirs_exist_ok=True, symlinks=True)
    state_dir = assets / 'staging-home' / '.local' / 'state'
    if state_dir.is_dir():
        shutil.copytree(state_dir, disk_root / 'work' / '.local' / 'state',
                        dirs_exist_ok=True, symlinks=True)
    content_bytes = sum(f.stat().st_size for f in disk_root.rglob('*') if f.is_file())
    # The guest reconstructs .git (re-hashed blobs) and installs node_modules into the
    # same overlay; size for that growth instead of the Systems 6 GiB floor.
    image_bytes = max(int(content_bytes * 1.5) + 3 * 1024 ** 3, 12 * 1024 ** 3)
    q = shlex.quote
    write_script(prep / 'steps3.sh', [
        'mkfs.ext4 -F -q -L UNITERA_CI_WS -d ' + q(str(disk_root)) + ' -b 4096 ' +
        q(str(assets / 'ws-base.img')) + ' ' + str(image_bytes // 4096),
        'echo ok > ' + q(str(prep / 'mkfs.rc')),
    ])
    return {'status': 'disk-ready', 'steps3': str(prep / 'steps3.sh'), 'image_bytes': image_bytes}


def finalize(private, commit, verified):
    private = private_path(private)
    assets = assets_dir(private)
    prep = private / 'prep'
    if not (prep / 'mkfs.rc').exists() or (prep / 'mkfs.rc').read_text().strip() != 'ok':
        raise ValueError('workspace image build missing or failed')
    store = store_manifest_digest(assets / 'store')
    (assets / 'store-manifest.sha256').write_text(store['manifest'])
    image_record = {'bytes': (assets / 'ws-base.img').stat().st_size,
                    'sha256': sha256_file(assets / 'ws-base.img'), 'label': 'UNITERA_CI_WS',
                    'content': {'src': 'validated typed source tree', 'store': 'offline pnpm-11 store',
                                'work': 'empty'}}
    (assets / 'ws-image.json').write_text(json.dumps(image_record, indent=2) + '\n')
    manifest = {'schema': 'relay.baum-ci-prep.v1', 'repository': REPOSITORY,
                'prepared_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'source': {'commit': commit, 'file_count': verified['file_count'],
                           'archive_sha256': verified['archive_sha256'],
                           'lockfile_sha256': verified['lockfile_sha256'],
                           'package_json_sha256': verified['package_json_sha256'],
                           'git_tree_sha': verified['git_tree_sha'],
                           'symlink_count': len(verified['symlinks']),
                           'gitlink_count': len(verified['gitlinks'])},
                'package_manager': verified['package_manager'],
                'pnpm_cache': verified.get('pnpm_cache'),
                'toolchain': verified['toolchain'],
                'store': {k: v for k, v in store.items() if k != 'manifest'},
                'workspace_image': image_record}
    (assets / 'ci-prep-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['plan', 'verify', 'disk', 'finalize'])
    parser.add_argument('--repo', type=Path)
    parser.add_argument('--private', required=True, type=Path)
    parser.add_argument('--sha')
    parser.add_argument('--verified-json', type=Path)
    args = parser.parse_args()
    if args.phase == 'plan':
        print(json.dumps(plan(args.repo, args.private, args.sha), indent=2))
    elif args.phase == 'verify':
        print(json.dumps(verify(args.private, args.sha), indent=2))
    elif args.phase == 'disk':
        payload = load_json(args.verified_json) if args.verified_json else None
        if payload is None:
            payload = load_json(private_path(args.private) / 'prep' / 'verified.json')
        print(json.dumps(disk(args.private, args.sha or payload['commit'], payload), indent=2))
    else:
        payload = load_json(args.verified_json) if args.verified_json else load_json(
            private_path(args.private) / 'prep' / 'verified.json')
        print(json.dumps(finalize(args.private, args.sha or payload['commit'], payload), indent=2))
