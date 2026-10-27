"""Trusted source/toolchain preparation (pure logic; mechanical steps are emitted for the shell lane).

Phases (each validates before the next mechanical step may run):
  plan    - verify repo inputs, download+verify pinned toolchain, emit steps1.sh
            (git identity/ls-tree/archive, ldd of node).
  verify  - bind the source archive to the commit via git blob object hashes (git's own
            content addressing, not a security digest; all security digests are SHA-256),
            extract the staging tree, emit the guest inventory manifests, emit steps2.sh
            (offline store build with lifecycle scripts disabled).
  disk    - require store rc 0, assemble the ext4 staging tree, emit steps3.sh (mkfs.ext4).
  finalize- digest store and workspace image, write ci-prep-manifest.json.

Emitted scripts run with a cleared environment and validated absolute paths only.
This module never executes anything itself.
"""
import argparse
import datetime
import hashlib
import json
import re
import shutil
import tarfile
from pathlib import Path

from ci_util import (MAX_ARCHIVE_BYTES, extract_member, load_json, parse_ls_tree,
                     sha256_file, store_manifest_digest, validate_tar_members, verify_download)
from paths import private_path

EXPECTED_REMOTE = 'https://github.com/baum777/Unitera_Systems.git'
SHA_RE = re.compile(r'[0-9a-f]{40}')


def git_blob_sha(data):
    # Git object ids are SHA-1 by repository format; this reimplementation only re-derives
    # that identity. Every security-relevant digest in this pipeline is SHA-256.
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\x00' + data).hexdigest()


def assets_dir(private):
    return private_path(private) / 'ci-assets'


def write_script(path, lines):
    path.write_text('\n'.join(['#!/bin/sh', 'set -eu'] + lines) + '\n')
    path.chmod(0o700)


def plan(systems, private, commit):
    private = private_path(private)
    systems = Path(systems).resolve()
    if not systems.is_dir() or not ((systems / '.git').exists() or (systems / 'HEAD').exists()):
        raise ValueError('systems repository directory required: ' + str(systems))
    if not SHA_RE.fullmatch(commit):
        raise ValueError('commit must be a full 40-hex sha')
    assets = assets_dir(private)
    assets.mkdir(mode=0o700, parents=True, exist_ok=True)
    prep = private / 'prep'
    prep.mkdir(mode=0o700, exist_ok=True)
    lock = load_json(Path(__file__).parent / 'ci-lock.json')
    existing = assets / 'ci-prep-manifest.json'
    if existing.exists():
        recorded = load_json(existing).get('source', {}).get('commit')
        if recorded == commit:
            return {'status': 'reconciled', 'manifest': str(existing)}
        raise ValueError('assets exist for a different commit; reconcile explicitly before re-preparing')
    for stale in ['staging-src', 'staging-home', 'store']:
        if (assets / stale).exists():
            raise ValueError('stale preparation state exists: ' + stale + '; reconcile explicitly')
    import fetch as vendor_fetch
    vendor_fetch.fetch(assets)
    node_tar = assets / 'node.tar.xz'
    pnpm_tar = assets / 'pnpm.tgz'
    verify_download(lock['node'], node_tar)
    verify_download(lock['pnpm'], pnpm_tar)
    node_bin = assets / 'node-dist' / 'node'
    if not node_bin.exists():
        member = 'node-v' + lock['node']['version'] + '-linux-x64/bin/node'
        node_bin.parent.mkdir(parents=True, exist_ok=True)
        node_bin.write_bytes(extract_member(node_tar, member))
        node_bin.chmod(0o755)
    pnpm_cjs = assets / 'pnpm.cjs'
    if not pnpm_cjs.exists():
        pnpm_cjs.write_bytes(extract_member(pnpm_tar, lock['pnpm']['cjs_entry']))
    pnpm_worker = assets / 'worker.js'
    if not pnpm_worker.exists():
        pnpm_worker.write_bytes(extract_member(pnpm_tar, lock['pnpm']['worker_entry']))
    write_script(prep / 'steps1.sh', [
        'cd ' + str(private),
        'git -C ' + str(systems) + ' remote get-url origin > prep/origin.txt',
        'git -C ' + str(systems) + ' rev-parse --verify ' + commit + '^{commit} > prep/resolved.txt',
        'git -C ' + str(systems) + ' ls-tree -r -z ' + commit + ' > prep/tree.txt',
        'git -C ' + str(systems) + ' archive --format=tar ' + commit + ' > prep/source.tar',
        'ldd ' + str(node_bin) + ' > prep/node-ldd.txt',
    ])
    return {'status': 'planned', 'steps1': str(prep / 'steps1.sh'), 'private': str(private),
            'commit': commit}


def _archive_inventory(archive_path, tree_entries):
    """Single pass: verify members, then re-read each file once computing git-blob and sha256 ids."""
    with tarfile.open(archive_path, 'r:') as tar:
        validate_tar_members(tar, expected_members=2 * len(tree_entries) + 1024)
        names = [m.name for m in tar.getmembers() if m.isfile()]
    if set(names) != set(tree_entries):
        missing = sorted(set(tree_entries) - set(names))[:5]
        extra = sorted(set(names) - set(tree_entries))[:5]
        raise ValueError('archive/tree name mismatch; missing=' + str(missing) + ' extra=' + str(extra))
    inventory = {}
    with tarfile.open(archive_path, 'r:') as tar:
        for member in tar:
            if not member.isfile():
                continue
            data = tar.extractfile(member).read()
            if git_blob_sha(data) != tree_entries[member.name][0]:
                raise ValueError('git blob object id mismatch for ' + member.name)
            inventory[member.name] = [hashlib.sha256(data).hexdigest(), len(data)]
    return inventory


def verify(private, commit):
    private = private_path(private)
    prep = private / 'prep'
    assets = assets_dir(private)
    origin = (prep / 'origin.txt').read_text().strip()
    if origin not in (EXPECTED_REMOTE, 'git@github.com:baum777/Unitera_Systems.git'):
        raise ValueError('unexpected systems remote: ' + origin)
    resolved = (prep / 'resolved.txt').read_text().strip()
    if resolved != commit:
        raise ValueError('resolved commit differs from requested commit')
    archive_path = prep / 'source.tar'
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError('source archive exceeds size budget')
    tree_entries = parse_ls_tree((prep / 'tree.txt').read_text())
    inventory = _archive_inventory(archive_path, tree_entries)
    destination = assets / ('source-' + commit[:12] + '.tar')
    if destination.exists():
        raise ValueError('prepared source archive already exists; reconcile explicitly')
    shutil.copyfile(archive_path, destination)
    staging_src = assets / 'staging-src'
    staging_src.mkdir(mode=0o700)
    import ci_util
    ci_util.safe_extract(destination, staging_src)
    shutil.rmtree(staging_src / 'node_modules', ignore_errors=True)
    lines = [inventory[name][0] + '  ' + name for name in sorted(inventory)]
    (assets / 'inventory.sha256').write_text('\n'.join(lines) + '\n')
    node_bin = assets / 'node-dist' / 'node'
    pnpm_cjs = assets / 'pnpm.cjs'
    pnpm_worker = assets / 'worker.js'
    (assets / 'toolchain.sha256').write_text(
        sha256_file(node_bin) + '  /usr/bin/node\n' + sha256_file(pnpm_cjs) + '  /pnpm/pnpm.cjs\n' +
        sha256_file(pnpm_worker) + '  /pnpm/worker.js\n')
    lockfile = staging_src / 'pnpm-lock.yaml'
    ldd_text = (prep / 'node-ldd.txt').read_text()
    import image
    libs = []
    for path in sorted(set(re.findall(r'(/[A-Za-z0-9_./+-]+)', ldd_text))):
        if Path(path).is_file():
            _data, record = image.verified_system_file(path)
            libs.append(record)
    home = assets / 'staging-home'
    home.mkdir(mode=0o700, exist_ok=True)
    (home / '.local' / 'share').mkdir(parents=True, exist_ok=True)
    write_script(prep / 'steps2.sh', [
        'cd ' + str(staging_src),
        'rc=0',
        '# manage-package-manager-versions stays off: the workspace root above this private dir pins a',
        '# different pnpm; the executor must run exactly the repository-pinned pnpm 10.5.2.',
        'env -i PATH=/usr/bin:/bin HOME=' + str(home) + ' XDG_DATA_HOME=' + str(home / '.local/share') +
        ' npm_config_manage_package_manager_versions=false' +
        ' ' + str(node_bin) + ' ' + str(pnpm_cjs) +
        ' install --frozen-lockfile --ignore-scripts --store-dir ' + str(assets / 'store') +
        ' > ' + str(prep / 'store-build.log') + ' 2>&1 || rc=$?',
        'echo "$rc" > ' + str(prep / 'store-build.rc'),
        'exit "$rc"',
    ])
    lock = load_json(Path(__file__).parent / 'ci-lock.json')
    toolchain = {'node': {'url': lock['node']['url'], 'tar_sha256': lock['node']['tar_sha256'],
                          'bin_sha256': sha256_file(node_bin), 'version': lock['node']['version']},
                 'pnpm': {'url': lock['pnpm']['url'], 'tar_sha512': lock['pnpm']['tar_sha512'],
                          'cjs_sha256': sha256_file(pnpm_cjs), 'version': lock['pnpm']['version']},
                 'pnpm_worker_sha256': sha256_file(assets / 'worker.js'),
                 'libs': libs}
    return {'status': 'verified', 'commit': commit, 'file_count': len(inventory),
            'archive_sha256': sha256_file(destination),
            'lockfile_sha256': sha256_file(lockfile) if lockfile.exists() else None,
            'toolchain': toolchain}


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
    # The store build ran inside staging-src and created node_modules trees at several depths;
    # the guest must receive the clean committed tree and perform its own install (check c3).
    shutil.copytree(assets / 'staging-src', disk_root / 'src',
                    ignore=shutil.ignore_patterns('node_modules'), symlinks=True)
    shutil.copytree(assets / 'store', disk_root / 'store')
    content_bytes = sum(f.stat().st_size for f in disk_root.rglob('*') if f.is_file())
    image_bytes = max(int(content_bytes * 1.5) + 3 * 1024 ** 3, 6 * 1024 ** 3)
    write_script(prep / 'steps3.sh', [
        'mkfs.ext4 -F -q -L UNITERA_CI_WS -d ' + str(disk_root) + ' -b 4096 ' +
        str(assets / 'ws-base.img') + ' ' + str(image_bytes // 4096),
        'echo ok > ' + str(prep / 'mkfs.rc'),
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
                    'content': {'src': 'validated source tree', 'store': 'offline pnpm store',
                                'work': 'empty'}}
    (assets / 'ws-image.json').write_text(json.dumps(image_record, indent=2) + '\n')
    manifest = {'schema': 'relay.ci-prep.v1',
                'prepared_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'systems_remote': EXPECTED_REMOTE,
                'source': {'commit': commit, 'file_count': verified['file_count'],
                           'archive_sha256': verified['archive_sha256'],
                           'lockfile_sha256': verified['lockfile_sha256']},
                'toolchain': verified['toolchain'],
                'store': {k: v for k, v in store.items() if k != 'manifest'},
                'workspace_image': image_record}
    (assets / 'ci-prep-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['plan', 'verify', 'disk', 'finalize'])
    parser.add_argument('--systems', type=Path)
    parser.add_argument('--private', required=True, type=Path)
    parser.add_argument('--sha')
    parser.add_argument('--verified-json', type=Path)
    args = parser.parse_args()
    if args.phase == 'plan':
        print(json.dumps(plan(args.systems, args.private, args.sha), indent=2))
    elif args.phase == 'verify':
        print(json.dumps(verify(args.private, args.sha), indent=2))
    elif args.phase == 'disk':
        payload = load_json(args.verified_json) if args.verified_json else None
        if payload is None and not args.sha:
            parser.error('disk requires --verified-json or cached state')
        if payload is None:
            cached = private_path(args.private) / 'prep' / 'verified.json'
            payload = load_json(cached)
        print(json.dumps(disk(args.private, args.sha or payload['commit'], payload), indent=2))
    else:
        cached = private_path(args.private) / 'prep' / 'verified.json'
        payload = load_json(args.verified_json) if args.verified_json else load_json(cached)
        print(json.dumps(finalize(args.private, args.sha or payload['commit'], payload), indent=2))
