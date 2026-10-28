"""Trusted marketing source/toolchain preparation (pure logic; mkfs is emitted for the shell lane).

Phases (each validates before the next mechanical step may run):
  plan    - run the reviewed git custody export (exact commit, blob re-derivation,
            full SHA-256 inventory, private/symlink/submodule denial), extract the
            verified staging tree, emit steps.sh (mkfs.ext4). Never executes
            marketing code; git archive/ls-tree are data operations only.
  finalize- digest the workspace image, bind it to the custody receipt and the
            verified Python runtime image, write marketing-prep-manifest.json.
"""
import argparse
import datetime
import json
import shutil
from pathlib import Path

from ci_util import load_json, safe_extract, sha256_file
from image import verified_system_file  # noqa: F401  (provenance gate reused by tests)
from marketing_source_custody import prepare as custody_prepare
from paths import private_path

SOURCE_REPO = 'baum777/unitera_marketing_agent-team'


def assets_dir(private):
    return private_path(private) / 'marketing-assets'


def write_script(path, lines):
    path.write_text('\n'.join(['#!/bin/sh', 'set -eu'] + lines) + '\n')
    path.chmod(0o700)


def plan(checkout, private, commit):
    private = private_path(private)
    checkout = Path(checkout).resolve()
    assets = assets_dir(private)
    prep = private / 'prep'
    prep.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (assets / 'marketing-prep-manifest.json').exists():
        recorded = load_json(assets / 'marketing-prep-manifest.json').get('source', {}).get('commit')
        if recorded == commit:
            return {'status': 'reconciled', 'manifest': str(assets / 'marketing-prep-manifest.json')}
        raise ValueError('assets exist for a different commit; reconcile explicitly before re-preparing')
    for stale in ['staging-src', 'ws-base.img']:
        if (assets / stale).exists():
            raise ValueError('stale preparation state exists: ' + stale + '; reconcile explicitly')
    custody_dir = prep / 'custody'
    if custody_dir.exists() and any(custody_dir.iterdir()):
        raise ValueError('custody destination must be empty; no implicit overwrite')
    receipt = custody_prepare(checkout, commit, custody_dir)
    assets.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = assets / 'staging-src'
    staging.mkdir(mode=0o700)
    safe_extract(custody_dir / 'source.tar', staging)
    inventory = receipt['inventory']
    if not all((staging / name).is_file() for name in inventory):
        raise ValueError('staging tree does not match the custody inventory')
    lines = [digest + '  ' + name for name, digest in sorted(inventory.items())]
    (assets / 'inventory.sha256').write_text('\n'.join(lines) + '\n')
    disk_root = prep / 'disk'
    if disk_root.exists():
        raise ValueError('staging disk exists; reconcile explicitly')
    (disk_root / 'work').mkdir(parents=True)
    shutil.copytree(staging, disk_root / 'src')
    content_bytes = sum(f.stat().st_size for f in disk_root.rglob('*') if f.is_file())
    image_bytes = max(content_bytes * 2 + 256 * 1024 ** 2, 512 * 1024 ** 2)
    write_script(prep / 'steps.sh', [
        'mkfs.ext4 -F -q -L UNITERA_MKT_WS -d ' + str(disk_root) + ' -b 4096 ' +
        str(assets / 'ws-base.img') + ' ' + str(image_bytes // 4096),
        'echo ok > ' + str(prep / 'mkfs.rc'),
    ])
    return {'status': 'planned', 'steps': str(prep / 'steps.sh'), 'commit': commit,
            'file_count': receipt['file_count'], 'image_bytes': image_bytes}


def finalize(private, commit):
    private = private_path(private)
    assets = assets_dir(private)
    prep = private / 'prep'
    if not (prep / 'mkfs.rc').exists() or (prep / 'mkfs.rc').read_text().strip() != 'ok':
        raise ValueError('workspace image build missing or failed')
    custody = load_json(prep / 'custody' / 'source-receipt.json')
    if custody.get('repository') != SOURCE_REPO or custody.get('commit') != commit:
        raise ValueError('custody receipt not bound to the requested commit')
    image = load_json(assets / 'marketing-image.json')
    if sha256_file(assets / 'marketing-initrd') != image['initrd_sha256']:
        raise ValueError('marketing initrd digest mismatch at finalize')
    inventory_text = (assets / 'inventory.sha256').read_text()
    import hashlib
    image_record = {'bytes': (assets / 'ws-base.img').stat().st_size,
                    'sha256': sha256_file(assets / 'ws-base.img'), 'label': 'UNITERA_MKT_WS',
                    'content': {'src': 'custody-verified source tree', 'work': 'empty'}}
    manifest = {'schema': 'relay.marketing-prep.v1',
                'prepared_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'source_repository': SOURCE_REPO,
                'source': {'commit': commit, 'file_count': custody['file_count'],
                           'archive_sha256': custody['archive_sha256'],
                           'inventory_sha256': hashlib.sha256(inventory_text.encode()).hexdigest(),
                           'source_bytes': custody['source_bytes']},
                'python_runtime': {'version': image['python_version'],
                                   'python_bin_sha256': image['python_bin_sha256'],
                                   'runtime_file_count': image['runtime_file_count'],
                                   'initrd_sha256': image['initrd_sha256'],
                                   'toolchain_manifest_sha256': image['toolchain_manifest_sha256']},
                'workspace_image': image_record}
    (assets / 'marketing-prep-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    shutil.rmtree(prep / 'disk', ignore_errors=True)
    shutil.rmtree(assets / 'staging-src', ignore_errors=True)
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['plan', 'finalize'])
    parser.add_argument('--checkout', type=Path)
    parser.add_argument('--private', required=True, type=Path)
    parser.add_argument('--sha')
    args = parser.parse_args()
    if args.phase == 'plan':
        print(json.dumps(plan(args.checkout, args.private, args.sha), indent=2))
    else:
        print(json.dumps(finalize(args.private, args.sha), indent=2))
