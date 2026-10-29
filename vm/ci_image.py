"""Build the source-CI guest initrd from verified assets. Pure file assembly, no execution.

The base kernel/initramfs/exit helpers come from the same signed Alpine ISO lane as the
synthetic profile (image.build). The CI initrd adds: busybox, the pinned node binary,
the pinned pnpm bundle, its dpkg-verified libraries, tiny failure-injection fixtures,
the guest executor script and the commit-bound inventory/toolchain manifests.

The baum-os profile adds bash, git and the dpkg-verified git-core helper directory,
the pinned pnpm 11 (ESM bin/dist layout plus a fixed /usr/bin/pnpm shim), and the
typed-tree manifests (inventory, symlinks, gitlinks, expected tree) consumed by the
guest's c1/c1b integrity checks.
"""
import gzip
import hashlib
import json
import stat
from pathlib import Path

from ci_util import load_json, sha256_file
from paths import private_path
from image import cpio, verified_system_file

FIXTURE_EXIT_ONE = 'process.exit(1);\n'
FIXTURE_HOLD = 'setTimeout(() => {}, 600000);\n'
BAUM_REPOSITORY = 'baum777/baum-os'


def _toolchain_digests(assets):
    return {line.split('  ')[1]: line.split('  ')[0]
            for line in (assets / 'toolchain.sha256').read_text().splitlines() if line}


def build_baum_initrd(assets, prep):
    """baum-os guest initrd: same signed base lane, plus bash/git/git-core, the pinned
    pnpm 11 ESM bundle with its shim, and the typed-tree manifests for c1/c1b."""
    import image
    if not (assets / 'kernel').exists() or not (assets / 'exit-success').exists():
        image.build(assets)
    node_bin = assets / 'node-dist' / 'node'
    expected = _toolchain_digests(assets)
    entries = {}
    busybox_data, _busybox_record = image.verified_system_file('/usr/bin/busybox')
    entries['usr/bin/busybox'] = (busybox_data, 0o755)
    entries['usr/bin/exit-success'] = ((assets / 'exit-success').read_bytes(), 0o755)
    entries['usr/bin/exit-failure'] = ((assets / 'exit-failure').read_bytes(), 0o755)
    def pinned(source, guest_path, mode):
        data = Path(source).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected[guest_path]:
            raise ValueError('toolchain digest drift for ' + guest_path)
        entries[guest_path.lstrip('/')] = (data, mode)
    pinned(node_bin, '/usr/bin/node', 0o755)
    pinned(assets / 'pnpm-pkg' / 'bin' / 'pnpm.mjs', '/pnpm/bin/pnpm.mjs', 0o644)
    pinned(assets / 'pnpm-pkg' / 'dist' / 'pnpm.mjs', '/pnpm/dist/pnpm.mjs', 0o644)
    pinned(assets / 'pnpm-pkg' / 'dist' / 'worker.js', '/pnpm/dist/worker.js', 0o644)
    pinned(assets / 'pnpm-shim', '/usr/bin/pnpm', 0o755)
    bash_data, _bash_record = image.verified_system_file('/usr/bin/bash')
    if hashlib.sha256(bash_data).hexdigest() != expected['/usr/bin/bash']:
        raise ValueError('toolchain digest drift for /usr/bin/bash')
    entries['usr/bin/bash'] = (bash_data, 0o755)
    git_data, _git_record = image.verified_system_file('/usr/bin/git')
    if hashlib.sha256(git_data).hexdigest() != expected['/usr/bin/git']:
        raise ValueError('toolchain digest drift for /usr/bin/git')
    entries['usr/bin/git'] = (git_data, 0o755)
    git_core = load_json(assets / 'git-core-files.json')['records']
    for record in git_core:
        data = Path(record['path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('git-core digest drift for ' + record['path'])
        entries[record['path'].lstrip('/')] = (data, 0o755)
    for record in prep['toolchain']['libs'] + load_json(assets / 'native-libs.json')['records']:
        data = Path(record['path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('library digest drift for ' + record['path'])
        destination = record['path'].lstrip('/')
        if destination.startswith('lib/'):
            destination = 'usr/' + destination
        entries[destination] = (data, 0o755)
    entries['fixtures/exit-one.mjs'] = (FIXTURE_EXIT_ONE.encode(), 0o644)
    entries['fixtures/hold.mjs'] = (FIXTURE_HOLD.encode(), 0o644)
    entries['inventory.sha256'] = ((assets / 'inventory.sha256').read_bytes(), 0o644)
    entries['toolchain.sha256'] = ((assets / 'toolchain.sha256').read_bytes(), 0o644)
    entries['symlinks.txt'] = ((assets / 'symlinks.txt').read_bytes(), 0o644)
    entries['gitlinks.txt'] = ((assets / 'gitlinks.txt').read_bytes(), 0o644)
    entries['expected-tree.txt'] = ((assets / 'expected-tree.txt').read_bytes(), 0o644)
    guest_init = (Path(__file__).parent / 'ci_guest.sh').read_bytes()
    entries['init'] = (guest_init, 0o755)
    initrd = (assets / 'base-initrd').read_bytes() + gzip.compress(
        cpio(entries), compresslevel=1, mtime=0)
    (assets / 'ci-initrd').write_bytes(initrd)
    record = {'initrd_sha256': hashlib.sha256(initrd).hexdigest(),
              'guest_init_sha256': hashlib.sha256(guest_init).hexdigest(),
              'kernel_sha256': sha256_file(assets / 'kernel'),
              'base_initrd_sha256': sha256_file(assets / 'base-initrd'),
              'node_bin_sha256': sha256_file(node_bin),
              'pnpm_bin_sha256': expected['/pnpm/bin/pnpm.mjs'],
              'pnpm_bundle_sha256': expected['/pnpm/dist/pnpm.mjs'],
              'pnpm_worker_sha256': expected['/pnpm/dist/worker.js'],
              'pnpm_shim_sha256': expected['/usr/bin/pnpm'],
              'bash_sha256': expected['/usr/bin/bash'],
              'git_sha256': expected['/usr/bin/git'],
              'git_core_file_count': len(git_core),
              'expected_tree_sha': (assets / 'expected-tree.txt').read_text().strip(),
              'entry_count': len(entries)}
    (assets / 'ci-image.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def build_ci_initrd(assets):
    assets = private_path(assets)
    import image
    prep = load_json(assets / 'ci-prep-manifest.json')
    if prep.get('repository') == BAUM_REPOSITORY:
        return build_baum_initrd(assets, prep)
    if not (assets / 'kernel').exists() or not (assets / 'exit-success').exists():
        image.build(assets)
    node_bin = assets / 'node-dist' / 'node'
    pnpm_cjs = assets / 'pnpm.cjs'
    pnpm_worker = assets / 'worker.js'
    toolchain_expected = {line.split('  ')[1]: line.split('  ')[0]
                          for line in (assets / 'toolchain.sha256').read_text().splitlines() if line}
    if sha256_file(node_bin) != toolchain_expected['/usr/bin/node']:
        raise ValueError('node binary no longer matches the prepared toolchain digest')
    if sha256_file(pnpm_cjs) != toolchain_expected['/pnpm/pnpm.cjs']:
        raise ValueError('pnpm bundle no longer matches the prepared toolchain digest')
    if sha256_file(pnpm_worker) != toolchain_expected['/pnpm/worker.js']:
        raise ValueError('pnpm worker no longer matches the prepared toolchain digest')
    entries = {}
    busybox_data, _busybox_record = verified_system_file('/usr/bin/busybox')
    entries['usr/bin/busybox'] = (busybox_data, 0o755)
    entries['usr/bin/exit-success'] = ((assets / 'exit-success').read_bytes(), 0o755)
    entries['usr/bin/exit-failure'] = ((assets / 'exit-failure').read_bytes(), 0o755)
    entries['usr/bin/node'] = (node_bin.read_bytes(), 0o755)
    entries['pnpm/pnpm.cjs'] = (pnpm_cjs.read_bytes(), 0o644)
    entries['pnpm/worker.js'] = (pnpm_worker.read_bytes(), 0o644)
    for record in prep['toolchain']['libs'] + load_json(assets / 'native-libs.json')['records']:
        data = Path(record['path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('library digest drift for ' + record['path'])
        destination = record['path'].lstrip('/')
        if destination.startswith('lib/'):
            destination = 'usr/' + destination
        entries[destination] = (data, 0o755)
    entries['fixtures/exit-one.mjs'] = (FIXTURE_EXIT_ONE.encode(), 0o644)
    entries['fixtures/hold.mjs'] = (FIXTURE_HOLD.encode(), 0o644)
    entries['inventory.sha256'] = ((assets / 'inventory.sha256').read_bytes(), 0o644)
    entries['toolchain.sha256'] = ((assets / 'toolchain.sha256').read_bytes(), 0o644)
    guest_init = (Path(__file__).parent / 'ci_guest.sh').read_bytes()
    entries['init'] = (guest_init, 0o755)
    initrd = (assets / 'base-initrd').read_bytes() + gzip.compress(
        cpio(entries), compresslevel=1, mtime=0)
    (assets / 'ci-initrd').write_bytes(initrd)
    record = {'initrd_sha256': hashlib.sha256(initrd).hexdigest(),
              'guest_init_sha256': hashlib.sha256(guest_init).hexdigest(),
              'kernel_sha256': sha256_file(assets / 'kernel'),
              'base_initrd_sha256': sha256_file(assets / 'base-initrd'),
              'node_bin_sha256': sha256_file(node_bin),
              'pnpm_cjs_sha256': sha256_file(pnpm_cjs),
              'entry_count': len(entries)}
    (assets / 'ci-image.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('assets', type=Path)
    print(json.dumps(build_ci_initrd(parser.parse_args().assets), indent=2))
