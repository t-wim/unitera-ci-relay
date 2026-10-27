"""Build the source-CI guest initrd from verified assets. Pure file assembly, no execution.

The base kernel/initramfs/exit helpers come from the same signed Alpine ISO lane as the
synthetic profile (image.build). The CI initrd adds: busybox, the pinned node binary,
the pinned pnpm bundle, its dpkg-verified libraries, tiny failure-injection fixtures,
the guest executor script and the commit-bound inventory/toolchain manifests.
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


def build_ci_initrd(assets):
    assets = private_path(assets)
    import image
    if not (assets / 'kernel').exists() or not (assets / 'exit-success').exists():
        image.build(assets)
    prep = load_json(assets / 'ci-prep-manifest.json')
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
