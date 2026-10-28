"""Build the marketing Python guest initrd from verified assets. Pure assembly, no execution.

The kernel/initramfs/exit helpers come from the same signed Alpine ISO lane as the
qualified profiles (image.build). The marketing initrd adds: busybox, the pinned
distribution Python 3 binary, its dpkg-verified shared libraries, the complete
standard library (py files plus lib-dynload extension modules and their resolved
libraries), tiny failure-injection fixtures, the guest executor script and the
commit-bound source/toolchain manifests. Marketing source code is never part of
this image and nothing from the checkout is executed here.
"""
import gzip
import hashlib
import json
from pathlib import Path

import ci_util
from ci_util import load_json, sha256_file
from paths import private_path
from image import cpio, verified_system_file

FIXTURE_EXIT_ONE = 'import sys\nsys.exit(1)\n'
FIXTURE_HOLD = 'import time\ntime.sleep(1800)\n'


def _runtime_files(lock):
    """Every distribution file that constitutes the guest Python runtime."""
    files = {}  # guest path -> host source path
    if lock.get('python_version') != '3.14.4':
        raise ValueError('lock python version is not the reviewed 3.14.4 runtime')
    import subprocess
    for package, expected_version in lock['packages'].items():
        installed = subprocess.run(['dpkg-query', '-W', '-f=${Version}', package],
                                   capture_output=True, text=True)
        if installed.returncode or installed.stdout != expected_version:
            raise ValueError('installed package version differs from runtime lock: ' + package)
    binary = Path(lock['binary'])
    if not binary.is_file():
        raise ValueError('pinned python binary missing on host')
    files['usr/bin/python3.14'] = binary
    files['usr/bin/python3'] = binary
    import re as _re
    ldd = subprocess.run(['ldd', str(binary)], capture_output=True, text=True,
                         env={'PATH': '/usr/bin:/bin'})
    for library in sorted(set(_re.findall(r'(/[A-Za-z0-9_./+-]+)', ldd.stdout))):
        if Path(library).is_file():
            files['usr/' + library.lstrip('/')] = Path(library)
    stdlib = Path(lock['stdlib_root'])
    excluded = set(lock['stdlib_excludes'])
    for path in sorted(stdlib.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in excluded for part in path.relative_to(stdlib).parts):
            continue
        files['usr/lib/python3.14/' + str(path.relative_to(stdlib))] = path
    if len(files) < 500:
        raise ValueError('python runtime file set implausibly small')
    return files


def _closure_libraries(host_paths):
    """DT_NEEDED closure over every ELF object in the runtime (lib-dynload included)."""
    records, seen = [], set()
    pending = list(host_paths)
    while pending:
        path = Path(pending.pop())
        if path in seen or not path.is_file() or path.is_symlink():
            continue
        seen.add(path)
        with path.open('rb') as handle:
            data = handle.read()
        if data[:4] != b'\x7fELF':
            continue
        for soname in ci_util.elf_needed_sonames(data):
            candidate = ci_util.resolve_host_soname(soname)
            if candidate is not None:
                pending.append(candidate)
    for path in sorted(seen):
        if path.is_file() and path.read_bytes()[:4] == b'\x7fELF':
            _data, record = verified_system_file(path)
            records.append(record)
    return records


def build_marketing_initrd(assets):
    assets = private_path(assets)
    import image
    if not (assets / 'kernel').exists() or not (assets / 'exit-success').exists():
        image.build(assets)
    lock = load_json(Path(__file__).parent / 'marketing-runtime-lock.json')
    runtime_files = _runtime_files(lock)
    entries = {}
    busybox_data, _busybox_record = verified_system_file('/usr/bin/busybox')
    entries['usr/bin/busybox'] = (busybox_data, 0o755)
    entries['usr/bin/exit-success'] = ((assets / 'exit-success').read_bytes(), 0o755)
    entries['usr/bin/exit-failure'] = ((assets / 'exit-failure').read_bytes(), 0o755)
    toolchain_lines = []
    runtime_records = []
    for guest_path, host_path in sorted(runtime_files.items()):
        data, record = verified_system_file(host_path)
        mode = 0o755 if guest_path.startswith('usr/bin/') or '/lib-dynload/' in guest_path \
            or guest_path.endswith('.so') or '.so.' in guest_path else 0o644
        entries[guest_path] = (data, mode)
        toolchain_lines.append(hashlib.sha256(data).hexdigest() + '  /' + guest_path)
        runtime_records.append(record)
    for record in _closure_libraries([Path(v) for v in runtime_files.values()]):
        data = Path(record['path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('library digest drift for ' + record['path'])
        destination = 'usr/' + record['path'].lstrip('/') if record['path'].startswith('/lib/') \
            else record['path'].lstrip('/')
        if destination not in entries:
            entries[destination] = (data, 0o755)
            toolchain_lines.append(record['sha256'] + '  /' + destination)
    entries['fixtures/exit-one.py'] = (FIXTURE_EXIT_ONE.encode(), 0o644)
    entries['fixtures/hold.py'] = (FIXTURE_HOLD.encode(), 0o644)
    entries['toolchain.sha256'] = ('\n'.join(sorted(toolchain_lines)) + '\n').encode(), 0o644
    guest_init = (Path(__file__).parent / 'marketing_guest.sh').read_bytes()
    entries['init'] = (guest_init, 0o755)
    initrd = (assets / 'base-initrd').read_bytes() + gzip.compress(
        cpio(entries), compresslevel=1, mtime=0)
    (assets / 'marketing-initrd').write_bytes(initrd)
    record = {'schema': 'relay.marketing-image.v1',
              'initrd_sha256': hashlib.sha256(initrd).hexdigest(),
              'guest_init_sha256': hashlib.sha256(guest_init).hexdigest(),
              'kernel_sha256': sha256_file(assets / 'kernel'),
              'base_initrd_sha256': sha256_file(assets / 'base-initrd'),
              'python_version': lock['python_version'],
              'python_bin_sha256': sha256_file(Path(lock['binary'])),
              'runtime_file_count': len(runtime_files),
              'entry_count': len(entries),
              'toolchain_manifest_sha256': hashlib.sha256(
                  entries['toolchain.sha256'][0]).hexdigest()}
    (assets / 'marketing-image.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('assets', type=Path)
    print(json.dumps(build_marketing_initrd(parser.parse_args().assets), indent=2))
