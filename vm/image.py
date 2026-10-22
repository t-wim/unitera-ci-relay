"""Build a private synthetic guest image; no host extraction or daemon API use."""
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
from paths import private_path

HERE = Path(__file__).resolve().parent
TOOLS = ['busybox', 'docker', 'dockerd', 'containerd', 'containerd-shim-runc-v2', 'runc']


def cpio(entries):
    result = bytearray()
    directories = set()
    for name in entries:
        path = Path(name)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('unsafe initramfs path')
        directories.update(str(p) for p in path.parents if str(p) != '.')
    records = [(name, b'', stat.S_IFDIR | 0o755) for name in sorted(directories, key=lambda p: (p.count('/'), p))]
    records += [(name, data, stat.S_IFREG | mode) for name, (data, mode) in entries.items()]
    records.append(('TRAILER!!!', b'', 0))
    for ino, (name, data, mode) in enumerate(records, 1):
        encoded = name.encode() + b'\0'
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
        result += b'070701' + ''.join(f'{n:08x}' for n in fields).encode() + encoded
        result += b'\0' * (-len(result) % 4)
        result += data
        result += b'\0' * (-len(result) % 4)
    return bytes(result)


def verified_system_file(path):
    """Only distribution-owned binaries/libraries, never configuration/home files."""
    path = Path(path)
    if not str(path).startswith(('/usr/bin/', '/usr/sbin/', '/usr/lib/', '/lib/', '/lib64/')):
        raise ValueError('system file outside executable/library allowlist')
    resolved = path.resolve(strict=True)
    if not str(resolved).startswith(('/usr/bin/', '/usr/sbin/', '/usr/lib/')):
        raise ValueError('resolved system file outside executable/library allowlist')
    data = resolved.read_bytes()
    candidates = {str(path).lstrip('/'), str(path.resolve()).lstrip('/')}
    owner = None
    for spelling in [path, path.resolve()]:
        r = subprocess.run(['dpkg-query', '-S', str(spelling)], capture_output=True, text=True)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                package, separator, owned = line.rpartition(': ')
                if separator and owned in {str(path), str(path.resolve())}:
                    checksums = Path('/var/lib/dpkg/info') / (package + '.md5sums')
                    if not checksums.exists():
                        continue
                    for row in checksums.read_text().splitlines():
                        expected, name = row.split(maxsplit=1)
                        if name in candidates and hashlib.md5(data).hexdigest() == expected:
                            owner = package
    if owner is None:
        raise ValueError('installed package checksum not verified: ' + str(path))
    return data, {'path': str(path), 'package': owner, 'sha256': hashlib.sha256(data).hexdigest()}


def build(assets):
    assets = private_path(assets)
    lock = json.loads((HERE / 'image-lock.json').read_text())
    iso = assets / 'base.iso'
    if hashlib.sha256(iso.read_bytes()).hexdigest() != lock['sha256']:
        raise ValueError('base ISO digest mismatch')
    verification = json.loads((assets / 'image-verification.json').read_text())
    if verification['iso_sha256'] != lock['sha256'] or verification['gpg_fingerprint'] != lock['signing_fingerprint'] or verification['gpg_exit'] != 0:
        raise ValueError('base signature qualification missing')
    # Reverify, do not treat a hand-written verification record as authority.
    r = subprocess.run(['gpg', '--homedir', str(assets / 'gpg'), '--batch', '--status-fd', '1',
                        '--verify', str(assets / 'base.iso.asc'), str(iso)], capture_output=True, text=True)
    if r.returncode or not any(line.startswith('[GNUPG:] VALIDSIG ' + lock['signing_fingerprint'] + ' ') for line in r.stdout.splitlines()):
        raise ValueError('base signature re-verification failed')
    for member, dest in [('boot/vmlinuz-virt', 'kernel'), ('boot/initramfs-virt', 'base-initrd')]:
        data = subprocess.check_output(['7z', 'e', '-so', str(iso), member])
        if not data:
            raise ValueError('missing signed image member')
        (assets / dest).write_bytes(data)
    entries, records = {}, []
    for name in TOOLS:
        path = shutil.which(name)
        if not path:
            raise ValueError('missing installed guest tool: ' + name)
        data, record = verified_system_file(path)
        entries['usr/bin/' + name] = (data, 0o755)
        records.append(record)
        r = subprocess.run(['ldd', path], capture_output=True, text=True, env={'PATH': '/usr/bin:/bin'})
        for library in set(re.findall(r'(/[A-Za-z0-9_./+-]+)', r.stdout)):
            if Path(library).is_file():
                libdata, librecord = verified_system_file(library)
                # The signed Alpine image uses /lib -> /usr/lib.
                destination = library.lstrip('/')
                if destination.startswith('lib/'):
                    destination = 'usr/' + destination
                entries[destination] = (libdata, 0o755)
                records.append(librecord)
    for label, value in [('success', 16), ('failure', 17)]:
        dest = assets / ('exit-' + label)
        subprocess.run(['cc', '-nostdlib', '-static', '-s', '-fno-stack-protector',
                        '-DEXIT_VALUE=' + str(value), '-o', str(dest), str(HERE / 'exit.c')], check=True)
        entries['usr/bin/exit-' + label] = (dest.read_bytes(), 0o755)
    guest_init = (HERE / 'guest-init.sh').read_bytes()
    entries['init'] = (guest_init, 0o755)
    initrd = (assets / 'base-initrd').read_bytes() + gzip.compress(cpio(entries), compresslevel=1, mtime=0)
    (assets / 'synthetic-initrd').write_bytes(initrd)
    manifest = {'base_sha256': lock['sha256'], 'kernel_sha256': hashlib.sha256((assets / 'kernel').read_bytes()).hexdigest(),
                'initrd_sha256': hashlib.sha256(initrd).hexdigest(), 'system_tools': records,
                'guest_init_sha256': hashlib.sha256(guest_init).hexdigest(),
                'builder_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (assets / 'derived-image.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('assets', type=Path)
    arguments = parser.parse_args()
    result = build(arguments.assets)
    print(json.dumps({k: v for k, v in result.items() if k != 'system_tools'}, indent=2))
