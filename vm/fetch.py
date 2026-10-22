"""Fetch only the public pinned VM image into private workspace assets."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import time
import urllib.request

from paths import private_path


def download(url, destination, maximum):
    if destination.exists():
        return
    partial = destination.with_suffix(destination.suffix + '.part')
    if partial.exists():
        raise ValueError('existing partial download requires explicit reconciliation')
    started, size = time.monotonic(), 0
    with urllib.request.urlopen(url, timeout=30) as response, partial.open('xb') as target:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > maximum or time.monotonic() - started > 300:
                raise RuntimeError('public image download budget exceeded')
            target.write(chunk)
    partial.replace(destination)


def fetch(directory):
    directory = private_path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = json.loads((Path(__file__).parent / 'image-lock.json').read_text())
    if not lock['image_url'].startswith('https://dl-cdn.alpinelinux.org/alpine/') or lock['signing_key_url'] != 'https://alpinelinux.org/keys/ncopa.asc':
        raise ValueError('unexpected public image publisher')
    for url, name, maximum in [(lock['image_url'], 'base.iso', 128 * 1024 ** 2),
                               (lock['image_url'] + '.sha256', 'base.iso.sha256', 2048),
                               (lock['image_url'] + '.asc', 'base.iso.asc', 16384),
                               (lock['signing_key_url'], 'image-signing-key.asc', 65536)]:
        download(url, directory / name, maximum)
    digest = hashlib.sha256((directory / 'base.iso').read_bytes()).hexdigest()
    if digest != lock['sha256'] or (directory / 'base.iso.sha256').read_text().split()[0] != digest:
        raise ValueError('image digest mismatch')
    keyhome = private_path(directory / 'gpg')
    keyhome.mkdir(mode=0o700, exist_ok=True)
    private_keys = keyhome / 'private-keys-v1.d'
    if private_keys.exists() and any(private_keys.iterdir()):
        raise ValueError('image verification must not use an existing private key store')
    prefix = ['gpg', '--homedir', str(keyhome), '--batch', '--no-auto-key-retrieve']
    subprocess.run(prefix + ['--import', str(directory / 'image-signing-key.asc')], capture_output=True, check=True)
    result = subprocess.run(prefix + ['--status-fd', '1', '--verify', str(directory / 'base.iso.asc'), str(directory / 'base.iso')],
                            capture_output=True, text=True)
    valid = any(line.startswith('[GNUPG:] VALIDSIG ' + lock['signing_fingerprint'] + ' ') for line in result.stdout.splitlines())
    if result.returncode or not valid:
        raise ValueError('pinned publisher signature invalid')
    record = {'verified_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'iso_url': lock['image_url'],
              'iso_sha256': digest, 'gpg_fingerprint': lock['signing_fingerprint'], 'gpg_exit': result.returncode}
    (directory / 'image-verification.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('assets', type=Path)
    args = parser.parse_args()
    print(json.dumps(fetch(args.assets), indent=2))
