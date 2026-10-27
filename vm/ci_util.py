"""Pure helpers for the source-CI executor. No subprocess, no shell, no dynamic code execution."""
import base64
import hashlib
import ipaddress
import json
import socket
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_FILE_COUNT = 20000
MAX_DOWNLOAD_BYTES = 96 * 1024 * 1024
DOWNLOAD_TIMEOUT_S = 120
ALLOWED_DOWNLOAD_HOSTS = {'nodejs.org', 'registry.npmjs.org', 'dl-cdn.alpinelinux.org', 'alpinelinux.org'}
NAME_PATTERN = r'[a-z0-9][a-z0-9_-]*'
PLAN_COMMAND_PATTERN = r'[A-Za-z0-9_./=:,* -]+'


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('redirect during pinned download rejected: ' + str(code))


def guarded_urlopen(url):
    if not url.startswith('https://'):
        raise ValueError('non-https download rejected: ' + url)
    host = urllib.parse.urlparse(url).hostname
    if host not in ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError('download host not allowlisted: ' + str(host))
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(host, 443, family)
        except socket.gaierror:
            continue
        for info in infos:
            address = ipaddress.ip_address(info[4][0])
            if not address.is_global:
                raise ValueError('download host resolves to non-global address: ' + str(address))
    return urllib.request.build_opener(_NoRedirect).open(url, timeout=DOWNLOAD_TIMEOUT_S)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_download(lock_entry, destination):
    """Fetch a pinned vendor artifact; digest is verified before the file becomes visible."""
    if destination.exists():
        return
    partial = destination.with_suffix(destination.suffix + '.part')
    if partial.exists():
        raise ValueError('existing partial download requires explicit reconciliation: ' + str(partial))
    sha512_mode = str(lock_entry.get('tar_sha512', '')).startswith('sha512-')
    digest = hashlib.sha512() if sha512_mode else hashlib.sha256()
    size = 0
    with guarded_urlopen(lock_entry['url']) as response, partial.open('xb') as target:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_DOWNLOAD_BYTES:
                raise RuntimeError('download budget exceeded for ' + lock_entry['url'])
            digest.update(chunk)
            target.write(chunk)
    if sha512_mode:
        expected = base64.b64decode(lock_entry['tar_sha512'].split('-', 1)[1])
        if digest.digest() != expected:
            raise ValueError('sha512 mismatch for ' + destination.name)
    elif digest.hexdigest() != lock_entry['tar_sha256']:
        raise ValueError('sha256 mismatch for ' + destination.name)
    partial.replace(destination)


def validate_tar_members(tar, expected_members=None):
    """Reject absolute paths, traversal, symlinks, hardlinks and special members."""
    seen = 0
    names = set()
    for member in tar:
        name = member.name
        if name.startswith('/') or name == '' or '..' in Path(name).parts:
            raise ValueError('unsafe archive member: ' + name)
        if member.issym() or member.islnk():
            raise ValueError('symlink/hardlink in artifact rejected: ' + name)
        if not (member.isfile() or member.isdir()):
            raise ValueError('non-regular archive member rejected: ' + name)
        seen += 1
        if seen > (expected_members or MAX_FILE_COUNT):
            raise ValueError('archive member count exceeds budget')
        names.add(name)
    return names


def safe_extract(tar_path, destination):
    with tarfile.open(tar_path, 'r:*') as tar:
        validate_tar_members(tar)
        tar.extractall(destination, filter='data')


def extract_member(tar_path, member_name):
    with tarfile.open(tar_path, 'r:*') as tar:
        member = tar.getmember(member_name)
        if not member.isfile():
            raise ValueError('member is not a regular file: ' + member_name)
        return tar.extractfile(member).read()


def inventory_from_tar(tar_path):
    with tarfile.open(tar_path, 'r:*') as tar:
        inventory = {}
        for member in tar:
            if member.isfile():
                inventory[member.name] = [hashlib.sha256(tar.extractfile(member).read()).hexdigest(), member.size]
        return inventory


def write_args_file(path, argv):
    """Serialize an exact argv for the mechanical shell launcher; every arg must be newline-free."""
    lines = []
    for argument in argv:
        if not isinstance(argument, str) or argument == '' or '\n' in argument or '\r' in argument or '\0' in argument:
            raise ValueError('launcher argument rejected: ' + repr(argument))
        lines.append(argument)
    path.write_text('\n'.join(lines) + '\n')


def read_args_file(path):
    lines = path.read_text().splitlines()
    if not lines:
        raise ValueError('empty launcher argument file: ' + str(path))
    return lines


def parse_ls_tree(text):
    """Parse `git ls-tree -r -z <sha>` output; every object must be a regular file or dir."""
    entries = {}
    for record in text.split('\0'):
        if not record:
            continue
        meta, name = record.split('\t', 1)
        mode, kind, sha = meta.split()
        if kind == 'tree':
            continue
        if mode == '120000':
            raise ValueError('committed symlink rejected: ' + name)
        if mode not in ('100644', '100755'):
            raise ValueError('non-regular committed object rejected: ' + name)
        if len(sha) != 40:
            raise ValueError('bad object hash in ls-tree')
        entries[name] = [sha, mode]
    return entries


def load_json(path):
    return json.loads(Path(path).read_text())


def store_manifest_digest(store_dir):
    files = sorted(p for p in Path(store_dir).rglob('*') if p.is_file())
    lines = [sha256_file(p) + '  ' + str(p.relative_to(store_dir)) for p in files]
    manifest = '\n'.join(lines) + '\n'
    return {'file_count': len(files), 'bytes': sum(p.stat().st_size for p in files),
            'manifest_sha256': hashlib.sha256(manifest.encode()).hexdigest(), 'manifest': manifest}


def elf_needed_sonames(data):
    """Extract DT_NEEDED shared-object names from a 64-bit little-endian ELF without executing it."""
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return []
    if data[4] != 2 or data[5] != 1:  # not ELF64 little-endian
        return []
    import struct
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    loads = []
    dynamic = None
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        if offset + 56 > len(data):
            return []
        p_type, p_flags, p_offset, p_vaddr = struct.unpack_from('<IIQQ', data, offset)
        if p_type == 1:
            loads.append((p_vaddr, p_offset))
        elif p_type == 2:
            dynamic = (p_vaddr, p_offset)
    if dynamic is None:
        return []

    def vaddr_to_offset(vaddr):
        for base_vaddr, base_offset in loads:
            if base_vaddr <= vaddr:
                return base_offset + (vaddr - base_vaddr)
        return None
    needed = []
    strtab = None
    cursor = dynamic[1]
    while cursor + 16 <= len(data):
        d_tag, d_val = struct.unpack_from('<QQ', data, cursor)
        cursor += 16
        if d_tag == 0:
            break
        if d_tag == 1:
            needed.append(d_val)
        elif d_tag == 5:
            strtab = d_val
    if strtab is None:
        return []
    strtab_offset = vaddr_to_offset(strtab)
    if strtab_offset is None:
        return []
    names = []
    for d_val in needed:
        start = strtab_offset + d_val
        end = data.find(b'\0', start)
        if end > start:
            try:
                names.append(data[start:end].decode('ascii'))
            except UnicodeDecodeError:
                continue
    return names


HOST_LIBRARY_DIRS = ['/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu', '/lib64', '/usr/lib']


def resolve_host_soname(soname):
    for directory in HOST_LIBRARY_DIRS:
        candidate = Path(directory) / soname
        if candidate.exists():
            return candidate
    return None


def native_lib_records(store_dir, verified):
    """Every shared object any stored package may dlopen, resolved to dpkg-verified host files."""
    sonames = set()
    for path in Path(store_dir).rglob('*'):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with open(path, 'rb') as handle:
                head = handle.read(64)
                if head[:4] != b'\x7fELF':
                    continue
                handle.seek(0)
                data = handle.read()
        except OSError:
            continue
        sonames.update(elf_needed_sonames(data))
    records = []
    unresolved = []
    for soname in sorted(sonames):
        if soname.startswith('ld-linux') or 'musl' in soname:
            # musl-targeted optional binaries (e.g. rollup-linux-x64-musl) never load on glibc.
            continue
        candidate = resolve_host_soname(soname)
        if candidate is None:
            unresolved.append(soname)
            continue
        _data, record = verified(candidate)
        records.append(record)
    return {'records': records, 'unresolved': unresolved}


def validate_check_name(name):
    import re
    if not re.fullmatch(NAME_PATTERN, name or ''):
        raise ValueError('check name rejected: ' + repr(name))


def validate_plan(plan):
    """A plan is trusted controller data; enforce its shape and per-argument charset strictly."""
    import re
    seen = set()
    for entry in plan:
        validate_check_name(entry.get('name'))
        if entry['name'] in seen:
            raise ValueError('duplicate plan entry: ' + entry['name'])
        seen.add(entry['name'])
        if not isinstance(entry.get('timeout_s'), int) or not 1 <= entry['timeout_s'] <= 7200:
            raise ValueError('plan timeout out of range: ' + entry['name'])
        argv = entry.get('argv')
        if not isinstance(argv, list) or not argv:
            raise ValueError('plan argv must be a non-empty list: ' + entry['name'])
        for argument in argv:
            if not isinstance(argument, str) or argument == '':
                raise ValueError('plan argv field must be a non-empty string: ' + entry['name'])
            for forbidden in ('\n', '\r', '\0', '\x1f', '|'):
                if forbidden in argument:
                    raise ValueError('plan argv field contains a separator: ' + entry['name'])
            if not re.fullmatch(PLAN_COMMAND_PATTERN, argument):
                raise ValueError('plan argv charset rejected: ' + entry['name'] + ' ' + repr(argument))
        if entry.get('cwd') not in (None, '/ws/src', '/ws/work'):
            raise ValueError('plan cwd rejected: ' + entry['name'])
    return True
