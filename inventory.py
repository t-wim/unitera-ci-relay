"""Offline inventory contract exercised only with an invented minimal fixture."""
import hashlib
import itertools
import json
import re
from pathlib import Path
import yaml

FIXTURES = Path(__file__).resolve().parent / 'fixtures'


def checked_fixture(root=FIXTURES):
    root = root.resolve()
    manifest = json.loads((root / 'manifest.json').read_text())
    if manifest.get('fixture_class') != 'SYNTHETIC_ONLY':
        raise ValueError('fixture classification missing')
    records = manifest['files']
    paths = [item['path'] for item in records]
    if len(paths) != len(set(paths)):
        raise ValueError('duplicate fixture path')
    for name in paths:
        path = root / name
        if Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError('fixture path escape or symlink')
    actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and p != root / 'manifest.json'}
    if actual != set(paths):
        raise ValueError('fixture file set drift')
    fixtures = []
    for item in records:
        data = (root / item['path']).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if hashlib.sha256(data).hexdigest() != item['sha256'] or blob != item['git_blob_sha']:
            raise ValueError('fixture digest mismatch')
        fixtures.append(yaml.load(data, Loader=yaml.BaseLoader))
    return fixtures


def variants(job):
    matrix = job.get('strategy', {}).get('matrix')
    if matrix is None:
        return [{}]
    if not isinstance(matrix, dict):
        raise ValueError('dynamic matrix requires an explicit mapping')
    axes = {k: v for k, v in matrix.items() if k not in {'include', 'exclude'}}
    if any(not isinstance(v, list) for v in axes.values()):
        raise ValueError('dynamic matrix axis')
    rows = [dict(zip(axes, values)) for values in itertools.product(*axes.values())] if axes else []
    rows = [row for row in rows if not any(all(row.get(k) == v for k, v in x.items()) for x in matrix.get('exclude', []))]
    originals = [dict(row) for row in rows]
    for extra in matrix.get('include', []):
        matched = False
        for row, original in zip(rows, originals):
            if all(k not in original or original[k] == v for k, v in extra.items()):
                row.update(extra)
                matched = True
        if not matched:
            rows.append(dict(extra))
    if not rows:
        raise ValueError('empty matrix')
    return rows


def render(value, matrix):
    if isinstance(value, str):
        return re.sub(r'\$\{\{\s*matrix\.([A-Za-z0-9_]+)\s*\}\}', lambda m: str(matrix.get(m[1], m[0])), value)
    if isinstance(value, list):
        return [render(item, matrix) for item in value]
    if isinstance(value, dict):
        return {key: render(item, matrix) for key, item in value.items()}
    return value


def inventory(root=FIXTURES):
    rows = []
    for workflow in checked_fixture(root):
        for job_id, job in workflow.get('jobs', {}).items():
            for matrix in variants(job):
                rows.append({'job_id': job_id, 'matrix': matrix, 'trigger': workflow.get('on'),
                             'workflow_environment': workflow.get('env', {}), 'job': render(job, matrix),
                             'execution_evidence': []})
    return {'fixture_class': 'SYNTHETIC_ONLY', 'qualifies_real_ci': False, 'gates': rows}


if __name__ == '__main__':
    print(json.dumps(inventory(), indent=2))
