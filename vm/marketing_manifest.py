"""Evidence manifest schema and assembly for marketing Python VM runs. Pure data handling.

Mirrors ci_manifest but binds the marketing repository, the pinned marketing source
commit, its custody inventory and the verified Python runtime. Schema constants are
shared with the independent verifier; acceptance logic is NOT shared."""
import datetime
import json
import re
from pathlib import Path

from ci_util import sha256_file, validate_check_name

SCHEMA = 'relay.marketing-run-manifest.v1'
RESULT_VALUES = {'PASS', 'FAIL', 'BLOCKED', 'SKIPPED'}
REPOSITORY = 'baum777/unitera_marketing_agent-team'
EXECUTION_PROFILE = 'marketing-python-vm-v1'
TOP_LEVEL_KEYS = {'schema', 'run_id', 'repository', 'source_commit_sha', 'source_artifact_digest',
                  'source_inventory_digest', 'relay_commit_sha', 'executor_version',
                  'vm_image_digest', 'python_runtime_sha256', 'python_version',
                  'test_plan', 'toolchain_versions', 'execution_profile_name', 'profile',
                  'started_at', 'finished_at', 'checks', 'overall_result', 'cleanup_result',
                  'isolation_result', 'evidence'}
CHECK_KEYS = {'check_name', 'command_identifier', 'exit_code', 'timeout', 'result', 'log_digest'}
SHA_RE = re.compile(r'[0-9a-f]{40}|[0-9a-f]{64}')
PLAN_NAME = re.compile(r'production|q[23]_[a-z_]+')


def validate_manifest(manifest):
    """Strict structural validation; raises ValueError with the exact defect."""
    if not isinstance(manifest, dict):
        raise ValueError('manifest must be an object')
    keys = set(manifest)
    missing = TOP_LEVEL_KEYS - keys
    if missing:
        raise ValueError('manifest missing keys: ' + ','.join(sorted(missing)))
    extra = keys - TOP_LEVEL_KEYS
    if extra:
        raise ValueError('manifest has unknown keys: ' + ','.join(sorted(extra)))
    if manifest['schema'] != SCHEMA:
        raise ValueError('schema mismatch: ' + str(manifest['schema']))
    if not isinstance(manifest['run_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', manifest['run_id']):
        raise ValueError('run_id must be a 32-hex string')
    if manifest['repository'] != REPOSITORY:
        raise ValueError('repository mismatch: ' + str(manifest['repository']))
    if manifest['execution_profile_name'] != EXECUTION_PROFILE:
        raise ValueError('execution profile mismatch: ' + str(manifest['execution_profile_name']))
    if not PLAN_NAME.fullmatch(manifest['test_plan']):
        raise ValueError('test plan name rejected: ' + str(manifest['test_plan']))
    for field in ('source_commit_sha', 'relay_commit_sha'):
        if not re.fullmatch(r'[0-9a-f]{40}', manifest[field]):
            raise ValueError(field + ' must be a 40-hex sha')
    for field in ('source_artifact_digest', 'source_inventory_digest', 'vm_image_digest',
                  'python_runtime_sha256'):
        if not re.fullmatch(r'[0-9a-f]{64}', manifest[field]):
            raise ValueError(field + ' must be a 64-hex digest')
    if not isinstance(manifest['executor_version'], dict):
        raise ValueError('executor_version must be an object')
    if not isinstance(manifest['toolchain_versions'], dict):
        raise ValueError('toolchain_versions must be an object')
    if not isinstance(manifest['python_version'], str) or not manifest['python_version']:
        raise ValueError('python_version required')
    if not isinstance(manifest['profile'], dict) or 'guest_mib' not in manifest['profile']:
        raise ValueError('profile missing resource fields')
    for field in ('started_at', 'finished_at'):
        datetime.datetime.fromisoformat(manifest[field])
    checks = manifest['checks']
    if not isinstance(checks, list) or not checks:
        raise ValueError('checks must be a non-empty list')
    seen = set()
    for check in checks:
        if not isinstance(check, dict) or set(check) != CHECK_KEYS:
            raise ValueError('check entry has wrong keys')
        validate_check_name(check['check_name'])
        if check['check_name'] in seen:
            raise ValueError('duplicate check: ' + check['check_name'])
        seen.add(check['check_name'])
        if not isinstance(check['command_identifier'], str) or not check['command_identifier']:
            raise ValueError('command_identifier required for ' + check['check_name'])
        if not isinstance(check['exit_code'], int) or not -128 <= check['exit_code'] <= 255:
            raise ValueError('exit_code out of range for ' + check['check_name'])
        if check['timeout'] not in (0, 1):
            raise ValueError('timeout must be 0/1 for ' + check['check_name'])
        if check['result'] not in RESULT_VALUES:
            raise ValueError('result not in enum for ' + check['check_name'])
        if check['result'] == 'PASS' and (check['exit_code'] != 0 or check['timeout'] != 0):
            raise ValueError('PASS check with failing exit/timeout: ' + check['check_name'])
        if check['result'] == 'FAIL' and check['exit_code'] == 0 and check['timeout'] == 0:
            raise ValueError('FAIL check with exit code 0 and no timeout: ' + check['check_name'])
        if not re.fullmatch(r'[0-9a-f]{64}|guest-native', check['log_digest']):
            raise ValueError('log_digest must be sha256 hex or guest-native')
    if manifest['overall_result'] not in RESULT_VALUES:
        raise ValueError('overall_result not in enum')
    if manifest['cleanup_result'] not in ('PASS', 'FAIL'):
        raise ValueError('cleanup_result must be PASS/FAIL')
    if manifest['isolation_result'] not in ('PASS', 'FAIL'):
        raise ValueError('isolation_result must be PASS/FAIL')
    evidence = manifest['evidence']
    if not isinstance(evidence, dict):
        raise ValueError('evidence must be an object')
    for name, digest in evidence.items():
        if not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('evidence digest invalid for ' + name)
    return True


def build_manifest(run):
    """Assemble the manifest from monitor-observed state; never from guest self-assessment."""
    checks = []
    for record in run['check_records']:
        checks.append({'check_name': record['name'],
                       'command_identifier': record['command'],
                       'exit_code': record['exit_code'],
                       'timeout': record['timeout'],
                       'result': record['result'],
                       'log_digest': record.get('log_digest', 'guest-native')})
    manifest = {'schema': SCHEMA, 'run_id': run['run_id'], 'repository': REPOSITORY,
                'source_commit_sha': run['source_commit_sha'],
                'source_artifact_digest': run['source_artifact_digest'],
                'source_inventory_digest': run['source_inventory_digest'],
                'relay_commit_sha': run['relay_commit_sha'],
                'executor_version': run['executor_version'],
                'vm_image_digest': run['vm_image_digest'],
                'python_runtime_sha256': run['python_runtime_sha256'],
                'python_version': run['python_version'],
                'test_plan': run['plan_name'],
                'toolchain_versions': run['toolchain_versions'],
                'execution_profile_name': EXECUTION_PROFILE,
                'profile': run['profile'],
                'started_at': run['started_at'], 'finished_at': run['finished_at'],
                'checks': checks, 'overall_result': run['overall_result'],
                'cleanup_result': run['cleanup_result'], 'isolation_result': run['isolation_result'],
                'evidence': run['evidence']}
    validate_manifest(manifest)
    return manifest
