"""Host-side regression battery for the source-CI executor. Pure unit tests, no execution."""
import hashlib
import json
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vm'))

import ci_manifest
import ci_monitor
import ci_plan
import ci_prep
import ci_util
import ci_verify

GUEST = (ROOT / 'vm' / 'ci_guest.sh').read_text()
START = (ROOT / 'vm' / 'ci_start.sh').read_text()


class TarValidationTests(unittest.TestCase):
    def _tar(self, name, data=b'x', kind='file', symlink=None):
        import io
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tar:
            if kind == 'file':
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            elif kind == 'symlink':
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = symlink
                tar.addfile(info)
            elif kind == 'fifo':
                info = tarfile.TarInfo(name)
                info.type = tarfile.FIFOTYPE
                tar.addfile(info)
        return buffer.getvalue()

    def _open(self, payload):
        import io
        return tarfile.open(fileobj=io.BytesIO(payload), mode='r:')

    def test_absolute_path_rejected(self):
        with self.assertRaises(ValueError):
            ci_util.validate_tar_members(self._open(self._tar('/etc/passwd')))

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError):
            ci_util.validate_tar_members(self._open(self._tar('../escape')))

    def test_symlink_rejected(self):
        with self.assertRaises(ValueError):
            ci_util.validate_tar_members(self._open(self._tar('lnk', kind='symlink', symlink='/etc')))

    def test_special_member_rejected(self):
        with self.assertRaises(ValueError):
            ci_util.validate_tar_members(self._open(self._tar('pipe', kind='fifo')))

    def test_count_budget_enforced(self):
        import io
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tar:
            for name in ('a', 'b'):
                info = tarfile.TarInfo(name)
                info.size = 1
                tar.addfile(info, io.BytesIO(b'x'))
        with tarfile.open(fileobj=io.BytesIO(buffer.getvalue()), mode='r:') as tar:
            with self.assertRaises(ValueError):
                ci_util.validate_tar_members(tar, expected_members=1)


class LsTreeTests(unittest.TestCase):
    def test_symlink_mode_rejected(self):
        with self.assertRaises(ValueError):
            ci_util.parse_ls_tree('120000 blob 0123456789012345678901234567890123456789\tlink')

    def test_bad_mode_rejected(self):
        with self.assertRaises(ValueError):
            ci_util.parse_ls_tree('160000 commit 0123456789012345678901234567890123456789\tsub')

    def test_bad_sha_rejected(self):
        with self.assertRaises(ValueError):
            ci_util.parse_ls_tree('100644 blob short\tf')

    def test_trees_skipped_and_files_kept(self):
        text = ('040000 tree 1111111111111111111111111111111111111111\tdir\0'
                '100644 blob 2222222222222222222222222222222222222222\tfile\0')
        self.assertEqual(ci_util.parse_ls_tree(text),
                         {'file': ['2222222222222222222222222222222222222222', '100644']})


class GitBlobTests(unittest.TestCase):
    def test_known_blob_ids(self):
        self.assertEqual(ci_prep.git_blob_sha(b''), 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391')
        self.assertEqual(ci_prep.git_blob_sha(b'test content\n'),
                         'd670460b4b4aece5915caf5c68d12f560a9fe3e4')


class ArgsFileTests(unittest.TestCase):
    def test_newline_argument_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                ci_util.write_args_file(Path(tmp) / 'a', ['ok', 'bad\narg'])

    def test_empty_argument_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                ci_util.write_args_file(Path(tmp) / 'a', ['ok', ''])

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'a'
            ci_util.write_args_file(path, ['systemd-run', '--user', '/x y/z'])
            self.assertEqual(ci_util.read_args_file(path), ['systemd-run', '--user', '/x y/z'])


class PlanTests(unittest.TestCase):
    def test_production_check_set_is_exact(self):
        self.assertEqual(ci_plan.expected_check_set('production'), {
            'c1_source_integrity', 'c2_toolchain_validation', 'c3_frozen_install',
            'c4_build_packages', 'c5_api_typecheck', 'c6_lint_ts', 'c7_api_unit_baseline',
            'c8_governance_check'})

    def test_fixture_plans_are_marked(self):
        for name, plan in ci_plan.FIXTURE_PLANS.items():
            for entry in plan:
                self.assertTrue(entry['name'].startswith('fixture_'), entry['name'])

    def test_bad_name_rejected(self):
        with self.assertRaises(ValueError):
            ci_util.validate_plan([{'name': 'EVIL;rm', 'timeout_s': 10, 'cwd': '/ws/src',
                                    'argv': ['node']}])

    def test_duplicate_rejected(self):
        entry = {'name': 'x', 'timeout_s': 10, 'cwd': '/ws/src', 'argv': ['node']}
        with self.assertRaises(ValueError):
            ci_util.validate_plan([entry, dict(entry)])

    def test_timeout_range(self):
        for bad in (0, 7201, '10'):
            with self.assertRaises(ValueError):
                ci_util.validate_plan([{'name': 'x', 'timeout_s': bad, 'cwd': '/ws/src',
                                        'argv': ['node']}])

    def test_argv_charset_rejected(self):
        for bad in ['node;rm', 'node $(x)', 'node `x`', 'node | x', 'node & x', 'node > x',
                    "node 'x'", 'node "x"', 'node\nx']:
            with self.assertRaises(ValueError):
                ci_util.validate_plan([{'name': 'x', 'timeout_s': 10, 'cwd': '/ws/src',
                                        'argv': [bad]}])

    def test_argv_separator_characters_rejected(self):
        for bad in ['a\x1fb', 'a|b', 'a\nb']:
            with self.assertRaises(ValueError):
                ci_util.validate_plan([{'name': 'x', 'timeout_s': 10, 'cwd': '/ws/src',
                                        'argv': [bad]}])

    def test_cwd_restricted(self):
        with self.assertRaises(ValueError):
            ci_util.validate_plan([{'name': 'x', 'timeout_s': 10, 'cwd': '/', 'argv': ['node']}])

    def test_serialized_plan_uses_separators_not_shell(self):
        text = ci_plan.serialize_plan(ci_plan.PRODUCTION_PLAN)
        self.assertIn('|', text)
        self.assertIn('\x1f', text)
        self.assertNotIn(' sh -c ', text)


class ManifestTests(unittest.TestCase):
    def base(self):
        return {'schema': ci_manifest.SCHEMA, 'run_id': 'a' * 32,
                'repository': 'baum777/Unitera_Systems',
                'source_commit_sha': 'b' * 40, 'source_artifact_digest': 'c' * 64,
                'relay_commit_sha': 'd' * 40, 'executor_version': {},
                'vm_image_digest': 'e' * 64, 'toolchain_versions': {'node': '24.19.0'},
                'dependency_lock_digest': 'f' * 64,
                'execution_profile': {'plan': 'production', 'guest_mib': 2560, 'smp': 2,
                                      'scope_memory_max': '3456M', 'cpu_quota_percent': 200,
                                      'tasks_max': 512, 'deadline_s': 900,
                                      'console_budget_bytes': 1},
                'started_at': '2026-10-26T20:00:00+00:00',
                'finished_at': '2026-10-26T20:05:00+00:00',
                'checks': [{'check_name': 'c1_source_integrity', 'command_identifier': 'guest-native',
                            'exit_code': 0, 'timeout': 0, 'result': 'PASS', 'log_digest': 'guest-native'}],
                'overall_result': 'PASS', 'cleanup_result': 'PASS', 'isolation_result': 'PASS',
                'evidence': {'result.json': '0' * 64}}

    def test_valid_manifest_accepted(self):
        self.assertTrue(ci_manifest.validate_manifest(self.base()))

    def test_missing_key_rejected(self):
        manifest = self.base()
        del manifest['run_id']
        with self.assertRaises(ValueError):
            ci_manifest.validate_manifest(manifest)

    def test_unknown_key_rejected(self):
        manifest = self.base()
        manifest['approval'] = 'granted'
        with self.assertRaises(ValueError):
            ci_manifest.validate_manifest(manifest)

    def test_bad_run_id_rejected(self):
        manifest = self.base()
        manifest['run_id'] = 'z' * 32
        with self.assertRaises(ValueError):
            ci_manifest.validate_manifest(manifest)

    def test_pass_with_failing_exit_rejected(self):
        manifest = self.base()
        manifest['checks'][0]['exit_code'] = 1
        with self.assertRaises(ValueError):
            ci_manifest.validate_manifest(manifest)

    def test_fail_with_success_exit_rejected(self):
        manifest = self.base()
        manifest['checks'][0]['result'] = 'FAIL'
        with self.assertRaises(ValueError):
            ci_manifest.validate_manifest(manifest)

    def test_duplicate_check_rejected(self):
        manifest = self.base()
        manifest['checks'].append(dict(manifest['checks'][0]))
        with self.assertRaises(ValueError):
            ci_manifest.validate_manifest(manifest)

    def test_bad_enum_rejected(self):
        manifest = self.base()
        manifest['overall_result'] = 'APPROVED'
        with self.assertRaises(ValueError):
            ci_manifest.validate_manifest(manifest)


class ProtocolTests(unittest.TestCase):
    def state(self):
        return {'expected': {'a', 'b', 'c1_source_integrity'}, 'check_lines': {}, 'exit_codes': {},
                'timeouts': {}, 'log_digests': {}, 'protocol_errors': [], 'markers': [],
                'ready_at': None, 'log_tail': '', 'noise_lines': 0}

    def test_check_and_exit(self):
        state = self.state()
        ci_monitor.parse_protocol_line('CHECK a PASS', state)
        ci_monitor.parse_protocol_line('EXIT a 0', state)
        ci_monitor.parse_protocol_line('TMO a 0', state)
        ci_monitor.parse_protocol_line('SRC_READY', state)
        self.assertEqual(state['check_lines'], {'a': 'PASS'})
        self.assertEqual(state['exit_codes'], {'a': 0})
        self.assertIsNotNone(state['ready_at'])

    def test_duplicate_check_poisons(self):
        state = self.state()
        ci_monitor.parse_protocol_line('CHECK a PASS', state)
        ci_monitor.parse_protocol_line('CHECK a PASS', state)
        self.assertTrue(state['protocol_errors'])

    def test_unexpected_name_poisons(self):
        state = self.state()
        ci_monitor.parse_protocol_line('CHECK evil PASS', state)
        self.assertTrue(state['protocol_errors'])

    def test_bad_exit_poisons(self):
        state = self.state()
        ci_monitor.parse_protocol_line('EXIT a zero', state)
        self.assertTrue(state['protocol_errors'])

    def test_bad_digest_poisons(self):
        state = self.state()
        ci_monitor.parse_protocol_line('LOGDIGEST a nothex', state)
        self.assertTrue(state['protocol_errors'])


class ArgvTests(unittest.TestCase):
    def test_qemu_argv_is_fixed_structure(self):
        profile = dict(ci_monitor.PROFILE)
        argv = ci_monitor.build_argv('/k', '/base.img', '/job', 'unitera-source-ci-x.scope', profile)
        self.assertEqual(argv[0], 'systemd-run')
        joined = ' '.join(argv)
        self.assertIn('restrict=on,ipv6=off', joined)
        self.assertIn('-sandbox', joined)
        self.assertIn('--clearenv', joined)
        self.assertIn('--ro-bind /base.img /base.img', joined)
        self.assertIn('--bind /job /job', joined)
        self.assertNotIn('--rw-bind', joined)
        self.assertNotIn('9p', joined)
        self.assertNotIn('virtiofs', joined)


class GuestStaticTests(unittest.TestCase):
    def test_guest_never_evaluates_shell_strings(self):
        self.assertNotIn('sh -c "$cmd"', GUEST)
        self.assertNotIn('eval ', GUEST)
        self.assertIn('timeout "$tmo" "$@"', GUEST)

    def test_guest_has_no_host_shares_or_forwarding(self):
        self.assertNotIn('hostfwd', GUEST)
        self.assertNotIn('-virtfs', GUEST)
        self.assertNotIn('mount -t 9p', GUEST)
        self.assertNotIn('mount -t nfs', GUEST)
        self.assertNotIn('ssh ', GUEST)

    def test_guest_isolation_checks_present(self):
        for name in ci_monitor.ISOLATION_CHECKS:
            self.assertIn(name, GUEST)

    def test_guest_two_stage_boot(self):
        self.assertIn('stage2', GUEST)
        self.assertIn('switch_root', GUEST)

    def test_launcher_is_mechanical(self):
        self.assertIn('set -eu', START)
        for allowed in ['qemu-img', 'git', 'date', 'exec "$@"', 'argv.args']:
            self.assertIn(allowed, START)
        self.assertNotIn('curl', START)
        self.assertNotIn('sudo', START)
        self.assertNotIn('eval', START)


class HelpersTests(unittest.TestCase):
    def test_lan_address_from_fixture(self):
        fixture = 'Main:\n  +-- 0.0.0.0/0\n     /32 host LOCAL\nLocal:\n  127.0.0.1/32 host LOCAL\n  192.168.1.39/32 link UP\n    /32 host LOCAL\n'
        self.assertEqual(ci_monitor.local_lan_address(fixture), '192.168.1.39')

    def test_lan_address_rejects_loopback_only(self):
        with self.assertRaises(RuntimeError):
            ci_monitor.local_lan_address('Local:\n 127.0.0.1/32 host LOCAL\n')

    def test_budget_fail_closed_on_low_memory(self):
        profile = dict(ci_monitor.PROFILE)
        low = 'MemAvailable: %d kB\n' % (profile['mem_min_mib'] - 1)
        with self.assertRaises(RuntimeError):
            ci_monitor.budget_check(profile, meminfo_text=low, free_bytes=10 ** 15)

    def test_budget_fail_closed_on_low_disk(self):
        profile = dict(ci_monitor.PROFILE)
        fine = 'MemAvailable: %d kB\n' % (profile['mem_min_mib'] + 1024)
        with self.assertRaises(RuntimeError):
            ci_monitor.budget_check(profile, meminfo_text=fine,
                                    free_bytes=profile['disk_min_bytes'] - 1)


class AggregateTests(unittest.TestCase):
    def base_state(self):
        expected = set(ci_plan.expected_check_set('q7_resource_timeout')) | set(ci_monitor.ISOLATION_CHECKS)
        state = {'expected': expected, 'check_lines': {}, 'exit_codes': {}, 'timeouts': {},
                 'log_digests': {}, 'protocol_errors': [], 'markers': [], 'ready_at': 1.0,
                 'log_tail': '', 'noise_lines': 0}
        for name in expected:
            state['check_lines'][name] = 'PASS'
            state['exit_codes'][name] = 0
            state['timeouts'][name] = 0
        return state

    def run_dict(self):
        return {'plan_name': 'q7_resource_timeout', 'profile': dict(ci_monitor.PROFILE)}

    def test_all_pass_with_exit_33(self):
        records, isolation, cleanup, overall = ci_monitor.aggregate(
            self.run_dict(), self.base_state(), {'cleanup_verified': True}, True, True, 33)
        self.assertEqual(overall, 'PASS')
        self.assertTrue(isolation and cleanup)

    def test_broken_isolation_denies_overall(self):
        state = self.base_state()
        state['check_lines']['lan_denied'] = 'FAIL'
        records, isolation, cleanup, overall = ci_monitor.aggregate(
            self.run_dict(), state, {'cleanup_verified': True}, True, True, 33)
        self.assertEqual(overall, 'FAIL')
        self.assertFalse(isolation)

    def test_cleanup_failure_denies_overall(self):
        records, isolation, cleanup, overall = ci_monitor.aggregate(
            self.run_dict(), self.base_state(), {'cleanup_verified': False}, True, True, 33)
        self.assertEqual(overall, 'FAIL')

    def test_missing_check_denies_overall(self):
        state = self.base_state()
        del state['check_lines']['c1_source_integrity']
        records, isolation, cleanup, overall = ci_monitor.aggregate(
            self.run_dict(), state, {'cleanup_verified': True}, True, True, 33)
        self.assertEqual(overall, 'FAIL')

    def test_exit_mismatch_denies_overall(self):
        records, isolation, cleanup, overall = ci_monitor.aggregate(
            self.run_dict(), self.base_state(), {'cleanup_verified': True}, True, True, 35)
        self.assertEqual(overall, 'FAIL')

    def test_timeout_check_recorded_as_fail(self):
        state = self.base_state()
        state['check_lines']['fixture_hold_timeout'] = 'FAIL'
        state['exit_codes']['fixture_hold_timeout'] = 124
        state['timeouts']['fixture_hold_timeout'] = 1
        records, _iso, _cl, overall = ci_monitor.aggregate(
            self.run_dict(), state, {'cleanup_verified': True}, True, True, 35)
        record = next(r for r in records if r['name'] == 'fixture_hold_timeout')
        self.assertEqual((record['result'], record['exit_code'], record['timeout']),
                         ('FAIL', 124, 1))
        self.assertEqual(overall, 'FAIL')


class VerifierTests(unittest.TestCase):
    def make_run(self, tmp, overall='PASS', break_console=False, drop_check=None,
                 isolation_fail=None):
        run_dir = Path(tmp)
        (run_dir / 'evidence').mkdir(parents=True, exist_ok=True)
        expected = sorted(set(ci_plan.expected_check_set('q7_resource_timeout')) |
                          set(ci_monitor.ISOLATION_CHECKS))
        lines = []
        for name in expected:
            if name == drop_check:
                continue
            value = 'FAIL' if name == isolation_fail else 'PASS'
            lines.append('CHECK %s %s' % (name, value))
            if value == 'PASS' and not name.startswith('c1') and not name.startswith('c2') \
                    and name not in ci_monitor.ISOLATION_CHECKS:
                lines.append('EXIT %s 0' % name)
                lines.append('TMO %s 0' % name)
        lines.insert(0, 'SRC_READY')
        console = '\n'.join(lines) + '\n'
        checks = []
        for name in expected:
            result = 'FAIL' if name in (drop_check, isolation_fail) else 'PASS'
            entry = {'check_name': name, 'command_identifier': 'x', 'exit_code': 0 if result == 'PASS' else 1,
                     'timeout': 0, 'result': result, 'log_digest': 'guest-native'}
            checks.append(entry)
        manifest = {'schema': ci_manifest.SCHEMA, 'run_id': 'a' * 32,
                    'repository': 'baum777/Unitera_Systems',
                    'source_commit_sha': 'b' * 40, 'source_artifact_digest': 'c' * 64,
                    'relay_commit_sha': 'd' * 40, 'executor_version': {},
                    'vm_image_digest': 'e' * 64, 'toolchain_versions': {},
                    'dependency_lock_digest': 'f' * 64,
                    'execution_profile': {'plan': 'q7_resource_timeout', 'guest_mib': 1, 'smp': 1,
                                          'scope_memory_max': '1M', 'cpu_quota_percent': 1,
                                          'tasks_max': 1, 'deadline_s': 1,
                                          'console_budget_bytes': 1},
                    'started_at': '2026-10-26T20:00:00+00:00',
                    'finished_at': '2026-10-26T20:05:00+00:00',
                    'checks': checks, 'overall_result': overall,
                    'cleanup_result': 'PASS',
                    'isolation_result': 'FAIL' if isolation_fail else 'PASS',
                    'evidence': {}}
        (run_dir / 'evidence' / 'manifest.json').write_text(json.dumps(manifest))
        # Realistic raw result record: the independent verifier cross-checks these
        # fields instead of trusting the manifest's PASS summary.
        result_json = {'overall_result': overall, 'outcome': 'exited',
                       'vm_exit': 33 if overall == 'PASS' else 35,
                       'limits_verified': True, 'inputs_unchanged': True,
                       'host_service_positive_controls': {'127.0.0.1': True, 'lan': True,
                                                          'synthetic_unix_socket': True},
                       'cleanup': {'cleanup_verified': True, 'scope_remaining_pids': [],
                                   'observed_pids_still_exist': []}}
        (run_dir / 'evidence' / 'result.json').write_text(json.dumps(result_json))
        (run_dir / 'evidence' / 'console.log').write_text(console)
        run = {'run_id': 'a' * 32, 'expected_checks': expected}
        (run_dir / 'run.json').write_text(json.dumps(run))
        envelope = {'schema': 'relay.ci-evidence-envelope.v1',
                    'run_id': 'a' * 32,
                    'files': {'result.json': ci_util.sha256_file(run_dir / 'evidence' / 'result.json'),
                              'manifest.json': ci_util.sha256_file(run_dir / 'evidence' / 'manifest.json'),
                              'console.log': ci_util.sha256_file(run_dir / 'evidence' / 'console.log')},
                    'run_json_sha256': ci_util.sha256_file(run_dir / 'run.json')}
        (run_dir / 'evidence' / 'envelope.json').write_text(json.dumps(envelope))
        if break_console:
            (run_dir / 'evidence' / 'console.log').write_text(
                console.replace('PASS', 'PASS\nTAMPERED-EXTRA-LINE', 1))
        return run_dir

    def test_consistent_run_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self.make_run(tmp)
            _manifest, problems = ci_verify.reasons_from(run_dir, expect_plan='q7_resource_timeout')
            self.assertEqual(problems, [])

    def test_tampered_console_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self.make_run(tmp, break_console=True)
            _manifest, problems = ci_verify.reasons_from(run_dir, expect_plan='q7_resource_timeout')
            self.assertTrue(any('digest mismatch' in p for p in problems))

    def test_missing_mandatory_check_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self.make_run(tmp, drop_check='fixture_hold_timeout')
            _manifest, problems = ci_verify.reasons_from(run_dir, expect_plan='q7_resource_timeout')
            self.assertTrue(problems)

    def test_isolation_failure_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self.make_run(tmp, isolation_fail='lan_denied')
            _manifest, problems = ci_verify.reasons_from(run_dir, expect_plan='q7_resource_timeout')
            self.assertTrue(any('isolation' in p for p in problems))

    def test_forged_overall_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self.make_run(tmp, overall='PASS', isolation_fail='lan_denied')
            _manifest, problems = ci_verify.reasons_from(run_dir, expect_plan='q7_resource_timeout')
            self.assertTrue(any('overall' in p or 'isolation' in p for p in problems))

    def test_ledger_replay_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with tempfile.TemporaryDirectory() as private:
                ci_verify.ledger_append(private, 'run1', '0' * 64)
                with self.assertRaises(ValueError):
                    ci_verify.ledger_append(private, 'run1', '0' * 64)


class GuardedDownloadTests(unittest.TestCase):
    """guarded_urlopen is the only sanctioned download path (SSRF rule:
    https-only, pre-request host allowlist, global-IP resolution check,
    redirect rejection)."""

    def _dns(self, ip):
        def fake_getaddrinfo(host, port, family):
            addr = (ip, port) if ':' not in ip else (ip, port, 0, 0)
            return [(family, 0, 0, '', addr)]
        return mock.patch('ci_util.socket.getaddrinfo', side_effect=fake_getaddrinfo)

    def test_rejects_non_https(self):
        with self.assertRaisesRegex(ValueError, 'non-https'):
            ci_util.guarded_urlopen('http://dl-cdn.alpinelinux.org/alpine/x.iso')

    def test_rejects_host_outside_allowlist(self):
        with self.assertRaisesRegex(ValueError, 'allowlisted'):
            ci_util.guarded_urlopen('https://evil.example.com/base.iso')

    def test_rejects_private_resolution(self):
        with self._dns('10.1.2.3'):
            with self.assertRaisesRegex(ValueError, 'non-global'):
                ci_util.guarded_urlopen('https://dl-cdn.alpinelinux.org/alpine/x.iso')

    def test_rejects_loopback_resolution(self):
        with self._dns('127.0.0.1'):
            with self.assertRaisesRegex(ValueError, 'non-global'):
                ci_util.guarded_urlopen('https://alpinelinux.org/keys/ncopa.asc')

    def test_no_redirect_handler_never_follows(self):
        with self.assertRaisesRegex(RuntimeError, 'redirect .* rejected'):
            ci_util._NoRedirect().redirect_request(None, None, 302, None, None, 'https://elsewhere.example.com/')

    def test_global_resolution_reaches_guarded_opener(self):
        calls = {}

        class FakeResponse:
            def read(self, n=-1):
                return b''

        opener = mock.Mock()
        opener.open = lambda url, timeout=None: calls.update(url=url, timeout=timeout) or FakeResponse()
        with self._dns('152.195.19.5'):
            with mock.patch('ci_util.urllib.request.build_opener', return_value=opener):
                ci_util.guarded_urlopen('https://dl-cdn.alpinelinux.org/alpine/x.iso')
        self.assertEqual(calls['url'], 'https://dl-cdn.alpinelinux.org/alpine/x.iso')
        self.assertEqual(calls['timeout'], ci_util.DOWNLOAD_TIMEOUT_S)

    def test_fetch_uses_guarded_download_path(self):
        source = (ROOT / 'vm' / 'fetch.py').read_text()
        self.assertIn('guarded_urlopen(url)', source)
        self.assertNotIn('urllib.request.urlopen', source)


if __name__ == '__main__':
    unittest.main()
