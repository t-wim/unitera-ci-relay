"""Focused W2.1 baum-os profile regressions; no application code, network or VM execution."""
import base64
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vm'))
import baum_ci_custody  # noqa: E402
import baum_prep  # noqa: E402
import ci_manifest  # noqa: E402
import ci_monitor  # noqa: E402
import ci_plan  # noqa: E402
import ci_util  # noqa: E402
import ci_verify  # noqa: E402
from ci_prep import git_blob_sha  # noqa: E402

SOURCE_SHA = 'd8f96217b121325ef1f4d46a8c3e5743e31fc0cb'
SOURCE_TREE = '0aa6204a90375277e93f8d5e2394d88b1dbe21df'
SOURCE_REPO = Path('/home/baum/workspace/baum-os')
PACKAGE_MANAGER_PIN = ('pnpm@11.9.0+sha512.bd682d5d03fe525ef7c9fd6780c6884d1e756ac'
                       '4c9c9fe00c538782824310dcf90e3ddc4f53835f06dfaebd5085e41855e'
                       '0bcbb3b60de2ac5bbab89e5036f03b')
RUN_SHA = {
    'g4_node24': 'd96c7df03e884ab303f50dd271a95d23f589691b304e019fe251ae6640583c1e',
    'g5_frozen_install': 'f733afb2da73a36bd48778fd7502436e384741ad191367d97182afc4909130a5',
    'g6_tracked_artifacts': '4f0492754b31859ad02e7200edfadc4f2543fd1d160c12a7dd5688994a9fdbe2',
    'g7_context_pack': '0aa8d6f53a60c8a1d999baa40eb8550515924b8510e293287035551dbcb4dd25',
    'g8_orchestration': 'be3af1046082ce9df8b86d706d0c6fd1fa282bf9ad6b82fa3232ae60b8751090',
}


def load_lock():
    return json.loads((ROOT / 'vm' / 'baum-lock.json').read_text())


class PlanBindingTests(unittest.TestCase):
    def test_script_bodies_bound_by_run_sha256(self):
        for name, digest in RUN_SHA.items():
            self.assertEqual(hashlib.sha256(ci_plan.BAUM_GOV[name][2].encode()).hexdigest(),
                             digest, name)

    def test_expected_check_set_is_exact(self):
        self.assertEqual(ci_plan.expected_check_set('baum_governance'),
                         {'c1_source_integrity', 'c2_toolchain_validation',
                          'c1b_git_tree_identity', 'g4_node24', 'g5_frozen_install',
                          'g6_tracked_artifacts', 'g7_context_pack', 'g8_orchestration'})

    def test_script_entry_validation_negatives(self):
        bad = [
            {'name': 'x', 'timeout_s': 10, 'cwd': '/ws/src',
             'argv': ['bash', '-e', '/plan/governance-guardrails.yml/governance/4.sh'],
             'script': 'true', 'script_path': '/plan/../evil.sh'},
            {'name': 'x', 'timeout_s': 10, 'cwd': '/ws/src',
             'argv': ['bash', '-e', '/plan/governance-guardrails.yml/governance/4.sh'],
             'script': 'true', 'script_path': '/plan/governance-guardrails.yml/governance/999.sh.x'},
            {'name': 'x', 'timeout_s': 10, 'cwd': '/ws/src',
             'argv': ['bash', '-e', '/plan/other.yml/job/4.sh'],
             'script': 'true', 'script_path': '/plan/governance-guardrails.yml/governance/4.sh'},
            {'name': 'x', 'timeout_s': 10, 'cwd': '/ws/src',
             'argv': ['bash', '-e', '/plan/governance-guardrails.yml/governance/4.sh'],
             'script': 'a\0b', 'script_path': '/plan/governance-guardrails.yml/governance/4.sh'},
        ]
        for entry in bad:
            with self.assertRaises(ValueError):
                ci_plan.validate_script_entries([entry])

    def test_plan_literals_match_workflow_at_pinned_commit(self):
        if not (SOURCE_REPO / '.git').exists():
            self.skipTest('pinned source repository not available')
        plan = baum_ci_custody.source_plan(SOURCE_REPO, SOURCE_SHA)
        self.assertEqual(plan['source_sha'], SOURCE_SHA)
        steps = plan['workflows'][0]['jobs']['governance']['steps']
        run_steps = [step for step in steps if 'run' in step]
        self.assertEqual(len(run_steps), 5)
        for step, name in zip(run_steps, ci_plan.BAUM_GOV_ORDER):
            self.assertEqual(step['run'], ci_plan.BAUM_GOV[name][2], name)
            self.assertEqual(step['exact_argv'], ['bash', '-e', ci_plan.BAUM_GOV[name][1]], name)
            self.assertEqual(step['run_sha256'], RUN_SHA[name], name)

    def test_guest_script_syntax_valid(self):
        result = subprocess.run(['bash', '-n', str(ROOT / 'vm' / 'ci_guest.sh')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_overlay_script_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            initrd = Path(temp) / 'initrd'
            initrd.write_bytes(b'base')
            entry = {'name': 'x', 'timeout_s': 10, 'cwd': '/ws/src',
                     'argv': ['bash', '-e', '/plan/governance-guardrails.yml/governance/4.sh'],
                     'script': 'true', 'script_path': '/plan/governance-guardrails.yml/governance/4.sh'}
            config = {'MODE': 'run', 'EXPECTED_TREE_SHA': '0' * 40}
            with self.assertRaises(ValueError):
                ci_monitor.append_job_overlay(initrd, config, [dict(entry, script_path='/plan/x')])
            overlay = ci_monitor.append_job_overlay(initrd, config, [entry])
            self.assertGreater(len(overlay), len(initrd.read_bytes()))


class LockProvenanceTests(unittest.TestCase):
    def test_pnpm_digest_encodings_prove_same_digest(self):
        lock = load_lock()
        hex_digest = base64.b64decode(lock['pnpm']['tar_sha512'].split('-', 1)[1]).hex()
        self.assertEqual(hex_digest, lock['pnpm']['tar_sha512_hex_from_package_manager'])
        self.assertEqual('sha512.' + hex_digest,
                         PACKAGE_MANAGER_PIN.split('+', 1)[1])

    def test_pnpm_pin_matches_committed_package_manager(self):
        if not (SOURCE_REPO / '.git').exists():
            self.skipTest('pinned source repository not available')
        committed = subprocess.run(
            ['git', '-C', str(SOURCE_REPO), 'show', SOURCE_SHA + ':package.json'],
            capture_output=True, text=True, check=True).stdout
        self.assertEqual(json.loads(committed)['packageManager'], PACKAGE_MANAGER_PIN)

    def test_node_pin_is_the_systems_lane_artifact(self):
        systems = json.loads((ROOT / 'vm' / 'ci-lock.json').read_text())
        self.assertEqual(load_lock()['node'], systems['node'])


class TypedTreeTests(unittest.TestCase):
    def make_archive(self, files, symlinks):
        entries = {}
        for path, (content, mode) in files.items():
            entries[path] = [git_blob_sha(content), mode]
        for path, target in symlinks.items():
            entries[path] = [git_blob_sha(target.encode()), '120000']
        raw = b''
        for path, (oid, mode) in entries.items():
            raw += ('%s %s %s\t%s' % (mode, 'blob' if mode != '160000' else 'commit', oid, path)).encode() + b'\0'
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tar:
            for path, (content, mode) in files.items():
                member = tarfile.TarInfo(path)
                member.size = len(content)
                member.mode = 0o755 if mode == '100755' else 0o644
                tar.addfile(member, io.BytesIO(content))
            for path, target in symlinks.items():
                member = tarfile.TarInfo(path)
                member.type = tarfile.SYMTYPE
                member.linkname = target
                tar.addfile(member)
        return raw, entries, buffer.getvalue()

    def test_typed_parse_and_archive_verification_materialize_exact_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = {'a.txt': (b'AAA\n', '100644'), 'bin/run.sh': (b'#!/bin/sh\n', '100755')}
            symlinks = {'os/current_state.md': '../current_state.md'}
            raw, entries, archive = self.make_archive(files, symlinks)
            regular, symlists, gitlinks = baum_prep.parse_typed_ls_tree(raw)
            self.assertEqual(sorted(regular), sorted(files))
            self.assertEqual([entry['path'] for entry in symlists], ['os/current_state.md'])
            self.assertEqual(gitlinks, [])
            (root / 'source.tar').write_bytes(archive)
            staging, inventory, targets = baum_prep._verify_archive(root / 'source.tar', regular, symlists)
            self.assertEqual((staging / 'a.txt').read_bytes(), b'AAA\n')
            self.assertTrue((staging / 'bin' / 'run.sh').stat().st_mode & 0o111)
            self.assertEqual((staging / 'os/current_state.md').readlink().as_posix(), '../current_state.md')
            self.assertEqual(sorted(inventory), sorted(files))

    def test_tampered_file_content_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            raw, entries, archive = self.make_archive({'a.txt': (b'AAA\n', '100644')}, {})
            (root / 'source.tar').write_bytes(archive.replace(b'AAA', b'BBB'))
            regular, symlists, _ = baum_prep.parse_typed_ls_tree(raw)
            with self.assertRaises(ValueError):
                baum_prep._verify_archive(root / 'source.tar', regular, symlists)

    def test_tampered_symlink_target_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            raw, entries, archive = self.make_archive({'a.txt': (b'A\n', '100644')}, {'link': 'a.txt'})
            regular, symlists, _ = baum_prep.parse_typed_ls_tree(raw)
            (root / 'source.tar').write_bytes(archive)
            _staging, _inventory, _targets = baum_prep._verify_archive(root / 'source.tar', regular, symlists)
            # a different target than the committed blob must fail git blob identity
            other = [dict(symlists[0], git_object=git_blob_sha(b'elsewhere'))]
            with self.assertRaises(ValueError):
                baum_prep._verify_archive(root / 'source.tar', regular, other)

    def test_unexpected_archive_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            raw, entries, archive = self.make_archive({}, {'rogue': '/etc/passwd'})
            (root / 'source.tar').write_bytes(archive)
            regular, symlists, _ = baum_prep.parse_typed_ls_tree(raw)
            with self.assertRaises(ValueError):
                baum_prep._verify_archive(root / 'source.tar', regular, [])

    def test_symlink_target_policy(self):
        self.assertEqual(baum_prep.validate_symlink_target('a/link', '../b'), 'relative-in-tree')
        self.assertEqual(baum_prep.validate_symlink_target('a/link', '/home/x/node_modules'), 'absolute-frozen')
        with self.assertRaises(ValueError):
            baum_prep.validate_symlink_target('a/link', '../../escape')
        with self.assertRaises(ValueError):
            baum_prep.validate_symlink_target('a/link', '..')

    def test_gitlink_entries_parse_as_typed_data(self):
        raw = b'160000 commit 1' + b'2' * 39 + b'\tagentic_workflow/agent_routing\0'
        regular, symlinks, gitlinks = baum_prep.parse_typed_ls_tree(raw)
        self.assertEqual(regular, {})
        self.assertEqual(gitlinks[0]['path'], 'agentic_workflow/agent_routing')

    def test_bad_oid_rejected(self):
        raw = b'100644 blob xyz\ta.txt\0'
        with self.assertRaises(ValueError):
            baum_prep.parse_typed_ls_tree(raw)

    def test_disk_preserves_tracked_node_modules_symlink(self):
        # Regression: copytree(ignore_patterns('node_modules')) once ate the tracked
        # .quarantine .../node_modules symlink; the guest's c1b tree proof caught it.
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            private = Path(temp)
            prep = private / 'prep'
            assets = private / 'ci-assets'
            (assets / 'store').mkdir(parents=True)
            (prep / 'staging-src' / '.quarantine').mkdir(parents=True)
            (prep / 'staging-src' / 'a.txt').write_text('A\n')
            (prep / 'staging-src' / 'node_modules').mkdir()
            (prep / 'staging-src' / 'node_modules' / 'host-built.js').write_text('x')
            (prep / 'staging-src' / '.quarantine' / 'node_modules').symlink_to('../a.txt')
            (prep / 'store-build.rc').write_text('0\n')
            with patch('baum_prep.private_path', lambda value: Path(value)):
                result = baum_prep.disk(private, 'a' * 40, {'symlinks': [], 'gitlinks': []})
            src = prep / 'disk' / 'src'
            self.assertEqual((src / 'a.txt').read_text(), 'A\n')
            self.assertFalse((src / 'node_modules').exists())
            self.assertTrue((src / '.quarantine' / 'node_modules').is_symlink())
            self.assertIn('steps3', result)


class BaumManifestTests(unittest.TestCase):
    def make_manifest(self, repository):
        return {'schema': ci_manifest.SCHEMA, 'run_id': 'a' * 32, 'repository': repository,
                'source_commit_sha': 'b' * 40, 'source_artifact_digest': 'c' * 64,
                'relay_commit_sha': 'd' * 40, 'executor_version': {},
                'vm_image_digest': 'e' * 64, 'toolchain_versions': {},
                'dependency_lock_digest': 'f' * 64,
                'execution_profile': {'plan': 'baum_governance', 'guest_mib': 1, 'smp': 1,
                                      'scope_memory_max': '1M', 'cpu_quota_percent': 1,
                                      'tasks_max': 1, 'deadline_s': 1, 'console_budget_bytes': 1},
                'started_at': '2026-10-28T20:00:00+00:00',
                'finished_at': '2026-10-28T20:05:00+00:00',
                'checks': [{'check_name': 'g4_node24', 'command_identifier': 'x', 'exit_code': 0,
                            'timeout': 0, 'result': 'PASS', 'log_digest': 'guest-native'}],
                'overall_result': 'PASS', 'cleanup_result': 'PASS',
                'isolation_result': 'PASS', 'evidence': {}}

    def test_both_lane_repositories_accepted_unknown_rejected(self):
        self.assertTrue(ci_manifest.validate_manifest(self.make_manifest('baum777/baum-os')))
        self.assertTrue(ci_manifest.validate_manifest(self.make_manifest('baum777/Unitera_Systems')))
        with self.assertRaises(ValueError):
            ci_manifest.validate_manifest(self.make_manifest('evil/repo'))


def make_baum_run(tmp, drop_check=None, extra_console=None, reseat=True):
    """Modelled on test_ci.VerifierTests.make_run, for the baum governance plan."""
    run_dir = Path(tmp)
    (run_dir / 'evidence').mkdir(parents=True, exist_ok=True)
    expected = sorted(ci_plan.expected_check_set('baum_governance') | set(ci_monitor.ISOLATION_CHECKS))
    plan_names = {entry['name'] for entry in ci_plan.plan_by_name('baum_governance')}
    lines = ['SRC_READY']
    for name in expected:
        if name == drop_check:
            continue
        lines.append('CHECK %s PASS' % name)
        if name in plan_names:
            lines.append('EXIT %s 0' % name)
            lines.append('TMO %s 0' % name)
    if extra_console:
        lines.extend(extra_console)
    console = '\n'.join(lines) + '\nGUEST_ALL_CHECKS_PASSED\n'
    checks = [{'check_name': name, 'command_identifier': 'bash -e /plan/x.sh', 'exit_code': 0,
               'timeout': 0, 'result': 'PASS', 'log_digest': 'guest-native'}
              for name in expected]
    manifest = {'schema': ci_manifest.SCHEMA, 'run_id': 'a' * 32, 'repository': 'baum777/baum-os',
                'source_commit_sha': 'b' * 40, 'source_artifact_digest': 'c' * 64,
                'relay_commit_sha': 'd' * 40, 'executor_version': {},
                'vm_image_digest': 'e' * 64, 'toolchain_versions': {'node': '24.19.0', 'pnpm': '11.9.0'},
                'dependency_lock_digest': 'f' * 64,
                'execution_profile': {'plan': 'baum_governance', 'guest_mib': 2816, 'smp': 2,
                                      'scope_memory_max': '3816M', 'cpu_quota_percent': 200,
                                      'tasks_max': 512, 'deadline_s': 5400,
                                      'console_budget_bytes': 67108864},
                'started_at': '2026-10-28T20:00:00+00:00',
                'finished_at': '2026-10-28T20:45:00+00:00',
                'checks': checks, 'overall_result': 'PASS', 'cleanup_result': 'PASS',
                'isolation_result': 'PASS', 'evidence': {}}
    (run_dir / 'evidence' / 'manifest.json').write_text(json.dumps(manifest))
    result_json = {'overall_result': 'PASS', 'outcome': 'exited', 'vm_exit': 33,
                   'limits_verified': True, 'inputs_unchanged': True,
                   'host_service_positive_controls': {'127.0.0.1': True, 'lan': True,
                                                      'synthetic_unix_socket': True},
                   'cleanup': {'cleanup_verified': True, 'scope_remaining_pids': [],
                               'observed_pids_still_exist': []}}
    (run_dir / 'evidence' / 'result.json').write_text(json.dumps(result_json))
    (run_dir / 'evidence' / 'console.log').write_text(console)
    run = {'run_id': 'a' * 32, 'plan_name': 'baum_governance', 'repository': 'baum777/baum-os',
           'expected_checks': expected, 'source_commit_sha': 'b' * 40}
    (run_dir / 'run.json').write_text(json.dumps(run))
    envelope = {'schema': 'relay.ci-evidence-envelope.v1', 'run_id': 'a' * 32,
                'files': {name: ci_util.sha256_file(run_dir / 'evidence' / name)
                          for name in ('result.json', 'manifest.json', 'console.log')},
                'run_json_sha256': ci_util.sha256_file(run_dir / 'run.json')}
    (run_dir / 'evidence' / 'envelope.json').write_text(json.dumps(envelope))
    return run_dir


def verify_baum(run_dir, private, **pins):
    arguments = {'relay_pin': 'd' * 40, 'source_pin': 'b' * 40}
    arguments.update(pins)
    return ci_verify.verify(run_dir, private, expect_plan='baum_governance', **arguments)


class BaumVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name) / 'private'
        self.private.mkdir()

    def test_consistent_baum_run_accepted(self):
        run = make_baum_run(Path(self.temp.name) / 'run-a')
        manifest, problems = verify_baum(run, self.private)
        self.assertEqual(problems, [])
        self.assertEqual(manifest['repository'], 'baum777/baum-os')

    def test_missing_c1b_in_console_rejected_despite_manifest_pass(self):
        run = make_baum_run(Path(self.temp.name) / 'run-b', drop_check='c1b_git_tree_identity')
        _manifest, problems = verify_baum(run, self.private)
        self.assertTrue(any('absent from console' in problem
                            for problem in problems), problems)

    def test_injected_fake_pass_marker_rejected(self):
        run = make_baum_run(Path(self.temp.name) / 'run-c',
                            extra_console=['CHECK g9_injected PASS'])
        _manifest, problems = verify_baum(run, self.private)
        self.assertTrue(any('unexpected checks' in problem for problem in problems), problems)

    def test_console_tampered_after_seal_rejected(self):
        run = make_baum_run(Path(self.temp.name) / 'run-d')
        with open(run / 'evidence' / 'console.log', 'a') as handle:
            handle.write('CHECK g4_node24 FAIL\n')
        _manifest, problems = verify_baum(run, self.private)
        self.assertTrue(any('digest mismatch' in problem for problem in problems), problems)

    def test_wrong_source_pin_rejected(self):
        run = make_baum_run(Path(self.temp.name) / 'run-e')
        _manifest, problems = verify_baum(run, self.private, source_pin=SOURCE_SHA)
        self.assertTrue(any('source commit differs' in problem for problem in problems), problems)

    def test_run_id_replay_rejected(self):
        run = make_baum_run(Path(self.temp.name) / 'run-f')
        self.assertEqual(verify_baum(run, self.private, append=True)[1], [])
        with self.assertRaisesRegex(ValueError, 'REPLAY_REJECTED'):
            verify_baum(run, self.private, append=True)


class VerifierHardeningTests(unittest.TestCase):
    """G3 negatives: raw-result cross-checks and independent asset re-derivation."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name) / 'private'
        self.private.mkdir()

    def make(self, name):
        return make_baum_run(Path(self.temp.name) / name)

    def reseal(self, run):
        envelope = json.loads((run / 'evidence' / 'envelope.json').read_text())
        for member in envelope['files']:
            envelope['files'][member] = ci_util.sha256_file(run / 'evidence' / member)
        envelope['run_json_sha256'] = ci_util.sha256_file(run / 'run.json')
        (run / 'evidence' / 'envelope.json').write_text(json.dumps(envelope))

    def patch_result(self, run, **fields):
        path = run / 'evidence' / 'result.json'
        payload = json.loads(path.read_text())
        payload.update(fields)
        path.write_text(json.dumps(payload))
        self.reseal(run)

    def make_assets(self, consistent=True):
        assets = self.private / 'ci-assets'
        assets.mkdir(exist_ok=True)
        (assets / 'ci-initrd').write_bytes(b'initrd-bytes')
        (assets / 'ws-base.img').write_bytes(b'ws-bytes')
        initrd_digest = ci_util.sha256_file(assets / 'ci-initrd')
        vm_digest = initrd_digest if consistent else 'e' * 64
        (assets / 'ci-image.json').write_text(json.dumps({'initrd_sha256': initrd_digest}))
        (assets / 'ws-image.json').write_text(json.dumps(
            {'sha256': ci_util.sha256_file(assets / 'ws-base.img')}))
        (assets / 'ci-prep-manifest.json').write_text(json.dumps(
            {'repository': 'baum777/baum-os', 'source': {'commit': 'b' * 40,
                                                         'lockfile_sha256': 'f' * 64}}))
        return assets, vm_digest

    def test_missing_limits_verification_rejects_pass(self):
        run = self.make('r1')
        self.patch_result(run, limits_verified=False)
        _m, problems = verify_baum(run, self.private)
        self.assertTrue(any('lacks limits_verified' in problem for problem in problems), problems)

    def test_cleanup_residue_rejects_pass(self):
        run = self.make('r2')
        self.patch_result(run, cleanup={'cleanup_verified': True,
                                        'scope_remaining_pids': [4242],
                                        'observed_pids_still_exist': []})
        _m, problems = verify_baum(run, self.private)
        self.assertTrue(any('residue' in problem for problem in problems), problems)

    def test_dropped_positive_control_rejects_pass(self):
        run = self.make('r3')
        self.patch_result(run, host_service_positive_controls={'127.0.0.1': True, 'lan': False})
        _m, problems = verify_baum(run, self.private)
        self.assertTrue(any('positive controls' in problem for problem in problems), problems)

    def test_manifest_vm_digest_not_bound_to_prepared_image_rejected(self):
        run = self.make('r4')
        _assets, _vm_digest = self.make_assets(consistent=False)
        _m, problems = verify_baum(run, self.private)
        self.assertTrue(any('vm image digest differs' in problem for problem in problems), problems)

    def test_tampered_initrd_bytes_rejected(self):
        run = self.make('r5')
        self.make_assets(consistent=True)
        manifest = json.loads((run / 'evidence' / 'manifest.json').read_text())
        manifest['vm_image_digest'] = ci_util.sha256_file(self.private / 'ci-assets' / 'ci-initrd')
        (run / 'evidence' / 'manifest.json').write_text(json.dumps(manifest))
        self.reseal(run)
        self.assertEqual([p for p in verify_baum(run, self.private)[1]
                          if 'prepared' in p or 'differs' in p or 'mismatch' in p], [])
        (self.private / 'ci-assets' / 'ci-initrd').write_bytes(b'tampered')
        _m, problems = verify_baum(run, self.private)
        self.assertTrue(any('ci initrd digest mismatch' in problem for problem in problems), problems)

    def test_consistent_prepared_assets_add_no_problems(self):
        run = self.make('r6')
        _assets, vm_digest = self.make_assets(consistent=True)
        manifest = json.loads((run / 'evidence' / 'manifest.json').read_text())
        manifest['vm_image_digest'] = vm_digest
        (run / 'evidence' / 'manifest.json').write_text(json.dumps(manifest))
        self.reseal(run)
        _m, problems = verify_baum(run, self.private)
        self.assertEqual(problems, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
