"""Synthetic tests for quarantine and publication boundaries, never source CI."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import yaml
import inventory
import audit_publication as audit

ROOT = Path(__file__).resolve().parent


class QuarantineTests(unittest.TestCase):
    def workflows(self):
        return [yaml.safe_load(p.read_text()) for p in sorted((ROOT / '.github/workflows').glob('*.yml'))]

    def test_both_entrypoints_have_no_source_or_credential_operation(self):
        self.assertEqual(len(self.workflows()), 2)
        for workflow in self.workflows():
            self.assertEqual(workflow['permissions'], {})
            self.assertEqual(set(workflow['jobs']), {'execution-pin', 'isolation-blocked'})
            self.assertEqual(workflow['jobs']['isolation-blocked']['needs'], ['execution-pin'])
            trigger = workflow.get('on', workflow.get(True))
            self.assertEqual(set(trigger), {'workflow_dispatch'})
            self.assertEqual(set(trigger['workflow_dispatch']['inputs']), {'source_sha', 'base_sha', 'expected_relay_sha', 'source_pr'})
            self.assertTrue(all(v['required'] for v in trigger['workflow_dispatch']['inputs'].values()))
            for job in workflow['jobs'].values():
                self.assertNotIn('continue-on-error', job)
                self.assertEqual(job['permissions'], {})
                self.assertEqual(job['runs-on'], ['self-hosted', 'Linux', 'X64', 'unitera-ci', 'relay'])
                for step in job['steps']:
                    for key in ['uses', 'continue-on-error', 'if']:
                        self.assertNotIn(key, step)
                    self.assertNotIn('secrets.', json.dumps(step))
                    self.assertNotIn('vars.', json.dumps(step))
                    self.assertNotRegex(step['run'], r'(?m)^\s*(git|docker|pnpm|curl|sudo|ssh|eval|source)\s')

    def test_correct_pin_and_qualification_flags_still_cannot_admit_execution(self):
        for workflow in self.workflows():
            for flag in ['', 'true', 'false']:
                run = workflow['jobs']['isolation-blocked']['steps'][0]['run']
                result = subprocess.run(['bash', '-c', run], capture_output=True, text=True,
                                        env={'PATH': '/usr/bin:/bin', 'QUALIFIED': flag})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('RELAY_QUARANTINED', result.stdout)

    def test_wrong_missing_and_malformed_pins_deny_before_any_other_job(self):
        for workflow in self.workflows():
            step = workflow['jobs']['execution-pin']['steps'][0]
            good = {'PATH': '/usr/bin:/bin', 'EXPECTED_RELAY_SHA': 'a'*40, 'ACTUAL_RELAY_SHA': 'a'*40,
                    'SOURCE_SHA': 'b'*40, 'BASE_SHA': 'c'*40, 'SOURCE_PR': '7'}
            cases = [({}, True), ({'ACTUAL_RELAY_SHA': 'd'*40}, False), ({'EXPECTED_RELAY_SHA': ''}, False),
                     ({'EXPECTED_RELAY_SHA': 'x'*40, 'ACTUAL_RELAY_SHA': 'x'*40}, False),
                     ({'SOURCE_SHA': 'invalid'}, False), ({'BASE_SHA': ''}, False),
                     ({'SOURCE_PR': '$(id)'}, False)]
            for change, ok in cases:
                result = subprocess.run(['bash', '-c', step['run']], env={**good, **change}, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, ok)
                self.assertEqual('RELAY_EXECUTION_PIN_PASS' in result.stdout, ok)

    def test_shell_syntax(self):
        for workflow in self.workflows():
            for job in workflow['jobs'].values():
                for step in job['steps']:
                    result = subprocess.run(['bash', '-n'], input=step['run'], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)


class SyntheticInventoryTests(unittest.TestCase):
    def test_invented_matrix_conditions_dependencies_and_steps_remain_data(self):
        result = inventory.inventory()
        self.assertEqual(result['fixture_class'], 'SYNTHETIC_ONLY')
        self.assertFalse(result['qualifies_real_ci'])
        self.assertEqual(len(result['gates']), 3)
        rows = [row for row in result['gates'] if row['job_id'] == 'sample']
        self.assertEqual([row['job']['steps'][0]['run'] for row in rows], ['printf fixture-alpha', 'printf fixture-beta'])
        summary = next(row for row in result['gates'] if row['job_id'] == 'summary')
        self.assertEqual(summary['job']['needs'], ['sample'])
        self.assertEqual(summary['job']['if'], 'always()')
        self.assertEqual(summary['job']['continue-on-error'], 'true')
        self.assertEqual(summary['execution_evidence'], [])

    def test_changed_or_extra_fixture_fails_closed(self):
        for mode in ['changed', 'extra']:
            with tempfile.TemporaryDirectory(dir=ROOT, prefix='.synthetic-test-') as temporary:
                path = Path(temporary) / 'fixtures'
                shutil.copytree(inventory.FIXTURES, path)
                target = path / ('synthetic-workflow.yml' if mode == 'changed' else 'extra.yml')
                with target.open('a') as handle:
                    handle.write('\n# invented mutation\n')
                with self.assertRaises(ValueError):
                    inventory.inventory(path)

    def test_fixture_path_escape_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix='.synthetic-test-') as temporary:
            path = Path(temporary)
            (path / 'manifest.json').write_text(json.dumps({'fixture_class': 'SYNTHETIC_ONLY', 'files': [{'path': '../outside'}]}))
            with self.assertRaisesRegex(ValueError, 'path escape'):
                inventory.checked_fixture(path)

    def test_fixture_classification_and_duplicate_paths_are_required(self):
        for manifest in [{'files': []}, {'fixture_class': 'SYNTHETIC_ONLY', 'files': [{'path': 'x'}, {'path': 'x'}]}]:
            with tempfile.TemporaryDirectory(dir=ROOT, prefix='.synthetic-test-') as temporary:
                path = Path(temporary)
                (path / 'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    inventory.checked_fixture(path)

    def test_unknown_matrix_is_not_silently_skipped(self):
        for matrix in ['${{ fromJson(inputs.matrix) }}', {'axis': '${{ inputs.axis }}'}, {}]:
            with self.assertRaises(ValueError):
                inventory.variants({'strategy': {'matrix': matrix}})

    def test_matrix_axes_include_and_exclude(self):
        rows = inventory.variants({'strategy': {'matrix': {
            'axis': ['a', 'b'], 'version': ['1', '2'], 'exclude': [{'axis': 'b', 'version': '2'}],
            'include': [{'axis': 'a', 'extra': 'synthetic'}, {'axis': 'c', 'version': '1'}]}}})
        self.assertEqual(len(rows), 4)
        self.assertIn({'axis': 'a', 'version': '1', 'extra': 'synthetic'}, rows)
        self.assertIn({'axis': 'c', 'version': '1'}, rows)

    def test_untrusted_expression_text_is_never_executed(self):
        payload = '$(invented-command); ${{ matrix.command }}'
        self.assertEqual(inventory.render(payload, {'command': '$(another-command)'}), '$(invented-command); $(another-command)')


class PublicationTests(unittest.TestCase):
    def test_credential_detector_uses_only_constructed_synthetic_values(self):
        fake = ('gh' + 'p_' + 'X'*36).encode()
        self.assertIn('github_credential', audit.scan_bytes(fake))
        marker = ('-----BEGIN ' + 'PRIVATE KEY-----').encode()
        self.assertIn('private_key', audit.scan_bytes(marker))
        self.assertEqual(audit.scan_bytes(b'ordinary synthetic fixture'), [])

    def test_private_copies_and_references_are_detected_without_printing_values(self):
        secret_text = b'invented confidential text ' * 12
        self.assertIn('exact_private_copy', audit.scan_bytes(secret_text, corpus=[secret_text]))
        self.assertIn('long_private_text_overlap', audit.scan_bytes(b'prefix ' + secret_text, corpus=[secret_text]))
        self.assertIn('forbidden_private_reference', audit.scan_bytes(b'invented-reference', [b'invented-reference']))

    def synthetic_commit(self, repo, files, parent=None):
        def git(*args, data=None):
            return subprocess.check_output(['git', '-C', str(repo), *args], input=data)
        git('read-tree', '--empty')
        for name, data in files.items():
            oid = git('hash-object', '-w', '--stdin', data=data.encode()).decode().strip()
            git('update-index', '--add', '--cacheinfo', '100644,' + oid + ',' + name)
        tree = git('write-tree').decode().strip()
        # Artificial unsigned Git objects are local test fixtures, not release commits.
        text = f'tree {tree}\n' + (f'parent {parent}\n' if parent else '')
        text += 'author Synthetic Test <synthetic@example.invalid> 1 +0000\ncommitter Synthetic Test <synthetic@example.invalid> 1 +0000\n\nSynthetic fixture\n'
        return git('hash-object', '-t', 'commit', '-w', '--stdin', data=text.encode()).decode().strip()

    def test_private_intermediate_commit_is_detected_even_after_final_deletion(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix='.publication-test-') as temporary:
            repo = Path(temporary)
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            subprocess.run(['git', '-C', str(repo), 'remote', 'add', 'origin', 'https://github.com/example/publication-test.git'], check=True)
            base = self.synthetic_commit(repo, {'safe.txt': 'synthetic baseline'})
            policy = json.dumps({'target_repository': 'example/publication-test', 'base_sha': base,
                                 'allowed_files': ['publication-policy.json', 'safe.txt']})
            private = 'invented confidential fixture ' * 12
            clean = {'safe.txt': 'synthetic content', 'publication-policy.json': policy}
            bad = self.synthetic_commit(repo, {**clean, 'private.txt': private}, base)
            final = self.synthetic_commit(repo, clean, bad)
            result = audit.review(repo, base, final, [private.encode()], [b'invented-private-reference'])
            self.assertEqual(result['new_commits'], [bad, final])
            self.assertEqual(result['scan_result'], 'REVIEW_BLOCKED')
            self.assertTrue(any(item.get('rule') == 'exact_private_copy' for item in result['findings']))
            self.assertTrue(any(item.get('commit') == bad for item in result['findings']))

    def test_clean_new_history_has_no_publication_authority(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix='.publication-test-') as temporary:
            repo = Path(temporary)
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            subprocess.run(['git', '-C', str(repo), 'remote', 'add', 'origin', 'https://github.com/example/publication-test.git'], check=True)
            base = self.synthetic_commit(repo, {'safe.txt': 'synthetic baseline'})
            policy = json.dumps({'target_repository': 'example/publication-test', 'base_sha': base,
                                 'allowed_files': ['publication-policy.json', 'safe.txt']})
            head = self.synthetic_commit(repo, {'safe.txt': 'synthetic updated', 'publication-policy.json': policy}, base)
            result = audit.review(repo, base, head, [b'unrelated invented corpus'], [b'invented-private-reference'])
            self.assertEqual(result['findings'], [])
            self.assertFalse(result['publication_authorized'])
            self.assertFalse(result['push_performed'])


if __name__ == '__main__':
    unittest.main()
