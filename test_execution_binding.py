"""Regression for nested-workspace SHA custody; no VM or remote operations."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vm'))
import ci_verify
import test_ci


class ExecutionBindingTests(unittest.TestCase):
    def test_launcher_records_inner_relay_commit_in_nested_git_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary)
            inner = outer / 'relay'
            inner.mkdir()
            for repo in (outer, inner):
                subprocess.run(['git', 'init', '-q', str(repo)], check=True)
                (repo / 'fixture').write_text(repo.name)
                subprocess.run(['git', '-C', str(repo), 'add', 'fixture'], check=True)
                subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Fixture',
                                '-c', 'user.email=fixture@example.invalid',
                                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture'], check=True)
            vm = inner / 'vm'
            vm.mkdir()
            launcher = vm / 'ci_start.sh'
            launcher.write_bytes((ROOT / 'vm/ci_start.sh').read_bytes())
            run = outer / 'run'
            (run / 'launch').mkdir(parents=True)
            base, overlay = run / 'base', run / 'overlay'
            base.touch()
            overlay.touch()
            (run / 'launch/overlay.txt').write_text(str(base) + '\n' + str(overlay) + '\n')
            (run / 'launch/argv.args').write_text('/usr/bin/true\n')
            subprocess.run(['sh', str(launcher), str(run)], cwd=outer, check=True)
            expected = subprocess.check_output(['git', '-C', str(inner), 'rev-parse', 'HEAD'], text=True)
            self.assertEqual((run / 'relay-head.txt').read_text(), expected)

    def test_correct_source_and_relay_pins_are_accepted(self):
        self.assertEqual(ci_verify.execution_pin_problems(
            {'relay_commit_sha': 'a' * 40, 'source_commit_sha': 'b' * 40},
            {'source_commit_sha': 'b' * 40}, 'a' * 40, 'b' * 40), [])

    def test_valid_but_wrong_relay_sha_is_rejected(self):
        problems = ci_verify.execution_pin_problems(
            {'relay_commit_sha': 'c' * 40, 'source_commit_sha': 'b' * 40},
            {'source_commit_sha': 'b' * 40}, 'a' * 40, 'b' * 40)
        self.assertIn('relay commit differs from trusted dispatch pin', problems)

    def test_source_drift_in_manifest_or_run_is_rejected(self):
        for manifest_source, run_source in [('c' * 40, 'b' * 40), ('b' * 40, 'c' * 40)]:
            self.assertTrue(ci_verify.execution_pin_problems(
                {'relay_commit_sha': 'a' * 40, 'source_commit_sha': manifest_source},
                {'source_commit_sha': run_source}, 'a' * 40, 'b' * 40))

    def test_missing_malformed_and_zero_pins_are_rejected(self):
        for bad in (None, '', 'main', 'a' * 39, '0' * 40, 'A' * 40):
            for relay_pin, source_pin in ((bad, 'b' * 40), ('a' * 40, bad)):
                with self.assertRaises(ValueError):
                    ci_verify.execution_pin_problems({}, {}, relay_pin, source_pin)

    def test_relay_mismatch_cannot_append_accepted_run_to_ledger(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = test_ci.VerifierTests().make_run(temporary)
            manifest, problems = ci_verify.verify(
                run, Path(temporary), expect_plan='q7_resource_timeout', append=True,
                relay_pin='a' * 40, source_pin='b' * 40)
            self.assertIn('relay commit differs from trusted dispatch pin', problems)
            self.assertFalse((Path(temporary) / 'ci-run-ledger.json').exists())


if __name__ == '__main__':
    unittest.main()
