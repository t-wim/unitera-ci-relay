"""Offline negative/boundary tests. Live VM evidence is a separate private ledger."""
import copy
import importlib
from pathlib import Path
import subprocess
import sys
import types
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vm'))
image = importlib.import_module('image')
lane = importlib.import_module('lane')
paths = importlib.import_module('paths')
qualifier = importlib.import_module('qualify')


class VMContractTests(unittest.TestCase):
    def test_no_guest_host_shares_or_forwarding_and_no_extra_arguments(self):
        argv = lane.command(Path('/synthetic-assets'), Path('/synthetic-job'), 'synthetic.scope')
        qemu = argv[argv.index('/usr/bin/qemu-system-x86_64'):]
        for forbidden in ['-drive', '-fsdev', '-virtfs', '-chardev', '-qmp', '-daemonize']:
            self.assertNotIn(forbidden, qemu)
        self.assertIn('user,id=isolated,restrict=on,ipv6=off', qemu)
        self.assertIn('--unshare-all', argv)
        self.assertIn('--clearenv', argv)
        self.assertIn('--die-with-parent', argv)
        for value in ['MemoryMax=1G', 'MemorySwapMax=0', 'CPUQuota=100%', 'TasksMax=128']:
            self.assertIn(value, argv)
        for value in ['hostfwd=', 'guestfwd=', 'smb=', 'tftp=', 'SSH_AUTH_SOCK', 'DOCKER_HOST']:
            self.assertNotIn(value, ' '.join(argv))

    def test_private_artifacts_cannot_be_in_repo_or_outside_authorized_workspace(self):
        with self.assertRaises(ValueError):
            paths.private_path(ROOT / 'private')
        with self.assertRaises(ValueError):
            paths.private_path('/etc/synthetic-vm-artifacts')

    def test_resources_fail_closed_without_allocating_a_vm(self):
        for available, disk in [(2, 40), (4, 31)]:
            with patch.object(lane.Path, 'read_text', return_value=f'MemAvailable: {available * 1024 ** 2} kB\n'), \
                 patch.object(lane.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=disk * lane.GIB)):
                with self.assertRaisesRegex(RuntimeError, 'BLOCKED_RESOURCES'):
                    lane.budget(ROOT)

    def test_resource_budget_has_hard_scope_and_personal_reserve(self):
        with patch.object(lane.Path, 'read_text', return_value='MemAvailable: 4194304 kB\n'), \
             patch.object(lane.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=40 * lane.GIB)):
            budget = lane.budget(ROOT)
        self.assertEqual(budget['guest_mib'], 768)
        self.assertEqual(budget['scope_memory_max_bytes'], lane.GIB)
        self.assertEqual(budget['scope_swap_max'], 0)
        self.assertEqual(budget['concurrency'], 1)

    def test_distinct_run_directories_contend_for_one_slot(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as directory:
            root = Path(directory)
            first = lane.acquire_slot(root / 'assets', root / 'run-01')
            try:
                with self.assertRaises(BlockingIOError):
                    lane.acquire_slot(root / 'assets', root / 'run-02')
            finally:
                first.close()
            lane.acquire_slot(root / 'assets', root / 'run-02').close()

    def test_builder_rejects_resolved_escape_before_read(self):
        with patch.object(image.Path, 'resolve', return_value=Path('/etc/synthetic')), \
             patch.object(image.Path, 'read_bytes', side_effect=AssertionError('must not read')):
            for path in ['/usr/bin/../../etc/synthetic', '/usr/lib/synthetic-symlink']:
                with self.assertRaises(ValueError):
                    image.verified_system_file(path)

    def test_archive_path_escape_is_denied(self):
        for path in ['../escape', '/absolute', 'safe/../../escape']:
            with self.assertRaises(ValueError):
                image.cpio({path: (b'invented', 0o600)})

    def test_archive_roundtrip_lists_only_synthetic_files(self):
        data = image.cpio({'invented/file': (b'synthetic only', 0o600)})
        result = subprocess.run(['cpio', '-it', '--quiet'], input=data, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.decode().splitlines(), ['invented', 'invented/file'])

    def test_builder_refuses_personal_or_configuration_files_before_read(self):
        with patch.object(image.Path, 'read_bytes', side_effect=AssertionError('must not read')):
            for path in ['/etc/shadow', '/home/synthetic/.ssh/key', '/run/docker.sock']:
                with self.assertRaises(ValueError):
                    image.verified_system_file(path)

    def test_guest_script_has_no_host_commands_and_shell_syntax_is_valid(self):
        source = (ROOT / 'vm/guest-init.sh').read_text()
        result = subprocess.run(['sh', '-n'], input=source, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('docker run --rm --network=none', source)
        self.assertIn('DOCKER_HOST=unix:///run/docker.sock', source)
        self.assertIn('switch_root /newroot /init stage2', source)


class QualificationDecisionTests(unittest.TestCase):
    def complete(self):
        outcomes = ['success', 'failure', 'timeout', 'cancel', 'success']
        results = []
        for outcome in outcomes:
            results.append({'outcome': outcome, 'ready_seen': True, 'qualification_pass': True,
                            'checks': {name: 'PASS' for name in lane.REQUIRED_CHECKS},
                            'cleanup_verified': True, 'limits_verified': True, 'inputs_unchanged': True, 'scope_ownership_verified': True,
                            'canary_contents_absent_from_console': True, 'observed_pids': [123],
                            'scope_remaining_pids': [], 'observed_pids_still_exist': [],
                            'final_scope_load_state': 'not-found', 'process_returncode': {'success': 33, 'failure': 35}.get(outcome, -9),
                            'termination_requested_while_running': True, 'cancel_signal_received': 15,
                            'ready_to_timeout_seconds': 2.1})
        return results, outcomes, {'loopback': True, 'lan': True, 'unix': True}, []

    def test_only_complete_five_run_evidence_can_qualify(self):
        self.assertTrue(qualifier.qualified(*self.complete()))

    def test_fake_pass_missing_checks_cleanup_or_actual_vm_denies(self):
        for key, bad in [('checks', {}), ('ready_seen', False), ('cleanup_verified', False),
                         ('inputs_unchanged', False), ('limits_verified', False), ('scope_ownership_verified', False), ('observed_pids', []),
                         ('final_scope_load_state', 'unknown'), ('process_returncode', 0)]:
            args = list(self.complete())
            args[0][0][key] = bad
            self.assertFalse(qualifier.qualified(*args), key)

    def test_leftover_jobs_and_failed_positive_controls_deny(self):
        args = list(self.complete()); args[3] = ['synthetic-leftover']
        self.assertFalse(qualifier.qualified(*args))
        args = list(self.complete()); args[2]['lan'] = False
        self.assertFalse(qualifier.qualified(*args))

    def test_missing_outcomes_or_unproven_cancel_and_timeout_deny(self):
        args = list(self.complete()); args[0] = args[0][:-1]
        self.assertFalse(qualifier.qualified(*args))
        for index, key, bad in [(3, 'cancel_signal_received', None), (2, 'ready_to_timeout_seconds', 0),
                                (2, 'termination_requested_while_running', False)]:
            args = list(self.complete()); args[0][index][key] = bad
            self.assertFalse(qualifier.qualified(*args))


if __name__ == '__main__':
    unittest.main()
