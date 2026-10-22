"""Own synthetic host canaries and sequential VM cases. All evidence stays private."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import socket
import socketserver
import subprocess
import threading

from lane import private_path, run, REQUIRED_CHECKS


def qualified(results, outcomes, positive, remaining):
    if outcomes != ['success', 'failure', 'timeout', 'cancel', 'success'] or len(results) != 5 or remaining:
        return False
    if len(positive) < 3 or not all(positive.values()):
        return False
    for expected, result in zip(outcomes, results):
        if result.get('outcome') != expected or not result.get('ready_seen') or not result.get('qualification_pass'):
            return False
        if set(result.get('checks', {})) != REQUIRED_CHECKS or any(v != 'PASS' for v in result['checks'].values()):
            return False
        if not all(result.get(key) for key in ['cleanup_verified', 'limits_verified', 'inputs_unchanged', 'canary_contents_absent_from_console', 'scope_ownership_verified']):
            return False
        if not result.get('observed_pids') or result.get('scope_remaining_pids') or result.get('observed_pids_still_exist'):
            return False
        if result.get('final_scope_load_state') != 'not-found':
            return False
        if expected in {'success', 'failure'} and result.get('process_returncode') != {'success': 33, 'failure': 35}[expected]:
            return False
        if expected in {'timeout', 'cancel'} and not result.get('termination_requested_while_running'):
            return False
        if expected == 'cancel' and result.get('cancel_signal_received') != 15:
            return False
        if expected == 'timeout' and result.get('ready_to_timeout_seconds', 0) < 2:
            return False
    return True


def qualify(assets, private, outcomes):
    implementation = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in Path(__file__).parent.iterdir() if p.is_file()}
    private = private_path(private)
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    protected = private / 'protected'
    protected.mkdir(mode=0o700, exist_ok=True)
    canaries = {}
    for label in ['host', 'review', 'status']:
        path = protected / (label + '.canary')
        value = ('SYNTHETIC_ONLY_' + secrets.token_hex(24)).encode()
        path.write_bytes(value)
        path.chmod(0o600)
        canaries[label] = (path, value)
    response = ('SYNTHETIC_SERVICE_' + secrets.token_hex(16) + '\n').encode()
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(response)
    server = socketserver.TCPServer(('0.0.0.0', 0), Handler)
    server.timeout = 1
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    unix_path = private / 'd.sock'
    unix_server = socketserver.UnixStreamServer(str(unix_path), Handler)
    unix_worker = threading.Thread(target=unix_server.serve_forever, daemon=True)
    unix_worker.start()
    port = server.server_address[1]
    addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'address', 'show', 'scope', 'global']))
    local = next((addr['local'] for interface in addresses for addr in interface.get('addr_info', [])
                  if addr.get('family') == 'inet'), None)
    if local is None:
        server.shutdown(); server.server_close()
        unix_server.shutdown(); unix_server.server_close(); unix_path.unlink()
        raise RuntimeError('no LAN address for a positively verified synthetic host endpoint')
    probe = {'LAN_PROBE': local, 'HOST_PORT': port, 'HOST_CANARY_PATH': str(canaries['host'][0]),
             'REVIEW_CANARY_PATH': str(canaries['review'][0]), 'STATUS_CANARY_PATH': str(canaries['status'][0]),
             'DOCKER_CANARY_PATH': str(unix_path)}
    positive = {}
    results = []
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        for address in ['127.0.0.1', local]:
            with socket.create_connection((address, port), timeout=2) as sock:
                positive[address] = sock.recv(1024) == response
        with socket.socket(socket.AF_UNIX) as sock:
            sock.connect(str(unix_path))
            positive['synthetic_unix_socket'] = sock.recv(1024) == response
        if not all(positive.values()):
            raise RuntimeError('host synthetic service positive control failed')
        for outcome in outcomes:
            mode = outcome if outcome in {'success', 'failure'} else 'hold'
            result, directory = run(assets, private, mode, probe, outcome)
            console = (directory / 'console.log').read_bytes()
            result['canary_contents_absent_from_console'] = all(value not in console for _, value in canaries.values())
            result['evidence'] = str(directory)
            result['qualification_pass'] &= result['canary_contents_absent_from_console']
            (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            results.append(result)
            print(json.dumps({'outcome': outcome, 'pass': result['qualification_pass'], 'duration': result['duration_seconds'],
                              'evidence': str(directory)}, sort_keys=True), flush=True)
            if not result['qualification_pass']:
                break
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        unix_server.shutdown()
        unix_server.server_close()
        unix_worker.join(timeout=3)
        unix_path.unlink()
    remaining = [str(p) for p in private.glob('job-*')]
    record = {'started_at': started, 'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'synthetic_only': True, 'host_service_positive_controls': positive,
              'synthetic_host_service_port': port, 'host_service_closed': True,
              'canary_digests': {name: hashlib.sha256(value).hexdigest() for name, (_, value) in canaries.items()},
              'results': results, 'job_directories_remaining': remaining,
              'VM_ISOLATION_QUALIFIED': qualified(results, outcomes, positive, remaining)}
    record['implementation_hashes'] = implementation
    record['implementation_unchanged'] = implementation == {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in Path(__file__).parent.iterdir() if p.is_file()}
    record['VM_ISOLATION_QUALIFIED'] &= record['implementation_unchanged']
    (private / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def exit_code(report, smoke=False):
    if smoke:
        # A smoke run tests one case; it never asserts full VM qualification.
        results = report.get('results', [])
        return 0 if len(results) == 1 and results[0].get('qualification_pass') is True else 1
    return 0 if report.get('VM_ISOLATION_QUALIFIED') is True else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--private', type=Path, required=True)
    parser.add_argument('--smoke', action='store_true')
    args = parser.parse_args(argv)
    outcomes = ['success'] if args.smoke else ['success', 'failure', 'timeout', 'cancel', 'success']
    report = qualify(args.assets, args.private, outcomes)
    return exit_code(report, smoke=args.smoke)


if __name__ == '__main__':
    raise SystemExit(main())
