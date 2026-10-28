"""Focused W2 offline regressions; no application code, network or VM execution."""
import hashlib,io,json,subprocess,sys,tarfile,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'vm'))
import ci_verify,ci_util,ci_prep,baum_ci_custody,baum_status_candidate
import test_ci

class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.run=test_ci.VerifierTests().make_run(self.root/'run')
        self.private=self.root/'private';self.private.mkdir()
        r=json.loads((self.run/'run.json').read_text());r['source_commit_sha']='b'*40
        (self.run/'run.json').write_text(json.dumps(r));self.reseal()
    def reseal(self):
        p=self.run/'evidence/envelope.json';e=json.loads(p.read_text())
        e['run_json_sha256']=ci_util.sha256_file(self.run/'run.json')
        for name in e['files']:e['files'][name]=ci_util.sha256_file(self.run/'evidence'/name)
        p.write_text(json.dumps(e))
    def verify(self,**kwargs):
        pins={'relay_pin':'d'*40,'source_pin':'b'*40};pins.update(kwargs)
        return ci_verify.verify(self.run,self.private,expect_plan='q7_resource_timeout',**pins)
    def test_valid_synthetic_evidence_consistent(self):self.assertEqual(self.verify()[1],[])
    def test_wrong_relay_pin_rejected(self):self.assertTrue(any('relay commit differs' in p for p in self.verify(relay_pin='e'*40)[1]))
    def test_wrong_source_pin_rejected(self):self.assertTrue(any('source commit differs' in p for p in self.verify(source_pin='e'*40)[1]))
    def test_missing_external_pins_cannot_verify(self):
        with self.assertRaises(TypeError):ci_verify.verify(self.run,self.private,expect_plan='q7_resource_timeout')
    def test_missing_trusted_plan_rejected(self):
        with self.assertRaisesRegex(ValueError,'trusted caller'):
            ci_verify.verify(self.run,self.private,relay_pin='d'*40,source_pin='b'*40)
    def test_missing_exit_denied_even_when_envelope_recomputed(self):
        p=self.run/'evidence/console.log';p.write_text(p.read_text().replace('EXIT fixture_hold_timeout 0\n',''));self.reseal()
        self.assertTrue(any('missing mandatory EXIT/TMO' in p for p in self.verify()[1]))
    def test_duplicate_pass_denied_even_when_envelope_recomputed(self):
        p=self.run/'evidence/console.log';p.write_text(p.read_text()+'CHECK fixture_hold_timeout PASS\n');self.reseal()
        self.assertTrue(any('duplicate console CHECK' in p for p in self.verify()[1]))
    def test_duplicate_timeout_record_rejected(self):
        p=self.run/'evidence/console.log';p.write_text(p.read_text()+'TMO fixture_hold_timeout 0\n');self.reseal()
        self.assertTrue(any('duplicate console TMO' in p for p in self.verify()[1]))
    def test_omitted_envelope_files_rejected(self):
        p=self.run/'evidence/envelope.json';e=json.loads(p.read_text());e['files']={};p.write_text(json.dumps(e))
        self.assertTrue(any('mandatory file set' in p for p in self.verify()[1]))
    def test_evidence_path_traversal_not_read(self):
        p=self.run/'evidence/envelope.json';e=json.loads(p.read_text());e['files']['../../not-read']='0'*64;p.write_text(json.dumps(e))
        self.assertTrue(any('unsafe/unexpected evidence name' in p for p in self.verify()[1]))
    def test_duplicate_manifest_check_rejected(self):
        p=self.run/'evidence/manifest.json';m=json.loads(p.read_text());m['checks'].append(m['checks'][0]);p.write_text(json.dumps(m));self.reseal()
        self.assertTrue(any('duplicate check' in p for p in self.verify()[1]))
    def test_repeated_run_id_rejected(self):
        self.assertEqual(self.verify(append=True)[1],[])
        with self.assertRaisesRegex(ValueError,'REPLAY_REJECTED'):self.verify(append=True)
    def test_incomplete_cleanup_rejected(self):
        p=self.run/'evidence/manifest.json';m=json.loads(p.read_text());m['cleanup_result']='FAIL';p.write_text(json.dumps(m));self.reseal()
        self.assertTrue(any('cleanup_result not PASS' in p for p in self.verify()[1]))
    def test_cli_missing_evidence_is_explicit_indeterminate(self):
        (self.run/'evidence/manifest.json').unlink()
        result=subprocess.run([sys.executable,str(ROOT/'vm/ci_verify.py'),'--run',str(self.run),
                    '--private',str(self.private),'--expect-plan','q7_resource_timeout',
                    '--relay-pin','d'*40,'--source-pin','b'*40],capture_output=True,text=True)
        self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stdout)['verdict'],'INDETERMINATE')

class SourceCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.repo=Path(self.temp.name)/'repo';self.repo.mkdir();self.git('init','-q')
        self.git('config','user.name','Synthetic');self.git('config','user.email','synthetic@example.invalid')
        self.git('remote','add','origin','https://github.com/baum777/baum-os.git')
        (self.repo/'input.txt').write_text('SYNTHETIC COMMITTED\n');self.git('add','input.txt');self.git('commit','-qm','fixture')
        self.sha=self.git('rev-parse','HEAD').strip()
    def git(self,*args):
        r=subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','commit.gpgSign=false','-C',str(self.repo),*args],capture_output=True,text=True)
        if r.returncode:raise RuntimeError(r.stderr)
        return r.stdout
    def test_dirty_tree_is_not_source(self):
        a=baum_ci_custody.source_inventory(self.repo,self.sha)
        (self.repo/'input.txt').write_text('UNCOMMITTED');(self.repo/'foreign').write_text('NOT SOURCE')
        b=baum_ci_custody.source_inventory(self.repo,self.sha)
        self.assertEqual(a,b);self.assertEqual(a['regular_file_count'],1)
    def test_repository_mismatch_fails(self):
        self.git('remote','set-url','origin','https://github.com/wrong/repo.git')
        with self.assertRaisesRegex(ValueError,'repository identity'):baum_ci_custody.source_inventory(self.repo,self.sha)
    def test_plan_repository_identity_is_not_inferred_from_paths(self):
        self.git('remote','set-url','origin','https://github.com/wrong/repo.git')
        with self.assertRaisesRegex(ValueError,'repository identity'):baum_ci_custody.source_plan(self.repo,self.sha)
    def test_source_symlink_never_materialized_or_followed(self):
        (self.repo/'link').symlink_to('/nonexistent/SYNTHETIC_SECRET');self.git('add','link');self.git('commit','-qm','link')
        result=baum_ci_custody.source_inventory(self.repo,self.git('rev-parse','HEAD').strip())
        self.assertIn('SOURCE_SYMLINKS_UNSUPPORTED_BY_CURRENT_GUEST_PROFILE',result['admission_blockers'])
        self.assertEqual(result['source_custody'],'PARTIAL');self.assertFalse(result['host_source_execution'])
    def test_source_ref_must_not_float(self):
        with self.assertRaisesRegex(ValueError,'full nonzero'):baum_ci_custody.source_inventory(self.repo,'main')
    def test_plan_ref_must_not_float(self):
        with self.assertRaisesRegex(ValueError,'full nonzero'):baum_ci_custody.source_plan(self.repo,'main')
    def test_unsafe_paths_rejected(self):
        for name in ('../escape','/absolute','safe/.git/config','a/../../b'):
            with self.assertRaises(ValueError):baum_ci_custody.validate_path(name)
    def test_tampered_source_archive_rejected(self):
        p=Path(self.temp.name)/'source.tar'
        with tarfile.open(p,'w') as t:
            m=tarfile.TarInfo('a');m.size=4;t.addfile(m,io.BytesIO(b'evil'))
        original=hashlib.sha1(b'blob 4\0good').hexdigest()
        with self.assertRaisesRegex(ValueError,'git blob object id mismatch'):
            ci_prep._archive_inventory(p,{'a':[original,'100644']})

class LauncherIdentityTests(unittest.TestCase):
    def test_nested_git_records_relay_not_workspace_without_starting_vm(self):
        with tempfile.TemporaryDirectory() as temp:
            outer=Path(temp)/'workspace';relay=outer/'relay';(relay/'vm').mkdir(parents=True)
            def commit(repo,name):
                def g(*args):
                    r=subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','commit.gpgSign=false',
                                      '-C',str(repo),*args],capture_output=True,text=True)
                    if r.returncode:raise RuntimeError(r.stderr)
                    return r.stdout.strip()
                g('init','-q');g('config','user.name','Synthetic');g('config','user.email','synthetic@example.invalid')
                (repo/'identity').write_text(name);g('add','identity');g('commit','-qm',name)
                return g('rev-parse','HEAD')
            outer_sha=commit(outer,'outer');relay_sha=commit(relay,'relay')
            self.assertNotEqual(outer_sha,relay_sha)
            launcher=relay/'vm/ci_start.sh';launcher.write_bytes((ROOT/'vm/ci_start.sh').read_bytes())
            run=Path(temp)/'run';(run/'launch').mkdir(parents=True)
            base=run/'base';base.touch();overlay=run/'overlay';overlay.touch()
            (run/'launch/overlay.txt').write_text(str(base)+'\n'+str(overlay)+'\n')
            (run/'launch/argv.args').write_text('/usr/bin/true\n')
            result=subprocess.run(['sh',str(launcher),str(run)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((run/'relay-head.txt').read_text().strip(),relay_sha)

class StatusCandidateTests(unittest.TestCase):
    def test_blocked_payload_is_valid_but_never_sent(self):
        candidate=baum_status_candidate.blocked_candidate('a'*40,'b'*64,'c'*64)
        self.assertEqual(baum_status_candidate.validate(candidate),{'payload_valid':True,'delivery_authorized':False,'provider_effect':'NOT_SENT'})
    def test_unknown_verdict_cannot_be_success(self):
        candidate=baum_status_candidate.blocked_candidate('a'*40,'b'*64,'c'*64);candidate['body']['state']='success'
        with self.assertRaises(ValueError):baum_status_candidate.validate(candidate)
    def test_payload_cannot_grant_its_own_send_authority(self):
        candidate=baum_status_candidate.blocked_candidate('a'*40,'b'*64,'c'*64);candidate['send_authorized']=True
        with self.assertRaises(ValueError):baum_status_candidate.validate(candidate)

if __name__=='__main__':unittest.main(verbosity=2)
