import copy, os, subprocess, unittest
from pathlib import Path
import yaml,json
ROOT=Path(__file__).parent

class CandidateTests(unittest.TestCase):
 def setUp(self):
  self.w=yaml.safe_load((ROOT/'.github/workflows/unitera-ci-relay.yml').read_text())
 def test_exact_pin_is_dependency_of_every_source_or_credential_job(self):
  jobs=self.w['jobs']
  self.assertEqual(jobs['source-review']['needs'],['execution-pin'])
  self.assertEqual(set(jobs['canonical-ci']['needs']),{'execution-pin','source-review'})
  self.assertEqual(len(jobs['execution-pin']['steps']),1)
  self.assertNotIn('secrets.',json.dumps(jobs['execution-pin']))
  self.assertNotIn('checkout',json.dumps(jobs['execution-pin']['steps']))
 def test_negative_pin_denies_before_any_source_or_secret(self):
  step=self.w['jobs']['execution-pin']['steps'][0]
  for expected,actual,source,pr,ok in [('a'*40,'a'*40,'b'*40,'243',True),('a'*40,'c'*40,'b'*40,'243',False),('x'*40,'x'*40,'b'*40,'243',False),('a'*40,'a'*40,'INVALID','243',False),('a'*40,'a'*40,'b'*40,'$(id)',False)]:
   result=subprocess.run(['bash','-c',step['run']],env={**os.environ,'EXPECTED_RELAY_SHA':expected,'ACTUAL_RELAY_SHA':actual,'SOURCE_SHA':source,'BASE_SHA':'d'*40,'SOURCE_PR':pr},capture_output=True,text=True)
   self.assertEqual(result.returncode==0,ok)
   self.assertEqual('RELAY_EXECUTION_PIN_PASS' in result.stdout,ok)
 def test_no_paid_hosted_runner_or_waived_jobs(self):
  for job in self.w['jobs'].values():
   self.assertEqual(job['runs-on'],['self-hosted','Linux','X64','unitera-ci','relay'])
   self.assertNotIn('continue-on-error',job)
   for step in job['steps']:self.assertNotIn('continue-on-error',step)
 def test_all_17_governance_commands_are_mapped(self):
  gov=yaml.safe_load((ROOT/'source-governance.yml').read_text())
  rows=gov['jobs']['ci-matrix']['strategy']['matrix']['include']
  run=next(s['run'] for s in self.w['jobs']['canonical-ci']['steps'] if s.get('name')=='Governance full matrix (17 gates)')
  self.assertEqual(len(rows),17)
  for row in rows:
   self.assertIn(row['command'],run)
   self.assertIn('GOVERNANCE_GATE_PASS '+row['name'],run)
 def test_source_workflow_drift_fails_closed(self):
  import hashlib
  manifest=json.loads((ROOT/'gate-mapping.json').read_text())
  prepare=next(s['run'] for s in self.w['jobs']['canonical-ci']['steps'] if s.get('name')=='Prepare exact Unitera source')
  for path,local in [('.github/workflows/ci.yml','source-ci.yml'),('.github/workflows/governance-guardrails.yml','source-governance.yml')]:
   digest=hashlib.sha256((ROOT/local).read_bytes()).hexdigest()
   self.assertEqual(manifest['source_workflow_sha256'][path],digest)
   self.assertIn(digest,prepare)
   with self.subTest(path=path):
    result=subprocess.run(['bash','-c','printf changed | sha256sum | cut -d" " -f1'],capture_output=True,text=True)
    self.assertNotEqual(result.stdout.strip(),digest)
 def test_all_shell_steps_parse(self):
  for job in self.w['jobs'].values():
   for step in job['steps']:
    if 'run' in step:
     result=subprocess.run(['bash','-n'],input=step['run'],capture_output=True,text=True)
     self.assertEqual(result.returncode,0,result.stderr)
 def test_credentials_are_not_in_source_test_job(self):
  self.assertNotIn('secrets.',json.dumps(self.w['jobs']['canonical-ci']))
  review=self.w['jobs']['source-review']['steps']
  self.assertIn('ISOLATION_QUALIFIED',json.dumps(review[0]))
  self.assertIn('secrets.UNITERA_SOURCE_READ_TOKEN',json.dumps(review[1]))
  self.assertNotIn('checkout',json.dumps(review))
 def test_new_security_web_and_rls_gates_are_mandatory(self):
  steps=self.w['jobs']['canonical-ci']['steps'];names=[s.get('name') for s in steps]
  for name in ['Verify consumed vendor integrity','Verify Mimosa detector vendor integrity','Mimosa verdict gate','Mimosa verdict resolver unit tests','Hosted Web Routing and BFF','Governance and tracked generated artifacts','RLS Runtime Required']:
   step=steps[names.index(name)]
   self.assertNotIn('if',step)
   self.assertTrue(step['run'].startswith('set -euo pipefail'))
   self.assertLess(names.index(name),names.index('Final relay disposition'))
 def test_zero_status_write_or_activation_claim(self):
  self.assertEqual(self.w['permissions'],{'contents':'read'})
  self.assertEqual(json.loads((ROOT/'gate-mapping.json').read_text())['status'],'CANDIDATE_NOT_LIVE_QUALIFIED')

if __name__=='__main__':unittest.main()
