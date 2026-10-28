"""Read-only baum-os Git custody and full workflow planning for the existing VM lane.

This module never executes source or starts a VM. Unsupported modes/guest requirements
remain explicit admission blockers. The Systems plan, image and workflow are unchanged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import yaml

REPOSITORY = 'baum777/baum-os'
REMOTES = {'https://github.com/baum777/baum-os.git', 'git@github.com:baum777/baum-os.git'}
WORKFLOWS = ('governance-guardrails.yml', 'secret-protection.yml', 'submodule-reachability.yml')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def environment():
    return {'PATH':'/usr/bin:/bin', 'HOME':'/nonexistent', 'GIT_CONFIG_NOSYSTEM':'1',
            'GIT_CONFIG_GLOBAL':'/dev/null', 'GIT_OPTIONAL_LOCKS':'0',
            'GIT_TERMINAL_PROMPT':'0', 'GIT_NO_LAZY_FETCH':'1'}

def git_args(repo, *args):
    return ['/usr/bin/git','--no-replace-objects','-c','core.fsmonitor=false',
            '-c','core.hooksPath=/dev/null','-C',str(repo),*args]

def git(repo, *args):
    return subprocess.run(git_args(repo,*args), env=environment(), check=True,
                          capture_output=True,timeout=120).stdout

def validate_path(path):
    if not path or path.startswith('/') or any(p in ('','.','..') or p.lower()=='.git' for p in path.split('/')):
        raise ValueError('unsafe source path')
    if any(ch in path for ch in ('\0','\n','\r')):
        raise ValueError('unrepresentable source path')

def source_inventory(repo, commit):
    preparer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if re.fullmatch(r'[0-9a-f]{40}',commit) is None or commit == '0'*40:
        raise ValueError('full nonzero commit SHA required')
    remote=git(repo,'remote','get-url','origin').decode().strip()
    if remote not in REMOTES: raise ValueError('repository identity mismatch')
    if git(repo,'rev-parse','--verify',commit+'^{commit}').decode().strip()!=commit:
        raise ValueError('source SHA mismatch')
    tree=git(repo,'rev-parse',commit+'^{tree}').decode().strip()
    rows=[]
    for item in git(repo,'ls-tree','-r','-z',commit).split(b'\0'):
        if not item:continue
        metadata,name=item.split(b'\t',1); mode,kind,oid=metadata.decode().split()
        path=name.decode('utf-8'); validate_path(path)
        if mode not in ('100644','100755','120000','160000'):
            raise ValueError('unsupported Git mode')
        rows.append({'path':path,'mode':mode,'kind':kind,'git_object':oid})
    process=subprocess.Popen(git_args(repo,'cat-file','--batch'), env=environment(),
                             stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    total=0
    try:
        for row in rows:
            if row['mode']=='160000':continue
            process.stdin.write((row['git_object']+'\n').encode());process.stdin.flush()
            header=process.stdout.readline().decode().strip().split()
            if len(header)!=3 or header[:2]!=[row['git_object'],'blob']:
                raise ValueError('missing/mismatched Git blob')
            size=int(header[2]); total+=size
            if size>128*1024**2 or total>1024**3:raise ValueError('source data budget exceeded')
            sha1=hashlib.sha1(b'blob '+str(size).encode()+b'\0');sha256=hashlib.sha256()
            remaining=size
            while remaining:
                chunk=process.stdout.read(min(1024*1024,remaining))
                if not chunk:raise ValueError('truncated Git blob')
                sha1.update(chunk);sha256.update(chunk);remaining-=len(chunk)
            if process.stdout.read(1)!=b'\n' or sha1.hexdigest()!=row['git_object']:
                raise ValueError('Git blob identity mismatch')
            row.update({'sha256':sha256.hexdigest(),'bytes':size})
    finally:
        process.stdin.close();process.stdout.close()
        if process.poll() is None:
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
    if process.returncode!=0:raise ValueError('Git object stream failed')
    blockers=[]
    symlinks=[row['path'] for row in rows if row['mode']=='120000']
    gitlinks=[row['path'] for row in rows if row['mode']=='160000']
    if symlinks:blockers.append('SOURCE_SYMLINKS_UNSUPPORTED_BY_CURRENT_GUEST_PROFILE')
    if gitlinks:blockers.append('GITLINKS_AND_FRESH_REMOTE_REACHABILITY_NOT_PROVISIONED')
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest()!=preparer_sha256:
        raise ValueError('source preparer changed during inventory')
    return {'schema':'relay.baum-source-custody.v1','repository':REPOSITORY,'remote':remote,
            'preparer_sha256':preparer_sha256,
            'source_sha':commit,'git_tree_sha':tree,'source_inventory_sha256':hashlib.sha256(canonical(rows)).hexdigest(),
            'entries':rows,'file_count':len(rows)-len(gitlinks),'regular_file_count':len(rows)-len(gitlinks)-len(symlinks),
            'symlinks':symlinks,'gitlinks':gitlinks,'blob_bytes_verified':total,
            'host_source_execution':False,'git_blob_inventory_binding':'VERIFIED',
            'guest_file_integrity':'NOT_RUN','source_custody':'PARTIAL',
            'admission_blockers':blockers+['GUEST_IMAGE_TOOLCHAIN_AND_IN_GUEST_VERIFICATION_NOT_QUALIFIED']}

def source_plan(repo, commit):
    if re.fullmatch(r'[0-9a-f]{40}',commit) is None or commit == '0'*40:
        raise ValueError('full nonzero commit SHA required for plan')
    if git(repo,'remote','get-url','origin').decode().strip() not in REMOTES:
        raise ValueError('repository identity mismatch for plan')
    workflows=[]; commands=0
    for name in WORKFLOWS:
        path='.github/workflows/'+name
        raw=git(repo,'show',commit+':'+path)
        data=yaml.load(raw,Loader=yaml.BaseLoader)
        workflow={'path':path,'source_sha':commit,'sha256':hashlib.sha256(raw).hexdigest(),
                  'name':data['name'],'on':data.get('on'),'env':data.get('env'),
                  'permissions':data.get('permissions'),'concurrency':data.get('concurrency'),'jobs':{}}
        for job_id,job in data['jobs'].items():
            result={key:value for key,value in job.items() if key!='steps'};result['steps']=[]
            for number,step in enumerate(job['steps'],1):
                record=dict(step)
                if 'run' in step:
                    body=step['run'];commands+=1
                    record['run_sha256']=hashlib.sha256(body.encode()).hexdigest()
                    record['script_path']='/plan/'+name+'/'+job_id+'/'+str(number)+'.sh'
                    shell=step.get('shell','bash')
                    record['exact_argv']=(['bash','--noprofile','--norc','-e','-o','pipefail',record['script_path']]
                                          if 'shell' in step and shell=='bash' else ['bash','-e',record['script_path']])
                    record['unresolved_github_expression']='${{' in body
                    record['execution_state']='NOT_RUN'
                else:record['action_translation']='NOT_QUALIFIED'
                result['steps'].append(record)
            workflow['jobs'][job_id]=result
        workflows.append(workflow)
    package=json.loads(git(repo,'show',commit+':package.json'))
    lock=git(repo,'show',commit+':pnpm-lock.yaml')
    plan={'schema':'relay.baum-source-plan.v1','repository':REPOSITORY,'source_sha':commit,
          'planner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'package_manager':package['packageManager'],'node_major':24,
          'package_json_sha256':hashlib.sha256(git(repo,'show',commit+':package.json')).hexdigest(),
          'dependency_lock_sha256':hashlib.sha256(lock).hexdigest(),'workflows':workflows,
          'workflow_count':len(workflows),'job_count':sum(len(w['jobs']) for w in workflows),'run_step_count':commands,
          'ci_parity':'MISSING','admission':'BLOCKED',
          'blockers':['CURRENT_VM_HAS_PNPM_10_NOT_REQUIRED_11','BASH_AND_GIT_NOT_IN_CURRENT_GUEST',
                      'FROZEN_DEPENDENCY_CLOSURE_NOT_PREPARED','GIT_HISTORY_AND_EVENT_BASIS_NOT_PROVISIONED',
                      'REMOTE_REACHABILITY_REQUIRES_SEPARATE_CREDENTIAL_CUSTODY_AND_FRESH_NETWORK_PROOF',
                      'ACTION_CONTEXT_IF_AND_SUMMARY_PARITY_NOT_QUALIFIED']}
    plan['execution_plan_sha256']=hashlib.sha256(canonical(plan)).hexdigest()
    return plan

def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True)
    p.add_argument('--source-sha',required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for name,data in [('source-inventory.json',source_inventory(a.repo,a.source_sha)),
                      ('execution-plan.json',source_plan(a.repo,a.source_sha))]:
        (a.output/name).write_text(json.dumps(data,indent=2)+'\n')
    print(json.dumps({'repository':REPOSITORY,'source_sha':a.source_sha,'source_custody':'PARTIAL',
                      'source_execution':'NOT_RUN','output':str(a.output)}))

if __name__=='__main__':main()
