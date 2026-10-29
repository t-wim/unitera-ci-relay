"""Format and validate a NOT-SENT baum-os status candidate. Contains no writer."""
import re

REPOSITORY='baum777/baum-os'
CONTEXT='unitera/sovereign-ci/baum-os'

def blocked_candidate(source_sha,plan_sha256,evidence_index_sha256):
    if re.fullmatch(r'[0-9a-f]{40}',source_sha) is None or source_sha=='0'*40:
        raise ValueError('exact nonzero source SHA required')
    for value in (plan_sha256,evidence_index_sha256):
        if re.fullmatch(r'[0-9a-f]{64}',value) is None:raise ValueError('invalid evidence/plan digest')
    return {'schema':'relay.baum-status-candidate.v1','repository':REPOSITORY,'source_sha':source_sha,
            'method':'POST','endpoint':'/repos/'+REPOSITORY+'/statuses/'+source_sha,
            'body':{'state':'error','context':CONTEXT,
                    'description':'W2 BLOCKED: no admitted VM source execution or independent acceptance'},
            'plan_sha256':plan_sha256,'evidence_index_sha256':evidence_index_sha256,
            'independent_verdict':'INDETERMINATE','actual_source_run_id':None,
            'send_authorized':False,'provider_effect':'NOT_SENT',
            'missing_gates':['T_WIM_CUSTODY','HOST_EXECUTION_AUTHORITY','CURRENT_VM_QUALIFICATION',
                             'IN_GUEST_SOURCE_CUSTODY','INDEPENDENT_REAL_RUN_VERIFICATION','STATUS_WRITE_AUTHORITY']}

def validate(candidate):
    expected=blocked_candidate(candidate['source_sha'],candidate['plan_sha256'],candidate['evidence_index_sha256'])
    if candidate!=expected:raise ValueError('blocked candidate modified; no status-success or send authority can be inferred')
    return {'payload_valid':True,'delivery_authorized':False,'provider_effect':'NOT_SENT'}
