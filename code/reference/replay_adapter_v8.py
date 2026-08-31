from __future__ import annotations
import hashlib,json
from copy import deepcopy
from typing import Iterable,Mapping

from network_config_v8 import render_state_configs

def canonical_json_bytes(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def canonical_sha256(obj): return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()
def canonical_bundle_sha256(configs): return canonical_sha256({k:configs[k] for k in sorted(configs)})
def _norm(owners): return {str(s):sorted({str(x) for x in xs}) for s,xs in sorted(owners.items())}

def apply_step_to_owners(owners,step):
    state={s:set(xs) for s,xs in _norm(owners).items()}; obj=str(step.get('object_id'))
    if obj not in state: state[obj]=set()
    op=step.get('operation'); dev=str(step.get('device_id'))
    if op=='add': state[obj].add(dev)
    elif op=='remove': state[obj].discard(dev)
    return {s:sorted(xs) for s,xs in sorted(state.items())}

def _states(case):
    state=_norm(case['baseline_owners']); forward=[]; cuts=[]
    for i,step in enumerate(case['forward_plan'],1):
        state=apply_step_to_owners(state,step); forward.append((f'forward-{i:02d}',state)); cuts.append(deepcopy(state))
    recovery=[]
    for cut,cut_state in enumerate(cuts,1):
        state=cut_state; rows=[]
        for j,step in enumerate(case['contingency_plan'],1):
            state=apply_step_to_owners(state,step); rows.append((f'recovery-cut-{cut:02d}-step-{j:02d}',state))
        recovery.append({'cut_index':cut,'states':rows})
    return forward,recovery

def _query_plan(case,state_ids):
    return {'schema':'GRANT1_PE8_BATFISH_QUERY_PLAN_V1','states':list(state_ids),'queries':[{'type':'initIssues'},*[{'type':'routes','network':svc,'nodes':'.*'} for svc in case['protected_services']]],'semantic_derivation':{'owners':'nodes with Protocol==connected for exact service prefix','route_visibility':'nodes with any route row for exact service prefix','availability':'owners nonempty AND route_visibility == complete router set'}}

def build_case_replay_plan(case):
    baseline=render_state_configs(case,case['baseline_owners']); forward,recovery=_states(case); states=[]; ids=[]
    for sid,owners in forward:
        cfg=render_state_configs(case,owners); states.append({'state_id':sid,'owners':owners,'config_bundle_sha256':canonical_bundle_sha256(cfg)}); ids.append(sid)
    for run in recovery:
        for sid,owners in run['states']:
            cfg=render_state_configs(case,owners); states.append({'state_id':sid,'owners':owners,'config_bundle_sha256':canonical_bundle_sha256(cfg)}); ids.append(sid)
    qp=_query_plan(case,ids)
    return {'schema':'GRANT1_PE8_REPLAY_PLAN_V1','case_id':case['case_id'],'base_task_id':case['base_task_id'],'protocol':case['protocol'],'topology_family':case['topology_family'],'topology_scale':case['topology_scale'],'protected_services':list(case['protected_services']),'baseline_configs':baseline,'baseline_config_bundle_sha256':canonical_bundle_sha256(baseline),'candidate_config_bundle_sha256':canonical_sha256([{'state_id':r['state_id'],'config_bundle_sha256':r['config_bundle_sha256']} for r in states]),'query_plan':qp,'query_plan_sha256':canonical_sha256(qp),'states':states}

def _route_semantics(routes_by_service,services):
    owners={}; visibility={}
    for svc in services:
        own=set(); vis=set()
        for row in routes_by_service.get(svc,[]):
            if str(row.get('Network'))!=svc: continue
            node=str(row.get('Node')); vis.add(node)
            if str(row.get('Protocol','')).lower()=='connected': own.add(node)
        owners[svc]=sorted(own); visibility[svc]=sorted(vis)
    return {'owners':owners,'route_visibility':visibility}

def semantic_payload_from_raw(case,raw):
    plan=build_case_replay_plan(case); expected={r['state_id']:r for r in plan['states']}; state_map=raw.get('states') if type(raw) is dict else None; issues=[]; derived={}; complete=(raw.get('executor_contract')=='GRANT1_PE8_EXECUTABLE_BATFISH_V1') if type(raw) is dict else False
    if type(state_map) is not dict: state_map={}; complete=False; issues.append('missing states mapping')
    if set(state_map)!=set(expected): complete=False; issues.append('state id set mismatch')
    for sid,row in expected.items():
        rec=state_map.get(sid)
        if type(rec) is not dict: complete=False; issues.append(f'{sid}:missing state record'); derived[sid]={'owners':{s:[] for s in case['protected_services']},'route_visibility':{s:[] for s in case['protected_services']}}; continue
        if rec.get('config_bundle_sha256')!=row['config_bundle_sha256']: complete=False; issues.append(f'{sid}:config hash mismatch')
        if rec.get('snapshot_name')!='pe8-'+row['config_bundle_sha256'][:20]: complete=False; issues.append(f'{sid}:snapshot name mismatch')
        init=rec.get('init_issues'); routes=rec.get('routes_by_service')
        if type(init) is not list: complete=False; issues.append(f'{sid}:initIssues missing'); init=[]
        if init: issues.extend(f'{sid}:init:{json.dumps(x,sort_keys=True,default=str)}' for x in init)
        if type(routes) is not dict or set(routes)!=set(case['protected_services']): complete=False; issues.append(f'{sid}:routes service set mismatch'); routes={} if type(routes) is not dict else routes
        derived[sid]=_route_semantics(routes,case['protected_services'])
    fids=[r['state_id'] for r in plan['states'] if r['state_id'].startswith('forward-')]; fstates=[derived[x] for x in fids]
    rr=[]
    for cut in range(1,len(case['forward_plan'])+1):
        ids=[r['state_id'] for r in plan['states'] if r['state_id'].startswith(f'recovery-cut-{cut:02d}-step-')]
        rr.append({'cut_index':cut,'states':[derived[x] for x in ids],'terminal_state':derived[ids[-1]] if ids else {'owners':{},'route_visibility':{}}})
    parser_clean=not any(':init:' in x for x in issues)
    return {'evidence_complete':bool(complete),'parser_clean':bool(parser_clean),'parser_issues':sorted(issues),'forward_states':fstates,'terminal_state':fstates[-1] if fstates else {'owners':{},'route_visibility':{}},'recovery_runs':rr}

def build_attested_evidence_from_raw(case,blind_case,raw):
    from semantic_evidence_v8 import build_attested_semantic_evidence
    plan=build_case_replay_plan(case); payload=semantic_payload_from_raw(case,raw)
    return build_attested_semantic_evidence(blind_case,payload,baseline_config_bundle_sha256=plan['baseline_config_bundle_sha256'],candidate_config_bundle_sha256=plan['candidate_config_bundle_sha256'],query_plan_sha256=plan['query_plan_sha256'],raw_batfish_output_sha256=canonical_sha256(raw))


def build_oracle_evidence_from_raw(case,blind_case,raw):
    # Backward-compatible development alias; PE8 scientific code uses the explicit attested name.
    return build_attested_evidence_from_raw(case,blind_case,raw)
