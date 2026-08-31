from __future__ import annotations

import hashlib
import json
from copy import deepcopy

from network_config_v8 import render_state_configs

EXPECTED = {
    "contract_version": 8,
    "schema_id": "GRANT1_PE8_BATFISH_ROUTE_VISIBILITY_EVIDENCE_V1",
    "replay_pipeline_id": "BATFISH_PRIMARY_PE8",
    "replay_executor_contract": "GRANT1_PE8_EXECUTABLE_BATFISH_V1",
    "batfish_image_digest": "batfish/allinone@sha256:09817554db90e2f2674b72562c2d659427094187de0a3dfc23534ab58bf26207",
    "pybatfish_version": "2025.07.07.2423",
}
PAYLOAD_FIELDS=("evidence_complete","parser_clean","parser_issues","forward_states","terminal_state","recovery_runs")


def _bytes(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def _sha(obj): return hashlib.sha256(_bytes(obj)).hexdigest()
def _bundle(configs): return _sha({k:configs[k] for k in sorted(configs)})
def _norm(state): return {str(s):sorted({str(x) for x in xs}) for s,xs in sorted(state.items())}


def _apply(state,step):
    out={s:set(xs) for s,xs in _norm(state).items()}; obj=str(step.get('object_id'))
    if obj not in out: out[obj]=set()
    op=step.get('operation'); dev=str(step.get('device_id'))
    if op=='add': out[obj].add(dev)
    elif op=='remove': out[obj].discard(dev)
    return {s:sorted(xs) for s,xs in sorted(out.items())}


def _expected_states(case):
    state=_norm(case['baseline_owners']); rows=[]; cuts=[]
    for i,step in enumerate(case['forward_plan'],1):
        state=_apply(state,step); cuts.append(deepcopy(state)); cfg=render_state_configs(case,state)
        rows.append({'state_id':f'forward-{i:02d}','owners':deepcopy(state),'config_bundle_sha256':_bundle(cfg)})
    for cut,cut_state in enumerate(cuts,1):
        state=deepcopy(cut_state)
        for j,step in enumerate(case['contingency_plan'],1):
            state=_apply(state,step); cfg=render_state_configs(case,state)
            rows.append({'state_id':f'recovery-cut-{cut:02d}-step-{j:02d}','owners':deepcopy(state),'config_bundle_sha256':_bundle(cfg)})
    return rows


def _query_plan(case,state_ids):
    return {
        'schema':'GRANT1_PE8_BATFISH_QUERY_PLAN_V1',
        'states':list(state_ids),
        'queries':[{'type':'initIssues'},*[{'type':'routes','network':svc,'nodes':'.*'} for svc in case['protected_services']]],
        'semantic_derivation':{
            'owners':'nodes with Protocol==connected for exact service prefix',
            'route_visibility':'nodes with any route row for exact service prefix',
            'availability':'owners nonempty AND route_visibility == complete router set',
        },
    }


def _route_semantics(routes_by_service,services):
    owners={}; visibility={}
    for svc in services:
        own=set(); vis=set()
        rows=routes_by_service.get(svc,[]) if type(routes_by_service) is dict else []
        for row in rows:
            if type(row) is not dict or str(row.get('Network'))!=svc: continue
            node=str(row.get('Node')); vis.add(node)
            if str(row.get('Protocol','')).lower()=='connected': own.add(node)
        owners[svc]=sorted(own); visibility[svc]=sorted(vis)
    return {'owners':owners,'route_visibility':visibility}


def _payload_from_raw(case,raw,expected_states):
    state_map=raw.get('states') if type(raw) is dict else None; issues=[]; derived={}
    complete=(type(raw) is dict and raw.get('executor_contract')==EXPECTED['replay_executor_contract'] and type(state_map) is dict)
    expected={r['state_id']:r for r in expected_states}
    if type(state_map) is not dict: state_map={}; issues.append('missing states mapping')
    if set(state_map)!=set(expected): complete=False; issues.append('state id set mismatch')
    for sid,row in expected.items():
        rec=state_map.get(sid)
        if type(rec) is not dict:
            complete=False; issues.append(f'{sid}:missing state record'); derived[sid]={'owners':{s:[] for s in case['protected_services']},'route_visibility':{s:[] for s in case['protected_services']}}; continue
        if rec.get('config_bundle_sha256')!=row['config_bundle_sha256']: complete=False; issues.append(f'{sid}:config hash mismatch')
        if rec.get('snapshot_name')!='pe8-'+row['config_bundle_sha256'][:20]: complete=False; issues.append(f'{sid}:snapshot name mismatch')
        init=rec.get('init_issues'); routes=rec.get('routes_by_service')
        if type(init) is not list: complete=False; init=[]; issues.append(f'{sid}:initIssues missing')
        if init: issues.extend(f'{sid}:init:{json.dumps(x,sort_keys=True,default=str)}' for x in init)
        if type(routes) is not dict or set(routes)!=set(case['protected_services']): complete=False; issues.append(f'{sid}:routes service set mismatch'); routes={} if type(routes) is not dict else routes
        derived[sid]=_route_semantics(routes,case['protected_services'])
    fids=[r['state_id'] for r in expected_states if r['state_id'].startswith('forward-')]; fstates=[derived[x] for x in fids]
    runs=[]
    for cut in range(1,len(case['forward_plan'])+1):
        ids=[r['state_id'] for r in expected_states if r['state_id'].startswith(f'recovery-cut-{cut:02d}-step-')]
        runs.append({'cut_index':cut,'states':[derived[x] for x in ids],'terminal_state':derived[ids[-1]] if ids else {'owners':{},'route_visibility':{}}})
    return {'evidence_complete':bool(complete),'parser_clean':not any(':init:' in x for x in issues),'parser_issues':sorted(issues),'forward_states':fstates,'terminal_state':fstates[-1] if fstates else {'owners':{},'route_visibility':{}},'recovery_runs':runs}


def audit_replay_evidence(case,blind_case,raw,evidence):
    failures=[]
    states=_expected_states(case); ids=[r['state_id'] for r in states]
    baseline=render_state_configs(case,case['baseline_owners'])
    expected_bindings={
        'baseline_config_bundle_sha256':_bundle(baseline),
        'candidate_config_bundle_sha256':_sha([{'state_id':r['state_id'],'config_bundle_sha256':r['config_bundle_sha256']} for r in states]),
    }
    qp=_query_plan(case,ids); expected_bindings['query_plan_sha256']=_sha(qp); expected_bindings['raw_batfish_output_sha256']=_sha(raw)
    recomputed_payload=_payload_from_raw(case,raw,states)
    p=evidence.get('evidence_provenance') if type(evidence) is dict else None
    if type(p) is not dict: return {'valid':False,'failures':['evidence_provenance'],'recomputed_payload':recomputed_payload}
    for k,v in EXPECTED.items():
        if p.get(k)!=v: failures.append(k)
    if p.get('case_id')!=blind_case.get('case_id'): failures.append('case_id')
    if p.get('blind_case_sha256')!=_sha(blind_case): failures.append('blind_case_sha256')
    for k,v in expected_bindings.items():
        if p.get(k)!=v: failures.append(k)
    payload={k:evidence.get(k) for k in PAYLOAD_FIELDS} if type(evidence) is dict else {}
    if payload!=recomputed_payload: failures.append('semantic_payload_content')
    if p.get('semantic_payload_sha256')!=_sha(recomputed_payload): failures.append('semantic_payload_sha256')
    actual_executor_contract = raw.get('executor_contract') if type(raw) is dict else None
    if actual_executor_contract != EXPECTED['replay_executor_contract']:
        failures.append('replay_executor_contract')
    return {'valid':not failures,'failures':list(dict.fromkeys(failures)),'recomputed_payload':recomputed_payload,'expected_bindings':expected_bindings,'query_plan':qp}
