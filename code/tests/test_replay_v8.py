from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

PHASE_E=Path(__file__).resolve().parents[1]
PRIMARY=PHASE_E/'01_primary_v8'; REPLAY=PHASE_E/'03_semantic_replay'
sys.path.insert(0,str(PRIMARY)); sys.path.insert(0,str(REPLAY))

from primary_generator_v8 import build_generation_cases
from blind_view_v8 import make_blind_view
from network_config_v8 import render_state_configs
from replay_adapter_v8 import build_case_replay_plan, semantic_payload_from_raw, build_attested_evidence_from_raw
from batfish_executor_v8 import canonicalize_frame_rows, expected_snapshot_name
from deterministic_replay_audit_v8 import audit_replay_evidence
from reference_pipeline_v8 import evaluate_reference


def _raw_from_plan(case):
    plan=build_case_replay_plan(case); states={}
    for row in plan['states']:
        routes={}
        for svc in case['protected_services']:
            owners=row['owners'][svc]
            visibility=list(case['routers']) if owners else []
            rr=[]
            for node in visibility:
                rr.append({'Node':node,'Network':svc,'Protocol':'connected' if node in owners else case['protocol'].lower(),'Next_Hop':'x'})
            routes[svc]=rr
        states[row['state_id']]={'snapshot_name':expected_snapshot_name(row['config_bundle_sha256']),'config_bundle_sha256':row['config_bundle_sha256'],'init_issues':[],'routes_by_service':routes}
    return {'executor_contract':'GRANT1_PE8_EXECUTABLE_BATFISH_V1','states':states}


def test_all_704_replay_plans_use_sealed_renderer_and_are_deterministic():
    cases=build_generation_cases(); assert len(cases)==704
    for case in cases:
        plan=build_case_replay_plan(case)
        assert plan['baseline_configs']==case['baseline_configs']==render_state_configs(case,case['baseline_owners'])
        assert plan==build_case_replay_plan(case)
        assert all(len(s['config_bundle_sha256'])==64 for s in plan['states'])


def test_semantic_payload_uses_network_wide_visibility_not_only_owner_presence():
    case=build_generation_cases()[0]; raw=_raw_from_plan(case)
    sid=next(iter(raw['states'])); svc=case['protected_services'][0]
    owner=next(r['Node'] for r in raw['states'][sid]['routes_by_service'][svc] if str(r['Protocol']).lower()=='connected')
    raw['states'][sid]['routes_by_service'][svc]=[r for r in raw['states'][sid]['routes_by_service'][svc] if r['Node']==owner]
    payload=semantic_payload_from_raw(case,raw); first=payload['forward_states'][0]
    assert first['owners'][svc]==[owner]
    assert first['route_visibility'][svc]==[owner]
    assert set(first['route_visibility'][svc]) != set(case['routers'])


def test_replay_audit_recomputes_bindings_and_rejects_caller_hash_tampering():
    case=build_generation_cases()[0]; blind=make_blind_view(case); raw=_raw_from_plan(case)
    evidence=build_attested_evidence_from_raw(case,blind,raw)
    result=audit_replay_evidence(case,blind,raw,evidence)
    assert result['valid'] is True
    assert result['failures']==[]
    tampered=deepcopy(evidence); tampered['evidence_provenance']['candidate_config_bundle_sha256']='0'*64
    result=audit_replay_evidence(case,blind,raw,tampered)
    assert result['valid'] is False
    assert 'candidate_config_bundle_sha256' in result['failures']


def test_raw_batfish_hash_tampering_is_detected_before_reference_labeling():
    case=build_generation_cases()[0]; blind=make_blind_view(case); raw=_raw_from_plan(case)
    evidence=build_attested_evidence_from_raw(case,blind,raw)
    changed=deepcopy(raw); sid=next(iter(changed['states'])); changed['states'][sid]['init_issues'].append({'Issue':'tamper'})
    result=audit_replay_evidence(case,blind,changed,evidence)
    assert result['valid'] is False
    assert 'raw_batfish_output_sha256' in result['failures'] or 'semantic_payload_sha256' in result['failures']


def test_reference_pipeline_requires_replay_audit_then_exact_dual_oracle_agreement():
    case=build_generation_cases()[0]; blind=make_blind_view(case); raw=_raw_from_plan(case)
    evidence=build_attested_evidence_from_raw(case,blind,raw)
    out=evaluate_reference(case,blind,raw,evidence)
    assert out['replay_audit']['valid'] is True
    assert out['consensus']['reference_verdict']=='safe'
    assert out['consensus']['agreement'] is True


def test_reference_pipeline_never_labels_when_replay_audit_fails():
    case=build_generation_cases()[0]; blind=make_blind_view(case); raw=_raw_from_plan(case)
    evidence=build_attested_evidence_from_raw(case,blind,raw)
    evidence['evidence_provenance']['query_plan_sha256']='0'*64
    out=evaluate_reference(case,blind,raw,evidence)
    assert out['replay_audit']['valid'] is False
    assert out['consensus']['reference_verdict']=='unverifiable'
    assert out['oracle_a'] is None
    assert out['oracle_b'] is None


def test_executor_row_canonicalization_is_json_safe_and_stable():
    class V:
        def __str__(self): return 'r1'
    rows=[{'Node':V(),'Network':V(),'Metric':1,'Flag':True,'None':None}]
    out=canonicalize_frame_rows(rows)
    assert out==[{'Flag':True,'Metric':1,'Network':'r1','Node':'r1','None':None}]
    assert json.dumps(out,sort_keys=True)==json.dumps(canonicalize_frame_rows(rows),sort_keys=True)


def test_snapshot_name_is_content_addressed():
    assert expected_snapshot_name('a'*64)=='pe8-'+('a'*20)
