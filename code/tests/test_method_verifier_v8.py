from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path

PHASE_E=Path(__file__).resolve().parents[1]
SCORING=PHASE_E/'02_scoring'
sys.path.insert(0,str(SCORING))

from method_verifier_v8 import verify_case  # noqa:E402
from primary_scorer_v8 import score_case  # noqa:E402

SERVICE='10.253.1.1/32'


def _blind():
    return {
      'case_id':'PE8-T','protocol':'BGP','routers':['r1','r2','r3'],'protected_services':[SERVICE],
      'baseline_owners':{SERVICE:['r2']},'target_owners':{SERVICE:['r3']},
      'authorization_contract':{'allowed_devices':['r2','r3'],'allowed_object_type':'route_advertisement','allowed_operations':['add','remove'],'protected_services':[SERVICE]},
      'forward_plan':[
        {'step_id':'f1','device_id':'r3','object_type':'route_advertisement','object_id':SERVICE,'operation':'add','parameters':{'prefix':SERVICE,'epoch':1},'depends_on':[]},
        {'step_id':'f2','device_id':'r2','object_type':'route_advertisement','object_id':SERVICE,'operation':'remove','parameters':{'prefix':SERVICE,'epoch':2},'depends_on':['f1']},
      ],
      'contingency_plan':[
        {'step_id':'c1','device_id':'r2','object_type':'route_advertisement','object_id':SERVICE,'operation':'add','parameters':{'prefix':SERVICE,'epoch':1},'depends_on':[]},
        {'step_id':'c2','device_id':'r3','object_type':'route_advertisement','object_id':SERVICE,'operation':'remove','parameters':{'prefix':SERVICE,'epoch':2},'depends_on':['c1']},
      ],
    }


def _state(owners,visible=None):
    return {'owners':{SERVICE:sorted(owners)},'route_visibility':{SERVICE:sorted(visible if visible is not None else ['r1','r2','r3'])}}


def _evidence():
    return {
      'evidence_complete':True,'parser_clean':True,'parser_issues':[],
      'forward_states':[_state(['r2','r3']),_state(['r3'])],
      'terminal_state':_state(['r3']),
      'recovery_runs':[
        {'cut_index':1,'states':[_state(['r2','r3']),_state(['r2'])],'terminal_state':_state(['r2'])},
        {'cut_index':2,'states':[_state(['r2','r3']),_state(['r2'])],'terminal_state':_state(['r2'])},
      ],
      'evidence_provenance':{'contract_version':7}
    }


def test_v8_method_verifier_safe_case_and_b5_full_accept():
    out=verify_case(_blind(),_evidence())
    for k in ('SchemaOK','AuthOK','ForwardSafe','FinalOK','RecoveryTerminalOK','RecoveryPathSafe','Recoverable'):
        assert out[k] is True, (k,out)
    scored=score_case('PE8-T',out)
    assert scored['B2'] and scored['B3'] and scored['B4'] and scored['B5'] and scored['Full']


def test_prefix_object_mismatch_is_schema_not_authorization():
    blind=_blind(); blind['forward_plan'][0]['parameters']['prefix']='10.253.1.2/32'
    out=verify_case(blind,_evidence())
    assert out['SchemaOK'] is False
    assert out['AuthOK'] is True
    scored=score_case('PE8-T',out)
    assert all(scored[k] is False for k in ('B1','B2','B3','B4','B5','Full'))


def test_b5_can_accept_eventual_recovery_when_full_rejects_unsafe_recovery_path():
    evidence=_evidence()
    evidence['recovery_runs'][0]['states'][0]=_state(['r2','r3'],visible=['r1','r2'])
    out=verify_case(_blind(),evidence)
    assert out['RecoveryTerminalOK'] is True
    assert out['RecoveryPathSafe'] is False
    assert out['Recoverable'] is False
    scored=score_case('PE8-T',out)
    assert scored['B5'] is True
    assert scored['Full'] is False


def test_forward_safety_uses_route_visibility_not_only_owner_nonempty():
    evidence=_evidence(); evidence['forward_states'][0]=_state(['r2','r3'],visible=['r1','r2'])
    out=verify_case(_blind(),evidence)
    assert out['ForwardSafe'] is False
    assert out['FinalOK'] is True


def test_method_verifier_does_not_accept_reference_labels_as_input_signal():
    evidence=_evidence(); evidence['reference_verdict']='unsafe'; evidence['expected_label']='unsafe'
    out=verify_case(_blind(),evidence)
    assert out['SchemaOK'] is True and out['FullGuardEquivalent'] is True


def test_all_704_generated_cases_stay_inside_authorization_surface_and_retarget_object_is_schema_only():
    import sys
    from pathlib import Path
    phase_e=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(phase_e/"01_primary_v8"))
    from primary_generator_v8 import build_generation_cases
    from blind_view_v8 import make_blind_view
    cases=build_generation_cases(); assert len(cases)==704
    for case in cases:
        out=verify_case(make_blind_view(case),{})
        assert out["AuthOK"] is True, case["case_id"]
    retarget=[c for c in cases if c["transformation_id"]=="retarget_step_object"]
    assert len(retarget)==64
    for case in retarget:
        out=verify_case(make_blind_view(case),{})
        assert out["SchemaOK"] is False and out["AuthOK"] is True
