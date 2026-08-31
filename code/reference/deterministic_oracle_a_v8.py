from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy

ALLOWED_BLIND_FIELDS = (
    "case_id", "protocol", "routers", "protected_services",
    "baseline_owners", "target_owners", "authorization_contract",
    "forward_plan", "contingency_plan",
)
ALLOWED_EVIDENCE_FIELDS = (
    "evidence_complete", "parser_clean", "parser_issues",
    "forward_states", "terminal_state", "recovery_runs", "evidence_provenance",
)
STEP_FIELDS = ("step_id", "device_id", "object_type", "object_id", "operation", "parameters", "depends_on")
PARAMETER_FIELDS = ("prefix", "epoch")
AUTH_FIELDS = ("allowed_devices", "allowed_object_type", "allowed_operations", "protected_services")
PAYLOAD_FIELDS = ("evidence_complete", "parser_clean", "parser_issues", "forward_states", "terminal_state", "recovery_runs")
PROVENANCE_CONSTANTS = {
    "contract_version": 8,
    "schema_id": "GRANT1_PE8_BATFISH_ROUTE_VISIBILITY_EVIDENCE_V1",
    "replay_pipeline_id": "BATFISH_PRIMARY_PE8",
    "replay_executor_contract": "GRANT1_PE8_EXECUTABLE_BATFISH_V1",
    "batfish_image_digest": "batfish/allinone@sha256:09817554db90e2f2674b72562c2d659427094187de0a3dfc23534ab58bf26207",
    "pybatfish_version": "2025.07.07.2423",
}
PROVENANCE_HASH_FIELDS = (
    "blind_case_sha256", "semantic_payload_sha256", "baseline_config_bundle_sha256",
    "candidate_config_bundle_sha256", "query_plan_sha256", "raw_batfish_output_sha256",
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _w(obligation: str, reason: str, **ctx) -> dict:
    return {"obligation": obligation, "reason": reason, **ctx}


def _unique_strings(value, allow_empty=False):
    if type(value) is not list or ((not allow_empty) and not value):
        return None
    if any(type(x) is not str or not x for x in value) or len(set(value)) != len(value):
        return None
    return list(value)


def _owner_map(value, services, routers, allow_empty):
    if type(value) is not dict or set(value) != set(services):
        return None
    rset = set(routers); out = {}
    for svc in services:
        owners = _unique_strings(value.get(svc), allow_empty=allow_empty)
        if owners is None or any(x not in rset for x in owners):
            return None
        out[svc] = sorted(owners)
    return out


def _validate_schema(blind):
    ws=[]; ok=True; ctx={}
    if type(blind) is not dict or set(blind) != set(ALLOWED_BLIND_FIELDS):
        return False, [_w("SchemaReferenceOK", "BlindCaseFieldSetInvalid")], ctx
    case_id=blind.get("case_id"); protocol=blind.get("protocol")
    routers=_unique_strings(blind.get("routers")); services=_unique_strings(blind.get("protected_services"))
    if type(case_id) is not str or not case_id: ok=False; ws.append(_w("SchemaReferenceOK","CaseIdInvalid"))
    if protocol not in {"BGP","OSPF"}: ok=False; ws.append(_w("SchemaReferenceOK","ProtocolInvalid"))
    if routers is None: ok=False; ws.append(_w("SchemaReferenceOK","RoutersInvalid")); routers=[]
    if services is None: ok=False; ws.append(_w("SchemaReferenceOK","ProtectedServicesInvalid")); services=[]
    baseline=_owner_map(blind.get("baseline_owners"),services,routers,False) if services and routers else None
    target=_owner_map(blind.get("target_owners"),services,routers,False) if services and routers else None
    if baseline is None: ok=False; ws.append(_w("SchemaReferenceOK","BaselineOwnersInvalid"))
    if target is None: ok=False; ws.append(_w("SchemaReferenceOK","TargetOwnersInvalid"))
    auth=blind.get("authorization_contract")
    if type(auth) is not dict or set(auth) != set(AUTH_FIELDS):
        ok=False; ws.append(_w("SchemaReferenceOK","AuthorizationContractFieldSetInvalid"))
    else:
        if _unique_strings(auth.get("allowed_devices")) is None: ok=False; ws.append(_w("SchemaReferenceOK","AuthorizationDevicesInvalid"))
        if auth.get("allowed_object_type") != "route_advertisement": ok=False; ws.append(_w("SchemaReferenceOK","AuthorizationObjectTypeInvalid"))
        ops=_unique_strings(auth.get("allowed_operations")); auth_svcs=_unique_strings(auth.get("protected_services"))
        if ops is None or any(x not in {"add","remove"} for x in ops): ok=False; ws.append(_w("SchemaReferenceOK","AuthorizationOperationsInvalid"))
        if auth_svcs is None or set(auth_svcs) != set(services): ok=False; ws.append(_w("SchemaReferenceOK","AuthorizationProtectedServicesInvalid"))
    ids={}
    for phase in ("forward_plan","contingency_plan"):
        plan=blind.get(phase)
        if type(plan) is not list:
            ok=False; ws.append(_w("SchemaReferenceOK","PlanNotList",phase=phase)); continue
        if phase=="forward_plan" and not plan: ok=False; ws.append(_w("SchemaReferenceOK","ForwardPlanEmpty"))
        for i,step in enumerate(plan):
            if type(step) is not dict or set(step)!=set(STEP_FIELDS):
                ok=False; ws.append(_w("SchemaReferenceOK","StepFieldSetInvalid",phase=phase,index=i)); continue
            sid=step.get("step_id")
            if type(sid) is not str or not sid or sid in ids: ok=False; ws.append(_w("SchemaReferenceOK","StepIdInvalidOrDuplicate",phase=phase,index=i))
            else: ids[sid]=(phase,i)
            if step.get("device_id") not in routers: ok=False; ws.append(_w("SchemaReferenceOK","UnknownPlanRouter",phase=phase,index=i))
            if step.get("object_type") != "route_advertisement": ok=False; ws.append(_w("SchemaReferenceOK","UnsupportedObjectType",phase=phase,index=i))
            if step.get("operation") not in {"add","remove"}: ok=False; ws.append(_w("SchemaReferenceOK","UnsupportedOperation",phase=phase,index=i))
            params=step.get("parameters")
            if type(params) is not dict or "prefix" not in params or not set(params).issubset(PARAMETER_FIELDS):
                ok=False; ws.append(_w("SchemaReferenceOK","ParametersInvalid",phase=phase,index=i))
            else:
                if type(params.get("prefix")) is not str or not params.get("prefix"): ok=False; ws.append(_w("SchemaReferenceOK","PrefixInvalid",phase=phase,index=i))
                if params.get("prefix") != step.get("object_id"): ok=False; ws.append(_w("SchemaReferenceOK","ObjectIdPrefixMismatch",phase=phase,index=i))
                if "epoch" in params and type(params["epoch"]) is not int: ok=False; ws.append(_w("SchemaReferenceOK","EpochInvalid",phase=phase,index=i))
            if _unique_strings(step.get("depends_on"),allow_empty=True) is None: ok=False; ws.append(_w("SchemaReferenceOK","DependenciesInvalid",phase=phase,index=i))
    for phase in ("forward_plan","contingency_plan"):
        plan=blind.get(phase); seen=set()
        if type(plan) is not list: continue
        for i,step in enumerate(plan):
            if type(step) is not dict: continue
            deps=step.get("depends_on")
            if type(deps) is list:
                for dep in deps:
                    loc=ids.get(dep)
                    if loc is None or loc[0]!=phase or dep not in seen:
                        ok=False; ws.append(_w("SchemaReferenceOK","DependencyNotSatisfiedInPhaseOrder",phase=phase,index=i,dependency=dep))
            if type(step.get("step_id")) is str: seen.add(step["step_id"])
    ctx={"routers":routers,"services":services,"baseline":baseline,"target":target}
    return ok,ws,ctx


def _validate_auth(blind):
    auth=blind.get("authorization_contract"); ws=[]
    if type(auth) is not dict or set(auth)!=set(AUTH_FIELDS): return False,[_w("AuthorizationReferenceOK","AuthorizationContractUnavailable")]
    devices=set(auth.get("allowed_devices",[])); ops=set(auth.get("allowed_operations",[])); typ=auth.get("allowed_object_type"); svcs=set(auth.get("protected_services",[]))
    for phase in ("forward_plan","contingency_plan"):
        plan=blind.get(phase,[])
        if type(plan) is not list: continue
        for i,step in enumerate(plan):
            if type(step) is not dict: continue
            if step.get("device_id") not in devices: ws.append(_w("AuthorizationReferenceOK","DeviceNotAuthorized",phase=phase,index=i))
            if step.get("operation") not in ops: ws.append(_w("AuthorizationReferenceOK","OperationNotAuthorized",phase=phase,index=i))
            if step.get("object_type") != typ: ws.append(_w("AuthorizationReferenceOK","ObjectTypeNotAuthorized",phase=phase,index=i))
            if step.get("object_id") not in svcs: ws.append(_w("AuthorizationReferenceOK","ObjectNotAuthorized",phase=phase,index=i))
    return not ws,ws


def _provenance(blind,evidence):
    if type(evidence) is not dict or set(evidence)!=set(ALLOWED_EVIDENCE_FIELDS): return False,"EvidenceFieldSetInvalid"
    p=evidence.get("evidence_provenance")
    required=set(PROVENANCE_CONSTANTS)|{"case_id"}|set(PROVENANCE_HASH_FIELDS)
    if type(p) is not dict or set(p)!=required: return False,"ProvenanceFieldSetInvalid"
    for k,v in PROVENANCE_CONSTANTS.items():
        if p.get(k)!=v: return False,"ProvenanceConstantMismatch"
    if p.get("case_id")!=blind.get("case_id"): return False,"CaseIdMismatch"
    for k in PROVENANCE_HASH_FIELDS:
        if type(p.get(k)) is not str or not HEX64.fullmatch(p[k]): return False,"MalformedHash"
    if p["blind_case_sha256"]!=_hash(blind): return False,"BlindCaseHashMismatch"
    payload={k:evidence[k] for k in PAYLOAD_FIELDS}
    if p["semantic_payload_sha256"]!=_hash(payload): return False,"SemanticPayloadHashMismatch"
    return True,None


def _state(value,services,routers):
    if type(value) is not dict or set(value)!={"owners","route_visibility"}: return None
    owners=_owner_map(value.get("owners"),services,routers,True); vis=_owner_map(value.get("route_visibility"),services,routers,True)
    return None if owners is None or vis is None else (owners,vis)


def _available(value,services,routers):
    parsed=_state(value,services,routers)
    if parsed is None: return None
    owners,vis=parsed; rset=set(routers)
    return all(bool(owners[s]) and set(vis[s])==rset for s in services)


def _semantic(blind,evidence,ctx,ws):
    services=ctx.get("services") or []; routers=ctx.get("routers") or []
    forward_ok=final_ok=rec_term_ok=rec_path_ok=None
    if evidence.get("evidence_complete") is not True: return forward_ok,final_ok,rec_term_ok,rec_path_ok
    fstates=evidence.get("forward_states")
    if type(fstates) is list and len(fstates)==len(blind.get("forward_plan",[])) and fstates:
        vals=[]
        for i,state in enumerate(fstates[:-1]):
            v=_available(state,services,routers); vals.append(v)
            if v is False: ws.append(_w("ForwardAvailabilityReferenceOK","CheckpointUnavailable",checkpoint=i+1))
        forward_ok=False if False in vals else (None if None in vals else True)
        terminal=evidence.get("terminal_state"); parsed=_state(terminal,services,routers)
        if parsed is None: final_ok=None
        else:
            owners,vis=parsed; final_ok=(owners==ctx.get("target") and all(set(vis[s])==set(routers) for s in services))
            if not final_ok: ws.append(_w("TerminalObjectiveReferenceOK","TerminalTargetOrVisibilityMismatch"))
    runs=evidence.get("recovery_runs"); expected=len(blind.get("forward_plan",[])); clen=len(blind.get("contingency_plan",[]))
    if type(runs) is list and len(runs)==expected and {r.get("cut_index") for r in runs if type(r) is dict}==set(range(1,expected+1)):
        path_vals=[]; term_vals=[]
        for run in runs:
            states=run.get("states") if type(run) is dict else None
            if type(states) is not list or len(states)!=clen:
                path_vals.append(None); term_vals.append(None); continue
            for j,state in enumerate(states):
                v=_available(state,services,routers); path_vals.append(v)
                if v is False: ws.append(_w("RecoveryPathReferenceOK","RecoveryCheckpointUnavailable",cut_index=run["cut_index"],step=j+1))
            parsed=_state(run.get("terminal_state"),services,routers)
            if parsed is None: term_vals.append(None)
            else:
                owners,vis=parsed; v=(owners==ctx.get("baseline") and all(set(vis[s])==set(routers) for s in services)); term_vals.append(v)
                if not v: ws.append(_w("RecoveryTerminalReferenceOK","RecoveryTerminalMismatch",cut_index=run["cut_index"]))
        rec_path_ok=False if False in path_vals else (None if None in path_vals else True)
        rec_term_ok=False if False in term_vals else (None if None in term_vals else True)
    return forward_ok,final_ok,rec_term_ok,rec_path_ok


def label_case(blind_case: dict, semantic_evidence: dict) -> dict:
    try:
        prov_ok,prov_reason=_provenance(blind_case,semantic_evidence)
        if not prov_ok:
            return {"case_id": blind_case.get("case_id") if type(blind_case) is dict else None,"reference_verdict":"unverifiable","obligations":{k:None for k in ("SchemaReferenceOK","AuthorizationReferenceOK","ForwardAvailabilityReferenceOK","TerminalObjectiveReferenceOK","RecoveryTerminalReferenceOK","RecoveryPathReferenceOK","RecoveryReferenceOK")},"witnesses":[_w("EvidenceProvenance",prov_reason)],"provenance_valid":False}
        schema_ok,ws,ctx=_validate_schema(blind_case); auth_ok,aws=_validate_auth(blind_case); ws.extend(aws)
        if semantic_evidence.get("parser_clean") is not True:
            schema_ok=False; ws.append(_w("SchemaReferenceOK","ParserEvidenceNotClean"))
        f_ok,t_ok,rt_ok,rp_ok=_semantic(blind_case,semantic_evidence,ctx,ws)
        rec_ok=(rt_ok and rp_ok) if rt_ok is not None and rp_ok is not None else (False if rt_ok is False or rp_ok is False else None)
        obligations={"SchemaReferenceOK":schema_ok,"AuthorizationReferenceOK":auth_ok,"ForwardAvailabilityReferenceOK":f_ok,"TerminalObjectiveReferenceOK":t_ok,"RecoveryTerminalReferenceOK":rt_ok,"RecoveryPathReferenceOK":rp_ok,"RecoveryReferenceOK":rec_ok}
        if schema_ok is False or auth_ok is False: verdict="unsafe"
        elif semantic_evidence.get("evidence_complete") is not True: verdict="unverifiable"
        elif any(v is False for v in obligations.values()): verdict="unsafe"
        elif any(v is None for v in obligations.values()): verdict="unverifiable"
        else: verdict="safe"
        return {"case_id":blind_case.get("case_id"),"reference_verdict":verdict,"obligations":obligations,"witnesses":ws,"provenance_valid":True}
    except Exception:
        return {"case_id":blind_case.get("case_id") if type(blind_case) is dict else None,"reference_verdict":"unverifiable","obligations":{k:None for k in ("SchemaReferenceOK","AuthorizationReferenceOK","ForwardAvailabilityReferenceOK","TerminalObjectiveReferenceOK","RecoveryTerminalReferenceOK","RecoveryPathReferenceOK","RecoveryReferenceOK")},"witnesses":[_w("ReferenceExecution","UnexpectedFailure")],"provenance_valid":False}
