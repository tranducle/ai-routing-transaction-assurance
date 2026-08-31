from __future__ import annotations

from copy import deepcopy

BLIND_FIELDS = (
    "case_id", "protocol", "routers", "protected_services",
    "baseline_owners", "target_owners", "authorization_contract",
    "forward_plan", "contingency_plan",
)
STEP_FIELDS = ("step_id", "device_id", "object_type", "object_id", "operation", "parameters", "depends_on")
PARAMETER_FIELDS = ("prefix", "epoch")
AUTH_FIELDS = ("allowed_devices", "allowed_object_type", "allowed_operations", "protected_services")
CONTEXT_FIELDS = ("case_id", "topology_edges")


def _w(obligation, reason, **ctx):
    return {"obligation": obligation, "reason": reason, **ctx}


def _strings(value, allow_empty=False):
    if type(value) is not list or ((not allow_empty) and not value): return None
    if any(type(x) is not str or not x for x in value) or len(set(value)) != len(value): return None
    return list(value)


def _owners(value, services, routers, allow_empty):
    if type(value) is not dict or set(value) != set(services): return None
    rs=set(routers); out={}
    for svc in services:
        xs=_strings(value.get(svc),allow_empty=allow_empty)
        if xs is None or any(x not in rs for x in xs): return None
        out[svc]=sorted(xs)
    return out


def _schema(blind):
    ws=[]; ok=True; ctx={}
    if type(blind) is not dict or set(blind)!=set(BLIND_FIELDS): return False,[_w("SchemaReferenceOK","BlindCaseFieldSetInvalid")],ctx
    routers=_strings(blind.get("routers")); services=_strings(blind.get("protected_services"))
    if type(blind.get("case_id")) is not str or not blind.get("case_id"): ok=False; ws.append(_w("SchemaReferenceOK","CaseIdInvalid"))
    if blind.get("protocol") not in {"BGP","OSPF"}: ok=False; ws.append(_w("SchemaReferenceOK","ProtocolInvalid"))
    if routers is None: ok=False; ws.append(_w("SchemaReferenceOK","RoutersInvalid")); routers=[]
    if services is None: ok=False; ws.append(_w("SchemaReferenceOK","ProtectedServicesInvalid")); services=[]
    baseline=_owners(blind.get("baseline_owners"),services,routers,False) if routers and services else None
    target=_owners(blind.get("target_owners"),services,routers,False) if routers and services else None
    if baseline is None: ok=False; ws.append(_w("SchemaReferenceOK","BaselineOwnersInvalid"))
    if target is None: ok=False; ws.append(_w("SchemaReferenceOK","TargetOwnersInvalid"))
    auth=blind.get("authorization_contract")
    if type(auth) is not dict or set(auth)!=set(AUTH_FIELDS): ok=False; ws.append(_w("SchemaReferenceOK","AuthorizationContractFieldSetInvalid"))
    else:
        if _strings(auth.get("allowed_devices")) is None: ok=False; ws.append(_w("SchemaReferenceOK","AuthorizationDevicesInvalid"))
        if auth.get("allowed_object_type")!="route_advertisement": ok=False; ws.append(_w("SchemaReferenceOK","AuthorizationObjectTypeInvalid"))
        ops=_strings(auth.get("allowed_operations")); asvcs=_strings(auth.get("protected_services"))
        if ops is None or any(x not in {"add","remove"} for x in ops): ok=False; ws.append(_w("SchemaReferenceOK","AuthorizationOperationsInvalid"))
        if asvcs is None or set(asvcs)!=set(services): ok=False; ws.append(_w("SchemaReferenceOK","AuthorizationProtectedServicesInvalid"))
    ids={}
    for phase in ("forward_plan","contingency_plan"):
        plan=blind.get(phase)
        if type(plan) is not list: ok=False; ws.append(_w("SchemaReferenceOK","PlanNotList",phase=phase)); continue
        if phase=="forward_plan" and not plan: ok=False; ws.append(_w("SchemaReferenceOK","ForwardPlanEmpty"))
        for i,step in enumerate(plan):
            if type(step) is not dict or set(step)!=set(STEP_FIELDS): ok=False; ws.append(_w("SchemaReferenceOK","StepFieldSetInvalid",phase=phase,index=i)); continue
            sid=step.get("step_id")
            if type(sid) is not str or not sid or sid in ids: ok=False; ws.append(_w("SchemaReferenceOK","StepIdInvalidOrDuplicate",phase=phase,index=i))
            else: ids[sid]=(phase,i)
            if step.get("device_id") not in routers: ok=False; ws.append(_w("SchemaReferenceOK","UnknownPlanRouter",phase=phase,index=i))
            if step.get("object_type")!="route_advertisement": ok=False; ws.append(_w("SchemaReferenceOK","UnsupportedObjectType",phase=phase,index=i))
            if step.get("operation") not in {"add","remove"}: ok=False; ws.append(_w("SchemaReferenceOK","UnsupportedOperation",phase=phase,index=i))
            params=step.get("parameters")
            if type(params) is not dict or "prefix" not in params or not set(params).issubset(PARAMETER_FIELDS): ok=False; ws.append(_w("SchemaReferenceOK","ParametersInvalid",phase=phase,index=i))
            else:
                if type(params.get("prefix")) is not str or not params.get("prefix"): ok=False; ws.append(_w("SchemaReferenceOK","PrefixInvalid",phase=phase,index=i))
                if params.get("prefix")!=step.get("object_id"): ok=False; ws.append(_w("SchemaReferenceOK","ObjectIdPrefixMismatch",phase=phase,index=i))
                if "epoch" in params and type(params["epoch"]) is not int: ok=False; ws.append(_w("SchemaReferenceOK","EpochInvalid",phase=phase,index=i))
            if _strings(step.get("depends_on"),allow_empty=True) is None: ok=False; ws.append(_w("SchemaReferenceOK","DependenciesInvalid",phase=phase,index=i))
    for phase in ("forward_plan","contingency_plan"):
        seen=set(); plan=blind.get(phase)
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
    return ok,ws,{"routers":routers,"services":services,"baseline":baseline,"target":target}


def _auth(blind):
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
            if step.get("object_type")!=typ: ws.append(_w("AuthorizationReferenceOK","ObjectTypeNotAuthorized",phase=phase,index=i))
            if step.get("object_id") not in svcs: ws.append(_w("AuthorizationReferenceOK","ObjectNotAuthorized",phase=phase,index=i))
    return not ws,ws


def _context(context,case_id,routers):
    if type(context) is not dict or set(context)!=set(CONTEXT_FIELDS) or context.get("case_id")!=case_id: return None
    edges=context.get("topology_edges")
    if type(edges) is not list: return None
    adj={r:set() for r in routers}
    for edge in edges:
        if type(edge) is not list or len(edge)!=2 or any(type(x) is not str for x in edge): return None
        a,b=edge
        if a not in adj or b not in adj or a==b: return None
        adj[a].add(b); adj[b].add(a)
    return adj


def _visibility(adj,owners):
    out={}
    for svc,starts in owners.items():
        seen=set(starts); stack=list(starts)
        while stack:
            cur=stack.pop()
            for nxt in adj.get(cur,set()):
                if nxt not in seen:
                    seen.add(nxt); stack.append(nxt)
        out[svc]=sorted(seen)
    return out


def _apply(state,step,services,routers):
    out={s:set(v) for s,v in state.items()}
    obj=step.get("object_id"); dev=step.get("device_id"); op=step.get("operation")
    if obj not in services or dev not in routers or op not in {"add","remove"}: return {s:sorted(v) for s,v in out.items()}
    if op=="add": out[obj].add(dev)
    else: out[obj].discard(dev)
    return {s:sorted(v) for s,v in out.items()}


def _available(owners,adj,services,routers):
    vis=_visibility(adj,owners); rset=set(routers)
    return all(bool(owners[s]) and set(vis[s])==rset for s in services)


def label_case(blind_case: dict, reference_context: dict) -> dict:
    keys=("SchemaReferenceOK","AuthorizationReferenceOK","ForwardAvailabilityReferenceOK","TerminalObjectiveReferenceOK","RecoveryTerminalReferenceOK","RecoveryPathReferenceOK","RecoveryReferenceOK")
    try:
        schema_ok,ws,ctx=_schema(blind_case); auth_ok,aws=_auth(blind_case); ws.extend(aws)
        routers=ctx.get("routers") or []; services=ctx.get("services") or []
        adj=_context(reference_context,blind_case.get("case_id") if type(blind_case) is dict else None,routers)
        if adj is None:
            return {"case_id":blind_case.get("case_id") if type(blind_case) is dict else None,"reference_verdict":"unverifiable","obligations":{k:None for k in keys},"witnesses":[_w("ReferenceContext","TopologyContextInvalid")],"context_valid":False}
        state=deepcopy(ctx.get("baseline") or {s:[] for s in services}); forward=[]; cuts=[]
        for step in blind_case.get("forward_plan",[]) if type(blind_case.get("forward_plan")) is list else []:
            state=_apply(state,step,services,routers); forward.append(deepcopy(state)); cuts.append(deepcopy(state))
        fvals=[_available(s,adj,services,routers) for s in forward[:-1]] if forward else []
        forward_ok=all(fvals) if fvals else True
        if not forward_ok: ws.append(_w("ForwardAvailabilityReferenceOK","GraphCheckpointUnavailable"))
        terminal=forward[-1] if forward else state
        final_ok=(terminal==ctx.get("target") and _available(terminal,adj,services,routers))
        if not final_ok: ws.append(_w("TerminalObjectiveReferenceOK","GraphTerminalTargetOrVisibilityMismatch"))
        path_vals=[]; term_vals=[]
        contingency=blind_case.get("contingency_plan",[]) if type(blind_case.get("contingency_plan")) is list else []
        for cut,cut_state in enumerate(cuts,start=1):
            rstate=deepcopy(cut_state)
            for j,step in enumerate(contingency,start=1):
                rstate=_apply(rstate,step,services,routers); v=_available(rstate,adj,services,routers); path_vals.append(v)
                if not v: ws.append(_w("RecoveryPathReferenceOK","GraphRecoveryCheckpointUnavailable",cut_index=cut,step=j))
            tv=(rstate==ctx.get("baseline") and _available(rstate,adj,services,routers)); term_vals.append(tv)
            if not tv: ws.append(_w("RecoveryTerminalReferenceOK","GraphRecoveryTerminalMismatch",cut_index=cut))
        rec_path_ok=all(path_vals) if path_vals else (len(contingency)==0)
        rec_term_ok=all(term_vals) if term_vals else (len(cuts)==0 and ctx.get("baseline")==ctx.get("target"))
        rec_ok=rec_path_ok and rec_term_ok
        obligations={"SchemaReferenceOK":schema_ok,"AuthorizationReferenceOK":auth_ok,"ForwardAvailabilityReferenceOK":forward_ok,"TerminalObjectiveReferenceOK":final_ok,"RecoveryTerminalReferenceOK":rec_term_ok,"RecoveryPathReferenceOK":rec_path_ok,"RecoveryReferenceOK":rec_ok}
        verdict="unsafe" if any(v is False for v in obligations.values()) else "safe"
        return {"case_id":blind_case.get("case_id"),"reference_verdict":verdict,"obligations":obligations,"witnesses":ws,"context_valid":True}
    except Exception:
        return {"case_id":blind_case.get("case_id") if type(blind_case) is dict else None,"reference_verdict":"unverifiable","obligations":{k:None for k in keys},"witnesses":[_w("ReferenceExecution","UnexpectedFailure")],"context_valid":False}
