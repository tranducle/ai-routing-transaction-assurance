from __future__ import annotations

from copy import deepcopy
from typing import Mapping, Sequence

TOP_LEVEL_FIELDS = (
    "case_id", "protocol", "routers", "protected_services", "baseline_owners", "target_owners",
    "authorization_contract", "forward_plan", "contingency_plan",
)
STEP_FIELDS = ("step_id", "device_id", "object_type", "object_id", "operation", "parameters", "depends_on")
PARAMETER_FIELDS = ("prefix", "epoch")
AUTH_FIELDS = ("allowed_devices", "allowed_object_type", "allowed_operations", "protected_services")


def _witness(obligation: str, reason: str, **ctx) -> dict:
    return {"obligation": obligation, "reason": reason, **ctx}


def _unique_strings(value, *, allow_empty: bool = False):
    if type(value) is not list:
        return None
    if (not allow_empty) and not value:
        return None
    if any(type(x) is not str or not x for x in value):
        return None
    if len(set(value)) != len(value):
        return None
    return list(value)


def _owner_map(value, services: Sequence[str], routers: Sequence[str], *, allow_empty: bool) -> dict | None:
    if type(value) is not dict or set(value) != set(services):
        return None
    router_set = set(routers)
    out = {}
    for service in services:
        owners = _unique_strings(value.get(service), allow_empty=allow_empty)
        if owners is None or any(owner not in router_set for owner in owners):
            return None
        out[service] = sorted(owners)
    return out


def _validate_schema(blind_case: Mapping) -> tuple[bool, list[dict], dict]:
    witnesses: list[dict] = []
    context: dict = {}
    schema_ok = True
    if type(blind_case) is not dict or set(blind_case) != set(TOP_LEVEL_FIELDS):
        return False, [_witness("SchemaOK", "BlindCaseFieldSetInvalid")], context

    case_id = blind_case.get("case_id")
    protocol = blind_case.get("protocol")
    routers = _unique_strings(blind_case.get("routers"))
    services = _unique_strings(blind_case.get("protected_services"))
    if type(case_id) is not str or not case_id:
        schema_ok = False; witnesses.append(_witness("SchemaOK", "CaseIdInvalid"))
    if protocol not in {"BGP", "OSPF"}:
        schema_ok = False; witnesses.append(_witness("SchemaOK", "ProtocolInvalid"))
    if routers is None:
        schema_ok = False; witnesses.append(_witness("SchemaOK", "RoutersInvalid")); routers = []
    if services is None:
        schema_ok = False; witnesses.append(_witness("SchemaOK", "ProtectedServicesInvalid")); services = []

    baseline = _owner_map(blind_case.get("baseline_owners"), services, routers, allow_empty=False) if services and routers else None
    target = _owner_map(blind_case.get("target_owners"), services, routers, allow_empty=False) if services and routers else None
    if baseline is None:
        schema_ok = False; witnesses.append(_witness("SchemaOK", "BaselineOwnersInvalid"))
    if target is None:
        schema_ok = False; witnesses.append(_witness("SchemaOK", "TargetOwnersInvalid"))

    auth = blind_case.get("authorization_contract")
    if type(auth) is not dict or set(auth) != set(AUTH_FIELDS):
        schema_ok = False; witnesses.append(_witness("SchemaOK", "AuthorizationContractFieldSetInvalid"))
    else:
        if _unique_strings(auth.get("allowed_devices")) is None:
            schema_ok = False; witnesses.append(_witness("SchemaOK", "AuthorizationDevicesInvalid"))
        if auth.get("allowed_object_type") != "route_advertisement":
            schema_ok = False; witnesses.append(_witness("SchemaOK", "AuthorizationObjectTypeInvalid"))
        ops = _unique_strings(auth.get("allowed_operations"))
        if ops is None or any(op not in {"add", "remove"} for op in ops):
            schema_ok = False; witnesses.append(_witness("SchemaOK", "AuthorizationOperationsInvalid"))
        auth_services = _unique_strings(auth.get("protected_services"))
        if auth_services is None or set(auth_services) != set(services):
            schema_ok = False; witnesses.append(_witness("SchemaOK", "AuthorizationProtectedServicesInvalid"))

    all_ids: dict[str, tuple[str, int]] = {}
    for phase in ("forward_plan", "contingency_plan"):
        plan = blind_case.get(phase)
        if type(plan) is not list:
            schema_ok = False; witnesses.append(_witness("SchemaOK", "PlanNotList", phase=phase)); continue
        if phase == "forward_plan" and not plan:
            schema_ok = False; witnesses.append(_witness("SchemaOK", "ForwardPlanEmpty"))
        for index, step in enumerate(plan):
            if type(step) is not dict or set(step) != set(STEP_FIELDS):
                schema_ok = False; witnesses.append(_witness("SchemaOK", "StepFieldSetInvalid", phase=phase, index=index)); continue
            sid = step.get("step_id")
            if type(sid) is not str or not sid or sid in all_ids:
                schema_ok = False; witnesses.append(_witness("SchemaOK", "StepIdInvalidOrDuplicate", phase=phase, index=index))
            else:
                all_ids[sid] = (phase, index)
            for field in ("device_id", "object_type", "object_id", "operation"):
                if type(step.get(field)) is not str or not step.get(field):
                    schema_ok = False; witnesses.append(_witness("SchemaOK", "StepStringFieldInvalid", phase=phase, index=index, field=field))
            if step.get("object_type") != "route_advertisement":
                schema_ok = False; witnesses.append(_witness("SchemaOK", "UnsupportedObjectType", phase=phase, index=index))
            if step.get("operation") not in {"add", "remove"}:
                schema_ok = False; witnesses.append(_witness("SchemaOK", "UnsupportedOperation", phase=phase, index=index))
            params = step.get("parameters")
            if type(params) is not dict or "prefix" not in params or not set(params).issubset(PARAMETER_FIELDS):
                schema_ok = False; witnesses.append(_witness("SchemaOK", "ParametersInvalid", phase=phase, index=index))
            else:
                if type(params.get("prefix")) is not str or not params.get("prefix"):
                    schema_ok = False; witnesses.append(_witness("SchemaOK", "PrefixInvalid", phase=phase, index=index))
                # Cross-field coherence is a schema/property consistency rule, not authorization.
                if type(step.get("object_id")) is str and params.get("prefix") != step.get("object_id"):
                    schema_ok = False; witnesses.append(_witness("SchemaOK", "ObjectIdPrefixMismatch", phase=phase, index=index))
                if "epoch" in params and (type(params["epoch"]) is not int):
                    schema_ok = False; witnesses.append(_witness("SchemaOK", "EpochInvalid", phase=phase, index=index))
            deps = _unique_strings(step.get("depends_on"), allow_empty=True)
            if deps is None:
                schema_ok = False; witnesses.append(_witness("SchemaOK", "DependenciesInvalid", phase=phase, index=index))

    for phase in ("forward_plan", "contingency_plan"):
        plan = blind_case.get(phase)
        if type(plan) is not list:
            continue
        seen: set[str] = set()
        for index, step in enumerate(plan):
            if type(step) is not dict:
                continue
            deps = step.get("depends_on")
            if type(deps) is list:
                for dep in deps:
                    # A dependency must be in the same phase and appear before the dependent step.
                    loc = all_ids.get(dep)
                    if loc is None or loc[0] != phase or dep not in seen:
                        schema_ok = False; witnesses.append(_witness("SchemaOK", "DependencyNotSatisfiedInPhaseOrder", phase=phase, index=index, dependency=dep))
            sid = step.get("step_id")
            if type(sid) is str:
                seen.add(sid)

    context.update({"routers": routers, "services": services, "baseline": baseline, "target": target})
    return schema_ok, witnesses, context


def _validate_authorization(blind_case: Mapping, context: Mapping) -> tuple[bool, list[dict]]:
    witnesses: list[dict] = []
    auth = blind_case.get("authorization_contract")
    if type(auth) is not dict or set(auth) != set(AUTH_FIELDS):
        return False, [_witness("AuthOK", "AuthorizationContractUnavailable")]
    allowed_devices = set(auth.get("allowed_devices", []))
    allowed_type = auth.get("allowed_object_type")
    allowed_ops = set(auth.get("allowed_operations", []))
    allowed_services = set(auth.get("protected_services", []))
    for phase in ("forward_plan", "contingency_plan"):
        for index, step in enumerate(blind_case.get(phase, [])) if type(blind_case.get(phase)) is list else []:
            if type(step) is not dict:
                continue
            if step.get("device_id") not in allowed_devices:
                witnesses.append(_witness("AuthOK", "DeviceNotAuthorized", phase=phase, index=index))
            if step.get("object_type") != allowed_type:
                witnesses.append(_witness("AuthOK", "ObjectTypeNotAuthorized", phase=phase, index=index))
            if step.get("operation") not in allowed_ops:
                witnesses.append(_witness("AuthOK", "OperationNotAuthorized", phase=phase, index=index))
            # Authorization is scoped by the declared logical object. Cross-field payload coherence is SchemaOK.
            if step.get("object_id") not in allowed_services:
                witnesses.append(_witness("AuthOK", "ObjectNotAuthorized", phase=phase, index=index))
    return not witnesses, witnesses


def _state_map(state, services, routers) -> tuple[dict | None, dict | None]:
    if type(state) is not dict or set(state) != {"owners", "route_visibility"}:
        return None, None
    owners = _owner_map(state.get("owners"), services, routers, allow_empty=True)
    visibility = _owner_map(state.get("route_visibility"), services, routers, allow_empty=True)
    return owners, visibility


def _fully_visible(state, services, routers) -> tuple[bool | None, list[str]]:
    owners, visibility = _state_map(state, services, routers)
    if owners is None or visibility is None:
        return None, list(services)
    router_set = set(routers); failed = []
    for service in services:
        if not owners[service] or set(visibility[service]) != router_set:
            failed.append(service)
    return not failed, failed


def verify_case(blind_case: dict, semantic_evidence: dict) -> dict:
    """Frozen PE8 method-verifier semantics. It never reads independent reference labels."""
    witnesses: list[dict] = []
    schema_ok, ws, context = _validate_schema(blind_case); witnesses.extend(ws)
    auth_ok, ws = _validate_authorization(blind_case, context); witnesses.extend(ws)
    evidence_complete = semantic_evidence.get("evidence_complete") is True if type(semantic_evidence) is dict else False
    parser_clean = semantic_evidence.get("parser_clean") is True if type(semantic_evidence) is dict else False
    if not parser_clean:
        schema_ok = False; witnesses.append(_witness("SchemaOK", "ParserEvidenceNotClean"))

    services=context.get("services") or []; routers=context.get("routers") or []
    forward_safe=False; final_ok=False; recovery_terminal_ok=False; recovery_path_safe=False
    if evidence_complete and services and routers and type(semantic_evidence) is dict:
        fstates=semantic_evidence.get("forward_states")
        if type(fstates) is list and len(fstates)==len(blind_case.get("forward_plan", [])) and fstates:
            forward_checks=[]
            for i,state in enumerate(fstates[:-1]):
                ok,failed=_fully_visible(state,services,routers); forward_checks.append(ok is True)
                if ok is not True: witnesses.append(_witness("ForwardSafe","RouteVisibilityViolationOrMalformedState",checkpoint=i+1,services=failed))
            forward_safe=all(forward_checks) if forward_checks else True
            terminal=semantic_evidence.get("terminal_state")
            owners,visibility=_state_map(terminal,services,routers)
            final_ok=(owners==context.get("target") and visibility is not None and all(set(visibility[s])==set(routers) for s in services))
            if not final_ok: witnesses.append(_witness("FinalOK","TerminalTargetOrVisibilityMismatch"))
        else:
            witnesses.append(_witness("ForwardSafe","ForwardEvidenceCardinalityMismatch")); witnesses.append(_witness("FinalOK","ForwardEvidenceCardinalityMismatch"))

        runs=semantic_evidence.get("recovery_runs")
        expected_cuts=len(blind_case.get("forward_plan", [])); contingency_len=len(blind_case.get("contingency_plan", []))
        if type(runs) is list and len(runs)==expected_cuts and {r.get('cut_index') for r in runs if type(r) is dict}==set(range(1,expected_cuts+1)):
            terminal_checks=[]; path_checks=[]
            for run in runs:
                states=run.get("states") if type(run) is dict else None
                if type(states) is not list or len(states)!=contingency_len:
                    terminal_checks.append(False); path_checks.append(False); witnesses.append(_witness("Recoverable","RecoveryEvidenceCardinalityMismatch",cut_index=run.get('cut_index') if type(run) is dict else None)); continue
                for j,state in enumerate(states):
                    ok,failed=_fully_visible(state,services,routers); path_checks.append(ok is True)
                    if ok is not True: witnesses.append(_witness("RecoveryPathSafe","RecoveryRouteVisibilityViolationOrMalformedState",cut_index=run['cut_index'],step=j+1,services=failed))
                terminal=run.get("terminal_state")
                owners,visibility=_state_map(terminal,services,routers)
                term_ok=(owners==context.get("baseline") and visibility is not None and all(set(visibility[s])==set(routers) for s in services))
                terminal_checks.append(term_ok)
                if not term_ok: witnesses.append(_witness("RecoveryTerminalOK","RecoveryTerminalMismatch",cut_index=run['cut_index']))
            recovery_terminal_ok=all(terminal_checks) if terminal_checks else False
            recovery_path_safe=all(path_checks) if path_checks else (contingency_len==0)
        else:
            witnesses.append(_witness("Recoverable","RecoveryRunCardinalityMismatch"))
    else:
        witnesses.append(_witness("Evidence","SemanticEvidenceIncomplete"))

    recoverable=recovery_terminal_ok and recovery_path_safe
    full=schema_ok and auth_ok and forward_safe and final_ok and recoverable
    return {
        "SchemaOK":bool(schema_ok),"AuthOK":bool(auth_ok),"ForwardSafe":bool(forward_safe),"FinalOK":bool(final_ok),
        "RecoveryTerminalOK":bool(recovery_terminal_ok),"RecoveryPathSafe":bool(recovery_path_safe),"Recoverable":bool(recoverable),
        "FullGuardEquivalent":bool(full),"witnesses":witnesses,
        "evidence_provenance":deepcopy(semantic_evidence.get("evidence_provenance",{})) if type(semantic_evidence) is dict else {},
    }
