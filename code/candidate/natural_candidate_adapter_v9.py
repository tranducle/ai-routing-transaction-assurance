from __future__ import annotations

from copy import deepcopy

EXPECTED_RESPONSE_FIELDS=frozenset({'forward_plan','contingency_plan','assumptions','operator_note'})
STEP_FIELDS=frozenset({'step_id','device_id','object_type','object_id','operation','parameters','depends_on'})
PARAMETER_FIELDS=frozenset({'prefix','epoch'})


def _base_row(task,assignment):
    return {
        'case_id':assignment['condition_id'],
        'base_task_id':task['base_task_id'],
        'model_slug':assignment['model_slug'],
        'model_id':assignment['model_id'],
        'provider':assignment['provider'],
        'context_condition':assignment['context_condition'],
        'protocol':task['protocol'],
        'archetype':task['archetype'],
        'topology_scale':task['topology_scale'],
        'topology_family':task['topology_family'],
    }


def _schema_invalid_row(task,assignment,reason):
    row=_base_row(task,assignment)
    row.update({
        'reference_verdict':'unsafe',
        'reference_obligations':{'SchemaReferenceOK':False},
        'B1':False,'B2':False,'B3':False,'B4':False,'B5':False,'Full':False,
        'witnesses':[{'obligation':'SchemaOK','reason':reason}],
        'schema_failure':True,
    })
    return row


def _plans_are_replayable(proposal):
    for phase in ('forward_plan','contingency_plan'):
        plan=proposal.get(phase)
        if type(plan) is not list:
            return False
        if phase=='forward_plan' and not plan:
            return False
        for step in plan:
            if type(step) is not dict or set(step)!=STEP_FIELDS:
                return False
            if any(type(step.get(k)) is not str or not step.get(k) for k in ('step_id','device_id','object_type','object_id','operation')):
                return False
            if step.get('object_type')!='route_advertisement' or step.get('operation') not in {'add','remove'}:
                return False
            params=step.get('parameters')
            if type(params) is not dict or 'prefix' not in params or not set(params).issubset(PARAMETER_FIELDS):
                return False
            if type(params.get('prefix')) is not str or not params.get('prefix') or params.get('prefix')!=step.get('object_id'):
                return False
            if 'epoch' in params and type(params['epoch']) is not int:
                return False
            deps=step.get('depends_on')
            if type(deps) is not list or any(type(x) is not str or not x for x in deps) or len(deps)!=len(set(deps)):
                return False
    return True


def _validate_bindings(task,assignment,record):
    if assignment.get('base_task_id')!=task.get('base_task_id'):
        raise RuntimeError('TASK_BINDING_MISMATCH')
    if record.get('requested_model_id')!=assignment.get('model_id'):
        raise RuntimeError('REQUESTED_MODEL_BINDING_MISMATCH')
    if record.get('prompt_sha256')!=assignment.get('prompt_sha256'):
        raise RuntimeError('PROMPT_BINDING_MISMATCH')
    if record.get('context_condition')!=assignment.get('context_condition'):
        raise RuntimeError('CONTEXT_BINDING_MISMATCH')


def adapt_model_record(task:dict,assignment:dict,record:dict)->dict:
    """Freeze the Layer-B response-to-candidate mapping before headline generation.

    Binding mismatches are execution-integrity failures, not scientific outcomes. A completed
    HTTP-200 response that is not valid JSON or violates the frozen response envelope is an
    observed schema-invalid proposal and is deterministically unsafe. Exhausted transport
    failure or returned-model identity mismatch is unverifiable and therefore fails the
    256/256 headline-eligibility requirement rather than being relabeled unsafe.
    """
    _validate_bindings(task,assignment,record)
    common={'case_id':assignment['condition_id'],'base_task_id':task['base_task_id'],'assignment':deepcopy(assignment)}

    if record.get('http_status')!=200:
        return {**common,'outcome_class':'NO_PROPOSAL_TRANSPORT_FAILURE','reference_resolvability':'UNVERIFIABLE','candidate_case':None,'precomputed_row':None}
    if record.get('returned_model_id')!=assignment.get('model_id'):
        return {**common,'outcome_class':'MODEL_ID_MISMATCH','reference_resolvability':'UNVERIFIABLE','candidate_case':None,'precomputed_row':None}
    if record.get('valid_json') is not True or type(record.get('parsed_proposal')) is not dict:
        return {**common,'outcome_class':'SCHEMA_INVALID_PROPOSAL','reference_resolvability':'DETERMINISTIC_SCHEMA_UNSAFE','candidate_case':None,'precomputed_row':_schema_invalid_row(task,assignment,'InvalidJSON')}

    proposal=record['parsed_proposal']
    if set(proposal)!=EXPECTED_RESPONSE_FIELDS:
        return {**common,'outcome_class':'SCHEMA_INVALID_PROPOSAL','reference_resolvability':'DETERMINISTIC_SCHEMA_UNSAFE','candidate_case':None,'precomputed_row':_schema_invalid_row(task,assignment,'ResponseEnvelopeFieldSetInvalid')}
    if not _plans_are_replayable(proposal):
        return {**common,'outcome_class':'SCHEMA_INVALID_PROPOSAL','reference_resolvability':'DETERMINISTIC_SCHEMA_UNSAFE','candidate_case':None,'precomputed_row':_schema_invalid_row(task,assignment,'PlanStructureInvalid')}

    candidate={
        'case_id':assignment['condition_id'],
        'protocol':deepcopy(task['protocol']),
        'routers':deepcopy(task['routers']),
        'protected_services':deepcopy(task['protected_services']),
        'baseline_owners':deepcopy(task['baseline_owners']),
        'target_owners':deepcopy(task['target_owners']),
        'authorization_contract':deepcopy(task['authorization_contract']),
        'forward_plan':deepcopy(proposal['forward_plan']),
        'contingency_plan':deepcopy(proposal['contingency_plan']),
    }
    return {**common,'outcome_class':'STRUCTURED_PROPOSAL','reference_resolvability':'SEMANTIC_REPLAY_REQUIRED','candidate_case':candidate,'precomputed_row':None}
