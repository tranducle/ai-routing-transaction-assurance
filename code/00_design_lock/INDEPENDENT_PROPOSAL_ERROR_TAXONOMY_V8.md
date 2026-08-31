{
  "error_transformations": [
    {
      "deterministic_parameterization_rule": "Create candidates as (forward, index) followed by (contingency, index), each in ascending index order. Let u be the first 16 hexadecimal characters of SHA-256(case_seed || id), interpreted as an unsigned integer; remove candidate[u mod candidate_count].",
      "id": "drop_one_step",
      "mechanical_rule": "Remove one selected step from its array without modifying any remaining step.",
      "name": "Omit one plan step",
      "preconditions": "The forward or contingency array contains at least one step."
    },
    {
      "deterministic_parameterization_rule": "Create candidates as (forward, index) followed by (contingency, index), each in ascending index order. Let u be the first 16 hexadecimal characters of SHA-256(case_seed || id), interpreted as an unsigned integer; duplicate candidate[u mod candidate_count].",
      "id": "duplicate_one_step",
      "mechanical_rule": "Insert a second copy immediately after the selected step, preserving its operation payload, target fields, and parameters. If IDs must be unique, assign the copy the deterministic ID original_id + '-dup-' + original_index.",
      "name": "Duplicate one plan step",
      "preconditions": "The forward or contingency array contains at least one step."
    },
    {
      "deterministic_parameterization_rule": "Let u be the first 16 hexadecimal characters of SHA-256(case_seed || id), interpreted as an unsigned integer. Select index i = u mod (forward_step_count - 1) and swap entries i and i + 1.",
      "id": "swap_forward_adjacent_steps",
      "mechanical_rule": "Swap one adjacent pair of forward steps.",
      "name": "Reorder adjacent forward steps",
      "preconditions": "The forward-step array has at least two entries."
    },
    {
      "deterministic_parameterization_rule": "Let u be the first 16 hexadecimal characters of SHA-256(case_seed || id), interpreted as an unsigned integer. Select index i = u mod (contingency_step_count - 1) and swap entries i and i + 1.",
      "id": "swap_contingency_adjacent_steps",
      "mechanical_rule": "Swap one adjacent pair of contingency steps.",
      "name": "Reorder adjacent contingency steps",
      "preconditions": "The contingency-step array has at least two entries."
    },
    {
      "deterministic_parameterization_rule": "Enumerate candidates as (phase, index, replacement_device_id), ordered by phase, index, then replacement_device_id. Let u be the first 16 hexadecimal characters of SHA-256(case_seed || id), interpreted as an unsigned integer; apply candidate[u mod candidate_count].",
      "id": "retarget_step_device",
      "mechanical_rule": "Replace one selected step's declared device_id with a different device_id already declared elsewhere in the plan; retain its object and operation payload unchanged.",
      "name": "Apply a step to the wrong device",
      "preconditions": "The plan declares at least two distinct device IDs and at least one step can be paired with a different declared device ID."
    },
    {
      "deterministic_parameterization_rule": "Enumerate candidates as (phase, index, replacement_object_id), ordered by phase, index, then replacement_object_id. Let u be the first 16 hexadecimal characters of SHA-256(case_seed || id), interpreted as an unsigned integer; apply candidate[u mod candidate_count].",
      "id": "retarget_step_object",
      "mechanical_rule": "Replace one selected step's object_id with a different object_id of the same declared object_type already present in the plan; retain its device_id and operation payload unchanged.",
      "name": "Apply a step to the wrong object",
      "preconditions": "At least two distinct object IDs of one object_type are declared in the plan."
    },
    {
      "deterministic_parameterization_rule": "Order eligible steps by phase and array index. Let u be the first 16 hexadecimal characters of SHA-256(case_seed || id), interpreted as an unsigned integer; invert the operation of step[u mod eligible_step_count].",
      "id": "invert_operation",
      "mechanical_rule": "Replace one normalized operation field using the fixed inverse map: add\u2194remove, create\u2194delete, enable\u2194disable, activate\u2194deactivate, permit\u2194deny. Do not alter other fields.",
      "name": "Invert a command operation",
      "preconditions": "At least one step has an operation field exactly equal to a key in the fixed inverse map."
    },
    {
      "deterministic_parameterization_rule": "Order source candidates by phase then index. Let u and v be the first and second 16-hexadecimal-character chunks of SHA-256(case_seed || id), interpreted as unsigned integers. Select source[u mod source_count] and insert it into the opposite array at index v mod (destination_count + 1).",
      "id": "move_step_to_opposite_section",
      "mechanical_rule": "Remove one step from its current array and insert it into the opposite array without changing its text, target fields, or parameters.",
      "name": "Place a step in the wrong plan section",
      "preconditions": "At least one forward or contingency step exists."
    },
    {
      "deterministic_parameterization_rule": "Enumerate candidates as (phase, suffix_length) for every suffix length from 1 through phase_length - 1, ordered by phase then suffix_length. Let u be the first 16 hexadecimal characters of SHA-256(case_seed || id), interpreted as an unsigned integer; remove the selected suffix.",
      "id": "truncate_phase_suffix",
      "mechanical_rule": "Remove a non-empty suffix from either the forward or contingency array.",
      "name": "Drop a trailing portion of a plan section",
      "preconditions": "At least one phase has two or more steps."
    }
  ],
  "exclusions": [
    {
      "category": "Vendor-specific semantic mutations",
      "reason": "Changing platform-specific BGP/OSPF commands, timers, attributes, or syntax requires vendor parsers and semantics."
    },
    {
      "category": "Packet corruption or protocol-message mutation",
      "reason": "These alter traffic or protocol exchanges rather than configuration-change plan text."
    },
    {
      "category": "Arbitrary link, node, process, or hardware failures",
      "reason": "These model external infrastructure faults rather than operator, tool, or automation plan-edit mistakes."
    }
  ],
  "safe_control_transformations": [
    {
      "deterministic_parameterization_rule": "Let u be the first 16 hexadecimal characters of SHA-256(case_seed || id), interpreted as an unsigned integer. Sort eligible pairs by their first array index and select pair[u mod pair_count].",
      "id": "control_forward_disjoint_adjacent_swap",
      "mechanical_rule": "Exchange one adjacent pair of forward-step array entries; do not modify either step's text, target fields, or parameters.",
      "name": "Swap adjacent disjoint forward steps",
      "preconditions": "At least one adjacent forward-step pair has different declared device IDs and different (object_type, object_id) tuples, and neither step declares the other in a depends_on field."
    },
    {
      "deterministic_parameterization_rule": "Let u be the first 16 hexadecimal characters of SHA-256(case_seed || id), interpreted as an unsigned integer. Sort eligible pairs by their first array index and select pair[u mod pair_count].",
      "id": "control_contingency_disjoint_adjacent_swap",
      "mechanical_rule": "Exchange one adjacent pair of contingency-step array entries; do not modify either step's text, target fields, or parameters.",
      "name": "Swap adjacent disjoint contingency steps",
      "preconditions": "At least one adjacent contingency-step pair has different declared device IDs and different (object_type, object_id) tuples, and neither step declares the other in a depends_on field."
    }
  ],
  "v8_provenance": {
    "active_transformation_count": 11,
    "filter": "removed substitute_stale_parameter before PE8 outcomes because the parameter was not consumed by sealed routing/replay semantics",
    "source": "INDEPENDENT_PROPOSAL_ERROR_TAXONOMY.md"
  }
}
