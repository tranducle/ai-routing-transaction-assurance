from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Tuple

from network_config_v8 import render_state_configs

HERE = Path(__file__).resolve().parent
PHASE_E = HERE.parent
LOCK = PHASE_E / "00_design_lock"
TAXONOMY_PATH = LOCK / "INDEPENDENT_PROPOSAL_ERROR_TAXONOMY_V8.md"

ARCHETYPES = (
    "two_service_parallel_handoff",
    "two_service_split_target_rebalance",
    "three_service_batch_handoff",
    "standby_rotation_two_service",
)
SCALES = (4, 8, 16, 32)
PROTOCOLS = ("BGP", "OSPF")
VARIANTS = (0, 1)
PLAN_TEMPLATES = (
    "grouped_make_before_break",
    "interleaved_forward",
    "interleaved_reverse",
    "cross_staged",
)
TOPOLOGY_FAMILIES = (
    "line",
    "ring",
    "star",
    "dual_path",
)


def _load_taxonomy() -> dict:
    return json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))


_TAXONOMY = _load_taxonomy()
TRANSFORMATION_IDS = tuple(
    row["id"]
    for key in ("safe_control_transformations", "error_transformations")
    for row in _TAXONOMY[key]
    if row["id"] != "substitute_stale_parameter"
)


def _sha_int(text: str) -> int:
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:16], 16)


def _service_prefix(task_index: int, service_index: int) -> str:
    fourth = (task_index * 5 + service_index * 17) % 250 + 1
    return f"10.253.{task_index}.{fourth}/32"


def _service_count(archetype: str) -> int:
    return 3 if archetype == "three_service_batch_handoff" else 2


def _topology_edges(scale: int, family: str) -> List[Tuple[str, str]]:
    routers = [f"r{i}" for i in range(1, scale + 1)]
    if family == "line":
        pairs = [(routers[i], routers[i + 1]) for i in range(scale - 1)]
    elif family == "ring":
        pairs = [(routers[i], routers[i + 1]) for i in range(scale - 1)] + [(routers[-1], routers[0])]
    elif family == "star":
        pairs = [(routers[0], routers[i]) for i in range(1, scale)]
    elif family == "dual_path":
        pairs = [(routers[i], routers[i + 1]) for i in range(scale - 1)]
        pairs += [(routers[i], routers[i + 2]) for i in range(scale - 2)]
    else:
        raise ValueError(family)
    # Canonical undirected de-duplication while preserving generation order.
    seen = set()
    out = []
    for a, b in pairs:
        key = tuple(sorted((a, b)))
        if key not in seen:
            seen.add(key)
            out.append((a, b))
    return out


def _target_owners(archetype: str, services: List[str], scale: int) -> Tuple[Dict[str, List[str]], List[str]]:
    far1 = f"r{scale}"
    far2 = f"r{max(3, scale - 1)}"
    mid = f"r{max(3, scale // 2 + 1)}"
    if archetype == "two_service_parallel_handoff":
        return {s: [far1] for s in services}, []
    if archetype == "two_service_split_target_rebalance":
        return {services[0]: [far1], services[1]: [far2]}, []
    if archetype == "three_service_batch_handoff":
        return {services[0]: [far1], services[1]: [far2], services[2]: [mid]}, []
    if archetype == "standby_rotation_two_service":
        return {s: [far1] for s in services}, [far2]
    raise ValueError(archetype)


def _step(step_id: str, operation: str, device: str, service: str, depends_on: List[str]) -> dict:
    return {
        "step_id": step_id,
        "device_id": device,
        "object_type": "route_advertisement",
        "object_id": service,
        "operation": operation,
        "parameters": {"prefix": service, "epoch": 0},
        "depends_on": list(depends_on),
    }


def _schedule(services: List[str], adds: Dict[str, dict], removes: Dict[str, dict], template: str) -> List[dict]:
    if template == "grouped_make_before_break":
        order = [adds[s] for s in services] + [removes[s] for s in services]
    elif template == "interleaved_forward":
        order = [step for s in services for step in (adds[s], removes[s])]
    elif template == "interleaved_reverse":
        order = [step for s in reversed(services) for step in (adds[s], removes[s])]
    elif template == "cross_staged":
        if len(services) == 2:
            # For two services, use an interleaved schedule; its paired contingency
            # template and topology family still make the complete task structurally distinct.
            order = [adds[services[0]], removes[services[0]], adds[services[1]], removes[services[1]]]
        else:
            s0, s1, s2 = services
            order = [adds[s0], adds[s1], removes[s0], adds[s2], removes[s2], removes[s1]]
    else:
        raise ValueError(template)
    out = [dict(step, parameters=dict(step["parameters"])) for step in order]
    for index, step in enumerate(out, start=1):
        step["parameters"]["epoch"] = index
    return out


def _base_plans(
    services: List[str],
    baseline: Dict[str, List[str]],
    target: Dict[str, List[str]],
    forward_template: str,
    contingency_template: str,
) -> Tuple[List[dict], List[dict]]:
    f_add = {}
    f_remove = {}
    c_add = {}
    c_remove = {}
    for index, service in enumerate(services, start=1):
        f_add_id = f"forward-add-{index:02d}"
        c_add_id = f"contingency-add-{index:02d}"
        f_add[service] = _step(f_add_id, "add", target[service][0], service, [])
        f_remove[service] = _step(
            f"forward-remove-{index:02d}", "remove", baseline[service][0], service, [f_add_id]
        )
        c_add[service] = _step(c_add_id, "add", baseline[service][0], service, [])
        c_remove[service] = _step(
            f"contingency-remove-{index:02d}", "remove", target[service][0], service, [c_add_id]
        )
    return (
        _schedule(services, f_add, f_remove, forward_template),
        _schedule(services, c_add, c_remove, contingency_template),
    )


def normalized_task_signature(task: dict) -> str:
    # Address-free signature for checking that paired variants differ structurally.
    service_index = {service: index for index, service in enumerate(task["protected_services"])}
    plan_sig = []
    for phase in ("forward_plan", "contingency_plan"):
        seq = []
        for step in task[phase]:
            seq.append(
                (
                    step["operation"],
                    step["device_id"],
                    service_index[step["object_id"]],
                    tuple(step["depends_on"]),
                )
            )
        plan_sig.append((phase, tuple(seq)))
    degrees = {r: 0 for r in task["routers"]}
    for a, b in task["topology_edges"]:
        degrees[a] += 1
        degrees[b] += 1
    payload = {
        "topology_family": task["topology_family"],
        "degree_sequence": sorted(degrees.values()),
        "plan_template_id": task["plan_template_id"],
        "contingency_template_id": task["contingency_template_id"],
        "plan": plan_sig,
        "target_role_pattern": [task["target_owners"][s][0] for s in task["protected_services"]],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def build_base_tasks() -> List[dict]:
    tasks: List[dict] = []
    task_index = 0
    for ai, archetype in enumerate(ARCHETYPES):
        for si, scale in enumerate(SCALES):
            for pi, protocol in enumerate(PROTOCOLS):
                for variant in VARIANTS:
                    task_index += 1
                    services = [_service_prefix(task_index, i) for i in range(_service_count(archetype))]
                    baseline = {s: ["r2"] for s in services}
                    target, standby = _target_owners(archetype, services, scale)
                    topology_family = TOPOLOGY_FAMILIES[(ai + si + 2 * pi + variant) % len(TOPOLOGY_FAMILIES)]
                    plan_template = PLAN_TEMPLATES[(ai + 2 * si + pi + variant) % len(PLAN_TEMPLATES)]
                    contingency_template = PLAN_TEMPLATES[(PLAN_TEMPLATES.index(plan_template) + 2) % len(PLAN_TEMPLATES)]
                    edges = _topology_edges(scale, topology_family)
                    forward, contingency = _base_plans(
                        services, baseline, target, plan_template, contingency_template
                    )
                    used_devices = sorted(
                        {step["device_id"] for step in forward + contingency}
                    )
                    authorization = {
                        "allowed_devices": used_devices,
                        "allowed_object_type": "route_advertisement",
                        "allowed_operations": ["add", "remove"],
                        "protected_services": services,
                    }
                    objective = {
                        "type": "route_availability_owner_change",
                        "protected_services": services,
                        "baseline_owners": baseline,
                        "target_owners": target,
                        "checkpoint_requirement": "at_least_one_advertiser_per_protected_service",
                        "terminal_requirement": "exact_target_owners",
                        "recovery_requirement": "exact_baseline_owners_after_every_modeled_cut",
                    }
                    task = {
                            "base_task_id": f"PE8-B{task_index:03d}",
                            "archetype": archetype,
                            "topology_scale": scale,
                            "protocol": protocol,
                            "task_variant": variant,
                            "topology_family": topology_family,
                            "topology_edges": [list(edge) for edge in edges],
                            "plan_template_id": plan_template,
                            "contingency_template_id": contingency_template,
                            "routers": [f"r{i}" for i in range(1, scale + 1)],
                            "protected_services": services,
                            "baseline_owners": baseline,
                            "target_owners": target,
                            "operator_objective": objective,
                            "authorization_contract": authorization,
                            "forward_plan": forward,
                            "contingency_plan": contingency,
                            "baseline_configs": {},
                            "standby_devices": standby,
                            "primary_comparator_policy": {
                                "B2_role": "PRIMARY_FINAL_STATE_COMPARATOR",
                                "B3_role": "DESCRIPTIVE_EQUIVALENCE_SANITY_NOT_SUPERIORITY_GATE",
                                "B4_role": "FORWARD_PLUS_FINAL_RECOVERY_BLIND_COMPARATOR",
                                "B5_role": "STRONG_RECOVERY_TERMINAL_AWARE_COMPARATOR",
                            },
                        }
                    task["baseline_configs"] = render_state_configs(task, baseline)
                    tasks.append(task)
    return tasks


def _all_steps(task: dict):
    return [
        (phase, index, step)
        for phase in ("forward_plan", "contingency_plan")
        for index, step in enumerate(task[phase])
    ]


def check_transformation_precondition(task: dict, transformation_id: str):
    forward = task["forward_plan"]
    contingency = task["contingency_plan"]
    all_steps = _all_steps(task)
    if transformation_id == "control_forward_disjoint_adjacent_swap":
        ok = any(
            a["device_id"] != b["device_id"]
            and (a["object_type"], a["object_id"]) != (b["object_type"], b["object_id"])
            and b["step_id"] not in a.get("depends_on", [])
            and a["step_id"] not in b.get("depends_on", [])
            for a, b in zip(forward, forward[1:])
        )
        return ok, "eligible adjacent disjoint forward pair" if ok else "no eligible adjacent disjoint forward pair"
    if transformation_id == "control_contingency_disjoint_adjacent_swap":
        ok = any(
            a["device_id"] != b["device_id"]
            and (a["object_type"], a["object_id"]) != (b["object_type"], b["object_id"])
            and b["step_id"] not in a.get("depends_on", [])
            and a["step_id"] not in b.get("depends_on", [])
            for a, b in zip(contingency, contingency[1:])
        )
        return ok, "eligible adjacent disjoint contingency pair" if ok else "no eligible adjacent disjoint contingency pair"
    if transformation_id in {"drop_one_step", "duplicate_one_step", "move_step_to_opposite_section"}:
        return bool(all_steps), "plan contains steps" if all_steps else "empty plan"
    if transformation_id == "swap_forward_adjacent_steps":
        return len(forward) >= 2, "forward length >=2" if len(forward) >= 2 else "forward length <2"
    if transformation_id == "swap_contingency_adjacent_steps":
        return len(contingency) >= 2, "contingency length >=2" if len(contingency) >= 2 else "contingency length <2"
    if transformation_id == "retarget_step_device":
        distinct = {step["device_id"] for _, _, step in all_steps}
        return len(distinct) >= 2, ">=2 declared devices" if len(distinct) >= 2 else "<2 declared devices"
    if transformation_id == "retarget_step_object":
        by_type: Dict[str, set] = {}
        for _, _, step in all_steps:
            by_type.setdefault(step["object_type"], set()).add(step["object_id"])
        ok = any(len(values) >= 2 for values in by_type.values())
        return ok, ">=2 object ids of same type" if ok else "no same-type alternative object"
    if transformation_id == "invert_operation":
        ok = any(step["operation"] in {"add", "remove", "create", "delete", "enable", "disable", "activate", "deactivate", "permit", "deny"} for _, _, step in all_steps)
        return ok, "invertible operation present" if ok else "no invertible operation"
    if transformation_id == "substitute_stale_parameter":
        for phase_steps in (forward, contingency):
            for later_index in range(1, len(phase_steps)):
                later = phase_steps[later_index]
                for earlier_index in range(later_index):
                    earlier = phase_steps[earlier_index]
                    for name, value in later.get("parameters", {}).items():
                        if name in {"prefix", "device_id", "object_id"}:
                            continue
                        if name in earlier.get("parameters", {}) and earlier["parameters"][name] != value:
                            return True, "shared differing non-target scalar parameter"
        return False, "no stale-parameter candidate"
    if transformation_id == "truncate_phase_suffix":
        ok = len(forward) >= 2 or len(contingency) >= 2
        return ok, "phase length >=2" if ok else "both phases <2"
    return False, f"unknown transformation {transformation_id}"


def build_seed_manifest() -> List[dict]:
    rows = []
    for task in build_base_tasks():
        for tid in TRANSFORMATION_IDS:
            token = f"GRANT1|PE8|{task['base_task_id']}|{tid}"
            rows.append(
                {
                    "case_id": f"PE8-C-{hashlib.sha256(token.encode()).hexdigest()[:20]}",
                    "base_task_id": task["base_task_id"],
                    "transformation_id": tid,
                    "case_seed": _sha_int(token),
                }
            )
    return rows


def build_generator_input_manifest() -> dict:
    tasks = build_base_tasks()
    failures = []
    for task in tasks:
        for tid in TRANSFORMATION_IDS:
            ok, reason = check_transformation_precondition(task, tid)
            if not ok:
                failures.append({"base_task_id": task["base_task_id"], "transformation_id": tid, "reason": reason})
    return {
        "design_lock_version": 8,
        "namespace": "PE8",
        "base_task_count": len(tasks),
        "case_count": len(tasks) * len(TRANSFORMATION_IDS),
        "base_tasks": tasks,
        "case_seeds": build_seed_manifest(),
        "transformation_ids": list(TRANSFORMATION_IDS),
        "transformation_taxonomy_path": "00_design_lock/INDEPENDENT_PROPOSAL_ERROR_TAXONOMY_V8.md",
        "transformation_taxonomy_sha256": hashlib.sha256(TAXONOMY_PATH.read_bytes()).hexdigest(),
        "precondition_policy": "HARD_FAIL_NO_SUBSTITUTE_NO_RESAMPLE",
        "all_preconditions_pass": not failures,
        "precondition_failures": failures,
        "reference_verifiability_required": "704_OF_704",
        "post_label_case_addition_allowed": False,
        "post_label_case_reweighting_allowed": False,
        "candidate_generation_allowed_before_independent_pass_and_seal": False,
    }
