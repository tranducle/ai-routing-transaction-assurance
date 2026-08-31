from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Dict, List, Tuple

from primary_design_v8 import TRANSFORMATION_IDS, build_base_tasks, build_seed_manifest, check_transformation_precondition

PHASE_KEYS = ("forward_plan", "contingency_plan")
INVERSE_OPERATION = {
    "add": "remove",
    "remove": "add",
    "create": "delete",
    "delete": "create",
    "enable": "disable",
    "disable": "enable",
    "activate": "deactivate",
    "deactivate": "activate",
    "permit": "deny",
    "deny": "permit",
}


def _digest(case_seed: int, transformation_id: str) -> str:
    # The taxonomy says SHA-256(case_seed || id); v4 freezes this as UTF-8 decimal seed
    # immediately concatenated with the transformation identifier, with no separator.
    return hashlib.sha256(f"{case_seed}{transformation_id}".encode("utf-8")).hexdigest()


def _u(case_seed: int, transformation_id: str) -> int:
    return int(_digest(case_seed, transformation_id)[:16], 16)


def _uv(case_seed: int, transformation_id: str) -> Tuple[int, int]:
    digest = _digest(case_seed, transformation_id)
    return int(digest[:16], 16), int(digest[16:32], 16)


def _eligible_disjoint_pairs(steps: List[dict]) -> List[int]:
    out = []
    for index in range(len(steps) - 1):
        a, b = steps[index], steps[index + 1]
        if a["device_id"] == b["device_id"]:
            continue
        if (a["object_type"], a["object_id"]) == (b["object_type"], b["object_id"]):
            continue
        if b["step_id"] in a.get("depends_on", []) or a["step_id"] in b.get("depends_on", []):
            continue
        out.append(index)
    return out


def _all_step_candidates(plan: dict):
    return [(phase, index) for phase in PHASE_KEYS for index in range(len(plan[phase]))]


def apply_transformation(base_task: dict, transformation_id: str, case_seed: int) -> Tuple[dict, dict]:
    if transformation_id not in TRANSFORMATION_IDS:
        raise KeyError(transformation_id)
    ok, reason = check_transformation_precondition(base_task, transformation_id)
    if not ok:
        raise RuntimeError(
            f"HARD_FAIL_NO_SUBSTITUTE_NO_RESAMPLE: {base_task['base_task_id']} {transformation_id}: {reason}"
        )

    out = deepcopy(base_task)
    meta = {
        "transformation_id": transformation_id,
        "case_seed": case_seed,
        "selection_digest_sha256": _digest(case_seed, transformation_id),
    }
    u = _u(case_seed, transformation_id)

    if transformation_id in {
        "control_forward_disjoint_adjacent_swap",
        "control_contingency_disjoint_adjacent_swap",
    }:
        phase = "forward_plan" if transformation_id.startswith("control_forward") else "contingency_plan"
        eligible = _eligible_disjoint_pairs(out[phase])
        index = eligible[u % len(eligible)]
        out[phase][index], out[phase][index + 1] = out[phase][index + 1], out[phase][index]
        meta.update({"phase": phase, "selected_index": index})
        return out, meta

    if transformation_id in {"drop_one_step", "duplicate_one_step"}:
        candidates = _all_step_candidates(out)
        phase, index = candidates[u % len(candidates)]
        if transformation_id == "drop_one_step":
            removed = out[phase].pop(index)
            meta.update({"phase": phase, "selected_index": index, "selected_step_id": removed["step_id"]})
        else:
            original = out[phase][index]
            duplicate = deepcopy(original)
            duplicate["step_id"] = f"{original['step_id']}-dup-{index}"
            out[phase].insert(index + 1, duplicate)
            meta.update({"phase": phase, "selected_index": index, "selected_step_id": original["step_id"]})
        return out, meta

    if transformation_id in {"swap_forward_adjacent_steps", "swap_contingency_adjacent_steps"}:
        phase = "forward_plan" if transformation_id.startswith("swap_forward") else "contingency_plan"
        index = u % (len(out[phase]) - 1)
        out[phase][index], out[phase][index + 1] = out[phase][index + 1], out[phase][index]
        meta.update({"phase": phase, "selected_index": index})
        return out, meta

    if transformation_id == "retarget_step_device":
        declared_devices = sorted({step["device_id"] for phase in PHASE_KEYS for step in out[phase]})
        candidates = []
        for phase in PHASE_KEYS:
            for index, step in enumerate(out[phase]):
                for replacement in declared_devices:
                    if replacement != step["device_id"]:
                        candidates.append((phase, index, replacement))
        phase, index, replacement = candidates[u % len(candidates)]
        old = out[phase][index]["device_id"]
        out[phase][index]["device_id"] = replacement
        meta.update({"phase": phase, "selected_index": index, "old_device_id": old, "replacement_device_id": replacement})
        return out, meta

    if transformation_id == "retarget_step_object":
        objects_by_type: Dict[str, set] = {}
        for phase in PHASE_KEYS:
            for step in out[phase]:
                objects_by_type.setdefault(step["object_type"], set()).add(step["object_id"])
        candidates = []
        for phase in PHASE_KEYS:
            for index, step in enumerate(out[phase]):
                for replacement in sorted(objects_by_type[step["object_type"]]):
                    if replacement != step["object_id"]:
                        candidates.append((phase, index, replacement))
        phase, index, replacement = candidates[u % len(candidates)]
        old = out[phase][index]["object_id"]
        out[phase][index]["object_id"] = replacement
        meta.update({"phase": phase, "selected_index": index, "old_object_id": old, "replacement_object_id": replacement})
        return out, meta

    if transformation_id == "invert_operation":
        candidates = []
        for phase in PHASE_KEYS:
            for index, step in enumerate(out[phase]):
                if step["operation"] in INVERSE_OPERATION:
                    candidates.append((phase, index))
        phase, index = candidates[u % len(candidates)]
        old = out[phase][index]["operation"]
        out[phase][index]["operation"] = INVERSE_OPERATION[old]
        meta.update({"phase": phase, "selected_index": index, "old_operation": old, "new_operation": INVERSE_OPERATION[old]})
        return out, meta

    if transformation_id == "move_step_to_opposite_section":
        u1, v = _uv(case_seed, transformation_id)
        sources = _all_step_candidates(out)
        source_phase, source_index = sources[u1 % len(sources)]
        destination_phase = "contingency_plan" if source_phase == "forward_plan" else "forward_plan"
        step = out[source_phase].pop(source_index)
        destination_index = v % (len(out[destination_phase]) + 1)
        out[destination_phase].insert(destination_index, step)
        meta.update(
            {
                "phase": source_phase,
                "selected_index": source_index,
                "destination_phase": destination_phase,
                "destination_index": destination_index,
                "selected_step_id": step["step_id"],
            }
        )
        return out, meta

    if transformation_id == "truncate_phase_suffix":
        candidates = []
        for phase in PHASE_KEYS:
            for suffix_length in range(1, len(out[phase])):
                candidates.append((phase, suffix_length))
        phase, suffix_length = candidates[u % len(candidates)]
        start_index = len(out[phase]) - suffix_length
        removed_ids = [step["step_id"] for step in out[phase][start_index:]]
        del out[phase][start_index:]
        meta.update(
            {
                "phase": phase,
                "suffix_length": suffix_length,
                "start_index": start_index,
                "removed_step_ids": removed_ids,
            }
        )
        return out, meta

    raise AssertionError(f"unhandled transformation: {transformation_id}")


def build_generation_cases() -> List[dict]:
    tasks = {task["base_task_id"]: task for task in build_base_tasks()}
    rows: List[dict] = []
    for seed_row in build_seed_manifest():
        base = tasks[seed_row["base_task_id"]]
        mutated, meta = apply_transformation(base, seed_row["transformation_id"], seed_row["case_seed"])
        row = deepcopy(mutated)
        row.update(
            {
                "case_id": seed_row["case_id"],
                "base_task_id": seed_row["base_task_id"],
                "transformation_id": seed_row["transformation_id"],
                "case_seed": seed_row["case_seed"],
                "mutation_parameters": meta,
            }
        )
        rows.append(row)
    return rows
