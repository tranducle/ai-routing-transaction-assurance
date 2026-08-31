from __future__ import annotations

from copy import deepcopy

ALLOWED_TOP_LEVEL = (
    "case_id",
    "protocol",
    "routers",
    "protected_services",
    "baseline_owners",
    "target_owners",
    "authorization_contract",
    "forward_plan",
    "contingency_plan",
)

ALLOWED_STEP_FIELDS = (
    "step_id",
    "device_id",
    "object_type",
    "object_id",
    "operation",
    "parameters",
    "depends_on",
)

ALLOWED_AUTH_FIELDS = (
    "allowed_devices",
    "allowed_object_type",
    "allowed_operations",
    "protected_services",
)

ALLOWED_PARAMETER_FIELDS = (
    "prefix",
    "epoch",
)


def _sanitize_step(step: dict) -> dict:
    out = {key: deepcopy(step[key]) for key in ALLOWED_STEP_FIELDS if key in step and key != "parameters"}
    if "parameters" in step and isinstance(step["parameters"], dict):
        out["parameters"] = {
            key: deepcopy(step["parameters"][key])
            for key in ALLOWED_PARAMETER_FIELDS
            if key in step["parameters"]
        }
    elif "parameters" in step:
        out["parameters"] = deepcopy(step["parameters"])
    return out


def _sanitize_auth(auth: dict) -> dict:
    return {key: deepcopy(auth[key]) for key in ALLOWED_AUTH_FIELDS if key in auth}


def make_blind_view(generation_case: dict) -> dict:
    """Return the exact immutable input surface permitted to the reference oracle."""
    out = {}
    for key in ALLOWED_TOP_LEVEL:
        if key not in generation_case:
            continue
        value = generation_case[key]
        if key in {"forward_plan", "contingency_plan"}:
            out[key] = [_sanitize_step(step) for step in value]
        elif key == "authorization_contract":
            out[key] = _sanitize_auth(value)
        else:
            out[key] = deepcopy(value)
    return out
