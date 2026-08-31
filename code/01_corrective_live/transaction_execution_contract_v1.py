#!/usr/bin/env python3
"""Prospective PE12 fail-closed execution contract.

This module is intentionally separate from the sealed Phase-E D6 helper. It governs
only new Phase-F evidence and cannot modify or reinterpret historical D6 outcomes.
A route-advertisement step is executable only after its semantic identity contract
has been validated. The canonical executable prefix is ``object_id``.
"""
from __future__ import annotations

from typing import List


class SemanticContractError(ValueError):
    """A transaction is semantically invalid for prospective live execution."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def validate_route_advertisement_step(case: dict, step: dict) -> str:
    """Return canonical ``object_id`` after fail-closed semantic validation."""
    if step.get("object_type") != "route_advertisement":
        raise SemanticContractError("UnsupportedObjectType")
    object_id = step.get("object_id")
    if not isinstance(object_id, str) or not object_id.strip():
        raise SemanticContractError("MissingObjectId")
    parameters = step.get("parameters")
    if not isinstance(parameters, dict):
        raise SemanticContractError("MissingParametersPrefix")
    prefix = parameters.get("prefix")
    if not isinstance(prefix, str) or not prefix.strip():
        raise SemanticContractError("MissingParametersPrefix")
    if object_id != prefix:
        raise SemanticContractError("ObjectIdPrefixMismatch")
    if step.get("operation") not in {"add", "remove"}:
        raise SemanticContractError("UnsupportedOperation")
    if case.get("protocol") not in {"BGP", "OSPF"}:
        raise SemanticContractError("UnsupportedProtocol")
    return object_id


def _normalized_lines(running_config: str) -> set[str]:
    return {line.strip() for line in str(running_config).splitlines() if line.strip()}


def _presence(case: dict, step: dict, running_config: str) -> tuple[bool, bool, str]:
    prefix = validate_route_advertisement_step(case, step)
    lines = _normalized_lines(running_config)
    owner_present = f"ip address {prefix}" in lines
    if case["protocol"] == "BGP":
        advertisement_present = f"network {prefix}" in lines
    else:
        advertisement_present = f"network {prefix} area 0" in lines
    return owner_present, advertisement_present, prefix


def plan_idempotent_step(case: dict, step: dict, running_config: str) -> dict:
    """Plan FRR CLI only after canonical semantic identity has been validated."""
    owner_present, advertisement_present, prefix = _presence(case, step, running_config)
    operation = step["operation"]
    want_present = operation == "add"
    commands: List[str] = []
    body: List[str] = []

    if want_present:
        if not owner_present:
            body += ["interface lo", f"ip address {prefix}", "exit"]
        if not advertisement_present:
            if case["protocol"] == "BGP":
                body += ["router bgp {ASN}", f"network {prefix}", "exit"]
            else:
                body += ["router ospf", f"network {prefix} area 0", "exit"]
    else:
        if advertisement_present:
            if case["protocol"] == "BGP":
                body += ["router bgp {ASN}", f"no network {prefix}", "exit"]
            else:
                body += ["router ospf", f"no network {prefix} area 0", "exit"]
        if owner_present:
            body += ["interface lo", f"no ip address {prefix}", "exit"]

    if body:
        commands = ["configure terminal", *body, "end"]
    return {
        "commands": commands,
        "noop": not commands,
        "canonical_prefix": prefix,
        "owner_present_before": owner_present,
        "advertisement_present_before": advertisement_present,
        "desired_present": want_present,
    }


def step_satisfied(case: dict, step: dict, running_config: str) -> bool:
    owner_present, advertisement_present, _ = _presence(case, step, running_config)
    if step["operation"] == "add":
        return owner_present and advertisement_present
    return (not owner_present) and (not advertisement_present)
