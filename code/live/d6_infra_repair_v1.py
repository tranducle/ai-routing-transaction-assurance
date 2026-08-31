#!/usr/bin/env python3
"""Infrastructure-only D6 repair helpers.

This module does not change D6 case selection, reference labels, semantic obligations,
acceptance thresholds, or scientific claim rules. It only maps the already-frozen
set-valued owner/advertisement operations onto FRR CLI idempotently and ensures
Containerlab timeouts terminate inside the Colima VM before retries begin.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

DEPLOY_TIMEOUT_SEC = 180
DESTROY_TIMEOUT_SEC = 120
REMOTE_KILL_AFTER_SEC = 10


def _normalized_lines(running_config: str) -> set[str]:
    return {line.strip() for line in str(running_config).splitlines() if line.strip()}


def _presence(case: dict, step: dict, running_config: str) -> tuple[bool, bool]:
    prefix = step["parameters"]["prefix"]
    lines = _normalized_lines(running_config)
    owner_present = f"ip address {prefix}" in lines
    if case["protocol"] == "BGP":
        advertisement_present = f"network {prefix}" in lines
    elif case["protocol"] == "OSPF":
        advertisement_present = f"network {prefix} area 0" in lines
    else:
        raise ValueError(f"unsupported protocol: {case['protocol']}")
    return owner_present, advertisement_present


def plan_idempotent_step(case: dict, step: dict, running_config: str) -> dict:
    """Translate a frozen set add/remove into only the FRR CLI deltas actually needed."""
    prefix = step["parameters"]["prefix"]
    operation = step["operation"]
    owner_present, advertisement_present = _presence(case, step, running_config)
    if operation not in {"add", "remove"}:
        raise ValueError(f"unsupported operation: {operation}")

    want_present = operation == "add"
    commands: List[str] = []
    body: List[str] = []

    # Add owner before protocol advertisement. For remove, withdraw advertisement first,
    # then remove the connected owner. No semantic checkpoint occurs between subcommands.
    if want_present:
        if not owner_present:
            body += ["interface lo", f"ip address {prefix}", "exit"]
        if not advertisement_present:
            if case["protocol"] == "BGP":
                # The caller replaces {ASN} because this helper intentionally knows no router numbering policy.
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
        "owner_present_before": owner_present,
        "advertisement_present_before": advertisement_present,
        "desired_present": want_present,
    }


def step_satisfied(case: dict, step: dict, running_config: str) -> bool:
    owner_present, advertisement_present = _presence(case, step, running_config)
    if step["operation"] == "add":
        return owner_present and advertisement_present
    if step["operation"] == "remove":
        return (not owner_present) and (not advertisement_present)
    raise ValueError(f"unsupported operation: {step['operation']}")


def containerlab_args(topology_path: Path, action: str) -> List[str]:
    topo = str(Path(topology_path).resolve())
    if action == "deploy":
        seconds = DEPLOY_TIMEOUT_SEC
        tail = ["containerlab", "deploy", "-t", topo, "--reconfigure"]
    elif action == "destroy":
        seconds = DESTROY_TIMEOUT_SEC
        tail = ["containerlab", "destroy", "-t", topo, "--cleanup"]
    else:
        raise ValueError(action)
    return [
        "colima",
        "ssh",
        "--",
        "timeout",
        "--signal=TERM",
        f"--kill-after={REMOTE_KILL_AFTER_SEC}s",
        f"{seconds}s",
        *tail,
    ]
