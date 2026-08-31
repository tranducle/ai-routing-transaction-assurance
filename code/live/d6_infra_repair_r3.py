#!/usr/bin/env python3
"""D6 infrastructure repair R3: enable intended eBGP NLRI exchange under FRR traditional profile.

This repair does not alter topology, route ownership operations, reference obligations,
semantic measurements, retry count, quiescence rule, or acceptance threshold. It removes
FRR's default RFC8212 eBGP policy requirement so the live harness can realize the already-
frozen abstract assumption that directly configured eBGP peers exchange reachable NLRI.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Tuple

POLICY_RELAXATION = " no bgp ebgp-requires-policy"


def inject_bgp_exchange_policy(case: dict, config_text: str) -> Tuple[str, Dict[str, Any]]:
    if case.get("protocol") != "BGP":
        return config_text, {"applied": False, "stanzas_modified": 0, "reason": "not_bgp"}

    text = str(config_text)
    if POLICY_RELAXATION in text:
        raise ValueError("BGP config already contains an eBGP policy override")

    matches = list(re.finditer(r"(?m)^router bgp \d+\s*$", text))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one router BGP stanza, found {len(matches)}")

    match = matches[0]
    line_end = text.find("\n", match.end())
    if line_end < 0:
        rendered = text + "\n" + POLICY_RELAXATION + "\n"
    else:
        rendered = text[: line_end + 1] + POLICY_RELAXATION + "\n" + text[line_end + 1 :]
    return rendered, {
        "applied": True,
        "stanzas_modified": 1,
        "command": POLICY_RELAXATION.strip(),
        "scientific_semantics_changed": False,
    }


def summary_has_ebgp_policy_block(summary_text: str) -> bool:
    return "(Policy)" in str(summary_text)
