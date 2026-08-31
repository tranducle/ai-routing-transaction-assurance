#!/usr/bin/env python3
"""D6 infrastructure repair R2: deterministic IGMP membership capacity repair.

Scientific semantics are unchanged. This repair addresses a Linux network-namespace
capacity limit observed on the frozen OSPF star scale-32 topology, where the hub needs
more multicast memberships than the kernel default of 20 permits.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

FRR_IMAGE = "quay.io/frrouting/frr@sha256:65e5967b922572c0565d968388fb06af69d7e9b3b3eea40ad7e3810687667f68"
LINUX_DEFAULT_IGMP_MAX_MEMBERSHIPS = 20
OSPF_IPV4_MULTICAST_GROUPS_PER_INTERFACE = 2
IGMP_HEADROOM = 2


def max_topology_degree(case: dict) -> int:
    routers = list(case.get("routers") or [])
    if not routers:
        raise ValueError("case routers are required")
    degree = {router: 0 for router in routers}
    for edge in case.get("topology_edges") or []:
        if not isinstance(edge, list) or len(edge) != 2:
            raise ValueError("topology edge must contain exactly two routers")
        a, b = edge
        if a not in degree or b not in degree:
            raise ValueError("topology edge references unknown router")
        degree[a] += 1
        degree[b] += 1
    return max(degree.values())


def required_igmp_capacity(case: dict) -> int | None:
    """Return an override only when the frozen topology can exceed Linux default.

    OSPFv2 may need AllSPFRouters (224.0.0.5) and AllDRouters (224.0.0.6)
    memberships per participating interface. Capacity is derived only from frozen
    topology degree, not from any semantic result.
    """
    if case.get("protocol") != "OSPF":
        return None
    required = OSPF_IPV4_MULTICAST_GROUPS_PER_INTERFACE * max_topology_degree(case) + IGMP_HEADROOM
    return required if required > LINUX_DEFAULT_IGMP_MAX_MEMBERSHIPS else None


def inject_igmp_sysctls(case: dict, topology_text: str) -> Tuple[str, Dict[str, Any]]:
    capacity = required_igmp_capacity(case)
    if capacity is None:
        return topology_text, {
            "applied": False,
            "capacity": None,
            "nodes_modified": 0,
            "reason": "no_override_required",
        }

    image_line = f"      image: {FRR_IMAGE}\n"
    node_count = topology_text.count(image_line)
    expected_nodes = len(case.get("routers") or [])
    if node_count != expected_nodes:
        raise ValueError(
            f"topology node count mismatch for IGMP repair: expected {expected_nodes}, found {node_count}"
        )
    if "net.ipv4.igmp_max_memberships:" in topology_text:
        raise ValueError("topology already contains an IGMP membership override")

    addition = (
        image_line
        + "      sysctls:\n"
        + f"        net.ipv4.igmp_max_memberships: {capacity}\n"
    )
    rendered = topology_text.replace(image_line, addition)
    return rendered, {
        "applied": True,
        "capacity": capacity,
        "nodes_modified": node_count,
        "max_topology_degree": max_topology_degree(case),
        "formula": "2*max_topology_degree+2",
        "scientific_semantics_changed": False,
    }
