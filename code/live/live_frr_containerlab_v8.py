#!/usr/bin/env python3
"""Frozen-before-D6-outcome FRR/Containerlab live semantic audit harness.

This module intentionally separates pure materialization/measurement logic from live process
execution. Any live caller MUST verify the D6 pre-execution seal before `containerlab deploy`.
The live audit measures only bounded route-availability/final/recovery semantics. Authorization
remains normative and is never inferred from live routing behavior.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

FRR_IMAGE = "quay.io/frrouting/frr@sha256:65e5967b922572c0565d968388fb06af69d7e9b3b3eea40ad7e3810687667f68"
FRR_VERSION = "10.7.0_git"
CONTAINERLAB_VERSION = "0.79.0"
QUIESCENCE_CONSECUTIVE_STABLE = 5
QUIESCENCE_SAMPLE_INTERVAL_SEC = 1
QUIESCENCE_TIMEOUT_SEC = 120
LIVE_SEMANTIC_FIELDS = (
    "ForwardAvailabilityReferenceOK",
    "TerminalObjectiveReferenceOK",
    "RecoveryPathReferenceOK",
    "RecoveryTerminalReferenceOK",
    "RecoveryReferenceOK",
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _router_number(router: str) -> int:
    m = re.fullmatch(r"r(\d+)", router)
    if not m:
        raise ValueError(f"unsupported router id: {router}")
    return int(m.group(1))


def _task_index(case: dict) -> int:
    m = re.search(r"(\d+)$", str(case.get("base_task_id", "")))
    if not m:
        raise ValueError("base_task_id must end in a numeric task index")
    return int(m.group(1))


def _link_inventory(case: dict) -> Dict[str, List[dict]]:
    task_idx = _task_index(case)
    inv = {r: [] for r in case["routers"]}
    iface_count = {r: 0 for r in case["routers"]}
    for li, edge in enumerate(case["topology_edges"], start=1):
        if len(edge) != 2:
            raise ValueError("topology edge must have exactly two routers")
        a, b = edge
        if a not in inv or b not in inv:
            raise ValueError("topology edge references unknown router")
        iface_count[a] += 1
        iface_count[b] += 1
        subnet = ipaddress.ip_network(f"172.63.{task_idx}.{li * 4}/30", strict=False)
        hosts = list(subnet.hosts())
        inv[a].append({"peer": b, "ifname": f"eth{iface_count[a]}", "ip": f"{hosts[0]}/30", "peer_ip": str(hosts[1])})
        inv[b].append({"peer": a, "ifname": f"eth{iface_count[b]}", "ip": f"{hosts[1]}/30", "peer_ip": str(hosts[0])})
    return inv


def apply_owner_step(owners: dict, step: dict) -> dict:
    out = {svc: sorted(set(vals)) for svc, vals in deepcopy(owners).items()}
    prefix = step["parameters"]["prefix"]
    router = step["device_id"]
    out.setdefault(prefix, [])
    if step["operation"] == "add":
        out[prefix] = sorted(set(out[prefix]) | {router})
    elif step["operation"] == "remove":
        out[prefix] = sorted(set(out[prefix]) - {router})
    else:
        raise ValueError(f"unsupported operation: {step['operation']}")
    return out


def build_expected_state_program(case: dict) -> dict:
    baseline = {k: sorted(v) for k, v in case["baseline_owners"].items()}
    owners = deepcopy(baseline)
    forward = []
    for step in case["forward_plan"]:
        owners = apply_owner_step(owners, step)
        forward.append({"step_id": step["step_id"], "owners": deepcopy(owners)})

    recovery_runs = []
    for cut in range(1, len(case["forward_plan"]) + 1):
        owners = deepcopy(baseline)
        for step in case["forward_plan"][:cut]:
            owners = apply_owner_step(owners, step)
        states = []
        for step in case["contingency_plan"]:
            owners = apply_owner_step(owners, step)
            states.append({"step_id": step["step_id"], "owners": deepcopy(owners)})
        recovery_runs.append({"cut_index": cut, "states": states, "terminal_owners": deepcopy(owners)})
    return {"baseline_owners": baseline, "forward": forward, "recovery_runs": recovery_runs}


def _daemons(protocol: str) -> str:
    bgp = "yes" if protocol == "BGP" else "no"
    ospf = "yes" if protocol == "OSPF" else "no"
    return (
        "zebra=yes\n"
        f"bgpd={bgp}\n"
        f"ospfd={ospf}\n"
        "staticd=yes\n"
        "vtysh_enable=yes\n"
    )


def _router_config(case: dict, router: str, links: Sequence[dict], owners: dict) -> str:
    task_idx = _task_index(case)
    rnum = _router_number(router)
    lines = [
        "frr defaults traditional",
        f"hostname {router}",
        "service integrated-vtysh-config",
        "!",
    ]
    for link in links:
        lines += [f"interface {link['ifname']}", f" ip address {link['ip']}", "!"]
    for svc in case["protected_services"]:
        if router in owners.get(svc, []):
            lines += ["interface lo", f" ip address {svc}", "!"]
    rid = f"10.255.{task_idx}.{rnum}"
    if case["protocol"] == "BGP":
        asn = 65000 + rnum
        lines += [f"router bgp {asn}", f" bgp router-id {rid}"]
        for link in links:
            lines.append(f" neighbor {link['peer_ip']} remote-as {65000 + _router_number(link['peer'])}")
        for svc in case["protected_services"]:
            if router in owners.get(svc, []):
                lines.append(f" network {svc}")
        lines += ["!"]
    elif case["protocol"] == "OSPF":
        lines += ["router ospf", f" ospf router-id {rid}"]
        for link in links:
            subnet = ipaddress.ip_interface(link["ip"]).network
            lines.append(f" network {subnet} area 0")
        for svc in case["protected_services"]:
            if router in owners.get(svc, []):
                lines.append(f" network {svc} area 0")
        lines += ["!"]
    else:
        raise ValueError(f"unsupported protocol: {case['protocol']}")
    lines += ["line vty", "!"]
    return "\n".join(lines) + "\n"


def materialize_lab(case: dict, out_dir: Path) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    links = _link_inventory(case)
    for router in case["routers"]:
        rdir = out_dir / router
        rdir.mkdir(parents=True, exist_ok=True)
        (rdir / "daemons").write_text(_daemons(case["protocol"]))
        (rdir / "frr.conf").write_text(_router_config(case, router, links[router], case["baseline_owners"]))

    safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "-", case["case_id"].lower())[-40:]
    lab_name = f"grant1-d6-{safe_name}"
    yml = [f"name: {lab_name}", "topology:", "  nodes:"]
    for router in case["routers"]:
        rdir = (out_dir / router).resolve()
        yml += [
            f"    {router}:",
            "      kind: linux",
            f"      image: {FRR_IMAGE}",
            "      binds:",
            f"        - {rdir / 'daemons'}:/etc/frr/daemons",
            f"        - {rdir / 'frr.conf'}:/etc/frr/frr.conf",
        ]
    yml += ["  links:"]
    iface_count = {r: 0 for r in case["routers"]}
    for a, b in case["topology_edges"]:
        iface_count[a] += 1
        iface_count[b] += 1
        yml += [f'    - endpoints: ["{a}:eth{iface_count[a]}", "{b}:eth{iface_count[b]}"]']
    topo = out_dir / "lab.clab.yml"
    topo.write_text("\n".join(yml) + "\n")
    return {
        "lab_name": lab_name,
        "topology_path": str(topo.resolve()),
        "topology_sha256": sha256_file(topo),
        "router_count": len(case["routers"]),
        "link_count": len(case["topology_edges"]),
    }


def semantic_state(snapshot: dict, case: dict) -> dict:
    routers = set(case["routers"])
    owners = {svc: sorted(snapshot.get("owners", {}).get(svc, [])) for svc in case["protected_services"]}
    visibility = {svc: sorted(snapshot.get("route_visibility", {}).get(svc, [])) for svc in case["protected_services"]}
    available = all(bool(owners[svc]) and set(visibility[svc]) == routers for svc in case["protected_services"])
    return {"owners": owners, "route_visibility": visibility, "available": available}


def compare_semantics(reference_obligations: dict, measured_obligations: dict) -> dict:
    comparisons = {field: {"reference": reference_obligations.get(field), "live": measured_obligations.get(field), "match": reference_obligations.get(field) == measured_obligations.get(field)} for field in LIVE_SEMANTIC_FIELDS}
    return {
        "compared_fields": list(LIVE_SEMANTIC_FIELDS),
        "comparisons": comparisons,
        "agreement": all(item["match"] for item in comparisons.values()),
    }


def verify_preexecution_seal(seal_path: Path, required_paths: Sequence[Path]) -> dict:
    seal_path = Path(seal_path).resolve()
    seal = json.loads(seal_path.read_text())
    if seal.get("verdict") != "PASS":
        raise RuntimeError("D6 pre-execution seal is not PASS; live deploy is forbidden")
    indexed = {str(Path(item["path"]).resolve()): item["sha256"] for item in seal.get("files", [])}
    for path in required_paths:
        p = Path(path).resolve()
        expected = indexed.get(str(p))
        if expected is None:
            raise RuntimeError(f"required harness path absent from D6 seal: {p}")
        if sha256_file(p) != expected:
            raise RuntimeError(f"D6 seal hash mismatch: {p}")
    return seal


def _run(args: Sequence[str], *, cwd: Path | None = None, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), cwd=str(cwd) if cwd else None, text=True, capture_output=True, timeout=timeout)


def _vtysh(container: str, commands: Sequence[str], timeout: int = 30) -> str:
    args = ["docker", "exec", container, "vtysh"]
    for command in commands:
        args += ["-c", command]
    proc = _run(args, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "vtysh failed")
    return proc.stdout


def step_commands(case: dict, step: dict) -> List[str]:
    router = step["device_id"]
    prefix = step["parameters"]["prefix"]
    operation = step["operation"]
    negate = "no " if operation == "remove" else ""
    commands = ["configure terminal", "interface lo", f" {negate}ip address {prefix}", "exit"]
    if case["protocol"] == "BGP":
        commands += [f"router bgp {65000 + _router_number(router)}", f" {negate}network {prefix}", "exit"]
    else:
        commands += ["router ospf", f" {negate}network {prefix} area 0", "exit"]
    commands += ["end"]
    return commands


def _json_vty(container: str, command: str) -> Any:
    raw = _vtysh(container, [command])
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"non-JSON FRR output for {command}: {raw[:200]}") from exc


def measure_snapshot(case: dict, lab_name: str) -> dict:
    owners = {svc: [] for svc in case["protected_services"]}
    visibility = {svc: [] for svc in case["protected_services"]}
    peer_state = {}
    ready = True
    expected_degree = {r: 0 for r in case["routers"]}
    for a, b in case["topology_edges"]:
        expected_degree[a] += 1
        expected_degree[b] += 1

    for router in case["routers"]:
        container = f"clab-{lab_name}-{router}"
        if case["protocol"] == "BGP":
            summary = _json_vty(container, "show bgp summary json")
            peers = (summary.get("ipv4Unicast") or {}).get("peers") or {}
            compact = sorted((ip, p.get("state")) for ip, p in peers.items())
            peer_state[router] = compact
            if len(compact) < expected_degree[router] or any(state != "Established" for _, state in compact):
                ready = False
        else:
            summary = _json_vty(container, "show ip ospf neighbor json")
            compact = []
            for rid, entries in (summary.get("neighbors") or {}).items():
                for e in entries:
                    state = e.get("converged") or e.get("nbrState") or e.get("state")
                    compact.append((rid, state))
            compact = sorted(compact)
            peer_state[router] = compact
            if len(compact) < expected_degree[router] or any(state != "Full" for _, state in compact):
                ready = False

        for svc in case["protected_services"]:
            route = _json_vty(container, f"show ip route {svc} json")
            vals = []
            for _, entries in route.items():
                if isinstance(entries, list):
                    vals.extend(entries)
            if vals:
                visibility[svc].append(router)
            if any(str(v.get("protocol", "")).lower() in {"connected", "local"} for v in vals if isinstance(v, dict)):
                owners[svc].append(router)

    snapshot = {
        "control_plane_ready": ready,
        "peer_state": peer_state,
        "owners": {k: sorted(v) for k, v in owners.items()},
        "route_visibility": {k: sorted(v) for k, v in visibility.items()},
    }
    snapshot["signature"] = canonical_sha256(snapshot)
    return snapshot


def wait_for_quiescence(case: dict, lab_name: str, *, timeout_sec: int = QUIESCENCE_TIMEOUT_SEC) -> dict:
    trace = []
    stable = 0
    last_sig = None
    start = time.monotonic()
    while time.monotonic() - start <= timeout_sec:
        snap = measure_snapshot(case, lab_name)
        if snap["control_plane_ready"] and snap["signature"] == last_sig:
            stable += 1
        elif snap["control_plane_ready"]:
            stable = 1
        else:
            stable = 0
        trace.append({"t_sec": round(time.monotonic() - start, 3), "stable_run": stable, "snapshot": snap})
        if stable >= QUIESCENCE_CONSECUTIVE_STABLE:
            return {"quiescent": True, "trace": trace, "final_snapshot": snap}
        last_sig = snap["signature"]
        time.sleep(QUIESCENCE_SAMPLE_INTERVAL_SEC)
    return {"quiescent": False, "trace": trace, "final_snapshot": trace[-1]["snapshot"] if trace else None}


def derive_measured_obligations(case: dict, forward_snapshots: Sequence[dict], recovery_runs: Sequence[dict]) -> dict:
    # Match frozen deterministic oracle semantics: forward safety excludes the final checkpoint,
    # while terminal objective is judged separately.
    forward_states = [semantic_state(s, case) for s in forward_snapshots]
    forward_values = [s["available"] for s in forward_states[:-1]]
    forward_ok = all(forward_values) if forward_values else True
    terminal = forward_states[-1] if forward_states else {"owners": {}, "route_visibility": {}, "available": False}
    final_ok = terminal["owners"] == {k: sorted(v) for k, v in case["target_owners"].items()} and terminal["available"]

    path_values = []
    terminal_values = []
    baseline = {k: sorted(v) for k, v in case["baseline_owners"].items()}
    for run in recovery_runs:
        states = [semantic_state(s, case) for s in run["snapshots"]]
        path_values.extend(s["available"] for s in states)
        terminal_state = semantic_state(run["terminal_snapshot"], case)
        terminal_values.append(terminal_state["owners"] == baseline and terminal_state["available"])
    recovery_path_ok = all(path_values) if path_values else True
    recovery_terminal_ok = all(terminal_values) if terminal_values else True
    return {
        "ForwardAvailabilityReferenceOK": forward_ok,
        "TerminalObjectiveReferenceOK": final_ok,
        "RecoveryPathReferenceOK": recovery_path_ok,
        "RecoveryTerminalReferenceOK": recovery_terminal_ok,
        "RecoveryReferenceOK": recovery_path_ok and recovery_terminal_ok,
    }
