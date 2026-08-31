from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PHASE_E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_E / "03_semantic_replay"))

import live_frr_containerlab_v8 as live


def _case(protocol="BGP"):
    return {
        "case_id": "case-x",
        "base_task_id": "PE8-B005",
        "protocol": protocol,
        "routers": ["r1", "r2", "r3", "r4"],
        "topology_edges": [["r1", "r2"], ["r2", "r3"], ["r3", "r4"]],
        "protected_services": ["10.253.5.10/32"],
        "baseline_owners": {"10.253.5.10/32": ["r1"]},
        "target_owners": {"10.253.5.10/32": ["r4"]},
        "forward_plan": [
            {"step_id": "f1", "device_id": "r4", "object_type": "route_advertisement", "object_id": "10.253.5.10/32", "operation": "add", "parameters": {"prefix": "10.253.5.10/32", "epoch": 1}, "depends_on": []},
            {"step_id": "f2", "device_id": "r1", "object_type": "route_advertisement", "object_id": "10.253.5.10/32", "operation": "remove", "parameters": {"prefix": "10.253.5.10/32", "epoch": 2}, "depends_on": ["f1"]},
        ],
        "contingency_plan": [
            {"step_id": "r1", "device_id": "r4", "object_type": "route_advertisement", "object_id": "10.253.5.10/32", "operation": "remove", "parameters": {"prefix": "10.253.5.10/32", "epoch": 1}, "depends_on": []},
            {"step_id": "r2", "device_id": "r1", "object_type": "route_advertisement", "object_id": "10.253.5.10/32", "operation": "add", "parameters": {"prefix": "10.253.5.10/32", "epoch": 2}, "depends_on": ["r1"]},
        ],
    }


def test_apply_owner_step_is_pure_and_exact():
    c = _case()
    owners = {k: list(v) for k, v in c["baseline_owners"].items()}
    after_add = live.apply_owner_step(owners, c["forward_plan"][0])
    assert after_add == {"10.253.5.10/32": ["r1", "r4"]}
    assert owners == {"10.253.5.10/32": ["r1"]}
    after_remove = live.apply_owner_step(after_add, c["forward_plan"][1])
    assert after_remove == c["target_owners"]


def test_build_expected_state_program_matches_forward_and_recovery_semantics():
    p = live.build_expected_state_program(_case())
    assert [s["owners"] for s in p["forward"]] == [
        {"10.253.5.10/32": ["r1", "r4"]},
        {"10.253.5.10/32": ["r4"]},
    ]
    assert len(p["recovery_runs"]) == 2
    assert p["recovery_runs"][0]["terminal_owners"] == {"10.253.5.10/32": ["r1"]}
    assert p["recovery_runs"][1]["terminal_owners"] == {"10.253.5.10/32": ["r1"]}


def test_render_lab_uses_exact_frr_digest_and_every_topology_edge(tmp_path):
    rendered = live.materialize_lab(_case(), tmp_path)
    yml = Path(rendered["topology_path"]).read_text()
    assert live.FRR_IMAGE in yml
    assert yml.count("kind: linux") == 4
    assert yml.count("endpoints:") == 3
    for router in _case()["routers"]:
        conf = (tmp_path / router / "frr.conf").read_text()
        assert f"hostname {router}" in conf
        assert "router bgp" in conf


def test_ospf_render_has_ospfd_not_bgpd(tmp_path):
    live.materialize_lab(_case("OSPF"), tmp_path)
    daemons = (tmp_path / "r1" / "daemons").read_text()
    conf = (tmp_path / "r1" / "frr.conf").read_text()
    assert "ospfd=yes" in daemons
    assert "bgpd=no" in daemons
    assert "router ospf" in conf


def test_semantic_summary_does_not_require_route_presence_for_quiescence():
    c = _case()
    snapshot = {
        "control_plane_ready": True,
        "owners": {"10.253.5.10/32": ["r4"]},
        "route_visibility": {"10.253.5.10/32": ["r1", "r2", "r3", "r4"]},
    }
    s = live.semantic_state(snapshot, c)
    assert s["available"] is True
    assert s["owners"] == c["target_owners"]

    missing = dict(snapshot)
    missing["route_visibility"] = {"10.253.5.10/32": ["r4"]}
    assert live.semantic_state(missing, c)["available"] is False


def test_compare_live_obligations_uses_only_forward_final_recovery_fields():
    ref = {
        "ForwardAvailabilityReferenceOK": True,
        "TerminalObjectiveReferenceOK": False,
        "RecoveryPathReferenceOK": True,
        "RecoveryTerminalReferenceOK": True,
        "RecoveryReferenceOK": True,
        "AuthorizationReferenceOK": False,
        "SchemaReferenceOK": False,
    }
    measured = {
        "ForwardAvailabilityReferenceOK": True,
        "TerminalObjectiveReferenceOK": False,
        "RecoveryPathReferenceOK": True,
        "RecoveryTerminalReferenceOK": True,
        "RecoveryReferenceOK": True,
    }
    out = live.compare_semantics(ref, measured)
    assert out["agreement"] is True
    assert set(out["compared_fields"]) == set(live.LIVE_SEMANTIC_FIELDS)


def test_seal_verifier_fails_closed_before_any_deploy(tmp_path):
    harness = Path(live.__file__).resolve()
    seal = tmp_path / "seal.json"
    seal.write_text(json.dumps({"verdict": "FAIL", "files": []}))
    with pytest.raises(RuntimeError, match="seal"):
        live.verify_preexecution_seal(seal, required_paths=[harness])
