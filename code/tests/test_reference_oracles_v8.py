from __future__ import annotations

import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path

PHASE_E = Path(__file__).resolve().parents[1]
PRIMARY = PHASE_E / "01_primary_v8"
REPLAY = PHASE_E / "03_semantic_replay"
for p in (PRIMARY, REPLAY):
    sys.path.insert(0, str(p))

from blind_view_v8 import make_blind_view
from deterministic_oracle_a_v8 import label_case as label_a
from deterministic_oracle_b_v8 import label_case as label_b
from primary_design_v8 import build_base_tasks
from reference_consensus_v8 import consensus_label


def _apply(state, step):
    out = {s: set(v) for s, v in state.items()}
    obj = step["object_id"]
    if step["operation"] == "add":
        out[obj].add(step["device_id"])
    elif step["operation"] == "remove":
        out[obj].discard(step["device_id"])
    return {s: sorted(v) for s, v in out.items()}


def _visibility(task, owners):
    # Test fixture mirrors the bounded connected-topology semantics but is independent
    # of either production oracle implementation.
    adj = {r: set() for r in task["routers"]}
    for a, b in task["topology_edges"]:
        adj[a].add(b); adj[b].add(a)
    out = {}
    for svc, svc_owners in owners.items():
        seen = set(svc_owners); stack = list(svc_owners)
        while stack:
            cur = stack.pop()
            for nxt in adj[cur]:
                if nxt not in seen:
                    seen.add(nxt); stack.append(nxt)
        out[svc] = sorted(seen)
    return out


def _semantic_payload(task, blind):
    state = {s: sorted(v) for s, v in blind["baseline_owners"].items()}
    forward = []
    cuts = []
    for step in blind["forward_plan"]:
        state = _apply(state, step)
        forward.append({"owners": deepcopy(state), "route_visibility": _visibility(task, state)})
        cuts.append(deepcopy(state))
    runs = []
    for cut, cut_state in enumerate(cuts, start=1):
        state = deepcopy(cut_state); states = []
        for step in blind["contingency_plan"]:
            state = _apply(state, step)
            states.append({"owners": deepcopy(state), "route_visibility": _visibility(task, state)})
        runs.append({"cut_index": cut, "states": states, "terminal_state": states[-1] if states else {"owners": deepcopy(state), "route_visibility": _visibility(task, state)}})
    return {
        "evidence_complete": True,
        "parser_clean": True,
        "parser_issues": [],
        "forward_states": forward,
        "terminal_state": forward[-1],
        "recovery_runs": runs,
    }


def _canonical_hash(obj):
    import hashlib
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _evidence(task, blind):
    payload = _semantic_payload(task, blind)
    evidence = deepcopy(payload)
    evidence["evidence_provenance"] = {
        "contract_version": 8,
        "schema_id": "GRANT1_PE8_BATFISH_ROUTE_VISIBILITY_EVIDENCE_V1",
        "case_id": blind["case_id"],
        "blind_case_sha256": _canonical_hash(blind),
        "semantic_payload_sha256": _canonical_hash(payload),
        "baseline_config_bundle_sha256": "a" * 64,
        "candidate_config_bundle_sha256": "b" * 64,
        "query_plan_sha256": "c" * 64,
        "raw_batfish_output_sha256": "d" * 64,
        "replay_pipeline_id": "BATFISH_PRIMARY_PE8",
        "replay_executor_contract": "GRANT1_PE8_EXECUTABLE_BATFISH_V1",
        "batfish_image_digest": "batfish/allinone@sha256:09817554db90e2f2674b72562c2d659427094187de0a3dfc23534ab58bf26207",
        "pybatfish_version": "2025.07.07.2423",
    }
    return evidence


def _base():
    task = deepcopy(build_base_tasks()[0])
    task["case_id"] = "PE8-TEST-CASE"
    blind = make_blind_view(task)
    context = {"case_id": blind["case_id"], "topology_edges": deepcopy(task["topology_edges"])}
    return task, blind, context


def test_oracles_agree_on_safe_base_transaction():
    task, blind, context = _base()
    a = label_a(blind, _evidence(task, blind))
    b = label_b(blind, context)
    assert a["reference_verdict"] == "safe"
    assert b["reference_verdict"] == "safe"
    c = consensus_label(a, b)
    assert c["reference_verdict"] == "safe"
    assert c["agreement"] is True


def test_oracles_agree_on_forward_availability_failure():
    task, blind, context = _base()
    # Break make-before-break by placing the first baseline remove before its target add.
    remove_i = next(i for i, s in enumerate(blind["forward_plan"]) if s["operation"] == "remove")
    add_i = next(i for i, s in enumerate(blind["forward_plan"]) if s["operation"] == "add" and s["object_id"] == blind["forward_plan"][remove_i]["object_id"])
    step = blind["forward_plan"].pop(remove_i)
    blind["forward_plan"].insert(add_i, step)
    # Make dependency list structurally valid for this semantic fixture so the unsafe signal is Forward, not Schema.
    blind["forward_plan"][add_i]["depends_on"] = []
    for s in blind["forward_plan"]:
        if s is step:
            s["depends_on"] = []
    evidence = _evidence(task, blind)
    a = label_a(blind, evidence)
    b = label_b(blind, context)
    assert a["reference_verdict"] == "unsafe"
    assert b["reference_verdict"] == "unsafe"
    assert a["obligations"]["ForwardAvailabilityReferenceOK"] is False
    assert b["obligations"]["ForwardAvailabilityReferenceOK"] is False


def test_terminal_only_failure_is_not_double_counted_as_forward_failure():
    task, blind, context = _base()
    evidence = _evidence(task, blind)
    svc = blind["protected_services"][0]
    evidence["terminal_state"]["owners"][svc] = []
    evidence["terminal_state"]["route_visibility"][svc] = []
    payload = {k: evidence[k] for k in ("evidence_complete", "parser_clean", "parser_issues", "forward_states", "terminal_state", "recovery_runs")}
    evidence["evidence_provenance"]["semantic_payload_sha256"] = _canonical_hash(payload)
    a = label_a(blind, evidence)
    assert a["reference_verdict"] == "unsafe"
    assert a["obligations"]["ForwardAvailabilityReferenceOK"] is True
    assert a["obligations"]["TerminalObjectiveReferenceOK"] is False


def test_oracle_a_provenance_failure_is_unverifiable_not_unsafe():
    task, blind, _ = _base()
    evidence = _evidence(task, blind)
    evidence["evidence_provenance"]["raw_batfish_output_sha256"] = "0" * 63
    a = label_a(blind, evidence)
    assert a["reference_verdict"] == "unverifiable"
    assert a["provenance_valid"] is False


def test_oracle_b_uses_topology_not_only_owner_arithmetic():
    task, blind, context = _base()
    # Disconnect r1 from every current/target owner while leaving owner sets nonempty.
    context["topology_edges"] = [["r1", "r3"]]
    b = label_b(blind, context)
    assert b["reference_verdict"] == "unsafe"
    assert b["obligations"]["ForwardAvailabilityReferenceOK"] is False or b["obligations"]["TerminalObjectiveReferenceOK"] is False


def test_consensus_disagreement_is_unverifiable_with_no_majority_vote():
    a = {"case_id": "x", "reference_verdict": "safe", "obligations": {"SchemaReferenceOK": True}, "witnesses": [], "provenance_valid": True}
    b = {"case_id": "x", "reference_verdict": "unsafe", "obligations": {"SchemaReferenceOK": False}, "witnesses": [], "context_valid": True}
    c = consensus_label(a, b)
    assert c["reference_verdict"] == "unverifiable"
    assert c["agreement"] is False
    assert c["adjudication"] == "NONE"
