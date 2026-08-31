from __future__ import annotations

from copy import deepcopy

from deterministic_oracle_a_v8 import label_case as label_a
from deterministic_oracle_b_v8 import label_case as label_b
from deterministic_replay_audit_v8 import audit_replay_evidence
from reference_consensus_v8 import consensus_label


def _blocked(case_id, reason):
    return {
        "case_id": case_id,
        "reference_verdict": "unverifiable",
        "agreement": False,
        "adjudication": "NONE",
        "reason": reason,
        "obligations": {},
    }


def evaluate_reference(case: dict, blind_case: dict, raw_batfish: dict, semantic_evidence: dict) -> dict:
    """Deterministic PE8 reference pipeline. Replay audit is a prerequisite to either oracle."""
    audit = audit_replay_evidence(case, blind_case, raw_batfish, semantic_evidence)
    if audit.get("valid") is not True:
        return {
            "case_id": blind_case.get("case_id"),
            "replay_audit": audit,
            "oracle_a": None,
            "oracle_b": None,
            "consensus": _blocked(blind_case.get("case_id"), "ReplayAuditFailed"),
        }
    context = {"case_id": blind_case.get("case_id"), "topology_edges": deepcopy(case.get("topology_edges"))}
    a = label_a(blind_case, semantic_evidence)
    b = label_b(blind_case, context)
    c = consensus_label(a, b)
    return {"case_id": blind_case.get("case_id"), "replay_audit": audit, "oracle_a": a, "oracle_b": b, "consensus": c}
