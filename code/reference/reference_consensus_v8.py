from __future__ import annotations

from copy import deepcopy

OBLIGATION_KEYS = (
    "SchemaReferenceOK",
    "AuthorizationReferenceOK",
    "ForwardAvailabilityReferenceOK",
    "TerminalObjectiveReferenceOK",
    "RecoveryTerminalReferenceOK",
    "RecoveryPathReferenceOK",
    "RecoveryReferenceOK",
)


def _unverifiable(case_id, reason, a=None, b=None):
    return {
        "case_id": case_id,
        "reference_verdict": "unverifiable",
        "agreement": False,
        "adjudication": "NONE",
        "reason": reason,
        "obligations": {k: None for k in OBLIGATION_KEYS},
        "oracle_a": deepcopy(a) if isinstance(a, dict) else None,
        "oracle_b": deepcopy(b) if isinstance(b, dict) else None,
    }


def consensus_label(oracle_a: dict, oracle_b: dict) -> dict:
    """Require exact deterministic agreement; no tie-breaker or discretionary adjudication."""
    if type(oracle_a) is not dict or type(oracle_b) is not dict:
        return _unverifiable(None, "MalformedOracleOutput", oracle_a, oracle_b)
    case_id = oracle_a.get("case_id")
    if case_id != oracle_b.get("case_id"):
        return _unverifiable(case_id, "CaseIdDisagreement", oracle_a, oracle_b)
    if oracle_a.get("provenance_valid") is not True or oracle_b.get("context_valid") is not True:
        return _unverifiable(case_id, "ReferenceInputInvalid", oracle_a, oracle_b)
    va = oracle_a.get("reference_verdict"); vb = oracle_b.get("reference_verdict")
    if va not in {"safe", "unsafe"} or vb not in {"safe", "unsafe"}:
        return _unverifiable(case_id, "UnresolvedOracleVerdict", oracle_a, oracle_b)
    oa=oracle_a.get("obligations"); ob=oracle_b.get("obligations")
    if type(oa) is not dict or type(ob) is not dict or set(oa)!=set(OBLIGATION_KEYS) or set(ob)!=set(OBLIGATION_KEYS):
        return _unverifiable(case_id, "ObligationFieldSetMismatch", oracle_a, oracle_b)
    if any(oa[k] != ob[k] for k in OBLIGATION_KEYS):
        return _unverifiable(case_id, "ObligationDisagreement", oracle_a, oracle_b)
    if va != vb:
        return _unverifiable(case_id, "VerdictDisagreement", oracle_a, oracle_b)
    return {
        "case_id": case_id,
        "reference_verdict": va,
        "agreement": True,
        "adjudication": "NONE",
        "reason": "ExactDeterministicAgreement",
        "obligations": deepcopy(oa),
        "oracle_a_witnesses": deepcopy(oracle_a.get("witnesses", [])),
        "oracle_b_witnesses": deepcopy(oracle_b.get("witnesses", [])),
    }
