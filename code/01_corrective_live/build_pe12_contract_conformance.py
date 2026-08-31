#!/usr/bin/env python3
"""Build and execute the frozen PE12-A 32-case execution-contract conformance suite."""
from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import transaction_execution_contract_v1 as contract  # noqa: E402


def _step(prefix: str, *, operation: str = "add") -> dict:
    return {
        "step_id": "pe12-a-step",
        "device_id": "r2",
        "object_type": "route_advertisement",
        "object_id": prefix,
        "operation": operation,
        "parameters": {"prefix": prefix, "epoch": 1},
        "depends_on": [],
    }


def _running(protocol: str, prefix: str, present: bool) -> str:
    if not present:
        return ""
    if protocol == "BGP":
        return f"interface lo\n ip address {prefix}\nrouter bgp 65002\n network {prefix}\n"
    return f"interface lo\n ip address {prefix}\nrouter ospf\n network {prefix} area 0\n"


def build_cases() -> list[dict]:
    rows: list[dict] = []
    ordinal = 0
    for protocol in ("BGP", "OSPF"):
        # 4 valid adds + 4 valid removes.
        for mode in ("valid_add", "valid_remove"):
            for variant in range(4):
                ordinal += 1
                prefix = f"10.252.{1 if protocol == 'BGP' else 2}.{ordinal}/32"
                operation = "add" if mode == "valid_add" else "remove"
                rows.append({
                    "case_id": f"PE12-A-{protocol}-{ordinal:02d}",
                    "protocol": protocol,
                    "step": _step(prefix, operation=operation),
                    "running_config": _running(protocol, prefix, present=operation == "remove"),
                    "expected_status": "PLANNABLE",
                    "expected_reason": None,
                })
        # 4 explicit object/prefix mismatches.
        for variant in range(4):
            ordinal += 1
            prefix = f"10.252.{3 if protocol == 'BGP' else 4}.{ordinal}/32"
            step = _step(prefix)
            step["object_id"] = f"10.252.{5 if protocol == 'BGP' else 6}.{ordinal}/32"
            rows.append({
                "case_id": f"PE12-A-{protocol}-{ordinal:02d}",
                "protocol": protocol,
                "step": step,
                "running_config": "",
                "expected_status": "REJECTED",
                "expected_reason": "ObjectIdPrefixMismatch",
            })
        # Four additional schema/operation negatives.
        negatives = [
            ("MissingObjectId", lambda s: s.__setitem__("object_id", "")),
            ("MissingParametersPrefix", lambda s: s["parameters"].pop("prefix")),
            ("UnsupportedObjectType", lambda s: s.__setitem__("object_type", "acl_rule")),
            ("UnsupportedOperation", lambda s: s.__setitem__("operation", "replace")),
        ]
        for reason, mutate in negatives:
            ordinal += 1
            prefix = f"10.252.{7 if protocol == 'BGP' else 8}.{ordinal}/32"
            step = _step(prefix)
            mutate(step)
            rows.append({
                "case_id": f"PE12-A-{protocol}-{ordinal:02d}",
                "protocol": protocol,
                "step": step,
                "running_config": "",
                "expected_status": "REJECTED",
                "expected_reason": reason,
            })
    return rows


def run_suite() -> dict:
    results = []
    for row in build_cases():
        emitted: list[str] = []
        actual_status = None
        actual_reason = None
        try:
            plan = contract.plan_idempotent_step(
                {"protocol": row["protocol"]}, deepcopy(row["step"]), row["running_config"]
            )
            emitted = list(plan["commands"])
            actual_status = "PLANNABLE"
        except contract.SemanticContractError as exc:
            actual_status = "REJECTED"
            actual_reason = exc.reason
        passed = actual_status == row["expected_status"] and actual_reason == row["expected_reason"]
        if row["expected_status"] == "REJECTED":
            passed = passed and emitted == []
        results.append({
            "case_id": row["case_id"],
            "protocol": row["protocol"],
            "expected_status": row["expected_status"],
            "expected_reason": row["expected_reason"],
            "actual_status": actual_status,
            "actual_reason": actual_reason,
            "commands_emitted": emitted,
            "passed": passed,
        })
    passed = sum(bool(r["passed"]) for r in results)
    protocols = {p: sum(r["protocol"] == p for r in results) for p in ("BGP", "OSPF")}
    return {
        "schema_id": "GRANT1_PE12_A_CONTRACT_CONFORMANCE_V1",
        "total_cases": len(results),
        "protocol_counts": protocols,
        "passed_cases": passed,
        "failed_cases": len(results) - passed,
        "verdict": "PASS" if passed == len(results) == 32 else "FAIL",
        "cases": results,
    }


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    result = run_suite()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: result[k] for k in ("total_cases", "protocol_counts", "passed_cases", "failed_cases", "verdict")}, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
