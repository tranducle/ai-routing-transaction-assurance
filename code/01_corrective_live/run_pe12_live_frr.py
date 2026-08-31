#!/usr/bin/env python3
"""Execute the preregistered PE12-B fresh FRR/Containerlab conformance study.

Scientific rules:
- PE12 is prospective and does not replace the official D6 78/80 result.
- Every route-advertisement step is validated by transaction_execution_contract_v1.
- Semantic-contract failures are never infrastructure retries.
- Infrastructure failures may receive at most one retry; all attempts are retained.
- Semantic mismatches are retained and are never replaced or rerun for score repair.
- The frozen PE12-B exact-agreement criterion is 100% of 40 selected cases.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, List

HERE = Path(__file__).resolve().parent
PHASE_F = HERE.parent
PHASE_E = PHASE_F.parent / "phase_E"
D6 = PHASE_E / "03_semantic_replay"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(D6))

import transaction_execution_contract_v1 as contract  # noqa: E402
import d6_infra_repair_v1 as infra1  # noqa: E402
import d6_infra_repair_r2 as infra2  # noqa: E402
import d6_infra_repair_r3 as infra3  # noqa: E402
import live_frr_containerlab_v8 as live  # noqa: E402

MAX_INFRA_RETRIES = 1
EXPECTED_CASES = 40
EXACT_AGREEMENT_REQUIRED = 1.0


class InfrastructureFailure(RuntimeError):
    pass


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _run(args: List[str], *, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout)


def _containerlab(case_dir: Path, action: str) -> dict:
    topo = case_dir / "lab.clab.yml"
    cmd = infra1.containerlab_args(topo, action)
    outer_timeout = (infra1.DEPLOY_TIMEOUT_SEC if action == "deploy" else infra1.DESTROY_TIMEOUT_SEC) + 30
    started = time.monotonic()
    try:
        proc = _run(cmd, timeout=outer_timeout)
    except subprocess.TimeoutExpired as exc:
        raise InfrastructureFailure(f"containerlab {action} outer timeout") from exc
    record = {
        "action": action,
        "command": cmd,
        "returncode": proc.returncode,
        "elapsed_sec": round(time.monotonic() - started, 3),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
    if proc.returncode != 0:
        raise InfrastructureFailure(
            f"containerlab {action} failed rc={proc.returncode}: {(proc.stderr or proc.stdout)[-1000:]}"
        )
    return record


def prepare_step_plan(case: dict, step: dict, running_config: str) -> dict:
    plan = contract.plan_idempotent_step(case, step, running_config)
    if case["protocol"] == "BGP":
        asn = 65000 + live._router_number(step["device_id"])
        plan = dict(plan)
        plan["commands"] = [command.replace("{ASN}", str(asn)) for command in plan["commands"]]
    return plan


def _apply_step(case: dict, lab_name: str, step: dict) -> dict:
    container = f"clab-{lab_name}-{step['device_id']}"
    started = time.monotonic()
    try:
        before = live._vtysh(container, ["show running-config"])
        plan = prepare_step_plan(case, step, before)
        stdout = ""
        if plan["commands"]:
            stdout = live._vtysh(container, plan["commands"])
        after = live._vtysh(container, ["show running-config"])
        if not contract.step_satisfied(case, step, after):
            raise InfrastructureFailure("FRR postcondition does not match canonical step")
    except contract.SemanticContractError:
        raise
    except InfrastructureFailure:
        raise
    except Exception as exc:
        raise InfrastructureFailure(f"vtysh step execution failed: {exc}") from exc
    return {
        "step_id": step["step_id"],
        "device_id": step["device_id"],
        "operation": step["operation"],
        "canonical_prefix": plan["canonical_prefix"],
        "commands": plan["commands"],
        "noop": plan["noop"],
        "postcondition_satisfied": True,
        "elapsed_sec": round(time.monotonic() - started, 3),
        "stdout": stdout,
    }


def _quiesce(case: dict, lab_name: str, label: str) -> dict:
    try:
        result = live.wait_for_quiescence(case, lab_name)
    except Exception as exc:
        raise InfrastructureFailure(f"quiescence measurement failed at {label}: {exc}") from exc
    if not result.get("quiescent"):
        raise InfrastructureFailure(f"control-plane quiescence timeout at {label}")
    return {"label": label, **result}


def _materialize_lab(case: dict, out_dir: Path) -> dict:
    lab = live.materialize_lab(case, out_dir)
    topo = Path(lab["topology_path"])
    text = topo.read_text()
    rendered, igmp_meta = infra2.inject_igmp_sysctls(case, text)
    if rendered != text:
        topo.write_text(rendered)
    lab["topology_sha256"] = live.sha256_file(topo)
    lab["igmp_capacity_repair"] = igmp_meta

    bgp_meta = {}
    modified = 0
    for router in case["routers"]:
        config = out_dir / router / "frr.conf"
        before = config.read_text()
        after, meta = infra3.inject_bgp_exchange_policy(case, before)
        if after != before:
            config.write_text(after)
        bgp_meta[router] = meta
        modified += int(meta.get("applied") is True)
    lab["bgp_exchange_policy_repair"] = {
        "applied": modified > 0,
        "routers_modified": modified,
        "per_router": bgp_meta,
        "scientific_semantics_changed": False,
    }
    return lab


def _cleanup_best_effort(episode_dir: Path) -> dict:
    try:
        record = _containerlab(episode_dir, "destroy")
        _write_json(episode_dir / "teardown.json", record)
        return record
    except Exception as exc:
        record = {"action": "destroy", "cleanup_success": False, "error": repr(exc)}
        _write_json(episode_dir / "teardown_failure.json", record)
        return record


def _episode(case: dict, root: Path, name: str, forward_steps: list[dict], recovery_steps: list[dict] | None = None) -> dict:
    episode_dir = root / name
    if episode_dir.exists():
        shutil.rmtree(episode_dir)
    episode_dir.mkdir(parents=True)
    lab = _materialize_lab(case, episode_dir)
    timeline = []
    deploy_started = False
    try:
        # Preclean is deterministic hygiene for stale partial labs from prior infrastructure attempts.
        try:
            timeline.append({"preclean": _containerlab(episode_dir, "destroy")})
        except InfrastructureFailure as exc:
            timeline.append({"preclean_nonblocking_failure": repr(exc)})
        deploy_started = True
        timeline.append({"deploy": _containerlab(episode_dir, "deploy")})
        baseline = _quiesce(case, lab["lab_name"], "baseline")
        timeline.append({"quiescence": baseline})
        forward_snapshots = []
        for index, step in enumerate(forward_steps, start=1):
            timeline.append({"transaction": _apply_step(case, lab["lab_name"], step)})
            q = _quiesce(case, lab["lab_name"], f"forward_{index}")
            timeline.append({"quiescence": q})
            forward_snapshots.append(q["final_snapshot"])
        recovery_snapshots = []
        if recovery_steps is not None:
            for index, step in enumerate(recovery_steps, start=1):
                timeline.append({"recovery_transaction": _apply_step(case, lab["lab_name"], step)})
                q = _quiesce(case, lab["lab_name"], f"recovery_{index}")
                timeline.append({"quiescence": q})
                recovery_snapshots.append(q["final_snapshot"])
        return {
            "episode": name,
            "lab": lab,
            "baseline_snapshot": baseline["final_snapshot"],
            "forward_snapshots": forward_snapshots,
            "recovery_snapshots": recovery_snapshots,
            "timeline": timeline,
        }
    finally:
        if deploy_started:
            _cleanup_best_effort(episode_dir)


def execute_complete_case(case_record: dict, attempt_dir: Path) -> dict:
    case = case_record["case"]
    _write_json(attempt_dir / "sealed_case_input.json", case_record)
    forward = _episode(case, attempt_dir, "forward_episode", list(case["forward_plan"]))
    _write_json(attempt_dir / "forward_episode" / "episode_result.json", forward)
    recovery_runs = []
    for cut in range(1, len(case["forward_plan"]) + 1):
        episode = _episode(
            case,
            attempt_dir,
            f"recovery_cut_{cut:02d}",
            list(case["forward_plan"][:cut]),
            list(case["contingency_plan"]),
        )
        _write_json(attempt_dir / f"recovery_cut_{cut:02d}" / "episode_result.json", episode)
        if not episode["recovery_snapshots"]:
            raise InfrastructureFailure(f"recovery cut {cut} yielded no snapshots")
        recovery_runs.append({
            "cut_index": cut,
            "snapshots": episode["recovery_snapshots"],
            "terminal_snapshot": episode["recovery_snapshots"][-1],
        })
    measured = live.derive_measured_obligations(case, forward["forward_snapshots"], recovery_runs)
    comparison = live.compare_semantics(case_record["reference_semantic_obligations"], measured)
    result = {
        "case_id": case_record["case_id"],
        "status": "COMPLETED",
        "reference_class": case_record["reference_class"],
        "reference_semantic_obligations": case_record["reference_semantic_obligations"],
        "measured_semantic_obligations": measured,
        "semantic_comparison": comparison,
        "agreement": comparison["agreement"],
        "infrastructure_failure": False,
        "historical_D6_replacement": False,
    }
    _write_json(attempt_dir / "case_semantic_result.json", result)
    return result


def execute_with_policy(case_record: dict, case_root: Path) -> dict:
    attempts = []
    for attempt_index in range(1, MAX_INFRA_RETRIES + 2):
        attempt_dir = case_root / f"attempt_{attempt_index:02d}"
        try:
            result = execute_complete_case(case_record, attempt_dir)
            attempts.append({"attempt_index": attempt_index, "classification": "COMPLETED", "result": result})
            return {
                "case_id": case_record["case_id"],
                "status": "COMPLETED",
                "agreement": result["agreement"],
                "primary_result": result,
                "attempts": attempts,
            }
        except contract.SemanticContractError as exc:
            record = {
                "case_id": case_record["case_id"],
                "status": "SEMANTIC_CONTRACT_FAILURE",
                "agreement": False,
                "semantic_reason": exc.reason,
                "attempts": attempts + [{"attempt_index": attempt_index, "classification": "SEMANTIC_CONTRACT_FAILURE", "reason": exc.reason}],
            }
            _write_json(case_root / "semantic_contract_failure.json", record)
            return record
        except InfrastructureFailure as exc:
            failure = {"attempt_index": attempt_index, "classification": "INFRASTRUCTURE_FAILURE", "error": repr(exc)}
            attempts.append(failure)
            _write_json(attempt_dir / "infrastructure_failure.json", failure)
    return {
        "case_id": case_record["case_id"],
        "status": "UNRESOLVED_INFRASTRUCTURE_FAILURE",
        "agreement": None,
        "attempts": attempts,
    }


def summarize(results: list[dict], expected_count: int = EXPECTED_CASES) -> dict:
    completed = [r for r in results if r.get("status") == "COMPLETED"]
    agreements = [r for r in completed if r.get("agreement") is True]
    mismatches = [r for r in completed if r.get("agreement") is False]
    unresolved = [r for r in results if r.get("status") != "COMPLETED"]
    rate = len(agreements) / expected_count if expected_count else 0.0
    passed = len(results) == expected_count and len(completed) == expected_count and rate == EXACT_AGREEMENT_REQUIRED
    return {
        "schema_id": "GRANT1_PE12_B_LIVE_SUMMARY_V1",
        "expected_cases": expected_count,
        "observed_case_records": len(results),
        "completed_cases": len(completed),
        "agreement_count": len(agreements),
        "semantic_mismatch_count": len(mismatches),
        "unresolved_count": len(unresolved),
        "agreement_rate": rate,
        "frozen_exact_agreement_required": EXACT_AGREEMENT_REQUIRED,
        "semantic_mismatch_case_ids": [r["case_id"] for r in mismatches],
        "unresolved_case_ids": [r["case_id"] for r in unresolved],
        "verdict": "PASS" if passed else "FAIL_CLAIM_NARROWING_REQUIRED",
        "historical_D6_replacement": False,
    }


def _verify_seal(seal_path: Path) -> dict:
    seal = json.loads(seal_path.read_text())
    if seal.get("verdict") != "PASS":
        raise SystemExit("PE12 preexecution seal is not PASS")
    for item in seal.get("files", []):
        path = Path(item["path"])
        if not path.exists() or live.sha256_file(path) != item["sha256"]:
            raise SystemExit(f"PE12 seal mismatch: {path}")
    return seal


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seal", type=Path, required=True)
    ap.add_argument("--inputs", type=Path, required=True)
    ap.add_argument("--output-root", type=Path, required=True)
    ap.add_argument("--case-id", action="append")
    args = ap.parse_args()
    _verify_seal(args.seal.resolve())
    manifest = json.loads(args.inputs.read_text())
    cases = list(manifest["cases"])
    if args.case_id:
        index = {r["case_id"]: r for r in cases}
        if any(cid not in index for cid in args.case_id):
            raise SystemExit("requested case is not in sealed PE12 manifest")
        cases = [index[cid] for cid in args.case_id]
    out = args.output_root.resolve()
    out.mkdir(parents=True, exist_ok=True)
    status_path = out / "PE12_B_CASE_STATUS.json"
    existing = []
    if status_path.exists():
        existing = json.loads(status_path.read_text())
    by_id = {r["case_id"]: r for r in existing}
    for ordinal, case_record in enumerate(cases, start=1):
        if case_record["case_id"] in by_id and by_id[case_record["case_id"]].get("status") == "COMPLETED":
            continue
        case_root = out / f"{ordinal:03d}_{case_record['case_id']}"
        result = execute_with_policy(case_record, case_root)
        by_id[result["case_id"]] = result
        ordered = [by_id[r["case_id"]] for r in cases if r["case_id"] in by_id]
        _write_json(status_path, ordered)
        partial = summarize(ordered, expected_count=len(cases))
        partial["run_state"] = "PARTIAL" if len(ordered) < len(cases) else "COMPLETE"
        _write_json(out / "PE12_B_LIVE_SUMMARY.json", partial)
        print(json.dumps({"case_id": result["case_id"], "status": result["status"], "agreement": result.get("agreement"), "done": len(ordered), "total": len(cases)}, sort_keys=True), flush=True)
    final = [by_id[r["case_id"]] for r in cases if r["case_id"] in by_id]
    summary = summarize(final, expected_count=len(cases))
    summary["run_state"] = "COMPLETE" if len(final) == len(cases) else "PARTIAL"
    _write_json(out / "PE12_B_LIVE_SUMMARY.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    return 0 if summary["verdict"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
