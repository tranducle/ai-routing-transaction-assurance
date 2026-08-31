#!/usr/bin/env python3
"""Recompute the manuscript headline counts from released generated evidence.

Usage: python reproduction/reproduce_reported_results.py
The script requires only Python's standard library for the headline counts.
SciPy is optional and used only to display the two-sided exact 95% upper
Clopper-Pearson endpoints for the zero-rejection safe controls.
"""
from __future__ import annotations
import csv, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "generated"
OUT = ROOT / "results" / "reproduced_evidence_summary.csv"

def load(path: Path):
    return json.loads(path.read_text())

def rate(k: int, n: int) -> float:
    return k / n if n else float("nan")

# PE11: independently released reference rows and method rows, joined by case_id.
pe11_ref = load(DATA / "pe11" / "reference_rows.json")
pe11_method = {r["case_id"]: r for r in load(DATA / "pe11" / "method_rows.json")}
assert len(pe11_ref) == 256 and len(pe11_method) == 256
pe11_unsafe = [r for r in pe11_ref if r["reference_verdict"] == "unsafe"]
pe11_safe = [r for r in pe11_ref if r["reference_verdict"] == "safe"]
pe11_b2 = sum(bool(pe11_method[r["case_id"]]["B2"]) for r in pe11_unsafe)
pe11_full_unsafe = sum(bool(pe11_method[r["case_id"]]["Full"]) for r in pe11_unsafe)
pe11_full_safe_reject = sum(not bool(pe11_method[r["case_id"]]["Full"]) for r in pe11_safe)

# PE13 recovery-unsafe is frozen as failure of recovery path OR recovery terminal.
pe13 = load(DATA / "pe13" / "joined_rows.json")
def recovery_unsafe(r):
    o = r.get("reference_obligations", {})
    return o.get("RecoveryPathReferenceOK") is False or o.get("RecoveryTerminalReferenceOK") is False
pe13_recovery = [r for r in pe13 if recovery_unsafe(r)]
pe13_safe = [r for r in pe13 if r.get("reference_verdict") == "safe"]
pe13_b5 = sum(bool(r["B5"]) for r in pe13_recovery)
pe13_full_recovery = sum(bool(r["Full"]) for r in pe13_recovery)
pe13_full_safe_reject = sum(not bool(r["Full"]) for r in pe13_safe)
# Mechanism check used in the paper discussion.
div = [r for r in pe13_recovery if r["B5"] and not r["Full"]]
assert len(div) == 78
assert all(r["reference_obligations"].get("AuthorizationReferenceOK") is True for r in div)
assert all(r["reference_obligations"].get("RecoveryTerminalReferenceOK") is True for r in div)
assert all(r["reference_obligations"].get("RecoveryPathReferenceOK") is False for r in div)

# Live and external boundary studies.
d6 = load(DATA / "d6" / "historical_live_result.json")["gate"]
pe12 = load(DATA / "pe12" / "prospective_live_summary.json")
d7 = load(DATA / "d7" / "external_mapping_gate.json")["summary"]

rows = [
    ("PE11", "terminal_only_unsafe_admissions", pe11_b2, len(pe11_unsafe), "B2 same-input nested ablation on deterministic-reference-unsafe proposals"),
    ("PE11", "full_unsafe_admissions", pe11_full_unsafe, len(pe11_unsafe), "Full guard on deterministic-reference-unsafe proposals"),
    ("PE11", "full_safe_rejections", pe11_full_safe_reject, len(pe11_safe), "Full guard on deterministic-reference-safe controls"),
    ("PE13", "recovery_ablation_unsafe_admissions", pe13_b5, len(pe13_recovery), "B5 same-input nested recovery ablation on recovery-unsafe proposals"),
    ("PE13", "full_recovery_unsafe_admissions", pe13_full_recovery, len(pe13_recovery), "Full guard on recovery-unsafe proposals"),
    ("PE13", "full_safe_rejections", pe13_full_safe_reject, len(pe13_safe), "Full guard on deterministic-reference-safe controls"),
    ("D6", "historical_live_agreement", int(d6["agreements"]), int(d6["completed"]), "Historical live study; failed the frozen 100% agreement criterion"),
    ("PE12", "prospective_live_agreement", int(pe12["agreement_count"]), int(pe12["completed_cases"]), "Separate prospective cohort after fail-closed identity correction"),
    ("D7", "compatible_public_units", int(d7["compatible_source_units"]), int(d7["attempted_source_units"]), "Compatibility exclusions; not method failures"),
]

# Hard assertions protect the manuscript's current headline evidence from drift.
expected = {
    ("PE11", "terminal_only_unsafe_admissions"): (19, 118),
    ("PE11", "full_unsafe_admissions"): (0, 118),
    ("PE11", "full_safe_rejections"): (0, 138),
    ("PE13", "recovery_ablation_unsafe_admissions"): (78, 97),
    ("PE13", "full_recovery_unsafe_admissions"): (0, 97),
    ("PE13", "full_safe_rejections"): (0, 530),
    ("D6", "historical_live_agreement"): (78, 80),
    ("PE12", "prospective_live_agreement"): (40, 40),
    ("D7", "compatible_public_units"): (0, 527),
}
for study, item, k, n, _ in rows:
    assert (k, n) == expected[(study, item)], (study, item, k, n)

OUT.parent.mkdir(parents=True, exist_ok=True)
with OUT.open("w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["study", "evidence_item", "numerator", "denominator", "rate", "interpretation"])
    for study, item, k, n, note in rows:
        w.writerow([study, item, k, n, f"{rate(k,n):.4f}", note])

print(f"PASS: reproduced {len(rows)} headline evidence rows -> {OUT.relative_to(ROOT)}")
print(f"PE13 mechanism check: {len(div)}/78 B5-Full divergences retain authorization + recovery terminal and fail recovery-path safety")
try:
    from scipy.stats import beta
    print(f"PE11 Full-safe zero-rejection exact-95 upper: {beta.ppf(.975, 1, len(pe11_safe)):.12f}")
    print(f"PE13 Full-safe zero-rejection exact-95 upper: {beta.ppf(.975, 1, len(pe13_safe)):.12f}")
except Exception:
    print("SciPy unavailable: headline counts reproduced; exact-binomial endpoint display skipped.")
