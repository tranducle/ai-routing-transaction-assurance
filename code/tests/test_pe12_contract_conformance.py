from __future__ import annotations

import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE = HERE.parent / "01_corrective_live" / "build_pe12_contract_conformance.py"


def _load():
    assert MODULE.exists(), "PE12-A builder must exist"
    spec = importlib.util.spec_from_file_location("build_pe12_contract_conformance", MODULE)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_pe12_a_builds_exact_balanced_32_case_contract_suite():
    m = _load()
    result = m.run_suite()
    assert result["total_cases"] == 32
    assert result["protocol_counts"] == {"BGP": 16, "OSPF": 16}
    assert result["passed_cases"] == 32
    assert result["failed_cases"] == 0
    assert result["verdict"] == "PASS"
    mismatch = [r for r in result["cases"] if r["expected_reason"] == "ObjectIdPrefixMismatch"]
    assert len(mismatch) == 8
    assert all(r["commands_emitted"] == [] for r in mismatch)
