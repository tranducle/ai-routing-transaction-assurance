# Code Map

The code is organized by scientific role while preserving the frozen source filenames used by the experiments.

- `candidate/`: blind-view construction, network-state rendering, and model-output adaptation.
- `verification/`: deterministic transaction verifier and B1--B5/Full scoring.
- `reference/`: semantic replay, Batfish execution, two independent deterministic oracles, consensus, and provenance audit.
- `live/`: frozen FRRouting/Containerlab execution backend and historical D6 infrastructure-repair helpers.
- `01_corrective_live/`: prospective fail-closed identity contract and PE12 live runner, retaining the frozen directory relationship used by its tests.
- `00_design_lock/`: frozen semantic/taxonomy contracts consumed by the released code.
- `tests/`: focused tests for the released verifier/reference/live components.

The version suffixes are intentionally retained because they are part of the frozen scientific provenance. `provenance/source_hashes.csv` maps every released code file to the SHA-256 of its frozen source copy.
