# Environment

The headline-result reproduction script uses only the Python standard library; SciPy is optional for displaying the exact-binomial confidence-bound endpoints.

The deterministic Batfish reference pipeline recorded `pybatfish 2025.07.07.2423`. The live FRRouting grounding used Containerlab 0.79.0 and FRR `10.7.0_git` with the pinned image digest recorded in `configs/d6_execution_environment.json`.

A convenient local setup is:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r environment/requirements.txt
```

The released experiment code preserves its frozen module filenames. For direct module-level tests, expose the code directories on `PYTHONPATH`:

```bash
export PYTHONPATH="$PWD/code/candidate:$PWD/code/verification:$PWD/code/reference:$PWD/code/live:$PWD/code/01_corrective_live"
pytest -q code/tests
```

Live FRR reproduction additionally requires a compatible Docker/Containerlab installation and the pinned FRR image. It is intentionally separate from the lightweight reproduction of the reported statistics.
