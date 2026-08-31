# Reproduction Workflow

This directory is the reviewer-facing entry point for reproducing the released analyses.

The final anonymous artifact should expose simple repository-relative commands for the following stages:

1. validate the released generated-data checksums;
2. reproduce deterministic reference labels and obligation vectors;
3. score B1--B5 and Full on identical semantic evidence;
4. reproduce PE11 summary statistics;
5. reproduce PE13 recovery-path statistics and row-level divergence decomposition;
6. summarize D6 historical live evidence and PE12 prospective live evidence as separate cohorts;
7. reproduce the D7 structural compatibility audit.

No command should require an author-specific absolute path, private API credential, or manuscript file.

## Expected public commands

When the sanitized code and generated evidence are populated, the preferred interface is:

```bash
python reproduction/verify_artifact.py
python reproduction/reproduce_pe11.py
python reproduction/reproduce_pe13.py
python reproduction/reproduce_live_grounding.py
python reproduction/reproduce_d7.py
```

A convenience script may additionally reproduce all deterministic analyses:

```bash
bash reproduction/reproduce_all.sh
```

Model-generation API calls are not required for reproducing the fixed-cohort analyses when the frozen generated proposals are included under `data/generated/`. This avoids requiring reviewers to possess provider credentials and avoids replacing the original frozen responses with newly sampled outputs.

Live FRRouting experiments may require Docker/Containerlab and the documented FRR environment; deterministic analysis of the released live evidence should remain possible without rerunning provider calls.
