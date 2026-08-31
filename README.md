# Deterministic Assurance for Untrusted AI-Generated Routing Transactions

## Reproducibility artifact

This repository contains the reviewer-facing code, generated evidence, frozen study metadata, and lightweight reproduction entry points for a study of deterministic admission checks for untrusted AI-generated routing transactions.

The artifact is deliberately narrower than the development repository. It excludes manuscript files, manuscript figures, credentials, provider account metadata, local paths, and unrelated project-management material.

## What can be reproduced quickly

From the repository root:

```bash
python reproduction/reproduce_reported_results.py
python reproduction/verify_artifact.py
```

The first command recomputes the paper's headline PE11, PE13, D6, PE12, and D7 counts from the released study-generated evidence. It also verifies the PE13 row-level mechanism statement for the 78 B5/Full divergence cases. The second command verifies SHA-256 checksums for the released artifact.

Expected headline results:

| Evidence | Reproduced result |
|---|---:|
| PE11 final-state-only unsafe admissions | 19 / 118 |
| PE11 Full unsafe admissions | 0 / 118 |
| PE11 Full safe rejections | 0 / 138 |
| PE13 recovery-ablation unsafe admissions | 78 / 97 |
| PE13 Full recovery-unsafe admissions | 0 / 97 |
| PE13 Full safe rejections | 0 / 530 |
| Historical D6 live agreement | 78 / 80 |
| Prospective PE12 live agreement | 40 / 40 |
| D7 compatible public units | 0 / 527 |

D6 and PE12 are intentionally kept as separate cohorts. D7 records compatibility exclusions, not 527 method failures.

## Layout

```text
code/          frozen verifier, reference, and live-execution code grouped by role
data/generated study-generated evidence used by the reported analyses
configs/       frozen protocol, assignment, environment, and seal metadata
environment/   dependency and runtime notes
reproduction/  reviewer-oriented reproduction and integrity checks
results/       reported and freshly reproduced evidence summaries
provenance/    source hashes, release checksums, and sanitization notes
```

## Reproduction levels

**Level 1 - reported statistics.** Requires only the released JSON evidence and Python. This is the recommended reviewer path and does not make paid model calls.

**Level 2 - deterministic verifier/reference inspection.** The code under `code/` exposes the frozen transaction guard, evidence/replay path, deterministic oracles, and scoring logic. See `code/README.md` and `environment/README.md`.

**Level 3 - live FRRouting grounding.** The live code and environment metadata are included, but reproduction requires Docker/Containerlab and the pinned FRR image. The historical 78/80 D6 result is preserved separately from the prospective 40/40 PE12 correction.

## Third-party inputs

Public benchmark sources used only for the external-compatibility audit are linked, not copied. See `DATA_SOURCES.md` for frozen revisions.

## Scope boundary

This artifact supports the paper's bounded exact-prefix BGP/OSPF transaction semantics. It is not evidence of vendor-general deployment safety, arbitrary network-change correctness, universal model behavior, or superiority over tools that solve different verification problems.
