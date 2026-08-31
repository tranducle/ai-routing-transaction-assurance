# AI Routing Transaction Assurance — Reproducibility Artifact

This repository is the **anonymous review artifact** accompanying a research study on deterministic assurance for untrusted AI-generated routing transactions.

The artifact is organized to help reviewers inspect the evaluation logic, reproduce the reported analyses, and understand the provenance of the experimental evidence without requiring access to the manuscript source or author identity.

> **Review anonymity.** Author names, affiliations, personal contact details, local machine paths, API credentials, provider secrets, and other identifying metadata are intentionally excluded from this repository during peer review.

## Scope

The study evaluates a deterministic transaction-admission contract for bounded BGP/OSPF route-advertisement changes. The artifact is organized around four evidence questions:

- **C1 — Beyond terminal-state-only checking:** whether additional transaction obligations change admission decisions on the same proposal and evidence.
- **C2 — Recovery-path nonredundancy:** whether checking the recovery path changes decisions beyond eventual recovery-terminal correctness.
- **C3 — Live execution grounding:** whether deterministic route-advertisement semantics agree with live FRRouting execution, including the separately evaluated prospective identity correction.
- **C4 — External compatibility boundary:** whether public benchmark instances expose the artifacts required for a fair same-contract evaluation.

The repository does **not** include the manuscript or manuscript figures.

## Repository layout

```text
.
├── README.md
├── ARTIFACT_MANIFEST.md
├── DATA_SOURCES.md
├── REVIEW_ANONYMITY.md
├── results/
│   └── reported_evidence_summary.csv
├── code/                 # sanitized evaluation/replay code
├── configs/              # frozen non-secret experiment configuration
├── data/
│   ├── generated/        # study-generated, non-sensitive artifacts
│   └── metadata/         # checksums and data provenance
├── reproduction/         # reviewer-oriented entry points
└── environment/          # dependency/environment specifications
```

Only files needed to audit or reproduce the reported evidence should be placed in the public artifact. Internal project-management files, manuscript sources, figures, credentials, private API metadata, and unrelated development artifacts are excluded.

## Reported evidence at a glance

The numerical values below are included only as a compact map from the paper claims to the artifact. Reproduction scripts should compute these values from the released generated evidence rather than hard-code them.

| Evidence item | Reported result | Interpretation boundary |
|---|---:|---|
| PE11 unsafe subset | 118 proposals | deterministic-reference unsafe |
| PE11 terminal-only admissions | 19 / 118 (16.1%) | same-input nested ablation |
| PE11 Full safe-control rejections | 0 / 138 | bounded safe-control result |
| PE13 recovery-unsafe subset | 97 proposals | independent recovery-enriched study |
| PE13 B5 admissions | 78 / 97 (80.4%) | same-input recovery ablation |
| PE13 Full admissions | 0 / 97 | bounded to PE13 semantics |
| PE13 Full safe-control rejections | 0 / 530 | bounded safe-control result |
| Historical D6 live agreement | 78 / 80 (97.5%) | failed frozen 100% criterion |
| Prospective PE12 live agreement | 40 / 40 (100%) | separate cohort after prospective correction |
| D7 public compatibility audit | 0 / 527 compatible units | external-validity boundary, not 527 method failures |

## Reproduction philosophy

The artifact follows four principles:

1. **Proposal generation is not correctness authority.** Model outputs are treated as untrusted proposals.
2. **Reference labeling is deterministic.** The scientific labels and obligation checks do not depend on an LLM judge.
3. **Historical failures remain visible.** The original D6 result is preserved and is not replaced by the later prospective PE12 result.
4. **Missing evidence does not become a favorable result.** Admission fails closed when required semantic evidence is incomplete, while scientific labeling treats unresolved evidence as unverifiable rather than silently unsafe.

## Data policy

Public third-party datasets or benchmark repositories are referenced by source URL and pinned revision where available rather than copied into this repository. Study-generated artifacts that are needed to reproduce the reported analyses are released under `data/generated/` after removal of secrets and identifying metadata.

See [`DATA_SOURCES.md`](DATA_SOURCES.md) for the source policy and [`ARTIFACT_MANIFEST.md`](ARTIFACT_MANIFEST.md) for the release inventory.

## Reviewer workflow

The intended workflow is:

```text
1. inspect ARTIFACT_MANIFEST.md
2. create the documented environment
3. obtain any referenced public inputs
4. run the deterministic replay/reference pipeline
5. run obligation scoring
6. reproduce PE11 / PE13 summary analyses
7. inspect D6 and PE12 live-evidence summaries separately
8. inspect the D7 compatibility audit
```

Reviewer-facing commands will be exposed through `reproduction/` and will use repository-relative paths only.

## Important limitations

This artifact supports the bounded transaction semantics evaluated in the study. It is not evidence of vendor-general deployment safety, universal model behavior, arbitrary network-change correctness, or broad superiority over systems that solve different verification tasks.

## Anonymous review notice

Please do not infer authorship from repository ownership, commit metadata, or external account information. The scientific artifact itself intentionally omits author-identifying information for the review process.
