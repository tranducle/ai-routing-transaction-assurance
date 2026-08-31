# Artifact Manifest

This document defines the intended reviewer-facing contents of the anonymous reproducibility artifact.

## Included

### Core code

The public release should contain only the code necessary to:

- validate transaction schema and authorization;
- reconstruct deterministic semantic evidence;
- evaluate forward, terminal, recovery-terminal, and recovery-path obligations;
- compute the same-input ablation guards;
- reproduce PE11 and PE13 summary statistics;
- inspect the historical D6 and prospective PE12 live-execution evidence separately;
- reproduce the D7 external-compatibility audit.

Public filenames should be descriptive and independent of internal project-stage naming. Recommended mappings are:

| Public path | Purpose |
|---|---|
| `code/transaction_schema.py` | schema and identity validation |
| `code/authorization.py` | authorization-scope checks |
| `code/obligations.py` | forward, terminal, and recovery predicates |
| `code/deterministic_verifier.py` | Full guard and obligation witnesses |
| `code/reference_oracle_semantic.py` | semantic-evidence reference oracle |
| `code/reference_oracle_graph.py` | independent graph-replay oracle |
| `code/reference_consensus.py` | safe / unsafe / unverifiable consensus |
| `code/live_frr_adapter.py` | fail-closed live execution adapter |
| `code/score_ablation_guards.py` | B1--B5 and Full scoring |
| `code/analyze_pe11.py` | PE11 fixed-cohort analysis |
| `code/analyze_pe13.py` | PE13 recovery analysis |
| `code/analyze_live_grounding.py` | D6 / PE12 live evidence analysis |
| `code/audit_external_compatibility.py` | D7 structural compatibility audit |

The exact public files should be sanitized copies of the experiment code that produced the released evidence. Internal orchestration, agent workflows, manuscript-generation scripts, and unrelated development utilities should not be released merely for completeness.

### Study-generated data

Study-generated, non-sensitive evidence required to inspect or reproduce the reported analyses belongs under:

```text
data/generated/
```

Preferred public organization:

```text
data/generated/
├── pe11/
│   ├── proposals/
│   ├── reference_labels.csv
│   ├── obligation_scores.csv
│   └── analysis_inputs.csv
├── pe13/
│   ├── proposals/
│   ├── reference_labels.csv
│   ├── obligation_scores.csv
│   └── analysis_inputs.csv
├── live/
│   ├── d6_historical_evidence.csv
│   └── pe12_prospective_evidence.csv
└── d7/
    └── compatibility_audit.csv
```

Raw provider responses may be released only after removing secrets, account identifiers, request headers, billing/request identifiers, private URLs, and local paths. Where a raw response is unnecessary for reproducing the paper result, a normalized transaction record is preferable.

### Frozen configuration

Non-secret frozen experiment settings belong under `configs/`. These may include task assignments, seeds, model aliases used in the study, context-condition definitions, thresholds, and deterministic analysis rules. Provider credentials and private endpoint metadata must not be included.

### Environment

The public artifact should include the dependency and execution specifications needed to reconstruct the deterministic analysis environment. Pin exact versions when they materially affect semantics.

## Excluded

The following content must not be pushed during anonymous review:

- manuscript `.tex`, compiled manuscript PDF, or manuscript figures;
- author names, affiliations, email addresses, ORCID identifiers, acknowledgments, grant identifiers that reveal identity, or institutional paths;
- API keys, tokens, cookies, authentication headers, private endpoints, or `.env` files;
- local absolute paths (for example `/Users/...`);
- internal project-management notes, agent logs, prompts unrelated to experimental reproduction, reviewer simulations, and manuscript-audit reports;
- cached downloads or third-party datasets that can be obtained from their public source;
- private billing/request metadata returned by model providers.

## Release gate

Before any generated file is published, verify that it passes all of the following checks:

1. no author-identifying text;
2. no credentials or secret-like strings;
3. no absolute local paths;
4. no manuscript or manuscript figures;
5. no unnecessary third-party data copies;
6. deterministic analysis inputs retain their original values and row identifiers;
7. historical D6 and prospective PE12 evidence remain distinct;
8. PE11 and PE13 are not pooled;
9. filenames and README instructions correspond to the public layout rather than internal project names.
