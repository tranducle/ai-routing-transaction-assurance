# Reproduction Entry Points

For the reviewer-facing statistical reproduction:

```bash
python reproduction/reproduce_reported_results.py
```

This recomputes all nine headline evidence rows from the released generated evidence and asserts the PE13 row-level recovery-path mechanism check.

To verify the released files against their SHA-256 manifest:

```bash
python reproduction/verify_artifact.py
```

These commands do not call model-provider APIs. See `environment/README.md` for deterministic-reference and live-FRRouting requirements.
