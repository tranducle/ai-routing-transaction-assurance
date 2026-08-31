# Artifact Manifest

## Released code

Frozen source files are grouped under `code/` by role. Their filenames and source hashes are preserved in `provenance/source_hashes.csv`.

## Released generated evidence

- `data/generated/pe11/`: deterministic reference rows, method rows, frozen analysis.
- `data/generated/d6/`: official historical live result retaining the 78/80 outcome.
- `data/generated/pe12/`: separate prospective 40/40 live summary.
- `data/generated/pe13/`: deterministic reference rows, method rows, joined rows, frozen recovery analysis.
- `data/generated/d7/`: all attempted compatibility mappings and the frozen external mapping gate.

## Released frozen metadata

`configs/` contains selected protocol, assignment, environment, and preexecution-seal records needed to understand how the confirmatory studies were frozen.

## Deliberately excluded

- manuscript and manuscript figures;
- third-party benchmark copies;
- provider credentials, headers, account/billing records, and private endpoints;
- machine-local paths and identifying host/user metadata;
- unrelated development, review, and project-management artifacts.

## Sanitization

Only non-scientific private metadata is removed or normalized. In particular, machine-local absolute path strings are replaced by `<LOCAL_PATH>/<basename>`. Scientific case IDs, labels, obligation values, method decisions, denominators, and result values are retained.
