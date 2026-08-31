# Data Sources

Third-party benchmark repositories are **not mirrored** here. The external-compatibility audit used these pinned public sources:

| Source | Public location | Frozen revision |
|---|---|---|
| NetAgentBench | https://github.com/twabi/NetAgentBench | `015ba50683f6d583f4e1fe269f98d8786deca6a5` |
| Cornetto | https://github.com/nsg-ethz/cornetto | `21641495fb6485c1d6d61d44597a58d87ed29de2` |
| Cornetto benchmark dataset | https://huggingface.co/datasets/iprotogeros/cornetto-benchmark | `cdf3d68ecc47b4afe63e6b3ca8f5c07821c191bd` |
| NetConfArena | https://github.com/liujona/NetConfArena | `7f99e17a641f9e598dd0073d776637f361b5cdd5` |

The study-generated evidence needed to audit the reported PE11, PE13, D6, PE12, and D7 findings is included under `data/generated/`. Machine-local paths in a small number of provenance fields were replaced with `<LOCAL_PATH>/<basename>`; numerical outcomes, case identifiers, reference labels, obligation values, method decisions, and frozen study counts were not changed.

Raw provider request headers, credentials, account/billing metadata, manuscript files, and manuscript figures are not part of this artifact.
