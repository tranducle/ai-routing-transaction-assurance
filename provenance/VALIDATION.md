# Release Validation

The reviewer-facing release passed the following local checks before publication:

- headline evidence reproduction: **9/9 expected rows reproduced**;
- PE13 row-level mechanism check: **78/78** B5-accept/Full-reject cases retained authorization and recovery-terminal correctness and failed recovery-path safety;
- focused released-code tests: **28 passed**;
- forbidden manuscript/figure file check: **PASS**;
- author/local-path/credential pattern scan: **PASS** after sanitization;
- release SHA-256 verification: generated after all content changes and checked before push.

The statistical reproduction script does not issue model API calls. Live FRRouting reproduction requires the external runtime described in `environment/README.md`.
