# Sanitization Record

The release was produced from frozen project artifacts. The following transformations are permitted in this public copy:

1. source-code files are byte-identical copies, reorganized into role-based directories;
2. generated JSON/config records have sensitive credential/account fields removed if present;
3. machine-local absolute path strings are replaced by `<LOCAL_PATH>/<basename>`;
4. no scientific label, case ID, obligation value, method decision, denominator, or reported numerical outcome is altered.

The public-file checksums in `checksums.sha256` bind the released form of the artifact.
