#!/usr/bin/env python3
"""Verify SHA-256 checksums for released files listed in provenance/checksums.sha256."""
from pathlib import Path
import hashlib, sys
root=Path(__file__).resolve().parents[1]
manifest=root/'provenance'/'checksums.sha256'
bad=[]; checked=0
for line in manifest.read_text().splitlines():
    if not line.strip(): continue
    digest, rel=line.split('  ',1)
    p=root/rel
    got=hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else '<missing>'
    checked += 1
    if got != digest: bad.append((rel,digest,got))
if bad:
    for x in bad: print('FAIL',*x)
    sys.exit(1)
print(f'PASS: {checked} released-file checksums verified')
