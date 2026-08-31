from __future__ import annotations
from copy import deepcopy

REQUIRED=("SchemaOK","AuthOK","ForwardSafe","FinalOK","RecoveryTerminalOK","RecoveryPathSafe","Recoverable")

def score_case(case_id:str, verifier_evidence:dict)->dict:
    missing=[k for k in REQUIRED if k not in verifier_evidence]
    if missing: raise ValueError(f"missing verifier evidence: {','.join(missing)}")
    vals={}
    for k in REQUIRED:
        if type(verifier_evidence[k]) is not bool: raise TypeError(f"{k} must be bool")
        vals[k]=verifier_evidence[k]
    schema=vals['SchemaOK']; auth=vals['AuthOK']; forward=vals['ForwardSafe']; final=vals['FinalOK']; rterm=vals['RecoveryTerminalOK']; rec=vals['Recoverable']
    return {
      'case_id':case_id,**vals,
      'B1':schema,
      'B2':schema and final,
      'B3':schema and auth and final,
      'B4':schema and forward and final,
      'B5':schema and forward and final and rterm,
      'Full':schema and auth and forward and final and rec,
      'witnesses':deepcopy(verifier_evidence.get('witnesses',[])),
      'evidence_provenance':deepcopy(verifier_evidence.get('evidence_provenance',{})),
    }
