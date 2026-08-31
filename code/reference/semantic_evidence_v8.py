from __future__ import annotations
import hashlib,json,re
from copy import deepcopy
from pathlib import Path

HERE=Path(__file__).resolve().parent
CONTRACT=json.loads((HERE.parent/'00_design_lock'/'SEMANTIC_EVIDENCE_CONTRACT_V8.json').read_text())
PAYLOAD_FIELDS=tuple(CONTRACT['semantic_payload_hash_fields']); PROVENANCE_FIELDS=tuple(CONTRACT['required_provenance_fields']); EXPECTED=CONTRACT['expected_constants']; HEX64=re.compile(r'^[0-9a-f]{64}$')

def canonical_json_bytes(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def canonical_sha256(obj): return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()
def semantic_payload(e): return {k:deepcopy(e[k]) for k in PAYLOAD_FIELDS if k in e}
def semantic_payload_sha256(e): return canonical_sha256(semantic_payload(e))

def build_attested_semantic_evidence(blind_case,payload,*,baseline_config_bundle_sha256,candidate_config_bundle_sha256,query_plan_sha256,raw_batfish_output_sha256):
    if set(payload)!=set(PAYLOAD_FIELDS): raise ValueError('semantic payload field set mismatch')
    bindings={'baseline_config_bundle_sha256':baseline_config_bundle_sha256,'candidate_config_bundle_sha256':candidate_config_bundle_sha256,'query_plan_sha256':query_plan_sha256,'raw_batfish_output_sha256':raw_batfish_output_sha256}
    for k,v in bindings.items():
        if type(v) is not str or not HEX64.fullmatch(v): raise ValueError(f'{k} must be lowercase sha256')
    out=deepcopy(payload); out['evidence_provenance']={'contract_version':EXPECTED['contract_version'],'schema_id':EXPECTED['schema_id'],'case_id':blind_case.get('case_id'),'blind_case_sha256':canonical_sha256(blind_case),'semantic_payload_sha256':canonical_sha256(payload),**bindings,'replay_pipeline_id':EXPECTED['replay_pipeline_id'],'replay_executor_contract':EXPECTED['replay_executor_contract'],'batfish_image_digest':EXPECTED['batfish_image_digest'],'pybatfish_version':EXPECTED['pybatfish_version']}
    return out

def verify_attestation(blind_case,evidence):
    failures=[]; p=evidence.get('evidence_provenance') if type(evidence) is dict else None
    if type(p) is not dict: return {'valid':False,'failures':['evidence_provenance']}
    if set(p)!=set(PROVENANCE_FIELDS): failures.append('provenance_fields')
    for k,v in EXPECTED.items():
        if p.get(k)!=v: failures.append(k)
    if p.get('case_id')!=blind_case.get('case_id'): failures.append('case_id')
    if p.get('blind_case_sha256')!=canonical_sha256(blind_case): failures.append('blind_case_sha256')
    if set(PAYLOAD_FIELDS).issubset(evidence):
        if p.get('semantic_payload_sha256')!=semantic_payload_sha256(evidence): failures.append('semantic_payload_sha256')
    else: failures.append('semantic_payload_sha256')
    for k in CONTRACT['reference_oracle_must_require_64hex_bindings']:
        if type(p.get(k)) is not str or not HEX64.fullmatch(p[k]): failures.append(k)
    return {'valid':not failures,'failures':list(dict.fromkeys(failures))}
