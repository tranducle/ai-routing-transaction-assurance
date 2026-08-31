from __future__ import annotations
import tempfile,shutil
from pathlib import Path

from network_config_v8 import render_state_configs
from replay_adapter_v8 import build_case_replay_plan,canonical_bundle_sha256

EXECUTOR_CONTRACT='GRANT1_PE8_EXECUTABLE_BATFISH_V1'

def expected_snapshot_name(config_hash): return 'pe8-'+str(config_hash)[:20]

def _json_value(v):
    if v is None or type(v) in (str,int,float,bool): return v
    return str(v)

def canonicalize_frame_rows(rows):
    out=[]
    for row in rows:
        if hasattr(row,'to_dict'): row=row.to_dict()
        out.append({str(k):_json_value(v) for k,v in sorted(dict(row).items(),key=lambda kv:str(kv[0]))})
    return sorted(out,key=lambda r:repr(sorted(r.items())))

def _write_snapshot(root,configs):
    cfgdir=Path(root)/'configs'; cfgdir.mkdir(parents=True,exist_ok=True)
    for node,text in configs.items(): (cfgdir/f'{node}.cfg').write_text(text)

def execute_owner_state(case,owners,*,bf,cache=None):
    """Execute one content-addressed owner-state snapshot using the pinned query family."""
    cache={} if cache is None else cache
    configs=render_state_configs(case,owners); cfg_hash=canonical_bundle_sha256(configs)
    if cfg_hash in cache:
        return cache[cfg_hash]
    tmp=Path(tempfile.mkdtemp(prefix='grant1-pe8-bf-'))
    try:
        _write_snapshot(tmp,configs); snap=expected_snapshot_name(cfg_hash)
        bf.init_snapshot(str(tmp),name=snap,overwrite=True)
        issues=canonicalize_frame_rows(bf.q.initIssues().answer(snapshot=snap).frame().to_dict('records'))
        routes={}
        for svc in case['protected_services']:
            routes[svc]=canonicalize_frame_rows(bf.q.routes(network=svc,nodes='.*').answer(snapshot=snap).frame().to_dict('records'))
        rec={'snapshot_name':snap,'config_bundle_sha256':cfg_hash,'init_issues':issues,'routes_by_service':routes}
        cache[cfg_hash]=rec
        return rec
    finally:
        shutil.rmtree(tmp,ignore_errors=True)


def execute_case(case,*,bf,cache=None):
    """Execute all PE8 modeled states against an already-network-bound PyBatfish Session."""
    cache={} if cache is None else cache; plan=build_case_replay_plan(case); raw={'executor_contract':EXECUTOR_CONTRACT,'states':{}}
    for state in plan['states']:
        sid=state['state_id']; rec=execute_owner_state(case,state['owners'],bf=bf,cache=cache)
        if rec['config_bundle_sha256']!=state['config_bundle_sha256']: raise RuntimeError(f'{sid}: renderer/hash drift')
        raw['states'][sid]=rec
    return raw

def new_session(host='localhost',network='grant1-pe8'):
    from pybatfish.client.session import Session
    bf=Session(host=host); bf.set_network(network); return bf
