from __future__ import annotations

import re
from typing import Dict, Iterable, List, Mapping, Tuple


def _task_index(task: Mapping) -> int:
    m=re.search(r"B(\d+)$",str(task["base_task_id"]))
    if not m: raise ValueError("base_task_id must end in B###")
    return int(m.group(1))


def _normalize_owners(owners: Mapping[str, Iterable[str]]) -> Dict[str,List[str]]:
    return {str(s):sorted({str(n) for n in ns}) for s,ns in sorted(owners.items())}


def _link_addresses(task_index:int, link_index:int)->Tuple[str,str,str]:
    base=link_index*4
    if base+2>254: raise ValueError("too many links for deterministic /24 allocator")
    subnet=f"172.63.{task_index}.{base}/30"
    return subnet,f"172.63.{task_index}.{base+1}/30",f"172.63.{task_index}.{base+2}/30"


def render_state_configs(task: Mapping, active_owners: Mapping[str, Iterable[str]]) -> Dict[str,str]:
    """Single authoritative PE8 FRR/Cumulus-concatenated renderer used by manifest and replay."""
    routers=list(task["routers"]); protocol=str(task["protocol"])
    edges=[tuple(e) for e in task["topology_edges"]]
    services=list(task["protected_services"]); owners=_normalize_owners(active_owners)
    task_idx=_task_index(task)
    iface_rows={r:[] for r in routers}; counts={r:0 for r in routers}; link_rows=[]
    for li,(left,right) in enumerate(edges):
        if left not in iface_rows or right not in iface_rows: raise ValueError("edge references unknown router")
        subnet,left_ip,right_ip=_link_addresses(task_idx,li)
        counts[left]+=1; counts[right]+=1
        lif=f"swp{counts[left]}"; rif=f"swp{counts[right]}"
        iface_rows[left].append((lif,left_ip,subnet)); iface_rows[right].append((rif,right_ip,subnet))
        link_rows.append((left,right,left_ip.split('/')[0],right_ip.split('/')[0],subnet))
    out={}
    for ri,router in enumerate(routers,start=1):
        rid=f"198.20.{task_idx}.{ri}"
        lines=[router,"# This file describes the network interfaces","","auto lo","iface lo inet loopback",f"    address {rid}/32"]
        for service in services:
            if router in owners.get(service,[]): lines.append(f"    address {service}")
        lines.append("")
        for ifname,ip,_ in iface_rows[router]: lines += [f"auto {ifname}",f"iface {ifname}",f"    address {ip}",""]
        lines += ["# ports.conf --","","frr version 10.7","frr defaults traditional",f"hostname {router}","!"]
        if protocol=="BGP":
            asn=65400+ri
            lines += [f"router bgp {asn}",f" bgp router-id {rid}"]
            for left,right,left_ip,right_ip,_ in link_rows:
                if router==left:
                    rri=routers.index(right)+1; lines.append(f" neighbor {right_ip} remote-as {65400+rri}")
                elif router==right:
                    rri=routers.index(left)+1; lines.append(f" neighbor {left_ip} remote-as {65400+rri}")
            lines.append(" address-family ipv4 unicast")
            for service in services:
                if router in owners.get(service,[]): lines.append(f"  network {service}")
            lines += [" exit-address-family","!"]
        elif protocol=="OSPF":
            lines += ["router ospf",f" ospf router-id {rid}"]
            for left,right,_lip,_rip,subnet in link_rows:
                if router in {left,right}: lines.append(f" network {subnet} area 0")
            for service in services:
                if router in owners.get(service,[]): lines.append(f" network {service} area 0")
            lines += ["!"]
        else: raise ValueError(f"unsupported protocol {protocol}")
        lines += ["line vty","!",""]
        out[router]="\n".join(lines)
    return out
