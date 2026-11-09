#!/usr/bin/env python3
"""Fresh declared owner-release and borrowed-span cases. O(visits+effects+
compression) time; O(compressed outputs+largest case+decoder cache) space.
Old unowned-pointer frontiers remain frozen; owned spans use new input headers.
"""
import itertools,json,hashlib,base64,zlib
from daemon_receive_tools import ROOT,SOURCE
from capture_daemon_record720 import sha
from probe_daemon_record720_handoff import cases as previous_cases,context as previous_context,produced
from daemon_record720_release_replay import execute
SNAPSHOTS=[0x100435cd8,0x100435d78,0x100260f18,0x1001c6100,0x10044dd8c,0x10044dea8,0x100315abc,0x1003e54a4,0x100478ef4,0x10040f7c8]
PAYLOADS=['3000','3003020101','3000020101','020101','040141','1f1f00']
def extend(c,cfg,index,state,kind,payload=None):
    c=json.loads(json.dumps(c));cfg=dict(cfg);c['case_index']=index;c['extension']={'runtime_scalar_variant':state,'kind':kind,'payload_hex':payload}
    for a in [0x1010b6570,0x1010b9278]:c['known_byte_groups'].append({'address':hex(a),'bytes_hex':(0 if state==0 else (1<<64)-1).to_bytes(8,'little').hex(),'provenance':'declared u64 runtime-state extension; native producer/value unknown'})
    if payload is not None:c['known_byte_groups'].append({'address':c['logical_U64'],'bytes_hex':payload,'provenance':'fresh borrowed byte-span owner, disjoint from frame/allocation; old scalar fixtures unchanged'})
    cfg.update({'void_result64':0 if cfg['physical_pattern']==0xa5 else (1<<64)-1,'snapshot_PCs':SNAPSHOTS});return c,cfg
def cases():
    index=0
    for c,cfg in previous_cases():
        if not c['imported_guard_supplied']:continue
        for state in [0,1]:yield extend(c,cfg,index,state,'unowned-leading-value');index+=1
    for F,P,runtime,state,pattern,U,h in itertools.product([0x6800020000,0x6800032060],[0x6800070000,0x6800071010],[0,1],[0,1],[0xa5,0x5a],[0x68000b0000,0x68000b1010],PAYLOADS):
        c=previous_context(index,F,P,U,len(bytes.fromhex(h)),runtime,True);cfg={'allocation_return64':P,'clobber_pattern':pattern*0x0101010101010101,'physical_pattern':pattern,'NZCV_after':0x50000000 if pattern==0xa5 else 0xa0000000};yield extend(c,cfg,index,state,'borrowed-input-span',h);index+=1
def pack(c,cfg,t):
    b=json.dumps(t,sort_keys=True,separators=(',',':')).encode();return {'case_index':c['case_index'],'context':c,'configuration':cfg,'source_visits':len(t['steps']),'boundary':t['boundary'],'payload_sha256':hashlib.sha256(b).hexdigest(),'payload_zlib_base64':base64.b64encode(zlib.compress(b,9)).decode()}
def main():
    rows=[]
    for c,cfg in cases():
        t=execute(c,cfg,limit=100000);assert t['boundary']['kind']!='source_visit_limit';rows.append(pack(c,cfg,t))
        if len(rows)%64==0:print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
    assert len(rows)==768
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_release_source.json','daemon_record720_release_replay.py','probe_daemon_record720_handoff.py','capture_daemon_record720_handoff.py','daemon_record720_handoff_profiles.json']},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'registry_publication_established':False,'new_port_emission_established':False,'full_goal_complete':False};(ROOT/'daemon_record720_release_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows)}),flush=True)
if __name__=='__main__':main()
