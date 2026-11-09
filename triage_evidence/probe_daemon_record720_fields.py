#!/usr/bin/env python3
"""Fresh allocation-to-certificate-field and readiness continuations.
O(visits+effects+compression) time; O(profiles+largest case+decoder cache)
space. Extra runtime cells/atomic initial state are declarations, not native.
"""
import copy,json
from daemon_receive_tools import ROOT,SOURCE
from capture_daemon_record720 import sha
from probe_daemon_record720_fingerprint import cases as parent_cases
from probe_daemon_record720_release import pack
from daemon_record720_fields_replay import execute

EXTRA=[0x1010c5320,0x1010b8210,0x1010b6998,0x1010b9260,0x1010b90e0,0x1010b8e00,0x1010c50c8,0x1010c52d0,0x1010b7fe0,0x1010b8e68,0x1010b6990,0x1010b81a0,0x1010b69b8]
SNAPSHOTS=[0x10044f7a4,0x10041f768,0x100161bdc,0x10040f1d4,0x1000af0f8,0x1004150f0,0x100413254,0x10000cd38,0x10044fdc0,0x10043aa98,0x10043ab00,0x10043cf70,0x10043fdb0,0x100610bd0,0x100503d18,0x100503d1c,0x10048d694]

def cases():
    index=0
    for parent,cfg in parent_cases():
        if not parent['extension']['payload_label'].startswith('certificate_'):continue
        choices=[None,0,1]if parent['extension']['payload_label']=='certificate_named'and parent['extension']['variant']=='baseline'else[None]
        for ready in choices:
            c=copy.deepcopy(parent);cfg=copy.deepcopy(cfg);c['case_index']=index;c['extension']['parent_case_index']=parent['case_index'];c['extension']['readiness_byte']=ready
            value=(1<<64)-1 if c['extension']['variant']=='callback_states_all_ones'else 0
            for a in EXTRA:c['known_byte_groups'].append({'address':hex(a),'bytes_hex':value.to_bytes(8,'little').hex(),'provenance':'declared callback runtime u64; native producer/value unknown'})
            c['known_byte_groups'].append({'address':'0x1010b5de0','bytes_hex':(0x5d96).to_bytes(4,'little').hex(),'provenance':'declared atomic word equal to original image initial bytes; native current state unknown'})
            if ready is not None:c['known_byte_groups'].append({'address':'0x1010c5798','bytes_hex':bytes([ready]).hex(),'provenance':'declared readiness byte; source producer documented separately'})
            cfg.update({'cpu_model':'MAX','snapshot_PCs':cfg['snapshot_PCs']+SNAPSHOTS});yield c,cfg;index+=1

if __name__=='__main__':
    rows=[]
    for c,cfg in cases():
        t=execute(c,cfg,limit=700000);assert t['boundary']['kind']not in['source_visit_limit','before_unsupported_memory_instruction'];rows.append(pack(c,cfg,t));print(json.dumps({'case':c['case_index'],'source_visits':len(t['steps']),'boundary':t['boundary']['pc']}),flush=True)
    assert len(rows)==18
    p={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_fields_source.json','daemon_record720_fields_replay.py','probe_daemon_record720_fingerprint.py','probe_daemon_record720_release.py']},'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
    (ROOT/'daemon_record720_fields_profiles.json').write_text(json.dumps(p,indent=2)+'\n')
