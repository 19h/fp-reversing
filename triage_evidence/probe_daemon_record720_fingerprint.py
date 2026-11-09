#!/usr/bin/env python3
"""Declared source-continuous allocation-to-fingerprint cases.
Eight baseline/one-variable variants per payload, not a Cartesian experiment.
O(visits + effects + compression) time; O(profiles + largest case) space.
No native target, allocator, cryptographic acceptance or IPC operation executes.
"""
import json
from daemon_receive_tools import ROOT,SOURCE
from capture_daemon_record720 import sha
from probe_daemon_record720_handoff import context,produced
from probe_daemon_record720_release import pack,SNAPSHOTS
from daemon_record720_release_replay import execute
from rpc502_body_fixtures import tlv,certificate

EXTRA_SNAPSHOTS=[0x10040f8e8,0x10040f9e4,0x10040f9e8,0x10045c570,0x10040fab0,0x100478ef8]

def payloads():
    out=[('empty_root',bytes.fromhex('3000')),('one_integer',bytes.fromhex('3003020101')),('trailing_integer',bytes.fromhex('3000020101'))]
    out.extend(('zeros_'+str(n),tlv(0x30,bytes(n)))for n in [63,64,65,127,128,129])
    out.extend([('certificate_empty_names',certificate(name=None)),('certificate_named',certificate()),('integer_control',bytes.fromhex('020101')),('octets_control',bytes.fromhex('040141')),('high_tag_control',bytes.fromhex('1f1f00'))])
    return out

def cases():
    variants=['baseline','frame_relocated','allocation_relocated','input_relocated','prior_runtime_variant','release_state_all_ones','callback_states_all_ones','backing_5a']
    for pi,(label,data) in enumerate(payloads()):
      for vi,variant in enumerate(variants):
        F=0x6800032060 if variant=='frame_relocated'else 0x6800020000
        P=0x6800071010 if variant=='allocation_relocated'else 0x6800070000
        U=0x68000b1010 if variant=='input_relocated'else 0x68000b0000
        pattern=0x5a if variant=='backing_5a'else 0xa5;runtime=int(variant=='prior_runtime_variant')
        index=pi*len(variants)+vi
        c=context(index,F,P,U,len(data),runtime,True)
        for a in [0x1010b6570,0x1010b9278,0x1010b7e78,0x1010b9230,0x1010b69d0]:
            is_release=a in[0x1010b6570,0x1010b9278]
            v=(1<<64)-1 if variant==('release_state_all_ones'if is_release else'callback_states_all_ones')else 0
            c['known_byte_groups'].append({'address':hex(a),'bytes_hex':v.to_bytes(8,'little').hex(),'provenance':'declared runtime u64; native producer/value unknown'})
        c['known_byte_groups'].append({'address':hex(U),'bytes_hex':data.hex(),'provenance':'fresh borrowed input bytes; not a native/certificate-authenticated input'})
        c['extension']={'payload_label':label,'payload_hex':data.hex(),'variant':variant}
        cfg={'allocation_return64':P,'clobber_pattern':pattern*0x0101010101010101,'physical_pattern':pattern,'NZCV_after':0x50000000 if pattern==0xa5 else 0xa0000000,'void_result64':0 if pattern==0xa5 else (1<<64)-1,'snapshot_PCs':SNAPSHOTS+EXTRA_SNAPSHOTS}
        yield c,cfg

if __name__=='__main__':
    rows=[]
    for c,cfg in cases():
        t=execute(c,cfg,limit=300000);assert t['boundary']['kind']!='source_visit_limit';rows.append(pack(c,cfg,t))
        if len(rows)%8==0:print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows),'last_boundary':t['boundary']['pc']}),flush=True)
    out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_fingerprint_source.json','daemon_record720_release_replay.py','probe_daemon_record720_handoff.py','probe_daemon_record720_release.py','rpc502_body_fixtures.py']},'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
    (ROOT/'daemon_record720_fingerprint_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
