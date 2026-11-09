#!/usr/bin/env python3
"""Original-A64 input fragments and declared allocation-to-dispatch cases.
O(input fragments+case visits/effects+compression) time; O(compressed outputs
+ largest case+source decoder cache) space. No original frontier is resumed.
"""
import itertools,json,hashlib,base64,zlib
from functools import lru_cache
from daemon_receive_tools import ROOT,SOURCE,FIXUPS
from replay_daemon_descriptor_producers import IMPORTS
from capture_daemon_record720 import sha
from capture_daemon_record720_handoff import source_inputs
from daemon_record720_handoff_replay import execute

@lru_cache(maxsize=None)
def produced(F,U,D):
    header=(U^0x9898989898989898).to_bytes(8,'big')+(D^0x98989898).to_bytes(4,'big')
    return source_inputs(F,header)

def context(index,F,owner,U,D,runtime,guard):
    producer=produced(F,U,D);groups=[]
    def word(a,n,v,provenance):groups.append({'address':hex(a),'bytes_hex':v.to_bytes(n,'little').hex(),'provenance':provenance})
    source=json.loads((ROOT/'daemon_record720_handoff_source.json').read_text())
    for r in source['retained_saved_roots']:word(F+int(r['offset'],16),8,int(r['u64'],16),'retained source-root value; this phase native continuity unknown')
    word(F+0x2dc0,8,int(producer['U64'],16),'actual input-fragment output, explicit component value handover')
    word(F+0x2fec,4,int(producer['V32'],16),'actual input-fragment output, explicit component value handover')
    values=[0,0,0,0]if runtime==0 else [0x12345678,0xfedcba9876543210,0x1020304050607080,0xfedcba9876543210]
    for a,v in zip([0x1010c4e18,0x1010c4670,0x1010b8e78,0x1010b7c58],values):word(a,8,v,'declared runtime/controller/cursor scalar')
    if guard:
        symbol=FIXUPS[0x1010b1e18]['target'];assert symbol.endswith('___stack_chk_guard')
        word(IMPORTS[symbol],8,0 if runtime==0 else 0xabcdef0123456789,'declared borrowed imported-data cell; native address/value unknown')
        word(0x1010b7d70,8,0 if runtime==0 else 0x8877665544332211,'declared dispatcher runtime state')
    regs=[('sp',F),('x29',F+0xdf40),('x25',0x100fc4130),('x22',0x123456789abcdef0),('x23',0x1010c4670),('w9',0x471c),('x28',0x1010c4e18),('x13',0x101031fa0),('x30',0x101039ef0)]
    return {'case_index':index,'SP':hex(F),'entry_PC':'0x100badfc0','entry_defined_GPRs':{n:hex(v)for n,v in regs},'known_byte_groups':groups,'allocated_owners':{},'owner_snapshots':{},'allocation_owner_address':hex(owner),'input_producer_sha256':hashlib.sha256(json.dumps(producer,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'logical_U64':hex(U),'logical_D32':hex(D),'runtime_variant':runtime,'imported_guard_supplied':guard,'native_caller_continuity':False}

def cases():
    for index,(F,owner,U,D,runtime,guard,pattern)in enumerate(itertools.product([0x6800020000,0x6800032060],[0x6800070000,0x6800071010],[0,0x123456789abcdef0,0xffffffffffffffff],[0,1,20,0xffffffff],[0,1],[False,True],[0xa5,0x5a])):
        cfg={'allocation_return64':owner,'clobber_pattern':pattern*0x0101010101010101,'physical_pattern':pattern,'NZCV_after':0x50000000 if pattern==0xa5 else 0xa0000000}
        yield context(index,F,owner,U,D,runtime,guard),cfg

def pack(c,cfg,t):
    b=json.dumps(t,sort_keys=True,separators=(',',':')).encode();return {'case_index':c['case_index'],'context':c,'configuration':cfg,'source_visits':len(t['steps']),'boundary':t['boundary'],'payload_sha256':hashlib.sha256(b).hexdigest(),'payload_zlib_base64':base64.b64encode(zlib.compress(b,9)).decode()}

def main():
    rows=[]
    for c,cfg in cases():
        t=execute(c,cfg,limit=100000);assert t['boundary']['kind']!='source_visit_limit';rows.append(pack(c,cfg,t))
        if len(rows)%32==0:print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
    inputs=[{'SP':hex(F),**produced(F,U,D)}for F,U,D in itertools.product([0x6800020000,0x6800032060],[0,0x123456789abcdef0,0xffffffffffffffff],[0,1,20,0xffffffff])]
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_handoff_source.json','capture_daemon_record720_handoff.py','daemon_record720_handoff_replay.py','daemon_cache_publication_replay.py']},'source_sha256':sha(SOURCE),'input_producers':inputs,'cases':rows,'new_port_emission_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_record720_handoff_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'total_cases':len(rows)}),flush=True)
if __name__=='__main__':main()
