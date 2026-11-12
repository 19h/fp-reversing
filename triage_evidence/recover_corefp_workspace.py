#!/usr/bin/env python3
"""Separate preparation bytes and compact original workspace construction.

Private input, context, pool and sequential/PAC premises remain explicit.
No native target/API/IPC or IDB operation. Whole original entry is retained;
O(C*(B+P*F+V*J+R)) time/space, at most 150000 source visits/profile.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
import recover_corefp_pool_transform as T
from verify_daemon_reader_record_payloads_publication import read
ROOT=T.ROOT;SHA=lambda b:sha256(b).hexdigest();PREPSRC=T.C.HEAP+768;PREP=0x62017f68;M32=(1<<32)-1


def configurations():
    cases=[('separate_ramp16',{}),('separate_zero16',{'preparation_kind':'zero'}),('separate_flip16',{'preparation_kind':'flip'}),
      ('separate_ramp32',{'length_u32':32}),('separate_zero32',{'length_u32':32,'preparation_kind':'zero'}),('separate_clobber',{'clobber_callers':True})]
    return [{'label':name,'length_u32':16,'selector_u8':1,'empty_holder':True,'malloc_success':True,'context_kind':'ramp','context_offset_u32':0,
      'preparation_kind':'ramp',**extra}for name,extra in cases]


def prep_bytes(c):
    b=bytearray(16)if c['preparation_kind']=='zero'else bytearray(range(16))
    if c['preparation_kind']=='flip':b[0]^=0x80
    return bytes(b)


def overlay(c):return T.overlay(c)+[(T.C.REC+16,PREPSRC.to_bytes(8,'little')),(PREPSRC,prep_bytes(c))]


class Run(T.Run):
    def __init__(self,s,c):
        super().__init__(s,c)
        for a,b in overlay(c):self.touch(a,len(b));self.u.mem_write(a,b)
        for a in self.pages:self.pages[a]=bytes(self.u.mem_read(a,4096))
    def run(self):
        p=super().run();p['declared_overlay']=[{'address':hex(a),'bytes_hex':b.hex()}for a,b in overlay(self.c)];return p


def construction(p,s):
    edges=[e for e in p['PAC_models']if e['target']==hex(T.C.BASE+0x1b69c4)];assert len(edges)==256
    indices=[int(e['CPU']['X31'][13],16)for e in edges];assert indices==list(range(256))
    fields=[0,3,6,7,9,10,11,14,15,16,19,20,21,22,23,24,25,26,27,28,30]
    initial={str(j):edges[0]['CPU']['X31'][j]for j in fields}
    assert all({str(j):e['CPU']['X31'][j]for j in fields}==initial for e in edges)
    stack={}
    for pc,label in [('0x1b69d8','left8'),('0x1b69fc','affine32'),('0x1b6a18','xor_first'),('0x1b6a40','xor_second')]:
        rr=[v for v in p['reads']if p['visits'][v['visit']]['pc']==pc];assert len(rr)==256 and len({v['bytes_hex']for v in rr})==1
        stack[label]=int.from_bytes(bytes.fromhex(rr[0]['bytes_hex']),'little')
    base32=int(initial['3'],16)-T.C.BASE;base16=int(initial['9'],16)-T.C.BASE
    return {'invariant_registers_u64':initial,'stack_u32':stack,'table32':{'address':hex(base32),'bytes_hex':s.read(base32,1024).hex()},
      'table16':{'address':hex(base16),'bytes_hex':s.read(base16,512).hex()},'counter_values':indices,
      'first_writes':[v for v in p['writes']if p['visits'][v['visit']]['pc']=='0x1b6a38'],
      'second_writes':[v for v in p['writes']if p['visits'][v['visit']]['pc']=='0x1b6a50']}


def main():
    s=T.C.Pointers();profiles=[];spans={};forms=[]
    for c in configurations():
        r=Run(s,c);p=r.run();profiles.append(p);spans.update(r.functions);forms.append(construction(p,s));print(json.dumps({'label':c['label'],'visits':len(p['visits'])}),flush=True)
    counts={'profiles':len(profiles),**{k:sum(len(p[k])for p in profiles)for k in ['visits','reads','writes','PAC_models','models','points','allocations','child_entries']}}
    deps=T.C.DEPS+['recover_corefp_pool_caller.py','recover_corefp_pool_transform.py']
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':T.C.THIN_SHA,'dependencies':{n:SHA(read(ROOT/n).encode())for n in deps},
      'source_spans':list(spans.values()),'base_declared_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in T.C.inputs()],
      'profiles':profiles,'workspace_constructions':forms,'verified_counts':counts,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,
      'source_PC_gap':False,'child_record_patched':False,'source_context_initializer_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_workspace_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
