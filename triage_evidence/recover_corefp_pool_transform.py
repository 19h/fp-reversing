#!/usr/bin/env python3
"""Continuous pool-backed transform, shared context and nonzero retirement.

An optional private context buffer is an explicit initial fixture, not a
source-initialized native object. No native target/API/IPC or IDB mutation.
Original entry, records, child calls and PC remain continuous. O(C*(B+P*F+
V*J+R)) conservative time/space; at most 150000 visits/profile.
"""
import json
from pathlib import Path
from hashlib import sha256
import recover_corefp_pool_caller as C
from verify_daemon_reader_record_payloads_publication import read
ROOT=C.ROOT;SHA=lambda b:sha256(b).hexdigest();CTX=0x64004000;BASEPTR=0x1d45f60;OFFSET=0x1d44440
EXTRA={0x1b0270:'transform_body_entry',0x1baf60:'context_index_input',0x1bafd8:'context_word_first',
 0x1bb0dc:'seven_round_ARX_end',0x1bb2a4:'context_second_index_input',0x1bb2b8:'context_word_second',
 0x1bb4f8:'context_third_index_input',0x1bb50c:'context_word_third',0x1b016c:'first_cleanup_return',0x1b01ec:'second_cleanup_return'}


def configurations():
    rows=[('original_context_zero',{'context_kind':'absent'}),('context_ramp_16',{}),('context_ramp_32',{'length_u32':32}),
      ('context_clobber',{'clobber_callers':True}),('context_zero_bytes',{'context_kind':'zero'}),
      ('context_changed_byte',{'context_kind':'changed'}),('context_offset8',{'context_offset_u32':8}),('context_offset16',{'context_offset_u32':16})]
    return [{'label':label,'length_u32':16,'selector_u8':1,'empty_holder':True,'malloc_success':True,
      'context_kind':'ramp','context_offset_u32':0,**v}for label,v in rows]


def context_bytes(c):
    b=bytearray(4096)if c['context_kind']=='zero'else bytearray(bytes(range(256))*16)
    if c['context_kind']=='changed':b[0]^=0x80
    return bytes(b)


def overlay(c):
    rows=C.overlay(c)+[(CTX,context_bytes(c))]
    if c['context_kind']!='absent':rows.extend([(C.BASE+BASEPTR,CTX.to_bytes(8,'little')),(C.BASE+OFFSET,c['context_offset_u32'].to_bytes(4,'little'))])
    return rows


class Run(C.Run):
    def __init__(self,s,c):
        super().__init__(s,c);self.u.mem_map(CTX,4096);self.fill_seen=set()
        for a,b in overlay(c):self.touch(a,len(b));self.u.mem_write(a,b)
        for a,n in [(C.BASE+BASEPTR,8),(C.BASE+OFFSET,4)]:self.touch(a,n)
        for a in self.pages:self.pages[a]=bytes(self.u.mem_read(a,4096))
    def snapshot(self,label):
        return {**super().snapshot(label),'arena8192_hex':bytes(self.u.mem_read(C.ARENA,8192)).hex(),
          'context_pointer_u64':hex(int.from_bytes(self.u.mem_read(C.BASE+BASEPTR,8),'little')),
          'context_offset_u32':int.from_bytes(self.u.mem_read(C.BASE+OFFSET,4),'little')}
    def code(self,u,pc,n,d):
        self.flush();at=pc-C.BASE
        if at==0x5c87d4:self.fill_seen=set()
        if at in [0x5c8cd8,0x5c9254]and at not in self.fill_seen:
            self.fill_seen.add(at);self.points.append(self.snapshot('cleanup_fill_entry_'+hex(at)))
        if at==0x1bafd8 and self.c['context_kind']=='absent':
            assert self.reg('x19')==self.reg('w8')==0
            return self.stop('before_uninitialized_context_read',source_pc=hex(at),base_u64='0x0',offset_u32=0,access_size_B=8,native_read_executed=False)
        if at in EXTRA:self.points.append(self.snapshot(EXTRA[at]))
        if at==0x1b0270:return C.Frozen.code(self,u,pc,n,d)
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(C.BASE+C.ENTRY,0,count=150001);self.flush();assert hasattr(self,'frontier')
        return {'configuration':self.c,'declared_overlay':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in overlay(self.c)],'initial_CPU':self.initial,
          'initial_RAM':[{'address':hex(a),'payload':C.pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,
          'frontier':self.frontier,'final_state':self.snapshot('frontier'),'final_RAM':[{'address':hex(a),'payload':C.pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'allocations':self.allocations,'child_entries':self.entries}


def main():
    s=C.Pointers();profiles=[];spans={}
    for c in configurations():
        r=Run(s,c);p=r.run();profiles.append(p);spans.update(r.functions)
        print(json.dumps({'label':c['label'],'visits':len(p['visits']),'reason':p['frontier']['reason']}),flush=True)
    counts={'profiles':len(profiles),**{k:sum(len(p[k])for p in profiles)for k in ['visits','reads','writes','PAC_models','models','points','allocations','child_entries']}}
    deps=C.DEPS+['recover_corefp_pool_caller.py']
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'dependencies':{n:SHA(read(ROOT/n).encode())for n in deps},
      'source_spans':list(spans.values()),'base_declared_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in C.inputs()],
      'profiles':profiles,'verified_counts':counts,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,
      'source_PC_gap':False,'child_record_patched':False,'source_context_initializer_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_pool_transform_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
