#!/usr/bin/env python3
"""Continuous original pool caller, two allocation records and null cleanup.

No native target/API/IPC or IDB operation. PAC, sequential CASAL and malloc
are declared private models. Backed paths stop before the large transform
body; raw holder stops before dereference. O(C*(B+P*F+V*J+R)) conservative
time/space; 60000 visits/profile. No child record or source PC is patched.
"""
import json
from pathlib import Path
from hashlib import sha256
import corefp_library_reader as L
L.SOURCE=Path(__file__).resolve().parent.parent/'CoreFP'
from unicorn import arm64_const as A
from recover_corefp_lookup_initialization import Run as Frozen,BASE,BIND,REC,HEAP,DONE,SP,OUT,ROOT,frame,pack,inputs
from corefp_fixups_reader import Pointers,THIN_SHA
from verify_daemon_reader_record_payloads_publication import read
SHA=lambda b:sha256(b).hexdigest();M=(1<<64)-1
ENTRY=0x1af6b8;CHILD=SP-0x88;PAIR=SP-0x108;TOKEN=0x1d33108;SELECTOR=0x1d44409;HOLDER=0x1d32dd0
DEPS=['recover_corefp_lookup_initialization.py','recover_fpsd1201_predicates.py','corefp_library_reader.py','corefp_fixups_reader.py',
 'corefp_fixups_inventory.json','probe_corefp_exports.py','daemon_receive_tools.py']
POINTS={0x1af928:'entry_dispatch',0x1afe90:'length_gate',0x1affb0:'first_allocation_call',0x1bc12c:'allocation_entry',
 0x1b0080:'second_allocation_call',0x1b008c:'allocation_pair_store',0x1b0168:'first_cleanup_call',0x1b01e8:'second_cleanup_call',
 0x5c87d4:'cleanup_entry',0x5c8938:'cleanup_operation_dispatch',0x1b0234:'outer_marker_store'}
ATOMICS={0x1bc344:('x27','w15','w12'),0x5c8974:('x9','w17','w6')}


def configurations():
    rows=[('length_0',{'length_u32':0}),('length_1',{'length_u32':1}),('length_15',{'length_u32':15}),
      ('length_16',{}),('length_32',{'length_u32':32}),('selector_two',{'selector_u8':2}),('selector_255',{'selector_u8':255}),
      ('malloc_null_16',{'empty_holder':True}),('malloc_null_32',{'empty_holder':True,'length_u32':32}),
      ('backed_16',{'empty_holder':True,'malloc_success':True}),('backed_32',{'empty_holder':True,'malloc_success':True,'length_u32':32}),
      ('backed_clobber',{'empty_holder':True,'malloc_success':True,'clobber_callers':True}),
      ('forward_16',{'layout':'forward'}),('overlap_reverse_16',{'layout':'overlap_reverse'}),('overlap_forward_16',{'layout':'overlap_forward'}),
      ('busy_token',{'selector_u8':1,'token_u32':0xa94ef}),('raw_holder_frontier',{'selector_u8':1})]
    return [{'label':name,'length_u32':16,'selector_u8':1 if extra.get('empty_holder')else 0,'malloc_success':False,**extra}for name,extra in rows]


def addresses(c):
    a,b={'reverse':(0x100,0x200),'forward':(0x200,0x100),'overlap_reverse':(0x100,0x108),'overlap_forward':(0x108,0x100)}[c.get('layout','reverse')]
    return HEAP+a,HEAP+b


def overlay(c):
    src,dst=addresses(c)
    key=((REC^0x542fbf9b)*0x4386951d)&0xffffffff;b=bytearray(b'\xa5'*48)
    fields=[(0,8,HEAP+0x80),(12,4,0x7f48^key),(16,8,HEAP+0x100),(24,8,(dst-0xe4106ba853ce6c9e)&M),
      (32,8,src),(40,4,((c['length_u32']+0x0c2f89b9)&0xffffffff)^key)]
    for off,n,v in fields:b[off:off+n]=v.to_bytes(n,'little')
    rows=[(REC,bytes(b)),(OUT,bytes(8)),(BASE+SELECTOR,bytes([c['selector_u8']]))]
    # Input/output storage is distinct from the declared malloc arena.
    rows.extend([(HEAP+0x80,b'\x42'*16),(dst,b'\xa5'*64),(src,bytes(range(64)))])
    if 'token_u32'in c:rows.append((BASE+TOKEN,c['token_u32'].to_bytes(4,'little')))
    if c.get('empty_holder'):
        rows.extend((BASE+HOLDER+j,(BASE+HOLDER+0x30).to_bytes(8,'little'))for j in [0x48,0x50])
    return rows


ARENA=HEAP+0x2000
class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c);self.u.mem_map(ARENA,8192)
        for a,b in overlay(c):self.touch(a,len(b));self.u.mem_write(a,b)
        for a,n in [(REC,48),(CHILD,32),(PAIR,16),(BASE+HOLDER,88),(BASE+TOKEN,4),(BASE+SELECTOR,1),(ARENA,8192)]:self.touch(a,n)
        for a in self.pages:self.pages[a]=bytes(self.u.mem_read(a,4096))
        self.u.reg_write(A.UC_ARM64_REG_X1,OUT);self.u.reg_write(A.UC_ARM64_REG_PC,BASE+ENTRY);self.initial=frame(self.u)
        self.functions={ENTRY:s.function(ENTRY)};self.allocations=[];self.entry_attempts=0;self.entries=[]
    def snapshot(self,label):
        return {'label':label,'CPU':frame(self.u),'record48_hex':bytes(self.u.mem_read(REC,48)).hex(),
          'child32_hex':bytes(self.u.mem_read(CHILD,32)).hex(),'pair16_hex':bytes(self.u.mem_read(PAIR,16)).hex(),
          'cursor8_hex':bytes(self.u.mem_read(OUT,8)).hex(),'transformed64_hex':bytes(self.u.mem_read(addresses(self.c)[1],64)).hex(),
          'holder88_hex':bytes(self.u.mem_read(BASE+HOLDER,88)).hex(),'selector_u8':self.u.mem_read(BASE+SELECTOR,1)[0],
          'token_u32':int.from_bytes(self.u.mem_read(BASE+TOKEN,4),'little')}
    def stop(self,reason,**extra):self.frontier={'reason':reason,'CPU':frame(self.u),**extra};self.u.emu_stop()
    def code(self,u,pc,n,d):
        self.flush();at=pc-BASE
        if pc==DONE:return self.stop('ordinary_return')
        if at==0x1b0270:return self.stop('before_transform_body',source_pc=hex(at),successful_processing_established=False)
        if at in [0x1bc12c,0x5c87d4]:self.entry_attempts=0;self.entries.append(hex(at))
        if at in ATOMICS:
            if self.entry_attempts:return self.stop('before_second_CASAL',source_pc=hex(at),concurrent_ordering_validated=False)
            ptr,cmpreg,newreg=ATOMICS[at];a=self.reg(ptr);old=int.from_bytes(u.mem_read(a,4),'little');compare=self.reg(cmpreg);new=self.reg(newreg)
            assert a==BASE+TOKEN and compare==0x5d96 and new==0xa94ef
            from daemon_receive_tools import CS
            raw=bytes(u.mem_read(pc,4));ins=next(CS.disasm(raw,at));assert ins.mnemonic=='casal'
            self.visits.append({'pc':hex(at),'bytes_hex':raw.hex(),'instruction':ins.mnemonic+' '+ins.op_str});self.entry_attempts+=1
            e={'kind':'declared_sequential_CASAL','visit':len(self.visits)-1,'before':frame(u),'pointer':hex(a),
              'old_u32':old,'compare_u32':compare,'replacement_u32':new,'memory':[],'concurrent_ordering_validated':False};self.models.append(e)
            if old==compare:e['memory']=[{'address':hex(a),'before_hex':bytes(u.mem_read(a,4)).hex(),'after_hex':new.to_bytes(4,'little').hex()}];u.mem_write(a,new.to_bytes(4,'little'))
            u.reg_write(getattr(A,'UC_ARM64_REG_'+cmpreg.upper()),old);u.reg_write(A.UC_ARM64_REG_PC,pc+4);e['after']=frame(u);return
        if at==0x1bca38 and not(self.c['malloc_success']and self.allocations and ARENA<=self.reg('x9')<ARENA+5000):
            return self.stop('before_unbacked_node_read',source_pc=hex(at),pointer=hex(self.reg('x9')),access_offset_B=8,access_size_B=8,native_read_executed=False)
        if at in POINTS:self.points.append(self.snapshot(POINTS[at]))
        if pc in self.imports:
            name=self.imports[pc];call=self.reg('lr')-4-BASE;args=[self.reg('x'+str(j))for j in range(8)]
            assert name=='_malloc'and call==0x1bcf5c and args[0]==5000 and len(self.allocations)<2
            value=ARENA if self.c['malloc_success']else 0;assert not value or not self.allocations
            e={'kind':'declared_API','name':name,'callsite':hex(call),'before':frame(u),'args_x0_x7':list(map(hex,args)),'memory':[],'return_u64':hex(value)};self.models.append(e)
            self.allocations.append({'pointer':hex(value),'size_B':5000})
            if value:
                b=b'\xa5'*5000;e['memory']=[{'address':hex(value),'before_hex':bytes(u.mem_read(value,5000)).hex(),'after_hex':b.hex()}];u.mem_write(value,b)
            self.returned(value);e['after']=frame(u);return
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=60001);self.flush();assert hasattr(self,'frontier')
        return {'configuration':self.c,'declared_overlay':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in overlay(self.c)],'initial_CPU':self.initial,
          'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,
          'frontier':self.frontier,'final_state':self.snapshot('frontier'),'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'allocations':self.allocations,'child_entries':self.entries}


def main():
    s=Pointers();spans={};profiles=[]
    for c in configurations():
        r=Run(s,c);profiles.append(r.run());spans.update(r.functions)
    counts={'profiles':len(profiles),**{k:sum(len(p[k])for p in profiles)for k in ['visits','reads','writes','PAC_models','models','points','allocations','child_entries']}}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source_spans':list(spans.values()),
      'base_declared_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()],'profiles':profiles,'verified_counts':counts,
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'source_PC_gap':False,'child_record_patched':False,'full_goal_complete':False}
    (ROOT/'corefp_pool_caller_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
