#!/usr/bin/env python3
"""Original selector-gated pool allocator with declared private arena state.

PAC, sequential CASAL and malloc effects are models; no native target/API/IPC
or IDB operation. Original raw holder pointer stops before dereference.
O(C*(B+P*F+V*J+R)) conservative time/space; 12000 visits/profile;
C cases, B source bytes, P pages, F fixups, V visits, J journals, R state.
"""
import json
from pathlib import Path
from hashlib import sha256
import corefp_library_reader as L
L.SOURCE=Path(__file__).resolve().parent.parent/'CoreFP'
from unicorn import arm64_const as A
from recover_corefp_lookup_initialization import Run as Frozen,BASE,BIND,REC,HEAP,DONE,SP,ROOT,frame,pack,inputs
from corefp_fixups_reader import Pointers,THIN_SHA
from verify_daemon_reader_record_payloads_publication import read
SHA=lambda b:sha256(b).hexdigest();M=(1<<64)-1
ENTRY=0x1bc12c;TOKEN=0x1d33108;SELECTOR=0x1d44409;HOLDER=0x1d32dd0
DEPS=['recover_corefp_lookup_initialization.py','recover_fpsd1201_predicates.py','corefp_library_reader.py','corefp_fixups_reader.py',
 'corefp_fixups_inventory.json','probe_corefp_exports.py','daemon_receive_tools.py']
POINTS={0x1bc2d4:'operation_dispatch',0x1bc3d4:'selector_read',0x1bc450:'decoded_request',0x1bc5d0:'allocation_extent',
 0x1bc9fc:'holder_head_read',0x1bca38:'node_extent_read',0x1bcf5c:'malloc_call',0x1bd058:'insert_node',
 0x1bcc30:'unlink_node',0x1bce50:'split_node',0x1bd188:'token_restore',0x1bd194:'result_store'}


def configurations():
    rows=[('selector_zero',{}),('selector_two',{'selector_u8':2}),('selector_255',{'selector_u8':255}),
      ('busy_token',{'selector_u8':1,'token_u32':0xa94ef}),('raw_holder_frontier',{'selector_u8':1}),
      ('malloc_null_32',{'empty_holder':True}),('malloc_null_0',{'empty_holder':True,'request_u64':0}),
      ('malloc_null_4799',{'empty_holder':True,'request_u64':4799}),('malloc_null_4800',{'empty_holder':True,'request_u64':4800}),
      ('malloc_null_5000',{'empty_holder':True,'request_u64':5000}),
      ('arena_0',{'empty_holder':True,'malloc_success':True,'request_u64':0}),
      ('arena_1',{'empty_holder':True,'malloc_success':True,'request_u64':1}),
      ('arena_32',{'empty_holder':True,'malloc_success':True}),
      ('arena_128',{'empty_holder':True,'malloc_success':True,'request_u64':128}),
      ('arena_32_clobber',{'empty_holder':True,'malloc_success':True,'clobber_callers':True})]
    return [{'label':label,'request_u64':32,'selector_u8':1 if extra.get('empty_holder')else 0,'malloc_success':False,**extra}for label,extra in rows]


def key(r):
    return (((((r&0x569daa3f03dab736)<<1)-r+0x296255c0fc2548c9)^0xe6e1187952a9dc51)*0x9e8a2055)&M


def overlay(c):
    b=bytearray(b'\xa5'*32);b[:8]=bytes(8)
    b[8:16]=((c['request_u64']-0xb055c0a249dc0450-key(REC))&M).to_bytes(8,'little')
    b[16:20]=((0x2b9b-key(REC))&0xffffffff).to_bytes(4,'little')
    rows=[(REC,bytes(b)),(BASE+SELECTOR,bytes([c['selector_u8']]))]
    if 'token_u32'in c:rows.append((BASE+TOKEN,c['token_u32'].to_bytes(4,'little')))
    if c.get('empty_holder'):
        for off in [0x48,0x50]:rows.append((BASE+HOLDER+off,(BASE+HOLDER+0x30).to_bytes(8,'little')))
    return rows


class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c);self.u.mem_map(HEAP+4096,4096)
        for a,b in overlay(c):self.touch(a,len(b));self.u.mem_write(a,b)
        for a,n in [(BASE+HOLDER,88),(BASE+SELECTOR,1),(BASE+TOKEN,4),(HEAP,8192)]:self.touch(a,n)
        for a in self.pages:self.pages[a]=bytes(self.u.mem_read(a,4096))
        self.u.reg_write(A.UC_ARM64_REG_PC,BASE+ENTRY);self.initial=frame(self.u)
        self.functions={ENTRY:s.function(ENTRY)};self.attempts=0;self.allocations=[]
    def snapshot(self,label):
        return {'label':label,'CPU':frame(self.u),'record32_hex':bytes(self.u.mem_read(REC,32)).hex(),
          'holder88_hex':bytes(self.u.mem_read(BASE+HOLDER,88)).hex(),'selector_u8':self.u.mem_read(BASE+SELECTOR,1)[0],
          'token_u32':int.from_bytes(self.u.mem_read(BASE+TOKEN,4),'little')}
    def stop(self,reason,**extra):
        self.frontier={'reason':reason,'CPU':frame(self.u),**extra};self.u.emu_stop()
    def code(self,u,pc,n,d):
        self.flush();at=pc-BASE
        if pc==DONE:return self.stop('ordinary_return')
        if at==0x1bc344:
            if self.attempts:return self.stop('before_second_CASAL',concurrent_ordering_validated=False)
            raw=bytes(u.mem_read(pc,4));assert raw.hex()=='6cffef88'
            self.visits.append({'pc':hex(at),'bytes_hex':raw.hex(),'instruction':'casal w15, w12, [x27]'})
            a=self.reg('x27');old=int.from_bytes(u.mem_read(a,4),'little');compare=self.reg('w15');new=self.reg('w12')
            assert a==BASE+TOKEN and compare==0x5d96 and new==0xa94ef
            self.attempts+=1;e={'kind':'declared_sequential_CASAL','visit':len(self.visits)-1,'before':frame(u),'pointer':hex(a),
              'old_u32':old,'compare_u32':compare,'replacement_u32':new,'memory':[],'concurrent_ordering_validated':False};self.models.append(e)
            if old==compare:
                e['memory']=[{'address':hex(a),'before_hex':bytes(u.mem_read(a,4)).hex(),'after_hex':new.to_bytes(4,'little').hex()}];u.mem_write(a,new.to_bytes(4,'little'))
            u.reg_write(A.UC_ARM64_REG_W15,old);u.reg_write(A.UC_ARM64_REG_PC,pc+4);e['after']=frame(u);return
        if at==0x1bca38 and not(self.allocations and HEAP<=self.reg('x9')<HEAP+self.allocations[0]['size_B']):
            return self.stop('before_unbacked_node_read',source_pc=hex(at),pointer=hex(self.reg('x9')),access_offset_B=8,access_size_B=8,native_read_executed=False)
        if at in POINTS:self.points.append(self.snapshot(POINTS[at]))
        if pc in self.imports:
            name=self.imports[pc];call=self.reg('lr')-4-BASE;args=[self.reg('x'+str(j))for j in range(8)]
            assert name=='_malloc'and call==0x1bcf5c and not self.allocations
            size=args[0];assert size==max(5000,self.c['request_u64']+201)and size<=8192
            value=HEAP if self.c['malloc_success']else 0;e={'kind':'declared_API','name':name,'callsite':hex(call),
              'before':frame(u),'args_x0_x7':list(map(hex,args)),'memory':[],'return_u64':hex(value)};self.models.append(e)
            self.allocations.append({'pointer':hex(value),'size_B':size})
            if value:
                self.touch(value,size);b=b'\xa5'*size;e['memory']=[{'address':hex(value),'before_hex':bytes(u.mem_read(value,size)).hex(),'after_hex':b.hex()}];u.mem_write(value,b)
            self.returned(value);e['after']=frame(u);return
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=12001);self.flush();assert hasattr(self,'frontier')and self.attempts==1
        return {'configuration':self.c,'declared_overlay':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in overlay(self.c)],'initial_CPU':self.initial,
          'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,
          'frontier':self.frontier,'final_state':self.snapshot('frontier'),
          'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],'allocations':self.allocations}


def main():
    s=Pointers();runs=[Run(s,c)for c in configurations()];profiles=[r.run()for r in runs]
    assert all(r.functions==runs[0].functions for r in runs)
    counts={'profiles':len(profiles),**{k:sum(len(p[k])for p in profiles)for k in ['visits','reads','writes','PAC_models','models','points','allocations']}}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source_spans':list(runs[0].functions.values()),
      'base_declared_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()],'profiles':profiles,'verified_counts':counts,
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'source_PC_gap':False,'full_goal_complete':False}
    (ROOT/'corefp_pool_allocator_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
