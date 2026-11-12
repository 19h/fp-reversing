#!/usr/bin/env python3
"""Cold lookup prefix with original once callbacks, lock construction and reset.

External once, allocator, pthread and PAC effects are declared private models.
No native target/API/IPC or IDB mutation. O(C*(B+F+V+J+R)) time/space;
original execution bounded at 12000 visits per case.
"""
import json,copy,bisect
from pathlib import Path
from hashlib import sha256
import unicorn as U
from unicorn import arm64_const as A
from recover_fpsd1201_predicates import frame,pack
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE,BIND
from daemon_receive_tools import CS
from verify_daemon_reader_record_payloads_publication import read
SHA=lambda b:sha256(b).hexdigest();M64=(1<<64)-1
STACK=0x62000000;SP=STACK+0x18000;REC=0x63000100;OUT=0x63000300;HEAP=0x64000000;DONE=0x65000000
PRIMARY=0x1d44448;SECONDARY=0x1d37838;LOCKS=[0x1d444a8,0x1d47fb8]
DEPS=['corefp_library_reader.py','corefp_fixups_reader.py','corefp_fixups_inventory.json','recover_fpsd1201_predicates.py']


def configurations():
    rows=[]
    for label,alloc,status,extra in [('both_success',[True,True],[0,0],{}),('to_bootstrap',[True,True],[0,0],{'continue_to_bootstrap':True}),
      ('bootstrap_malloc_fallback',[False,True],[0,0],{'continue_to_bootstrap':True}),('bootstrap_init_fallback',[True,True],[16,0],{'continue_to_bootstrap':True}),
      ('first_malloc_null',[False,True],[0,0],{}),('second_malloc_null',[True,False],[0,0],{}),('both_malloc_null',[False,False],[0,0],{}),
      ('first_init_16',[True,True],[16,0],{}),('second_init_16',[True,True],[0,16],{}),
      ('first_init_12',[True,True],[12,0],{}),('second_init_12',[True,True],[0,12],{}),
      ('first_init_22',[True,True],[22,0],{}),('second_init_22',[True,True],[0,22],{}),
      ('volatile_clobber',[True,True],[0,0],{'clobber_callers':True})]:
        rows.append({'label':label,'allocation_success':alloc,'lock_init_status_u32':status,**extra})
    return rows


def inputs():
    key=(((((REC&0xffffffff)|0x20d7d4ce)-(REC&0xffffffff)+((REC&0xffffffff)&0xdf282b31))&0xffffffff)^0xab997307)*0x0bcb7857&0xffffffff
    record=bytearray(b'\xa5'*32);record[8:16]=OUT.to_bytes(8,'little');record[16:24]=(OUT+4).to_bytes(8,'little');record[24]=(key+9)&255;record[28:32]=((key+0xba27)&0xffffffff).to_bytes(4,'little')
    return [(REC,bytes(record)),(OUT,b'\xa5'*8),(BASE+PRIMARY,(0x5017).to_bytes(4,'little')),
      (BASE+SECONDARY,(0x5034).to_bytes(4,'little')),(BASE+SECONDARY+0x158,bytes.fromhex('4433221188776655ccbbaa990a000000')),
      (BIND+86*16,(0x1b57).to_bytes(4,'little'))]


class Run:
    def __init__(self,s,c):
        self.s=s;self.c=c;u=self.u=U.Uc(U.UC_ARCH_ARM64,U.UC_MODE_ARM)
        for seg in s.meta['segments']:
            n=(seg['vm_size']+4095)&~4095
            if n:u.mem_map(BASE+seg['address'],n)
            if seg['file_size']:u.mem_write(BASE+seg['address'],s.data[seg['file_offset']:seg['file_offset']+seg['file_size']])
        for a,n in [(STACK,0x20000),(REC&~4095,4096),(HEAP,4096),(BIND,0x2000),(DONE,4096)]:u.mem_map(a,n)
        self.imports={BIND+r['ordinal']*16:r['name']for r in s.imports}
        for a,r in s.decoded.items():
            v=BIND+r['import']['ordinal']*16+r['pointer_addend']if r['bind']else BASE+int(r['target'],16);u.mem_write(BASE+a,v.to_bytes(8,'little'))
        u.mem_write(STACK,b'\xa5'*0x20000)
        for a,b in inputs():u.mem_write(a,b)
        for j in range(31):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),((j+1)*0x123456789abcdef)&M64)
        for j in range(32):u.reg_write(A.UC_ARM64_REG_Q0+j,int.from_bytes(bytes([j])*16,'little'))
        for n,v in [('SP',SP),('PC',BASE+0x1cdb24),('X0',REC),('LR',DONE),('NZCV',0x60000000),('CPACR_EL1',3<<20)]:u.reg_write(getattr(A,'UC_ARM64_REG_'+n),v)
        self.initial=frame(u);self.pages={};self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.models=[];self.pacs=[];self.points=[];self.functions={};self.once=[];self.once_done=set();self.allocs=0;self.current_records=[]
        for a,n in [(REC,32),(OUT,8),(BASE+PRIMARY,4),(BASE+SECONDARY,0x170)]+[(BASE+a,8)for a in LOCKS]:self.touch(a,n)
        u.hook_add(U.UC_HOOK_CODE,self.code);u.hook_add(U.UC_HOOK_MEM_READ,self.memory);u.hook_add(U.UC_HOOK_MEM_WRITE,self.memory)
    def reg(self,n):return self.u.reg_read(getattr(A,'UC_ARM64_REG_'+n.upper()))
    def touch(self,a,n):
        for p in range(a&~4095,((a+n-1)&~4095)+1,4096):
            if p not in self.pages:self.pages[p]=bytes(self.u.mem_read(p,4096))
    def memory(self,u,access,a,n,v,d):
        self.touch(a,n)
        if access==U.UC_MEM_READ:self.reads.append({'visit':len(self.visits)-1,'address':hex(a),'size_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        else:
            e={'visit':len(self.visits)-1,'address':hex(a),'size_B':n,'before_hex':bytes(u.mem_read(a,n)).hex()};self.writes.append(e);self.pending.append(e)
    def flush(self):
        for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_B'])).hex()
        self.pending=[]
    def returned(self,v):
        if self.c.get('clobber_callers'):
            for j in range(1,18):self.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),j*0x13579bdf2468ace&M64)
            self.u.reg_write(A.UC_ARM64_REG_NZCV,0xa0000000)
        self.u.reg_write(A.UC_ARM64_REG_X0,v);self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'))
    def snapshot(self,label):
        return {'label':label,'CPU':frame(self.u),'locks_u64':[hex(int.from_bytes(self.u.mem_read(BASE+a,8),'little'))for a in LOCKS],
          'primary_u32':int.from_bytes(self.u.mem_read(BASE+PRIMARY,4),'little'),'secondary_u32':int.from_bytes(self.u.mem_read(BASE+SECONDARY,4),'little'),
          'metadata20_hex':bytes(self.u.mem_read(BASE+SECONDARY+0x158,20)).hex(),'reset_word_u32':int.from_bytes(self.u.mem_read(BASE+SECONDARY+0x38,4),'little')}
    def code(self,u,pc,n,d):
        self.flush()
        if pc==DONE+0x100:
            control,lr,callback=self.once.pop();self.once_done.add(control);e={'kind':'declared_once_return','before':frame(u),'memory':[], 'control':hex(control),'callback':hex(callback)}
            self.points.append(self.snapshot('once_callback_return_'+hex(callback-BASE)));u.reg_write(A.UC_ARM64_REG_LR,lr);self.returned(0);e['after']=frame(u);self.models.append(e);return
        if pc in self.imports:
            name=self.imports[pc];args=[self.reg('x'+str(j))for j in range(8)]
            if name=='_bootstrap_look_up'or name=='_pthread_rwlock_wrlock'and not self.c.get('continue_to_bootstrap'):
                self.frontier={'reason':'before_'+name,'CPU':frame(u),'args_x0_x7':[hex(v)for v in args],'callsite':hex(self.reg('lr')-4-BASE)};u.emu_stop();return
            e={'kind':'declared_API','name':name,'before':frame(u),'args_x0_x7':[hex(v)for v in args],'callsite':hex(self.reg('lr')-4-BASE),'memory':[]};self.models.append(e)
            if name=='_pthread_once':
                assert args[0]not in self.once_done and args[1]in [BASE+0x4a21e0,BASE+0x59e868];e['kind']='declared_once_enter';self.once.append((args[0],self.reg('lr'),args[1]));u.reg_write(A.UC_ARM64_REG_LR,DONE+0x100);u.reg_write(A.UC_ARM64_REG_PC,args[1]);e['after']=frame(u);return
            if name=='_malloc':
                assert args[0]==200 and self.allocs<2;j=self.allocs;self.allocs+=1;v=HEAP+j*0x100 if self.c['allocation_success'][j]else 0
                if v:
                    self.touch(v,200);e['memory']=[{'address':hex(v),'before_hex':bytes(u.mem_read(v,200)).hex(),'after_hex':('a5'*200)}];u.mem_write(v,b'\xa5'*200)
            elif name=='_pthread_rwlock_init':
                j=(args[0]-HEAP)//0x100;assert j in [0,1]and args[:2]==[HEAP+j*0x100,0];v=self.c['lock_init_status_u32'][j]
            elif name=='_pthread_rwlock_wrlock':assert args[0]==(HEAP if self.c['allocation_success'][0]and self.c['lock_init_status_u32'][0]==0 else BASE+0x1d27bf0);v=0
            elif name=='___chkstk_darwin':assert self.reg('x9')<0x17000;u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'));e['after']=frame(u);return
            else:raise AssertionError('unmodeled import '+name)
            e['return_u64']=hex(v);self.returned(v);e['after']=frame(u);return
        at=pc-BASE;assert 0<=at<0x15d2000
        ix=bisect.bisect_right(self.s.starts,at)-1;start=self.s.starts[ix];end=self.s.starts[ix+1]
        if start not in self.functions:self.functions[start]=self.s.function(start)
        raw=bytes(u.mem_read(pc,4));i=next(CS.disasm(raw,at));self.visits.append({'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str})
        if at==0x59e33c:self.current_records.append(self.reg('x0'));self.points.append({'label':'constructor_entry','CPU':frame(u),'record16_hex':bytes(u.mem_read(self.reg('x0'),16)).hex()})
        if at in [0x4a2438,0x4a2504]:
            p=self.current_records[-1];self.points.append({'label':'constructor_return','CPU':frame(u),'record':hex(p),'record16_hex':bytes(u.mem_read(p,16)).hex()})
        if i.mnemonic in ['braa','blraa']:
            regs=i.op_str.split(', ');target=self.reg(regs[0]);mod=self.reg(regs[1]);match=next((r for r in reversed(self.reads)if r['size_B']==8 and int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')==target),None);assert match
            slot=int(match['address'],16)-BASE;row=self.s.decoded[slot];assert row['authenticated']and row['key']=='IA'
            assert mod==(BASE+slot if row['address_diversity']else int(row['diversity'],16))
            self.pacs.append({'visit':len(self.visits)-1,'pc':hex(at),'target':hex(target),'modifier':hex(mod),'load_index':self.reads.index(match),'pointer_row':row,'CPU':frame(u)})
            if i.mnemonic=='blraa':u.reg_write(A.UC_ARM64_REG_LR,pc+4)
            u.reg_write(A.UC_ARM64_REG_PC,target)
        elif i.mnemonic.startswith(('pac','aut')):u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif i.mnemonic=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'))
    def run(self):
        self.u.emu_start(BASE+0x1cdb24,0,count=12001);self.flush();assert hasattr(self,'frontier')and not self.once
        return {'configuration':self.c,'initial_CPU':self.initial,'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,'frontier':self.frontier,
          'final_state':self.snapshot('frontier'),'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],'allocations_attempted':self.allocs}


def main():
    s=Pointers();rows=[];spans={}
    for c in configurations():
        p=Run(s,c);rows.append(p.run());spans.update(p.functions)
    counts={'profiles':len(rows),**{k:sum(len(p[k])for p in rows)for k in ['visits','reads','writes','PAC_models','models','points']}}
    e={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},
      'source_spans':list(spans.values()),'declared_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()], 'profiles':rows,'verified_counts':counts,
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'corefp_lookup_initialization_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
