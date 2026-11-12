#!/usr/bin/env python3
"""Cold protected caller through selected failure cleanup and matched release.

Original source produces the child lookup record and cleanup record. API/PAC,
daemon envelope and allocator-null effects are explicit private models. A lock
ledger describes those models, never native ownership or successful retirement.
O(C*(B+F+V+J+R)) time/space; 30000 client and 2000 daemon visit bounds.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from unicorn import arm64_const as A
from recover_corefp_cold_metadata import Run as Frozen,DEPS as PARENT_DEPS
from recover_corefp_lookup_initialization import frame,pack,ROOT,BASE,REC,OUT,DONE,inputs
from corefp_fixups_reader import Pointers,THIN_SHA
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M64=(1<<64)-1
ENTRY=0x8e81c8;PARENT=0x63000800;DATA=0x63000900;AUX=0x63000c00;CURSOR=0x63000e00
DEPS=PARENT_DEPS+['recover_corefp_cold_metadata.py']


def parent_inputs():
    k=((PARENT^0x84b771aed97ffe38)*0xfcf33521)&M64
    b=bytearray(b'\xa5'*48);struct.pack_into('<Q',b,8,DATA);struct.pack_into('<I',b,20,(k+0xc1f7)&0xffffffff)
    struct.pack_into('<I',b,24,k&0xffffffff);struct.pack_into('<Q',b,32,AUX)
    return [(PARENT,bytes(b)),(DATA,b'\0'*128),(AUX,b'\0'*128),(CURSOR,b'\0'*8)]


def configurations():
    boot=lambda s,p=None:{'status_u32':s,**({'write_port_u32':p}if p is not None else {})}
    rows=[]
    for label,seq,extra in [('primary_null',[boot(0,0x5017)],{}),('fallback_null',[boot(1102),boot(0,0x5034)],{}),
      ('static_null',[boot(0,0x5017)],{'allocation_success':[False,True]}),
      ('clobber_null',[boot(0,0x5017)],{'clobber_callers':True}),
      ('unlock_error',[boot(0,0x5017)],{'unlock_status_u32':5}),
      ('lookup_error',[boot(5)],{}),('fallback_error',[boot(1102),boot(5)],{})]:
        rows.append({'label':label,'allocation_success':[True,True],'lock_init_status_u32':[0,0],
          'continue_to_bootstrap':True,'bootstrap_results':seq,'unlock_status_u32':0,**extra})
    return rows


class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c)
        for a,b in parent_inputs():self.u.mem_write(a,b)
        self.u.reg_write(A.UC_ARM64_REG_X0,PARENT);self.u.reg_write(A.UC_ARM64_REG_X1,CURSOR);self.u.reg_write(A.UC_ARM64_REG_PC,BASE+ENTRY)
        self.initial=frame(self.u);self.held=None;self.lock_events=[];self.handoffs=[];self.certificate_attempts=0;self.lookup_pointer=None
        # The parent-input page was already retained by the frozen setup.
        self.pages[REC&~4095]=bytes(self.u.mem_read(REC&~4095,4096))
    def checkpoint(self,label):
        p=self.lookup_pointer
        row={**self.snapshot(label),'parent_record48_hex':bytes(self.u.mem_read(PARENT,48)).hex(),
          'cursor_u64':hex(int.from_bytes(self.u.mem_read(CURSOR,8),'little')),'held_lock_model':None if self.held is None else hex(self.held),
          'visits_so_far':len(self.visits),'models_so_far':len(self.models)}
        if p:
            raw=bytes(self.u.mem_read(p,32));a,b=struct.unpack_from('<QQ',raw,8)
            row.update({'lookup_record':hex(p),'lookup_record32_hex':raw.hex(),
              'lookup_output_addresses':[hex(a),hex(b)],'lookup_output_words':[int.from_bytes(self.u.mem_read(a,4),'little'),int.from_bytes(self.u.mem_read(b,4),'little')]})
        return row
    def code(self,u,pc,n,d):
        self.flush()
        if pc==DONE:
            self.frontier={'reason':'parent_return','CPU':frame(u)};self.parent_return=self.snapshot('parent_return')
            self.parent_return.update({'parent_record48_hex':bytes(u.mem_read(PARENT,48)).hex(),'cursor_u64':hex(int.from_bytes(u.mem_read(CURSOR,8),'little')),
              'held_lock_model':None if self.held is None else hex(self.held)});u.emu_stop();return
        if pc==BASE+0x1cdb24:
            assert self.lookup_pointer is None;self.lookup_pointer=self.reg('x0');self.handoffs.append(self.checkpoint('source_lookup_entry'))
        if pc==BASE+0x8e8520:self.handoffs.append(self.checkpoint('source_lookup_return'))
        if pc==BASE+0x457838:
            r=self.reg('x0');self.handoffs.append({'label':'cleanup_wrapper_entry','CPU':frame(u),'caller_callsite':hex(self.reg('lr')-4-BASE),
              'record':hex(r),'record16_hex':bytes(u.mem_read(r,16)).hex()})
        if pc==BASE+0x1be978:
            r=self.reg('x0');self.handoffs.append({'label':'unlock_helper_entry','CPU':frame(u),'record':hex(r),'record16_hex':bytes(u.mem_read(r,16)).hex(),
              'caller_callsite':hex(self.reg('lr')-4-BASE)})
        name=self.imports.get(pc)
        if name=='_pthread_rwlock_wrlock':
            assert self.held is None;self.held=self.reg('x0');self.lock_events.append({'kind':'declared_acquire','CPU':frame(u),'pointer':hex(self.held),'callsite':hex(self.reg('lr')-4-BASE),'status_u32':0})
        if name=='_pthread_rwlock_unlock'or name=='_malloc'and self.reg('lr')-4-BASE==0x249368:
            args=[self.reg('x'+str(j))for j in range(8)]
            e={'kind':'declared_API','name':name,'before':frame(u),'args_x0_x7':list(map(hex,args)),'callsite':hex(self.reg('lr')-4-BASE),'memory':[]};self.models.append(e)
            if name=='_malloc':assert args[0]==760;self.certificate_attempts+=1;value=0
            else:
                assert e['callsite']=='0x1becc8'and args[0]==self.held;value=self.c['unlock_status_u32']
                self.lock_events.append({'kind':'declared_release','CPU':frame(u),'pointer':hex(args[0]),'callsite':e['callsite'],'status_u32':value})
                if value==0:self.held=None
            e['return_u64']=hex(value);self.returned(value);e['after']=frame(u);return
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=30001);self.flush();assert hasattr(self,'frontier')and not self.once
        assert self.boots==len(self.c['bootstrap_results'])
        return {'configuration':self.c,'initial_CPU':self.initial,'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,'frontier':self.frontier,
          'final_state':self.snapshot('frontier'),'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'allocations_attempted':self.allocs,'metadata_returns':self.metadata_returns,'daemon_children':self.children,'bootstrap_calls':self.boots,
          'handoffs':self.handoffs,'lock_events':self.lock_events,'certificate_allocation_attempts':self.certificate_attempts,'parent_return':self.parent_return}


def main():
    s=Pointers();rows=[];spans={}
    for c in configurations():
        run=Run(s,c);p=run.run();rows.append(p);spans.update(run.functions)
    counts={'profiles':len(rows),**{k:sum(len(p[k])for p in rows)for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children','handoffs','lock_events']},
      'bootstrap_calls':sum(p['bootstrap_calls']for p in rows),'certificate_allocation_attempts':sum(p['certificate_allocation_attempts']for p in rows)}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,'daemon_thin_sha256':SHA(SOURCE.read_bytes()),
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source_spans':list(spans.values()),'declared_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()+parent_inputs()],
      'profiles':rows,'verified_counts':counts,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'corefp_lookup_release_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
