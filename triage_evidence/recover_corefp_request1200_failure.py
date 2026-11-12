#!/usr/bin/env python3
"""Cold caller certificate staging through request1200 transport-error cleanup.

All source execution is private. Allocator/free, NDR/task data, once/locks/PAC,
metadata envelopes, sequential CASAL and nonzero mach_msg results are models.
No reply success, entropy, native transport/ownership or IDB mutation supplied.
O(C*(B+F+V+J+R)) time/space; 30000 client visits per profile.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from unicorn import arm64_const as A
from recover_corefp_lookup_release import Run as Frozen,DEPS as PARENT_DEPS,parent_inputs
from recover_corefp_lookup_initialization import frame,ROOT,BASE,BIND,HEAP,inputs
from corefp_fixups_reader import Pointers,THIN_SHA
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();CERT=HEAP+0x400
DEPS=PARENT_DEPS+['recover_corefp_lookup_release.py']


def extra_inputs():return [(BIND+175*16,bytes.fromhex('0000000001000000')),(BIND+82*16,(0x1717).to_bytes(4,'little'))]


def configurations():
    boot=lambda s,p=None:{'status_u32':s,**({'write_port_u32':p}if p is not None else {})}
    rows=[]
    for label,extra in [('primary_invalid_dest',{}),('primary_other_error',{'request1200_status_u32':0x10000004}),
      ('fallback_entropy_frontier',{'bootstrap_results':[boot(1102),boot(0,0x5034)],'continue_atomic_to_entropy':True}),
      ('static_invalid_dest',{'allocation_success':[False,True]}),('clobber_invalid_dest',{'clobber_callers':True}),
      ('unlock_error',{'unlock_status_u32':5})]:
        row={'label':label,'allocation_success':[True,True],'lock_init_status_u32':[0,0],'continue_to_bootstrap':True,
          'bootstrap_results':[boot(0,0x5017)],'unlock_status_u32':0,'request1200_status_u32':0x10000003,**extra}
        if row.get('continue_atomic_to_entropy'):del row['request1200_status_u32']
        rows.append(row)
    return rows


class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c)
        for a,b in extra_inputs():self.u.mem_write(a,b)
        self.certificate_live=False;self.transactions=[];self.certificate_events=[]
    def code(self,u,pc,n,d):
        self.flush();name=self.imports.get(pc);call=self.reg('lr')-4-BASE if name else None
        if pc==BASE+0x8ea868:
            assert self.c.get('continue_atomic_to_entropy')and not self.transactions
            pointer=self.reg('x12');old=int.from_bytes(u.mem_read(pointer,4),'little');compare=self.reg('x8')&0xffffffff;new=self.reg('x11')&0xffffffff
            raw=bytes(u.mem_read(pc,4));assert raw.hex()=='8bfde888'and pointer==BASE+0x1d33108 and old==compare==0x5d96 and new==0xa94ef
            self.visits.append({'pc':'0x8ea868','bytes_hex':raw.hex(),'instruction':'casal w8, w11, [x12]'})
            e={'kind':'declared_sequential_CASAL','visit':len(self.visits)-1,'before':frame(u),'memory':[],'pointer':hex(pointer),
              'old_u32':old,'compare_u32':compare,'replacement_u32':new,'concurrent_ordering_validated':False};self.models.append(e)
            self.effect(e,pointer,new.to_bytes(4,'little'));u.reg_write(A.UC_ARM64_REG_W8,old);u.reg_write(A.UC_ARM64_REG_PC,pc+4);e['after']=frame(u);return
        if name=='_arc4random':
            assert self.c.get('continue_atomic_to_entropy')and not self.transactions
            self.frontier={'reason':'before_fallback_entropy','CPU':frame(u),'callsite':hex(call),'name':name,
              'token4_hex':bytes(u.mem_read(BASE+0x1d33108,4)).hex(),'held_lock_model':None if self.held is None else hex(self.held)}
            self.parent_return=None;u.emu_stop();return
        own=(name=='_malloc'and call==0x249368)or name=='_free'or name=='_mach_msg'and self.reg('x2')==64
        if own:
            args=[self.reg('x'+str(j))for j in range(8)];e={'kind':'declared_API','name':name,'before':frame(u),'args_x0_x7':list(map(hex,args)),'callsite':hex(call),'memory':[]};self.models.append(e);value=0
            if name=='_malloc':
                assert args[0]==760 and self.certificate_attempts==0;self.certificate_attempts+=1;self.certificate_live=True;value=CERT;self.effect(e,CERT,b'\xa5'*760)
                self.certificate_events.append({'kind':'declared_allocate','CPU':frame(u),'pointer':hex(CERT),'size_B':760,'callsite':hex(call)})
            elif name=='_free':
                assert self.certificate_live and args[0]==CERT and call==0x8e9fa8;self.certificate_live=False
                self.certificate_events.append({'kind':'declared_free','CPU':frame(u),'pointer':hex(CERT),'size_B':760,'callsite':hex(call),'allocation760_hex_at_free':bytes(u.mem_read(CERT,760)).hex(),
                  'model':'mark private allocation inactive; retain mapped bytes for evidence; no native free'})
            else:
                assert args[1:7]==[3,64,220,0x5173,0,0]and call==0x8ba8 and not self.transactions and not self.certificate_live
                wire=bytes(u.mem_read(args[0],64));assert struct.unpack_from('<I',wire,20)[0]==1200
                ptr=struct.unpack_from('<Q',wire,28)[0];size=struct.unpack_from('<I',wire,40)[0];assert size==756
                t={'CPU':frame(u),'message_address':hex(args[0]),'request64_hex':wire.hex(),'OOL_address':hex(ptr),'OOL_size_B':size,'OOL756_hex':bytes(u.mem_read(ptr,size)).hex(),
                  'callsite':hex(call),'status_u32':self.c['request1200_status_u32'],'held_lock_model':None if self.held is None else hex(self.held),'native_message_emitted':False}
                self.transactions.append(t);e['transaction_index']=0;value=t['status_u32'];assert value!=0
            e['return_u64']=hex(value);self.returned(value);e['after']=frame(u);return
        return super().code(u,pc,n,d)
    def run(self):
        p=super().run();assert len(self.transactions)==(0 if self.c.get('continue_atomic_to_entropy')else 1)and not self.certificate_live
        p.update({'transactions':self.transactions,'certificate_events':self.certificate_events});return p


def main():
    s=Pointers();rows=[];spans={}
    for c in configurations():
        run=Run(s,c);p=run.run();rows.append(p);spans.update(run.functions)
    counts={'profiles':len(rows),**{k:sum(len(p[k])for p in rows)for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children','handoffs','lock_events','transactions','certificate_events']},
      'bootstrap_calls':sum(p['bootstrap_calls']for p in rows),'certificate_allocation_attempts':sum(p['certificate_allocation_attempts']for p in rows)}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,'daemon_thin_sha256':SHA(SOURCE.read_bytes()),
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source_spans':list(spans.values()),'declared_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()+parent_inputs()+extra_inputs()],
      'profiles':rows,'verified_counts':counts,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'corefp_request1200_failure_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
