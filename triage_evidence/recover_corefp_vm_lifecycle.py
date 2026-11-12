#!/usr/bin/env python3
"""Coherent caller through declared VM effects, ingress/root and cleanup.

Original source produces metadata, VM-buffer fields and protected-root records.
VM allocation/deallocation and void-free residual X0 are declared private API
effects; backing remains mapped for audit. No native API, IPC or IDB mutation.
Replay/enumeration O(C*(B+P*F+V*L+R+N)) time/space upper bound, including
per-page fixup and reaching-load scans; 100000 visits/profile, N=4096 B.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from unicorn import arm64_const as A
from recover_corefp_ingress_callers import Run as Frozen,configurations as previous_configurations,DEPS as PRIOR_DEPS,caller_inputs
from recover_corefp_lookup_initialization import frame,pack,ROOT,BASE,REC,DONE,inputs
from recover_corefp_lookup_release import parent_inputs
from corefp_fixups_reader import Pointers,THIN_SHA
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();ENTRY=0x2e4280;META=0x64000800;VM=0x66000000;N=4096
DEPS=PRIOR_DEPS+['recover_corefp_ingress_callers.py','corefp_ingress_callers_checks.json','corefp_ingress_callers_audit.json']


def configurations():
    base=previous_configurations()[4];rows=[]
    for label,vm,release,free,boots,extra in [
      ('vm_failure',5,0,0,[],{}),('vm_failure_release_error',3,5,0xfeed,[],{}),
      ('primary_null',0,0,0,[{'status_u32':0,'write_port_u32':0x5017}],{}),
      ('lookup_error',0,5,0xfeed,[{'status_u32':5}],{}),
      ('clobber_primary',0,0,0,[{'status_u32':0,'write_port_u32':0x5017}],{'clobber_callers':True}),
      ('payload_16',0,0,0,[{'status_u32':0,'write_port_u32':0x5017}],{'entry_scalar_u32':16,'payload_pattern':True})]:
        rows.append({**base,'label':label,'vm_status_u32':vm,'deallocate_status_u32':release,'free_residual_X0_u64':free,
          'bootstrap_results':boots,**extra})
    return rows


def payload_inputs(c):
    return [(0x63000c00,bytes((37*j+11)&255 for j in range(128)))]if c.get('payload_pattern')else []


class Run(Frozen):
    def __init__(self,s,c):
        super().__init__(s,c);self.u.mem_map(VM,N);self.vm_points=[];self.vm_calls=self.deallocate_calls=self.free_calls=0
        for a,b in payload_inputs(c):self.u.mem_write(a,b)
        self.pages[REC&~4095]=bytes(self.u.mem_read(REC&~4095,4096))
        self.buffer_iterations=self.metadata_iterations=0;self.ingress=None;self.root_record=None
    def vm_point(self,label):
        self.touch(META,32)
        row={'label':label,'CPU':frame(self.u),'visits_so_far':len(self.visits),'models_so_far':len(self.models),
          'metadata32_hex':bytes(self.u.mem_read(META,32)).hex()}
        if self.ingress is not None:
            row.update({'ingress_address':hex(self.ingress),'ingress48_hex':bytes(self.u.mem_read(self.ingress,48)).hex()})
            holder=int.from_bytes(self.u.mem_read(self.ingress+24,8),'little')
            row['ingress_pointer24_holder_word']=hex(int.from_bytes(self.u.mem_read(holder,8),'little'))
        if self.root_record is not None:row.update({'root_record_address':hex(self.root_record),'root_record40_hex':bytes(self.u.mem_read(self.root_record,40)).hex()})
        if self.vm_calls and not self.c['vm_status_u32']:
            self.touch(VM,N);row['VM4096']=pack(bytes(self.u.mem_read(VM,N)))
        self.vm_points.append(row)
    def code(self,u,pc,n,d):
        self.flush();at=pc-BASE;name=self.imports.get(pc)
        if at==0x2e490c:self.ingress=self.reg('x0');self.vm_point('before_ingress_call')
        if at==0x5f48c0:self.root_record=self.reg('x0');self.vm_point('before_root_adapter')
        if at in [0x8e81c8,0x5f48d8,0x2e4910,0x653c70,0x1ca59c,0x1ca8bc,0x1ca8d0,0x653edc,0x654024,0x654034,0x6540ec]:
            self.vm_point({0x8e81c8:'root_entry',0x5f48d8:'before_ingress_result_store',0x2e4910:'ingress_return',0x653c70:'cleanup_entry',
              0x1ca59c:'VM_allocator_return',0x1ca8bc:'before_VM_metadata_publish',0x1ca8d0:'VM_metadata_published',
              0x653edc:'before_buffer_overwrite',0x654024:'before_VM_deallocate',0x654034:'before_metadata_overwrite',0x6540ec:'before_free'}[at])
        if at==0x653f0c:
            self.buffer_iterations+=1
            if self.buffer_iterations==1:self.vm_point('first_buffer_iteration')
        if at==0x654060:
            self.metadata_iterations+=1
            if self.metadata_iterations==1:self.vm_point('first_metadata_iteration')
        if name in ['_vm_allocate','_vm_deallocate','_free']:
            args=[self.reg('x'+str(j))for j in range(8)];call=self.reg('lr')-4-BASE
            e={'kind':'declared_API','name':name,'before':frame(u),'args_x0_x7':list(map(hex,args)),'callsite':hex(call),'memory':[]};self.models.append(e)
            if name=='_vm_allocate':
                assert self.vm_calls==0 and call==0x1ca598 and args[:4]==[self.c['task_port_u32'],0x62017d70,N,1];self.vm_calls+=1
                value=self.c['vm_status_u32']
                if value==0:self.effect(e,args[1],struct.pack('<Q',VM))
            elif name=='_vm_deallocate':
                assert self.deallocate_calls==0 and call==0x654024 and args[:3]==[self.c['task_port_u32'],0 if self.c['vm_status_u32']else VM,0 if self.c['vm_status_u32']else N]
                self.deallocate_calls+=1;value=self.c['deallocate_status_u32']
            else:
                assert self.free_calls==0 and call==0x6540ec and args[0]==META;self.free_calls+=1;value=self.c['free_residual_X0_u64']
            e['return_u64']=hex(value);self.returned(value);e['after']=frame(u);return
        if pc==DONE:self.vm_point('outer_return')
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=100001);self.flush();assert self.frontier['reason']=='parent_return'and not self.once
        assert self.vm_calls==self.deallocate_calls==self.free_calls==1 and self.metadata_iterations==32
        assert self.buffer_iterations==(0 if self.c['vm_status_u32']else N)and self.boots==len(self.c['bootstrap_results'])
        return {'configuration':self.c,'initial_CPU':self.initial,'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,'frontier':self.frontier,
          'final_state':self.snapshot('frontier'),'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'allocations_attempted':self.allocs,'metadata_returns':self.metadata_returns,'daemon_children':self.children,'bootstrap_calls':self.boots,
          'handoffs':self.handoffs,'lock_events':self.lock_events,'certificate_allocation_attempts':self.certificate_attempts,'parent_return':self.parent_return,
          'caller_points':self.caller_points,'metadata_allocation_attempts':self.metadata_allocations,'vm_points':self.vm_points,
          'vm_allocate_calls':self.vm_calls,'vm_deallocate_calls':self.deallocate_calls,'free_calls':self.free_calls,
          'buffer_iterations':self.buffer_iterations,'metadata_iterations':self.metadata_iterations}


def main():
    s=Pointers();rows=[];spans={}
    for c in configurations():
        run=Run(s,c);rows.append(run.run());spans.update(run.functions)
    counts={'profiles':len(rows),'complete_outer_returns':len(rows),'coherent_ingress_calls':sum(not p['configuration']['vm_status_u32']for p in rows),
      **{k:sum(len(p[k])for p in rows)for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children','handoffs','lock_events','caller_points','vm_points']},
      **{k:sum(p[k]for p in rows)for k in ['metadata_allocation_attempts','vm_allocate_calls','vm_deallocate_calls','free_calls','buffer_iterations','metadata_iterations','bootstrap_calls','certificate_allocation_attempts']}}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,'daemon_thin_sha256':SHA(SOURCE.read_bytes()),
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source_spans':list(spans.values()),
      'declared_base_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()+parent_inputs()],
      'profile_caller_inputs':[[{'address':hex(a),'bytes_hex':b.hex()}for a,b in caller_inputs(s,c)]for c in configurations()],
      'profile_payload_inputs':[[{'address':hex(a),'bytes_hex':b.hex()}for a,b in payload_inputs(c)]for c in configurations()],
      'declared_VM_backing':{'address':hex(VM),'size_B':N,'initial_fill_u8':0,'native_allocation':False,'retained_after_declared_deallocation':True},
      'profiles':rows,'verified_counts':counts,'source_PC_gap':False,'restored_parent_frame':False,'root_record_patched':False,
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'corefp_vm_lifecycle_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
