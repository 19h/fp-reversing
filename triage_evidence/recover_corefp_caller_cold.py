#!/usr/bin/env python3
"""Coherent upstream caller/VM/ingress to the cold optional-input frontier.

Original instructions produce all intervening records and private buffer data.
Frozen private API/PAC/once/lock/CASAL/entropy/time models are composed with a
callsite-specific certificate-free route. No PC gap, frame restore, record
patch, native API/IPC/target execution or IDB mutation occurs. The next input
read is stopped before execution. O(C*(B+P*F+V*J+R+624)) time/space upper
bound, including frozen page/fixup/reaching-load scans; 100000 visits/profile.
"""
import json
from pathlib import Path
from hashlib import sha256
from recover_corefp_vm_lifecycle import Run as VMRun,configurations as vm_configs,DEPS as VM_DEPS,payload_inputs,VM,N,ENTRY
from recover_corefp_cold_seed import Run as ColdRun,configurations as cold_configs,DEPS as COLD_DEPS
from recover_corefp_request1200_failure import extra_inputs
from recover_corefp_ingress_callers import caller_inputs
from recover_corefp_lookup_release import parent_inputs
from recover_corefp_lookup_initialization import frame,pack,ROOT,BASE,inputs
from corefp_fixups_reader import Pointers,THIN_SHA
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest()
DEPS=list(dict.fromkeys(VM_DEPS+COLD_DEPS+[
 'recover_corefp_vm_lifecycle.py','corefp_vm_lifecycle_checks.json','corefp_vm_lifecycle_audit.json',
 'recover_corefp_cold_seed.py','corefp_cold_seed_checks.json','corefp_cold_seed_audit.json']))
LIST_FIELDS=['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children',
 'handoffs','lock_events','transactions','certificate_events','constructor_points','caller_points','vm_points','flow_points']
SCALAR_FIELDS=['metadata_allocation_attempts','vm_allocate_calls','vm_deallocate_calls','free_calls','buffer_iterations',
 'metadata_iterations','bootstrap_calls','certificate_allocation_attempts','entropy_calls','clock_calls','seed_iterations']


def configurations():
    base={**vm_configs()[2],**cold_configs()[0]}
    return [{**base,'label':label,**extra}for label,extra in [
      ('caller_cold',{}),('caller_cold_clobber',{'clobber_callers':True}),
      ('caller_clock_error',{'time_status_u32':0xffffffff}),
      ('caller_payload_16',{'entry_scalar_u32':16,'payload_pattern':True}),
      ('caller_stack_5a_clock_error',{'stack_fill_u8':0x5a,'time_status_u32':0xffffffff})]]


class Run(VMRun,ColdRun):
    def __init__(self,s,c):super().__init__(s,c);self.flow_points=[]
    def code(self,u,pc,n,d):
        # VMRun owns metadata free, ColdRun owns certificate free. Selection by
        # original callsite prevents a broad symbol-name interception collision.
        if self.imports.get(pc)=='_free'and self.reg('lr')-4-BASE==0x8e9fa8:
            return ColdRun.code(self,u,pc,n,d)
        if pc-BASE in [0x8ea890,0x8ea894,0x8ea8ac,0x8eb7a4,0x8eba0c,0x8eba3c,0x8eba40,0x8eba44]:
            self.flush();self.flow_points.append({'CPU':frame(u),'visits_so_far':len(self.visits),'models_so_far':len(self.models)})
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=100001);self.flush()
        assert self.frontier['reason']=='before_optional_input_word_read'and not self.once
        assert [self.entropy_count,self.clock_count,self.seed_iterations,self.boots]==[3,1,623,2]
        assert not self.transactions and not self.certificate_live and self.parent_return is None
        assert self.vm_calls==self.metadata_allocations==1
        assert self.deallocate_calls==self.free_calls==self.buffer_iterations==self.metadata_iterations==0
        return {'configuration':self.c,'initial_CPU':self.initial,
          'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.visits,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,
          'frontier':self.frontier,'final_state':self.snapshot('frontier'),
          'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'allocations_attempted':self.allocs,'metadata_returns':self.metadata_returns,'daemon_children':self.children,
          'bootstrap_calls':self.boots,'handoffs':self.handoffs,'lock_events':self.lock_events,
          'certificate_allocation_attempts':self.certificate_attempts,'parent_return':self.parent_return,
          'transactions':self.transactions,'certificate_events':self.certificate_events,'constructor_points':self.constructor_points,
          'entropy_calls':self.entropy_count,'clock_calls':self.clock_count,'seed_iterations':self.seed_iterations,
          'caller_points':self.caller_points,'metadata_allocation_attempts':self.metadata_allocations,'vm_points':self.vm_points,
          'vm_allocate_calls':self.vm_calls,'vm_deallocate_calls':self.deallocate_calls,'free_calls':self.free_calls,
          'buffer_iterations':self.buffer_iterations,'metadata_iterations':self.metadata_iterations,'flow_points':self.flow_points}


def main():
    s=Pointers();rows=[];spans={};configs=configurations()
    for c in configs:
        run=Run(s,c);rows.append(run.run());spans.update(run.functions)
    counts={'profiles':len(rows),**{k:sum(len(p[k])for p in rows)for k in LIST_FIELDS},
      **{k:sum(p[k]for p in rows)for k in SCALAR_FIELDS}}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,
      'daemon_thin_sha256':SHA(SOURCE.read_bytes()),'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},
      'source_spans':list(spans.values()),
      'declared_base_inputs':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in inputs()+parent_inputs()+extra_inputs()],
      'profile_caller_inputs':[[{'address':hex(a),'bytes_hex':b.hex()}for a,b in caller_inputs(s,c)]for c in configs],
      'profile_payload_inputs':[[{'address':hex(a),'bytes_hex':b.hex()}for a,b in payload_inputs(c)]for c in configs],
      'initialization_order':['base','parent','certificate_extra','optional_stack_fill','caller','VM_zero_page','payload'],
      'declared_VM_backing':{'address':hex(VM),'size_B':N,'initial_fill_u8':0,'native_allocation':False,'retained_at_frontier':True},
      'certificate_free_model_dispatch':{'callsite':'0x8e9fa8','owner':'frozen_cold_certificate_model'},
      'profiles':rows,'verified_counts':counts,'source_PC_gap':False,'restored_parent_frame':False,'root_record_patched':False,
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'corefp_caller_cold_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
