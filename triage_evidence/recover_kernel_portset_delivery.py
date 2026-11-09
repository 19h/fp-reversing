#!/usr/bin/env python3
"""Original kernel port-set allocation/membership/ready selection and CF pairing.
O(image+source+symbols+cache hashes), O(image+source+symbols). No native IPC,
port-set construction, allocator, scheduling, CF runtime or hardware PAC.
"""
import json
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from recover_cf_source_scheduling import build as cf_build
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_portset_delivery';ALLOC=0xfffffe000bcdb7a4;INSERT=0xfffffe000bcdbcc4;PSET_CREATE=0xfffffe000bcd23ec;LINK=0xfffffe000bd6d744;READY=0xfffffe000bd6d864;SELECT=0xfffffe000bd6bfb0
ADDITIONAL=[ALLOC,INSERT,0xfffffe000bcde264,PSET_CREATE,0xfffffe000bcbc250,0xfffffe000bcdfec8,0xfffffe000bcc936c,0xfffffe000bcd2fbc,0xfffffe000bcc78a8,LINK,READY,SELECT,0xfffffe000bcd2378,0xfffffe000bd0b1f8,0xfffffe000bcbbf50]
def build():
 im=Image();old=json.loads((ROOT/'kernel_request_delivery_source.json').read_text());starts=sorted({int(f['start'],16)for f in old['functions']}|set(ADDITIONAL));syms=im.k.symbols(starts);fs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 tables=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text());traps=[]
 for index in(16,22):
  oldrow=tables['mach_entries'][index];ptr=im.pointer(0xfffffe0007efb010+24*index+8);assert ptr['target']==oldrow['handler_pointer']['target']and ptr['raw']==oldrow['handler_pointer']['raw'];traps.append({'index':index,'signed_selector':-index,'original_name':oldrow['name'],'argument_count':oldrow['argument_count'],'pointer':ptr})
 helpers=[{'address':hex(a),'role':role,'bytes16_hex':im.k.read(a,16).hex()}for a,role in[(0xfffffe000bcfb4f0,'declared_task_name_to_task'),(0xfffffe000bd75c64,'declared_zeroed_raw_pset_storage'),(0xfffffe000bcfefc8,'declared_zeroed_raw_waitq_link')]]
 return{'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['kernel_request_delivery_source.json','kernel_request_delivery_profiles.json','kernel_dispatch_contracts.json','kernel_zone_startup_profiles.json','cf_source_scheduling_source.json','cf_source_scheduling_profiles.json','cf_source_scheduling_checks.json','probe_kernel_request_delivery.py','replay_kernel_request_delivery.py','kernel_vm_mig_tools.py']},'kernel_sha256':im.k.sha256,'functions':fs,'original_trap_bindings':traps,'lower_boundaries':helpers,'CF_source':cf_build(),**{k:False for k in FLAGS}}
if __name__=='__main__':
 out=build();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'kernel_functions':len(out['functions']),'kernel_instructions':sum(len(f['instructions'])for f in out['functions']),'CF_functions':len(out['CF_source']['CF_functions'])}),flush=True)
