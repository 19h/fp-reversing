#!/usr/bin/env python3
"""Original timer dynamic-zone startup, Mach -91 and shared-set constructor.
Original source/fixups and explicitly modeled raw allocation/runtime epochs;
no native startup, kernel, IPC, scheduler or hardware PAC effects.
"""
import json
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_timer_port_create';CREATE=0xfffffe000bd13314;SENDREF=0xfffffe000bccfc94;CALLBACK=0xfffffe000bd13480;PUBLICATION=0xfffffe0007e64000

def build():
 im=Image();old=json.loads((ROOT/'kernel_root_port_construct_source.json').read_text());zs=json.loads((ROOT/'kernel_zone_startup_source.json').read_text());e=next(e for e in zs['zone_startup_entries']if e['name']=='mk_timer');assert e['requested_size_u64']==168 and e['identifier_u16']==65535 and e['optional_publication_pointer']['target']==hex(PUBLICATION);assert im.k.read(int(e['specification_address'],16),48).hex()==e['specification_bytes48_hex']and im.pointer(int(e['specification_address'],16))==e['optional_publication_pointer']and im.k.read(PUBLICATION,8)==bytes(8)
 starts=sorted({int(f['start'],16)for f in old['functions']+zs['functions']}|{CREATE,SENDREF,CALLBACK});syms=im.k.symbols(starts);fs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 row=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text())['mach_entries'][91];ptr=im.pointer(0xfffffe0007efb010+24*91+8);assert ptr==row['handler_pointer']and ptr['target']==hex(CREATE)and row['returns_port']and row['argument_count']==0
 return{**old,'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['kernel_root_port_construct_source.json','kernel_root_port_construct_profiles.json','kernel_root_port_construct_checks.json','kernel_zone_startup_source.json','kernel_zone_startup_profiles.json','probe_kernel_root_port_construct.py','replay_kernel_root_port_construct.py','probe_kernel_zone_startup.py','replay_kernel_zone_startup.py','kernel_dispatch_contracts.json']},'functions':fs,'timer_startup_specification':e,'timer_trap_binding':row,'timer_publication_file_bytes8_hex':im.k.read(PUBLICATION,8).hex()}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'functions':len(s['functions']),'instructions':sum(len(f['instructions'])for f in s['functions'])}),flush=True)
