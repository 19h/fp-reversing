#!/usr/bin/env python3
"""Original timer arm, expiration header/send and actual set receive interfaces.
Clock/scheduler delivery and inherited runtime contracts remain explicit;
original source bytes only, with no native kernel/IPC/timer/PAC execution.
"""
import json
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_timer_expiration_delivery';ARM=0xfffffe000bd13808;ARMCORE=0xfffffe000bd13824;CALLBACK=0xfffffe000bd13480;SEND=0xfffffe000bcf5754;SCHEDULE=0xfffffe000bd5d120
ADDITIONAL=[ARM,ARMCORE,0xfffffe000bccc3c0,0xfffffe000bcc92e4,0xfffffe000bcd2cc0,SEND]
def build():
 im=Image();old=json.loads((ROOT/'kernel_timer_port_create_source.json').read_text());starts=sorted({int(f['start'],16)for f in old['functions']}|set(ADDITIONAL));syms=im.k.symbols(starts);fs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 row=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text())['mach_entries'][93];assert im.pointer(0xfffffe0007efb010+24*93+8)==row['handler_pointer']and row['handler_pointer']['target']==hex(ARM)and row['argument_count']==2
 return{**old,'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['kernel_timer_port_create_source.json','kernel_timer_port_create_profiles.json','kernel_timer_port_create_checks.json','probe_kernel_timer_port_create.py','replay_kernel_timer_port_create.py','kernel_dispatch_contracts.json']},'functions':fs,'timer_arm_trap_binding':row,'expiration_original_header_constant':{'address':'0xfffffe000700dd10','bytes8_hex':im.k.read(0xfffffe000700dd10,8).hex()},'expiration_lower_boundaries':[{'address':hex(a),'role':role,'original_bytes16_hex':im.k.read(a,16).hex()}for a,role in[(SCHEDULE,'declared scheduler newly queued result0'),(0xfffffe000bcc0f9c,'declared send preflight result0'),(0xfffffe000bcd9f3c,'declared message tag helper result0')]],'timer_scheduler_boundary':{'address':hex(SCHEDULE),'bytes16_hex':im.k.read(SCHEDULE,16).hex()},'timer_counter_read_instruction':{'address':'0xfffffe000bd13980','bytes4_hex':im.k.read(0xfffffe000bd13980,4).hex()},'original_instrumentation_flag4_hex':im.k.read(0xfffffe000cb11544,4).hex()}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'functions':len(s['functions']),'instructions':sum(len(f['instructions'])for f in s['functions'])}),flush=True)
