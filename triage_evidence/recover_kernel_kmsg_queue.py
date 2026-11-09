#!/usr/bin/env python3
"""Original kmsg queue admission, receiver handoff, circular enqueue and lock ABI.
O(image+source), O(image+source). No native IPC, queue, thread or IDB effects.
"""
import json
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_kmsg_queue';STARTS=[0xfffffe000bcc7c34,0xfffffe000bccc128,0xfffffe000bd0aecc,0xfffffe000bd0ab18,0xfffffe000bd6c4b0,0xfffffe000bd7e9c4,0xfffffe000bcc2bc4,0xfffffe000bcc4bb4,0xfffffe000bcc2068]
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_kmsg_allocation_source.json').read_text()));out.pop('candidate_kmsg_initialization_record',None);zone_src=json.loads((ROOT/'kernel_zone_startup_source.json').read_text());out['related_fixed_zone_specs']=[e for e in zone_src['zone_startup_entries']if e['identifier_u16']in[22,24]];starts=[*[int(f['start'],16)for f in out['functions']],*STARTS];syms=im.k.symbols(starts);funcs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];funcs.append(f)
 sites=[0xfffffe000bcc7c70,0xfffffe000bcc7c7c,0xfffffe000bcc7ce8,0xfffffe000bcc7cf4,0xfffffe000bcc7d3c,0xfffffe000bcc7df8,0xfffffe000bcc7e68,0xfffffe000bcc7ea4,0xfffffe000bcc7ed0,0xfffffe000bcc7ff8,0xfffffe000bcc8004,0xfffffe000bcc8008,0xfffffe000bcc8020,0xfffffe000bcc8228,0xfffffe000bcc2c24,0xfffffe000bcc2c2c,0xfffffe000bccc16c]
 roles={}
 for a in sites:i=next(im.k.cs.disasm(im.k.read(a,4),a));roles[hex(a)]={'pc':hex(a),'bytes_hex':im.k.read(a,4).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
 sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/message.h');wanted={'MACH_RCV_LARGE','MACH_SEND_TIMED_OUT','MACH_SEND_NO_BUFFER','MACH_RCV_IN_PROGRESS','MACH_RCV_TOO_LARGE','MACH_MSG_TYPE_MOVE_SEND_ONCE','MACH_MSG_TYPE_MOVE_SEND','MACH_SEND_TIMEOUT'};defs=[{'line':j,'text':line}for j,line in enumerate(sdk.read_text().splitlines(),1)if line.startswith('#define')and len(line.split())>1 and line.split()[1]in wanted];assert{e['text'].split()[1]for e in defs}==wanted
 out.update(SDK_message_definitions={'path':str(sdk),'sha256':sha(sdk),'definitions':defs},scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_kmsg_allocation_source.json','kernel_kmsg_allocation_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_task_map_source.json','kernel_zone_startup_source.json','kernel_vm_mig_tools.py','kext_port_tools.py']},functions=funcs,queue_instruction_roles=roles,new_queue_functions=[hex(a)for a in STARTS],native_queue_delivery_observed=False,**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'new_functions':len(STARTS)}),flush=True)
if __name__=='__main__':main()
