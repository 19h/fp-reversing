#!/usr/bin/env python3
"""Original waitq selection/staging, identified-receiver release and thread-state ABI.
O(image+source), O(image+source). No native scheduler, IPC, interrupts or IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_waitq_receiver';STARTS=[0xfffffe000bd6cf80,0xfffffe000bd6c660,0xfffffe000bd6c9dc,0xfffffe000bd6ce44,0xfffffe000bd6cbcc,0xfffffe000bd6d0d4,0xfffffe000bd0bfa4,0xfffffe000bd0c2cc,0xfffffe000be7c458,0xfffffe000be81fa8,0xfffffe000bd26ba8,0xfffffe000bd7e084]
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_kmsg_queue_source.json').read_text()));starts=[*[int(f['start'],16)for f in out['functions']],*STARTS];syms=im.k.symbols(starts);funcs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];funcs.append(f)
 sites=[0xfffffe000bd6c6b0,0xfffffe000bd6ce98,0xfffffe000bd6cea8,0xfffffe000bd6cee8,0xfffffe000bd6cf18,0xfffffe000bd6cc1c,0xfffffe000bd6cc20,0xfffffe000bd6cc34,0xfffffe000bd6ccd8,0xfffffe000bd6cd44,0xfffffe000bd6cd78,0xfffffe000bd6d0b0,0xfffffe000bd6d0b4,0xfffffe000bd6d120,0xfffffe000bd6d144,0xfffffe000bd26c40]
 roles={}
 for a in sites:i=next(im.k.cs.disasm(im.k.read(a,4),a));roles[hex(a)]={'pc':hex(a),'bytes_hex':im.k.read(a,4).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_kmsg_queue_source.json','kernel_kmsg_queue_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_vm_mig_tools.py','kext_port_tools.py']},functions=funcs,waitq_instruction_roles=roles,new_waitq_functions=[hex(a)for a in STARTS],waitq_control_file_bytes=[{'address':hex(a),'bytes_hex':im.k.read(a,n).hex()}for a,n in[(0xfffffe000cb11544,4),(0xfffffe000cb1154c,4),(0xfffffe000cb5c400,4),(0xfffffe000cb0c4c8,4),(0xfffffe000cac74e0,48)]],native_receiver_execution_observed=False,**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'new_functions':len(STARTS)}),flush=True)
if __name__=='__main__':main()
