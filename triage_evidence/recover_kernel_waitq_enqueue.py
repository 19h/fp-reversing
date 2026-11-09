#!/usr/bin/env python3
"""Original port/turnstile initialization, receive assert-wait and enqueue contracts.
O(image+source), O(image+source). No native allocation, blocking, IPC or IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_waitq_enqueue'
STARTS=[0xfffffe000bccd170,0xfffffe000bd682cc,0xfffffe000bd68474,0xfffffe000bd28280,0xfffffe000bd6bc48,0xfffffe000bd69c78,0xfffffe000c48b42c,0xfffffe000bd69354,0xfffffe000bd68d08,0xfffffe000bccece8,0xfffffe000bd69ae8,0xfffffe000bcc83b4,0xfffffe000bcc8514,0xfffffe000bd69f7c]
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_waitq_receiver_source.json').read_text()));starts=[int(f['start'],16)for f in out['functions']]+STARTS;syms=im.k.symbols(starts);funcs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];funcs.append(f)
 sites=[0xfffffe000bccd184,0xfffffe000bccd1a4,0xfffffe000bccd21c,0xfffffe000bd682fc,0xfffffe000bd6831c,0xfffffe000bd68480,0xfffffe000bd68484,0xfffffe000bd684c4,0xfffffe000bcc88cc,0xfffffe000bcc88f0,0xfffffe000bcc8910,0xfffffe000bd28348,0xfffffe000bd28360,0xfffffe000bd69d00,0xfffffe000bd69d0c,0xfffffe000bd6be3c,0xfffffe000bd6be40,0xfffffe000bd6c78c]
 roles={}
 for a in sites:i=next(im.k.cs.disasm(im.k.read(a,4),a));roles[hex(a)]={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
 zs=json.loads((ROOT/'kernel_zone_startup_source.json').read_text());out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_waitq_receiver_source.json','kernel_waitq_receiver_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_zone_startup_source.json','kernel_vm_mig_tools.py','kext_port_tools.py']},functions=funcs,new_enqueue_functions=[hex(a)for a in STARTS],enqueue_instruction_roles=roles,initialization_constants=[{'address':hex(a),'bytes_hex':im.k.read(a,n).hex()}for a,n in[(0xfffffe000700dca8,8),(0xfffffe000700dd68,8),(0xfffffe0007010fe8,48)]],turnstile_zone_spec=next(e for e in zs['zone_startup_entries']if e['identifier_u16']==28),native_wait_enqueue_observed=False,**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'new_functions':len(STARTS)}))
if __name__=='__main__':main()
