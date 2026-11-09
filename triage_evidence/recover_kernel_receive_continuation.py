#!/usr/bin/env python3
"""Original block/continuation storage, invocation fragment, trampoline and receive callback.
O(image+source), O(image+source). No native scheduling, key programming, IPC or IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_receive_continuation';STARTS=[0xfffffe000bd28f6c,0xfffffe000bd29140,0xfffffe000bd2a064,0xfffffe000be8b3c4,0xfffffe000bc9c300,0xfffffe000bcc89bc,0xfffffe000bcdd12c,0xfffffe000bccf10c,0xfffffe000be82048]
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_waitq_enqueue_source.json').read_text()));starts=[int(f['start'],16)for f in out['functions']]+STARTS;syms=im.k.symbols(starts);funcs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];funcs.append(f)
 sites=[0xfffffe000bcc8428,0xfffffe000bcc8438,0xfffffe000bd29008,0xfffffe000bd29030,0xfffffe000bd2a09c,0xfffffe000bd2a1d0,0xfffffe000bd2a1e0,0xfffffe000bd2a354,0xfffffe000bd2a35c,0xfffffe000bc9c308,0xfffffe000bc9c314,0xfffffe000bc9c318,0xfffffe000bc9c338,0xfffffe000bc9c380,0xfffffe000bc9c3bc,0xfffffe000bc9c3c8,0xfffffe000bcc8a04,0xfffffe000bcdd140]
 roles={}
 for a in sites:i=next(im.k.cs.disasm(im.k.read(a,4),a));roles[hex(a)]={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_waitq_enqueue_source.json','kernel_waitq_enqueue_profiles.json','kernel_waitq_receiver_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_vm_mig_tools.py','kext_port_tools.py']},functions=funcs,new_continuation_functions=[hex(a)for a in STARTS],continuation_instruction_roles=roles,native_continuation_execution_observed=False,**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'new_functions':len(STARTS)}))
if __name__=='__main__':main()
