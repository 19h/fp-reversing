#!/usr/bin/env python3
"""Original receive frontend/reference producers, ordinary completion and user copyout.
O(image+source), O(image+source). No native IPC, VM protection or allocator retirement.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_receive_copyout';STARTS=[0xfffffe000bcd0694,0xfffffe000bcdd4e4,0xfffffe000bcc8cf4,0xfffffe000bcd2cc0,0xfffffe000bcca438,0xfffffe000bd0b274,0xfffffe000bc9d5a0,0xfffffe000bcdcc7c,0xfffffe000bcc1344,0xfffffe000bcda458,0xfffffe000bcc4e98,0xfffffe000bcc222c,0xfffffe000bd794c4,0xfffffe000bccd418,0xfffffe000bcca164,0xfffffe000bccf39c,0xfffffe000bcc5564,0xfffffe000bcc62d0,0xfffffe000bcc2868,0xfffffe000c6480c0,0xfffffe000be7798c,0xfffffe000bcce5b8,0xfffffe000bd68a7c]
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_receive_continuation_source.json').read_text()));starts=list(dict.fromkeys([int(f['start'],16)for f in out['functions']]+STARTS));syms=im.k.symbols(starts);funcs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];funcs.append(f)
 sites=[0xfffffe000bcd0728,0xfffffe000bcd073c,0xfffffe000bcc8d64,0xfffffe000bcdd564,0xfffffe000bcdd69c,0xfffffe000bcdd6b0,0xfffffe000bcdce04,0xfffffe000bcce68c,0xfffffe000bd68c0c,0xfffffe000bcca2a4,0xfffffe000bcca2c0,0xfffffe000bcc53dc,0xfffffe000bcc663c,0xfffffe000bcc6708,0xfffffe000bcc67a0]
 roles={}
 for a in sites:i=next(im.k.cs.disasm(im.k.read(a,4),a));roles[hex(a)]={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
 zp=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'][0];out['zone_validation_source']={'path':'kernel_zone_startup_profiles.json','case':0,'address':'0xfffffe000caec6b0','bytes8_hex':bytes.fromhex(zp['final_zone192_hex'])[0x30:0x38].hex(),'whole_zone_epoch_transferred':False}
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_receive_continuation_source.json','kernel_receive_continuation_profiles.json','kernel_waitq_receiver_profiles.json','kernel_waitq_enqueue_profiles.json','kernel_send_right_lifecycle_profiles.json','kernel_namespace_contracts.json','kernel_zone_startup_profiles.json','kernel_zone_startup_source.json','kernel_vm_mig_tools.py','kext_port_tools.py']},functions=funcs,new_copyout_functions=[hex(a)for a in STARTS],copyout_instruction_roles=roles,native_receive_copyout_observed=False,**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'new_functions':len(STARTS)}))
if __name__=='__main__':main()
