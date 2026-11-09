#!/usr/bin/env python3
"""Original reply-right entry reservation/allocation/publication and lookup source.
O(image+source) time/space. No native namespace, scheduling, IPC or PAC effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_reply_namespace'
STARTS=[0xfffffe000bccffa4,0xfffffe000bccc258,0xfffffe000bcbc0f0,0xfffffe000bcbbff4,0xfffffe000bcbc3a8,0xfffffe000bcd5b90,0xfffffe000bd0af50,0xfffffe000bd0b348,0xfffffe000bccb384,0xfffffe000be57f8c,0xfffffe000bcc92e4]
SITES=[0xfffffe000bcbc074,0xfffffe000bcbc090,0xfffffe000bcbc1a4,0xfffffe000bcbc1b0,0xfffffe000bcbc1c8,0xfffffe000bcbc1e4,0xfffffe000bcbc208,0xfffffe000bcbc218,0xfffffe000bcbc220,0xfffffe000bcc51b0,0xfffffe000bcc5214,0xfffffe000bcd5d50,0xfffffe000bcd5d68,0xfffffe000bcd5d78,0xfffffe000bcc9318,0xfffffe000bcc932c]
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_receive_copyout_source.json').read_text()));old={int(f['start'],16)for f in out['functions']};aa=list(dict.fromkeys([int(f['start'],16)for f in out['functions']]+STARTS));syms=im.k.symbols(aa);fs=[]
 for a in aa:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 roles={}
 for a in SITES:i=next(im.k.cs.disasm(im.k.read(a,4),a));roles[hex(a)]={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
 z=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'][1]
 out['reply_type_policy']={'address':'0xfffffe0007e62ba0','bytes2_hex':im.k.read(0xfffffe0007e62ba0,2).hex()}
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_receive_copyout_source.json','kernel_receive_copyout_profiles.json','kernel_zone_startup_profiles.json','kernel_zone_startup_source.json','kext_constructor_request_profiles.json','kext_constructor_request_source.json','kernel_vm_mig_tools.py']},functions=fs,new_reply_namespace_functions=[hex(a)for a in STARTS if a not in old],reply_namespace_instruction_roles=roles,port_zone_validation_source={'path':'kernel_zone_startup_profiles.json','case':1,'address':'0xfffffe000caec530','bytes8_hex':bytes.fromhex(z['final_zone192_hex'])[0x30:0x38].hex(),'whole_zone_epoch_transferred':False},native_reply_namespace_observed=False,**{k:False for k in FLAGS})
 (ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'instructions':sum(len(f['instructions'])for f in fs),'new_functions':len(out['new_reply_namespace_functions'])}))
if __name__=='__main__':main()
