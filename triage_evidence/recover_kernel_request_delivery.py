#!/usr/bin/env python3
"""Original produced request object through receive descriptor and user packing.
O(image+source), O(image+source). No native target, VM, scheduling, IPC or IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_request_delivery'
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_request_copyin_source.json').read_text()));old={int(f['start'],16)for f in out['functions']};aa=list(old)
 aa+= [int(f['start'],16)for f in json.loads((ROOT/'rpc502_vm_handoff_source.json').read_text())['functions']]
 aa+= [int(f['start'],16)for f in json.loads((ROOT/'kernel_user_copyout_contracts.json').read_text())['native_ranges']];aa=list(dict.fromkeys(aa));aa.sort();syms=im.k.symbols(aa);fs=[]
 for a in aa:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 pcs=[0xfffffe000bcc5564,0xfffffe000bcc5698,0xfffffe000bcc56e8,0xfffffe000bcc55b4,0xfffffe000bcc55b8,0xfffffe000bcdcf9c,0xfffffe000bcc6468,0xfffffe000bcc663c,0xfffffe000bcc6670]
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_request_copyin_source.json','kernel_request_copyin_profiles.json','kernel_request_receive_profiles.json','rpc502_vm_handoff_source.json','kernel_user_copyout_contracts.json','kernel_vm_mig_tools.py']},functions=fs,new_request_delivery_functions=[hex(a)for a in aa if a not in old],request_delivery_roles={hex(a):{'pc':hex(a),'bytes_hex':im.k.read(a,4).hex(),'mnemonic':(i:=next(im.k.cs.disasm(im.k.read(a,4),a))).mnemonic,'operands':i.op_str}for a in pcs},**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'instructions':sum(len(f['instructions'])for f in fs),'new_functions':len(out['new_request_delivery_functions'])}))
if __name__=='__main__':main()
