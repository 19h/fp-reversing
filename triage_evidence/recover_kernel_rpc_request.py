#!/usr/bin/env python3
"""Original kext caller and kernel RPC request preparation/copyin/send source.
O(image+source), O(image+source). No native target, IPC, VM, PAC or IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_rpc_request';STARTS=[0xfffffe000bcf5e28,0xfffffe000bcc2390,0xfffffe000bcd0628,0xfffffe000bcf27ac,0xfffffe000bcf258c,0xfffffe000bcf5f18,0xfffffe000bcc0f9c,0xfffffe000bcd9f3c,0xfffffe000c647f10,0xfffffe000bcd00bc,0xfffffe000bd57150,0xfffffe000bcd9e98,0xfffffe000bcd8264,0xfffffe000bd7e9c4]
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_special_reply_source.json').read_text()));old={int(f['start'],16)for f in out['functions']};aa=list(dict.fromkeys([int(f['start'],16)for f in out['functions']]+STARTS));syms=im.k.symbols(aa);fs=[]
 for a in aa:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 out['rpc_request_instruction_roles']={hex(a):{'pc':hex(a),'bytes_hex':im.k.read(a,4).hex(),'mnemonic':(i:=next(im.k.cs.disasm(im.k.read(a,4),a))).mnemonic,'operands':i.op_str}for a in [0xfffffe000bcf5e28,0xfffffe000bcf5a48,0xfffffe000bcf5a6c,0xfffffe000bcf5aa8,0xfffffe000bcf5ad8,0xfffffe000bcf5ae8,0xfffffe000bcf5af0,0xfffffe000bcf5b2c,0xfffffe000bcf5b38,0xfffffe000bcf5b40,0xfffffe000bcf5b88,0xfffffe000bcf5ba8,0xfffffe000bcf5c14,0xfffffe000bcf5c28,0xfffffe000bcf5c44,0xfffffe000bcd015c,0xfffffe000bcd0170,0xfffffe000bcd064c,0xfffffe000bcd0660,0xfffffe000bcc2420,0xfffffe000bcc23b8]}
 out['rpc_zone_entries']=[e for e in json.loads((ROOT/'kernel_zone_startup_source.json').read_text())['zone_startup_entries']if e['name']in ['ipc ports','ipc kmsgs','turnstiles','ipc spaces']]
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_special_reply_source.json','kernel_special_reply_profiles.json','kext_constructor_request_source.json','kext_constructor_request_profiles.json','kernel_zone_startup_source.json','kernel_vm_mig_tools.py']},functions=fs,new_rpc_request_functions=[hex(a)for a in STARTS if a not in old],native_rpc_request_observed=False,**{k:False for k in FLAGS})
 (ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'instructions':sum(len(f['instructions'])for f in fs),'new':len(out['new_rpc_request_functions'])}))
if __name__=='__main__':main()
