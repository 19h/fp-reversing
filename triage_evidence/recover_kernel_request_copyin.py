#!/usr/bin/env python3
"""Original constructor request VM-copy adapter, exported wrapper and factory.
O(image+source), O(image+source). No native kernel, IPC, VM, PAC or IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_request_copyin'
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_rpc_request_source.json').read_text()));aa=list(dict.fromkeys([int(f['start'],16)for f in out['functions']]+[int(f['start'],16)for f in json.loads((ROOT/'rpc502_reply_copyin_source.json').read_text())['functions']]+[0xfffffe000bdd1594,0xfffffe000bdc6bc8]));syms=im.k.symbols(aa);fs=[]
 for a in aa:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 adapter={'adapter':'0xfffffe000a508e2c','adapter_bytes8_hex':im.k.read(0xfffffe000a508e2c,8).hex(),'stub':'0xfffffe000a69f464','stub_bytes16_hex':im.k.read(0xfffffe000a69f464,16).hex(),'pointer':im.pointer(0xfffffe000847c560),'target_symbols':im.k.symbols([0xfffffe000bdd1594])['0xfffffe000bdd1594']}
 pcs=[0xfffffe000bdd1594,0xfffffe000bdd16c8,0xfffffe000bdd183c,0xfffffe000bdd1864,0xfffffe000bdd1e94,0xfffffe000bdd1eb4,0xfffffe000bdd1ef8,0xfffffe000bdd1f0c,0xfffffe000bdd1f18,0xfffffe000bdd1f24,0xfffffe000bdd1f28,0xfffffe000bdd1f2c,0xfffffe000bdd1f38]
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_rpc_request_source.json','kernel_rpc_request_profiles.json','rpc502_reply_copyin_source.json','kernel_copyin_policy_source.json','kext_port_vm_contracts.json','kernel_vm_mig_tools.py']},functions=fs,vm_copyin_adapter=adapter,request_copyin_roles={hex(a):{'pc':hex(a),'bytes_hex':im.k.read(a,4).hex(),'mnemonic':(i:=next(im.k.cs.disasm(im.k.read(a,4),a))).mnemonic,'operands':i.op_str}for a in pcs},copy_policy_file={'address':'0xfffffe0007e6a01c','bytes4_hex':im.k.read(0xfffffe0007e6a01c,4).hex()},copy_zone_file={'address':'0xfffffe000caec2c0','bytes192_hex':im.k.read(0xfffffe000caec2c0,192).hex(),'creation_caller_established':False},**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'instructions':sum(len(f['instructions'])for f in fs),'roles':len(pcs)}))
if __name__=='__main__':main()
