#!/usr/bin/env python3
"""Original source for queued constructor request -> receive frontend and header.
O(image+source), O(image+source). No native target, scheduling, IPC, VM or IDB effects.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_request_receive'
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_rpc_request_source.json').read_text()));fs=[]
 for old in out['functions']:
  a=int(old['start'],16);f=im.k.function(a);f['exact_symbols']=im.k.symbols([a])[hex(a)];fs.append(f)
 pcs=[0xfffffe000bcdd530,0xfffffe000bcdd564,0xfffffe000bcc8d54,0xfffffe000bcdd69c,0xfffffe000bcdd6a8,0xfffffe000bcdd6b0,0xfffffe000bcdd6d0,0xfffffe000bcc86e4,0xfffffe000bcc86e8,0xfffffe000bcc86f8,0xfffffe000bcc8758,0xfffffe000bcc875c,0xfffffe000bcc87b0,0xfffffe000bcc87b4,0xfffffe000bcc87d4,0xfffffe000bcdd708,0xfffffe000bcdce04,0xfffffe000bcdcf28,0xfffffe000bcc5564]
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_rpc_request_source.json','kernel_rpc_request_profiles.json','kernel_vm_mig_tools.py']},functions=fs,request_receive_roles={hex(a):{'pc':hex(a),'bytes_hex':im.k.read(a,4).hex(),'mnemonic':(i:=next(im.k.cs.disasm(im.k.read(a,4),a))).mnemonic,'operands':i.op_str}for a in pcs},native_request_receive_observed=False,**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'instructions':sum(len(f['instructions'])for f in fs),'roles':len(pcs)}))
if __name__=='__main__':main()
