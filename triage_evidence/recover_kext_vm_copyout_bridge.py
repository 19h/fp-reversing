#!/usr/bin/env python3
"""Original kext VM adapter bindings, constructor ranges and kernel consumer bodies.
O(image+source bytes), O(image+source). No native target/IPC/VM or IDB effects.
"""
import json,hashlib
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,IMAGE
from recover_aes_command_gate import sha
P='kext_vm_copyout_bridge'
def main():
 im=Image();old=json.loads((ROOT/'rpc502_vm_handoff_source.json').read_text());out=dict(old);funcs=[]
 for f in old['functions']:
  a=int(f['start'],16);v=im.k.function(a,exact=True);v['exact_symbols']=im.k.symbols([a])[hex(a)];funcs.append(v)
 ranges=[];seen=set()
 for name in ['kext_constructor_request_source.json','kext_constructor_reply_state_source.json']:
  for r in json.loads((ROOT/name).read_text())['ranges']:
   a=int(r['start'],16);z=int(r['end'],16)
   if a>=0xfffffe000b000000 or(a,z)in seen:continue
   seen.add((a,z));b=im.k.read(a,z-a);assert IMAGE.read(a,z-a)==b;ranges.append({'start':hex(a),'end':hex(z),'bytes_hex':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]})
 adapters=[]
 for b in json.loads((ROOT/'kext_port_vm_contracts.json').read_text())['adapters']:
  if b['adapter']not in['0xfffffe000a508e34','0xfffffe000a508e24','0xfffffe000a508e0c','0xfffffe000a508e4c']:continue
  a=int(b['adapter'],16);s=int(b['stub']['start'],16);adapters.append({'adapter':hex(a),'adapter_bytes8_hex':im.k.read(a,8).hex(),'stub_start':hex(s),'stub_bytes16_hex':im.k.read(s,16).hex(),'pointer':im.pointer(int(b['slot'],16)),'target_exact_symbols':im.k.symbols([int(b['target'],16)])[b['target']]})
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in ['rpc502_vm_handoff_source.json','rpc502_reply_copyin_profiles.json','kext_constructor_request_source.json','kext_constructor_reply_state_source.json','kext_port_vm_contracts.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},functions=funcs,kext_ranges=ranges,kext_VM_adapters=adapters);(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'kernel_functions':len(funcs),'kernel_instructions':sum(len(f['instructions'])for f in funcs),'kext_ranges':len(ranges),'kext_instructions':sum(len(f['instructions'])for f in ranges),'adapter_bindings':len(adapters)}),flush=True)
if __name__=='__main__':main()
