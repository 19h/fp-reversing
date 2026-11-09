#!/usr/bin/env python3
"""Original command-pool factory/actions, provider seeding and carrier ABI.
O(image+symbols+instructions), O(image+captured source); no target operations.
"""
import json
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
P='aes_command_pool'
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'workloop_gate_attachment_source.json').read_text());funcs=list(old['functions']);have={int(r['start'],16)for r in funcs}
 for a in [0xfffffe000c520c24,0xfffffe000c52006c,0xfffffe000c51ff48,0xfffffe000c51fe7c,0xfffffe000c51fd90,0xfffffe000c51fcec,0xfffffe000c51fb58,0xfffffe000c4434ec]:
  if a not in have:r=k.function(a,exact=True);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 slots=[]
 for name,a in [('pool_init',0xfffffe0007f40058+0x138),('pool_get',0xfffffe0007f40058+0x148),('pool_return',0xfffffe0007f40058+0x150),('pool_gated_get',0xfffffe0007f40058+0x158),('pool_gated_return',0xfffffe0007f40058+0x160),('pool_meta_alloc',0xfffffe0007f40218+0xa8),('command_new',0xfffffe000858a598),('command_constructor',0xfffffe000858a648),('meta_instanceConstructed',0xfffffe000858a678),('gate_sleep',0xfffffe0007f3fbb0+0x200),('gate_wakeup',0xfffffe0007f3fbb0+0x208)]:
  ptr=im.pointer(a);slots.append({'name':name,'pointer':ptr,'exact_symbols':k.symbols([int(ptr['target'],16)])[ptr['target']]})
 stubs=[]
 for a in [0xfffffe000abff9e4,0xfffffe000abffb44,0xfffffe000abffba4]:stubs.append({'start':hex(a),'end':hex(a+16),'bytes_hex':k.read(a,16).hex()})
 header=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/IOKit/IOCommandPool.h');text=header.read_text();assert 'virtual void returnCommand'in text and 'virtual IOReturn gatedReturnCommand'in text and 'OSPtr<IOCommand> getCommand'in text
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['workloop_gate_attachment_source.json','workloop_gate_attachment_profiles.json','kernel_vm_mig_tools.py','aes_command_pool_prior_manifest.json']},'kernel_sha256':k.sha256,'functions':funcs,'additional_slots':slots,'seed_stubs':stubs,'SDK_reference':{'path':str(header),'sha256':sha(header),'compile_executed':False,'binary_return_ABI_established_from_instructions':True},'pool_metaclass':{'object':'0xfffffe000cb52de0','file_vptr_hex':k.read(0xfffffe000cb52de0,8).hex(),'nominal_vptr':'0xfffffe0007f40218','vtable_exact_symbols':k.symbols([0xfffffe0007f40208])['0xfffffe0007f40208'],'runtime_identity_established':False},'command_vptr':'0xfffffe0008588d98','command_vtable_symbols':k.symbols([0xfffffe0008588d88])['0xfffffe0008588d88'],'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'additional_slots':len(slots)}),flush=True)
if __name__=='__main__':main()
