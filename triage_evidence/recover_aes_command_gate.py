#!/usr/bin/env python3
"""Original AES action registration, gate owner/default-action and dispatch ABI.
O(image bytes+symbols+instructions), O(image+captured source); no target effects.
"""
import hashlib,json
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_aes_handoff import function
P='aes_command_gate'
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 im=Image();k=im.k;e=next(e for e in k.entries if e['name']=='com.apple.iokit.IOCryptoAcceleratorFamily');slots=[]
 specs=[('AES_queueLocked',0xfffffe0008588380+0x8d0),('AES_getWorkLoop',0xfffffe0008588380+0x6b8),('gate_init',0xfffffe0007f3fbb0+0x1d8),('gate_setAction',0xfffffe0007f3fbb0+0x160),('gate_runAction',0xfffffe0007f3fbb0+0x1e8),('gate_runCommand',0xfffffe0007f3fbb0+0x1e0),('loop_addEventSource',0xfffffe0007f3f638+0x160),('loop_closeGate',0xfffffe0007f3f638+0x1a0),('loop_onThread',0xfffffe0007f3f638+0x150),('loop_openGate',0xfffffe0007f3f638+0x198),('gate_factory',0xfffffe000858a5f0),('pool_factory',0xfffffe000858a5f8),('ptmf_conversion',0xfffffe000858a610),('pool_returnCommand',0xfffffe0007f40058+0x150)]
 for name,a in specs:
  ptr=im.pointer(a);slots.append({'name':name,'pointer':ptr,'exact_symbols':k.symbols([int(ptr['target'],16)])[ptr['target']]})
 targets={s['name']:int(s['pointer']['target'],16)for s in slots};assert targets['AES_queueLocked']==0xfffffe000abfd2d8 and targets['AES_getWorkLoop']==0xfffffe000abfcd54 and targets['gate_init']==0xfffffe000c51e6e8
 # Pool class address is independently pinned by the prior handoff capture.
 old=json.loads((ROOT/'kext_aes_handoff_contracts.json').read_text());pool=next(s for s in old['nominal_slots']if s['kind']=='command_pool'and s['offset_from_vptr']==0x150);assert pool['slot']==hex(specs[-1][1])and pool['target']==hex(targets['pool_returnCommand'])
 funcs=[function(k,e,a)for a in [0xfffffe000abfc450,0xfffffe000abfcd54,0xfffffe000abfcb1c]]
 for a in sorted({targets[n]for n in ['gate_factory','gate_init','gate_setAction','gate_runAction','gate_runCommand','loop_addEventSource']}|{0xfffffe000c51bec4}):funcs.append(k.function(a,exact=True))
 for r in funcs:r['exact_symbols']=k.symbols([int(r['start'],16)])[r['start']]
 a=0xfffffe000abffa94;raw=k.read(a,0x50);stubs={'start':hex(a),'end':hex(a+len(raw)),'bytes_hex':raw.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]}
 header=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/IOKit/IOCommandGate.h');h=header.read_text();assert 'runAction'in h and 'runCommand'in h and 'commandGate'in h
 ptr=im.pointer(0xfffffe000858a598);seed={'loop_range':['0xfffffe000abfc71c','0xfffffe000abfc7a0'],'initial_counter':32,'size_argument_bytes':144,'new_stub_start':'0xfffffe000abff9e4','new_stub_bytes_hex':k.read(0xfffffe000abff9e4,16).hex(),'new_pointer':ptr,'new_exact_symbols':k.symbols([int(ptr['target'],16)])[ptr['target']],'object_vptr':'0xfffffe0008588d98','loop_executed':False}
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','recover_kext_aes_handoff.py','kext_aes_handoff_contracts.json','aes_command_gate_prior_manifest.json']},'kernel_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'functions':funcs,'slots':slots,'import_stubs':stubs,'component_registration_range':['0xfffffe000abfc598','0xfffffe000abfc70c'],'SDK_reference':{'path':str(header),'sha256':sha(header),'compile_executed':False},'pool_seed_context':seed,'direct_API_symbols':k.symbols([0xfffffe000bcfeb8c,0xfffffe000c57b280]),'expansion_allocation_view':{'address':'0xfffffe0007e55c58','bytes64_hex':k.read(0xfffffe0007e55c58,64).hex()},'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(r['instructions'])for r in funcs),'slots':len(slots)}),flush=True)
if __name__=='__main__':main()
