#!/usr/bin/env python3
"""Original quantum carrier/job/descriptor/cache and transfer-consumer interfaces.
O(image+symbols+instructions), O(image+captured source); no target operations.
"""
import json
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import function
P='aes_quantum_binding'
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'aes_hardware_job_source.json').read_text());funcs=list(old['functions']);have={int(r['start'],16)for r in funcs};hw=next(e for e in k.entries if e['name']=='com.apple.driver.AppleS8000AES')
 for a in [0xfffffe0009d4f964,0xfffffe0009d4fcf8,0xfffffe0009d51168]:
  if a not in have:r=function(k,hw,a);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 slots=[]
 for name,a in [('DMA_bind',0xfffffe0007f411f8+0x148),('DMA_clear',0xfffffe0007f411f8+0x150),('DMA_segments',0xfffffe0007f411f8+0x178),('descriptor_operation',0xfffffe0007f85d80+0x148)]:
  p=im.pointer(a);slots.append({'name':name,'pointer':p,'exact_symbols':k.symbols([int(p['target'],16)])[p['target']]})
 headers=[]
 for name in ['IODMACommand.h','IOMemoryDescriptor.h']:
  h=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/IOKit')/name;headers.append({'path':str(h),'sha256':sha(h),'matched_collection_source_revision_established':False})
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['aes_hardware_job_source.json','aes_hardware_job_profiles.json','kernel_vm_mig_tools.py','recover_kext_aes_handoff.py',P+'_prior_manifest.json']},'kernel_sha256':k.sha256,'functions':funcs,'additional_slots':slots,'seed_stubs':old['seed_stubs'],'driver_stubs':old['driver_stubs'],'SDK_references':headers,'native_target_executed':False,'native_IPC_executed':False,'native_DMA_or_cache_effects_executed':False,'native_device_or_crypto_executed':False,'hardware_PAC_executed':False,'runtime_candidate_identity_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(r['instructions'])for r in funcs),'slots':len(slots)}),flush=True)
if __name__=='__main__':main()
