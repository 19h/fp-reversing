#!/usr/bin/env python3
"""Original hardware-job pool, IODMA factory/constructor/specification/output ABI.
O(image+symbols+instructions), O(image+captured source); no target operations.
"""
import json
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import function
P='aes_hardware_job'
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'aes_synchronous_wait_source.json').read_text());funcs=list(old['functions']);have={int(r['start'],16)for r in funcs};fam=next(e for e in k.entries if e['name']=='com.apple.iokit.IOCryptoAcceleratorFamily');hw=next(e for e in k.entries if e['name']=='com.apple.driver.AppleS8000AES')
 for a,e in [(0xfffffe000abfcd54,fam),(0xfffffe0009d4e998,hw),(0xfffffe0009d4ea18,hw)]:
  if a not in have:r=function(k,e,a);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 for a in [0xfffffe000c4458c4,0xfffffe000c529b0c,0xfffffe000c529048,0xfffffe000c528c08,0xfffffe000c526b48,0xfffffe000c529dd8]:
  if a not in have:r=k.function(a,exact=True);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 slots=[]
 for name,a in [('job_new',0xfffffe00082fe580),('job_base',0xfffffe00082fe600),('job_bookkeeping',0xfffffe00082fe628),('DMA_factory',0xfffffe00082fe5b0),('inner_pool_factory',0xfffffe00082fe5c0),('segment_output',0xfffffe00082fe670),('DMA_meta_alloc',0xfffffe0007f414f8),('DMA_legacy_init',0xfffffe0007f41338),('DMA_options_init',0xfffffe0007f41398),('DMA_release',0xfffffe0007f411f8+0x28),('provider_workloop',0xfffffe00082fdf30)]:
  p=im.pointer(a);slots.append({'name':name,'pointer':p,'exact_symbols':k.symbols([int(p['target'],16)])[p['target']]})
 stubs=[{'start':hex(a),'end':hex(a+16),'bytes_hex':k.read(a,16).hex()}for a in [0xfffffe0009d52ae4,0xfffffe0009d52be4,0xfffffe0009d52c34,0xfffffe0009d52b44,0xfffffe0009d52b64]]
 h=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/IOKit/IODMACommand.h');text=h.read_text();assert 'struct SegmentOptions'in text and 'UInt64 fIOVMAddr, fLength;'in text and 'OutputLittle64'in text
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['aes_synchronous_wait_source.json','aes_synchronous_wait_profiles.json','kernel_vm_mig_tools.py','recover_kext_aes_handoff.py',P+'_prior_manifest.json']},'kernel_sha256':k.sha256,'functions':funcs,'additional_slots':slots,'seed_stubs':old['seed_stubs'],'driver_stubs':stubs,'job_type_view':{'address':'0xfffffe00082fe528','bytes_hex':k.read(0xfffffe00082fe528,64).hex(),'exact_symbols':k.symbols([0xfffffe00082fe528])['0xfffffe00082fe528']},'DMA_metaclass':{'address':'0xfffffe000cb52ea8','file64_hex':k.read(0xfffffe000cb52ea8,64).hex(),'nominal_vptr':'0xfffffe0007f41450','runtime_identity_established':False},'DMA_zone_cache':{'address':'0xfffffe0007f41438','file_hex':k.read(0xfffffe0007f41438,8).hex(),'runtime_value_established':False},'SDK_reference':{'path':str(h),'sha256':sha(h),'matched_collection_source_revision_established':False,'compile_executed':False},'native_target_executed':False,'native_IPC_executed':False,'native_allocation_or_DMA_executed':False,'hardware_PAC_executed':False,'runtime_candidate_identity_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(r['instructions'])for r in funcs),'slots':len(slots),'stubs':len(stubs)}),flush=True)
if __name__=='__main__':main()
