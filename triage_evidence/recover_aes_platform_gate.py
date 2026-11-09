#!/usr/bin/env python3
"""Original platform-device cast, service-gates predicate and clock/power ABI.
O(image+symbols+instructions), O(image+captured source); no target operations.
"""
import json
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import function,definitions
P='aes_platform_gate'
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'aes_quantum_binding_source.json').read_text());funcs=list(old['functions']);have={int(r['start'],16)for r in funcs};hw=next(e for e in k.entries if e['name']=='com.apple.driver.AppleS8000AES');platform=next(e for e in k.entries if e['name']=='com.apple.driver.AppleARMPlatform');soc=next(e for e in k.entries if e['name']=='com.apple.driver.AppleT6041')
 for a,e in [(0xfffffe0009d4f650,hw),*[(a,platform)for a in [0xfffffe0008cb33e4,0xfffffe0008cb3894,0xfffffe0008cb39b8,0xfffffe0008cb3ac8,0xfffffe0008cb2d90,0xfffffe0008cb2da0,0xfffffe0008cb2dc0,0xfffffe0008cb3f80]],*[(a,soc)for a in [0xfffffe0009f764ac,0xfffffe0009f76580]]]:
  if a not in have:r=function(k,e,a);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 for a in [0xfffffe000c442080,0xfffffe000c44af9c,0xfffffe000c481304,0xfffffe000c4c79ec]:
  if a not in have:r=k.function(a,exact=True);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 slots=[]
 for name,a in [('ARM_type_import',0xfffffe00082fe678),('data_type_import',0xfffffe00082fe688),('cast_import',0xfffffe00082fe5c8),('ARM_meta_cell',0xfffffe0007ff24c0),('data_meta_cell',0xfffffe0007f89a58),('ARM_get_meta',0xfffffe0007ff24e0+0x38),('data_get_meta',0xfffffe0007f31568+0x38),('string_get_meta',0xfffffe0007f34760+0x38),('device_property',0xfffffe0007ff24e0+0x2d8),('device_clock',0xfffffe0007ff24e0+0x8a8),('device_power',0xfffffe0007ff24e0+0x8b0),('device_psd',0xfffffe0007ff24e0+0x8c8),('controller_clock',0xfffffe0007ff1a68+0x8a8),('controller_power',0xfffffe0007ff1a68+0x8b0),('controller_psd',0xfffffe0007ff1a68+0x8c0),('IOKit_debug',0xfffffe0008013140),('kdebug_enable',0xfffffe00080131a0),('trace_API',0xfffffe0008012e70),('candidate_clock',0xfffffe000838c4e0+0x8a8),('candidate_power',0xfffffe000838c4e0+0x8b0),('candidate_psd',0xfffffe000838c4e0+0x8c0),('candidate_super',0xfffffe000838c4c8)]:
  p=im.pointer(a);slots.append({'name':name,'pointer':p,'exact_symbols':k.symbols([int(p['target'],16)])[p['target']]})
 defs=definitions(k,['__ZN8OSString10gMetaClassE','__ZTV16AppleARMIODevice','__ZTV10AppleARMIO','__ZTV17AppleH16GFamilyIO','__ZN17AppleH16GFamilyIO10superClassE','__ZN10AppleARMIO10gMetaClassE','__ZTV6OSData','__ZTV8OSString']);sm=int(defs['__ZN8OSString10gMetaClassE'][0]['address'],16);adj=[0xfffffe0008cfa1e8,0xfffffe0008cfa2e4,0xfffffe0008cfa5fc,0xfffffe0008cf98e8,0xfffffe0008cf9994,0xfffffe0008cf9b9c]
 stubs=old['driver_stubs']+[{'start':hex(0xfffffe0009d52b74),'end':hex(0xfffffe0009d52b84),'bytes_hex':k.read(0xfffffe0009d52b74,16).hex()}];headers=[]
 h=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/IOKit/IOReturn.h');assert 'iokit_common_err(0x2c7)'in h.read_text();headers.append({'path':str(h),'sha256':sha(h),'matched_collection_source_revision_established':False})
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['aes_quantum_binding_source.json','aes_hardware_job_profiles.json','kernel_vm_mig_tools.py','recover_kext_aes_handoff.py',P+'_prior_manifest.json']},'kernel_sha256':k.sha256,'functions':funcs,'additional_slots':slots,'seed_stubs':old['seed_stubs'],'driver_stubs':stubs,'platform_stubs':[{'start':'0xfffffe0008cff338','end':'0xfffffe0008cff348','bytes_hex':k.read(0xfffffe0008cff338,16).hex()}],'property_key':{'address':'0xfffffe000771cb00','bytes_hex':k.read(0xfffffe000771cb00,14).hex(),'ascii':'service-gates'},'metaclasses':{'ARM':'0xfffffe000cc08988','data':'0xfffffe000cb51a90','string':hex(sm),'data_file_super_hex':k.read(0xfffffe000cb51a90+0x10,8).hex(),'string_file_super_hex':k.read(sm+0x10,8).hex(),'runtime_hierarchy_established':False},'debug_globals':[{'address':hex(a),'file_hex':k.read(a,n).hex(),'size_bytes':n,'runtime_value_established':False}for a,n in [(0xfffffe000caac518,8),(0xfffffe000cb5c400,4)]],'named_definitions':defs,'adjacent_IORPC_symbol_inventory':k.symbols(adj),'SDK_references':headers,'native_target_executed':False,'native_IPC_executed':False,'native_registry_or_platform_effects_executed':False,'hardware_PAC_executed':False,'runtime_device_or_controller_identity_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(r['instructions'])for r in funcs),'slots':len(slots)}),flush=True)
if __name__=='__main__':main()
