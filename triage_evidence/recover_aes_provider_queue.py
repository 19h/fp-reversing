#!/usr/bin/env python3
"""Original provider packing, source configuration and candidate driver handoff.
O(image+symbols+instructions), O(image+captured source); no target operations.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import function
P='aes_provider_queue'
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'aes_command_pool_source.json').read_text());funcs=list(old['functions']);have={int(r['start'],16)for r in funcs};family=next(e for e in k.entries if e['name']=='com.apple.iokit.IOCryptoAcceleratorFamily');hw=next(e for e in k.entries if e['name']=='com.apple.driver.AppleS8000AES')
 for a,e in [(0xfffffe000abff358,family),(0xfffffe000abfd2d8,family),(0xfffffe000abfd4bc,family),(0xfffffe0009d51ad8,hw),(0xfffffe0009d4ead0,hw)]:
  if a not in have:r=function(k,e,a);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 slots=[]
 for name,a in [('candidate_performAES',0xfffffe00082fd878+0x890),('candidate_options',0xfffffe00082fd878+0x8a0),('candidate_quantum',0xfffffe00082fd878+0x8a8),('candidate_queue',0xfffffe00082fd878+0x8d0),('candidate_startCommand',0xfffffe00082fd878+0x8d8),('descriptor_prepare',0xfffffe0007f85d80+0x218),('physical_address',0xfffffe000858a620)]:
  ptr=im.pointer(a);slots.append({'name':name,'pointer':ptr,'exact_symbols':k.symbols([int(ptr['target'],16)])[ptr['target']]})
 a=0xfffffe000abffaf4;out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['aes_command_pool_source.json','aes_command_pool_profiles.json','kernel_vm_mig_tools.py','recover_kext_aes_handoff.py','aes_provider_queue_prior_manifest.json']},'kernel_sha256':k.sha256,'functions':funcs,'additional_slots':slots,'seed_stubs':old['seed_stubs'],'physical_stub':{'start':hex(a),'end':hex(a+16),'bytes_hex':k.read(a,16).hex()},'source_components':{'hardware_configuration':['0xfffffe0009d4f32c','0xfffffe0009d4f340'],'common_limits':['0xfffffe000abfc4ac','0xfffffe000abfc598'],'action_binding':['0xfffffe000abfc598','0xfffffe000abfc644']},'nominal_candidate_vptr':'0xfffffe00082fd878','candidate_vtable_symbols':k.symbols([0xfffffe00082fd868])['0xfffffe00082fd868'],'runtime_candidate_identity_established':False,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(r['instructions'])for r in funcs),'slots':len(slots)}),flush=True)
if __name__=='__main__':main()
