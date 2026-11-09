#!/usr/bin/env python3
"""Original interrupt/job-carrier adapter and conditional completion consumers.
O(image+symbols+instructions), O(image+captured source); no target operations.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import function
P='aes_completion_contract'
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'aes_provider_queue_source.json').read_text());funcs=list(old['functions']);have={int(r['start'],16)for r in funcs};fam=next(e for e in k.entries if e['name']=='com.apple.iokit.IOCryptoAcceleratorFamily');hw=next(e for e in k.entries if e['name']=='com.apple.driver.AppleS8000AES')
 for a,e in [(0xfffffe000abfd174,fam),(0xfffffe000abfd598,fam),(0xfffffe0009d50a28,hw),(0xfffffe0009d5153c,hw),(0xfffffe0009d4f558,hw)]:
  if a not in have:r=function(k,e,a);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 slots=[]
 for name,a in [('candidate_complete_quantum',0xfffffe00082fd878+0x8b0),('candidate_framework_finalize',0xfffffe00082fd878+0x8e0),('descriptor_complete',0xfffffe0007f85d80+0x220),('provider_gate_wakeup',0xfffffe0007f3fbb0+0x208)]:
  p=im.pointer(a);slots.append({'name':name,'pointer':p,'exact_symbols':k.symbols([int(p['target'],16)])[p['target']]})
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['aes_provider_queue_source.json','aes_provider_queue_profiles.json','kernel_vm_mig_tools.py','recover_kext_aes_handoff.py','aes_completion_contract_prior_manifest.json']},'kernel_sha256':k.sha256,'functions':funcs,'additional_slots':slots,'seed_stubs':old['seed_stubs'],'origin_source_sites':{'job_carrier_publication':'0xfffffe0009d50a9c','job_carrier_load':'0xfffffe0009d516bc','job_backlink_clear':'0xfffffe0009d51784','job_pool_return':'0xfffffe0009d51808','framework_complete_quantum_call':'0xfffffe0009d51844','IRQ_completion_branch':'0xfffffe0009d4f628'},'hardware_origin_executed':False,'authentic_completion_status_established':False,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(r['instructions'])for r in funcs),'slots':len(slots)}),flush=True)
if __name__=='__main__':main()
