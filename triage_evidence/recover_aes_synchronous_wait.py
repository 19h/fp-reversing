#!/usr/bin/env python3
"""Original AES NULL-callback sleep/wake, workloop and kernel boundary ABI.
O(image+symbols+instructions), O(image+captured source); no target operations.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
P='aes_synchronous_wait'
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'aes_completion_contract_source.json').read_text());funcs=list(old['functions']);have={int(r['start'],16)for r in funcs}
 for a in [0xfffffe000c51e1d4,0xfffffe000c51e19c,0xfffffe000c51c928,0xfffffe000c519a8c,0xfffffe000c519a78,0xfffffe000bd0c8f4,0xfffffe000bd2b480]:
  if a not in have:r=k.function(a,exact=True);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 slots=[]
 for name,a in [('gate_sleep',0xfffffe0007f3fbb0+0x200),('gate_wake',0xfffffe0007f3fbb0+0x208),('loop_inGate',0xfffffe0007f3f638+0x158),('loop_sleep',0xfffffe0007f3f638+0x1b0),('loop_wake',0xfffffe0007f3f638+0x1b8)]:
  p=im.pointer(a);slots.append({'name':name,'pointer':p,'exact_symbols':k.symbols([int(p['target'],16)])[p['target']]})
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['aes_completion_contract_source.json','aes_carrier_initialization_profiles.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},'kernel_sha256':k.sha256,'functions':funcs,'additional_slots':slots,'seed_stubs':old['seed_stubs'],'scheduler_effects_executed':False,'authentic_completion_status_established':False,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(r['instructions'])for r in funcs),'slots':len(slots)}),flush=True)
if __name__=='__main__':main()
