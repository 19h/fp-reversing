#!/usr/bin/env python3
"""Original reply copyin -> produced copy objects -> copyout/discard closure.
O(image+captured bytes), O(image+source). No native VM/transport or IDB change.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
P='rpc502_vm_handoff'
def main():
 im=Image();names=['rpc502_reply_copyin_source.json','kernel_reply_copyout_source.json','kernel_copyin_policy_source.json'];old=[json.loads((ROOT/n).read_text())for n in names];starts=list(dict.fromkeys(int(f['start'],16)for s in old for f in s['functions']));funcs=[]
 for a in starts:
  f=im.k.function(a,exact=True);f['exact_symbols']=im.k.symbols([a])[hex(a)];funcs.append(f)
 roles={prefix+'_'+n:e for prefix,s in zip(['send','receive','policy'],old,strict=True)for n,e in s.get('exact_instruction_roles',{}).items()}
 for e in roles.values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [*names,'rpc502_reply_copyin_profiles.json','kext_port_vm_contracts.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},'kernel_sha256':im.k.sha256,'functions':funcs,'exact_instruction_roles':roles,'file_environment':[{'address':hex(a),'bytes_hex':im.k.read(a,4).hex()}for a in[0xfffffe0007e6a01c,0xfffffe0007f8b5f0]],'native_target_executed':False,'native_VM_effects_executed':False,'native_retirement_executed':False,'native_namespace_conversion_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'roles':len(roles),'file_environment':out['file_environment']}),flush=True)
if __name__=='__main__':main()
