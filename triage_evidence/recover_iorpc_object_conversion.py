#!/usr/bin/env python3
"""Original IORPC object/port codecs and IOMachPort registry construction.
O(image+symbols+instructions), O(image+captured source); no native operations.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import definitions
P='iorpc_object_conversion'
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'iorpc_remote_source.json').read_text());out=dict(old);funcs=list(old['functions']);have={int(f['start'],16)for f in funcs}
 for a in [0xfffffe000c56114c,0xfffffe000c561300,0xfffffe000bcf4fa0,0xfffffe000be351d0,0xfffffe000bccfc94,0xfffffe000c444e0c,0xfffffe000c49f41c,0xfffffe000be35a54,0xfffffe000bcf4a5c,0xfffffe000c444fa8]:
  if a not in have:f=k.function(a,exact=True);f['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(f);have.add(a)
 slots=[]
 for name,a in [('node_retain',0xfffffe0007f502d8+0x20),('node_release',0xfffffe0007f502d8+0x28),('node_init',0xfffffe0007f502d8+0xa8),('device_tagged_retain',0xfffffe0007ff24e0+0x48)]:
  p=im.pointer(a);slots.append({'name':name,'pointer':p,'exact_symbols':k.symbols([int(p['target'],16)])[p['target']]})
 gs=[(0xfffffe000cba3ab8,8),(0xfffffe000cb0bc50,4),(0xfffffe000cb53478,32768),(0xfffffe000cb53450,40),(0xfffffe0007f50418,8),(0xfffffe0007e5ca50,8)]
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in ['iorpc_remote_source.json','iorpc_remote_profiles.json','platform_iorpc_profiles.json','aes_platform_gate_profiles.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},functions=funcs,object_conversion_slots=slots,IOMachPort_definitions=definitions(k,['__ZTV10IOMachPort','__ZN10IOMachPort10gMetaClassE']),registry_file_globals=[{'address':hex(a),'size_bytes':n,'bytes_hex':k.read(a,n).hex(),'runtime_epoch_established':False}for a,n in gs],block_constants={'address':'0xfffffe000700dcd0','bytes_hex':k.read(0xfffffe000700dcd0,16).hex()},native_object_port_registry_effects_executed=False,full_goal_complete=False)
 (ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'object_slots':len(slots)}),flush=True)
if __name__=='__main__':main()
