#!/usr/bin/env python3
"""Original kernel VM MIG registration, selector, receiver and caller ABI.
O(KC bytes+fixups+routines+instructions) time/space. Static source capture;
pre-startup hash state is a model, not native table attestation.
"""
import json
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image,INIT,SELECTOR,STUB,DISPATCH,LEAF,CONVERT,RELEASE,REGISTRY,SUBSYSTEM,HASH,MAXPROBE,COUNT,NDR
FUNCTIONS=[INIT,SELECTOR,STUB,DISPATCH,LEAF,CONVERT,RELEASE,0xfffffe000bcc2104,0xfffffe000c2c45a0,0xfffffe000be2d060]
def recover():
 image=Image();subs=image.subsystems();model=image.hash_model(subs);records=[image.k.function(a)for a in FUNCTIONS];p=subs[0]['routines'][1];assert p['id']==4801 and p['stub']['target']==hex(STUB)and p['reply_size_word1c']==44 and p['reply_descriptor_word18']==0;row=next(x for x in model['insertions']if x['id']==4801);source={}
 for f in records:
  for e in f['instructions']:source[e['ea']]=image.k.read(int(e['ea'],16),4).hex()
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kernel_native_reader.py','resolve_kernel_collection_interfaces.py','daemon_vm_cleanup_contracts.json']},'kernel_sha256':image.k.sha256,'registry':hex(REGISTRY),'subsystem':hex(SUBSYSTEM),'subsystems':subs,'hash_model':model,'message4801':{'routine':p,'initialized_hash_entry':row},'functions':records,'original_exact_symbols':image.k.symbols(FUNCTIONS),'unique_source':source,'NDR':{'address':hex(NDR),'bytes_hex':image.k.read(NDR,8).hex()},'native_target_executed':False,'native_runtime_table_attested':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'kernel_vm_mig_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'subsystems':len(r['subsystems']),'registered_routines':r['hash_model']['inserted_count'],'maximum_probe':r['hash_model']['maximum_probe'],'4801':r['message4801'],'functions':len(r['functions']),'unique_source':len(r['unique_source'])}),flush=True)
