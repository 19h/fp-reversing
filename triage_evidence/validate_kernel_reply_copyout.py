#!/usr/bin/env python3
"""Recapture original bytes, replay CPU/effects and check an ownership oracle.
O(source bytes+case visits+effect bytes) time, O(profiles+one private map) space.
No native target, VM, IPC, release, map switching or PAC operation is executed.
"""
from collections import Counter
import json
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
from recover_kernel_reply_copyout import recover
from replay_kernel_reply_copyout import Replay
P=0x6500000000;COPY=P+0x68000;DEST=P+0x50000
def main():
 source=json.loads((ROOT/'kernel_reply_copyout_source.json').read_text());assert source==recover();p=json.loads((ROOT/'kernel_reply_copyout_profiles.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_kernel_reply_copyout.py')
 for n,h in p['dependencies'].items():assert sha(ROOT/n)==h
 image=Image();totals=Counter();counts=Counter()
 for j,r in enumerate(p['cases']):
  replayer=Replay(image,r);totals.update(replayer.run());c=r['configuration'];n=c['extent'];label=c['case'];counts[label]+=1;models=r['API_models'];names=[e['symbol']for e in models];initial=next(bytes.fromhex(x['bytes_hex'])for x in r['initial_private_fixtures']if int(x['address'],16)==COPY)
  consumes=(label=='success'and c['consume'])or label=='discard';assert names.count('payload_release_request')==int(consumes)and names.count('copy_header_release_request')==int(consumes)
  assert r['copy_header_hex']==('00'*48 if consumes else initial.hex());assert bytes(replayer.u.mem_read(COPY,48)).hex()==r['copy_header_hex']
  if consumes:
   counts['payload_release_requests']+=1;counts['copy_header_release_requests']+=1
   payload=next(x for x in models if x['symbol']=='payload_release_request');header=next(x for x in models if x['symbol']=='copy_header_release_request')
   assert [int(x,16)for x in payload['arguments8'][:3]]==[0xfffffe0007f8bfb0,P+0x70000,n];assert [int(x,16)for x in header['arguments8'][:4]]==[P+0x60000,P+0x62000,COPY,48]
   clear_pc=0xfffffe000bdc64e8 if label=='discard'else 0xfffffe000bdcbf0c
   clear=[x for x in r['source_writes']if int(x['pc'],16)==clear_pc];assert len(clear)==1 and clear[0]['address']==hex(COPY)and clear[0]['after_hex']=='00'*8 and clear[0]['source_visit_index']<payload['before_source_visit_index']<header['before_source_visit_index']
  if c['kind']=='copyout':
   expected=6 if label=='allocation_error'else 1 if label=='copy_error'else 5 if label=='extent_mismatch'else 0;assert r['return_u32']==expected,(j,expected)
   success=label in ['success','borrowed_success'];assert r['mapped_address']==(DEST if success else 0)
   want=bytes((37*k+17)&255 for k in range(n))+bytes([0xa5])*max(64-n,0)if success else bytes([0xa5])*max(n,64);assert r['mapped_bytes_hex']==want.hex();assert bytes(replayer.u.mem_read(DEST,len(want)))==want
   if success:counts['copied_payload_bytes']+=n
   if label=='copy_error':
    assert names.count('map_range_remove_model')==1;ev=next(e for e in models if e['symbol']=='map_range_remove_model');assert [int(x,16)for x in ev['arguments8'][:3]]==[P+0x3000,DEST,DEST+((n+16383)//16384)*16384];counts['mapping_cleanup_requests']+=1
   else:assert 'map_range_remove_model'not in names
   switch=(not c['same_map'])and label in ['success','borrowed_success','copy_error'];assert names.count('map_switch_leaf_model')==2*int(switch);counts['paired_original_map_contexts']+=int(switch)
   if switch:
    saved=[x for x in r['source_writes']if int(x['pc'],16)==0xfffffe000bdcc340];mode=[x for x in r['source_writes']if int(x['pc'],16)==0xfffffe000bdcc344];assert len(saved)==len(mode)==2 and ''.join(x['after_hex']for x in saved)==(P+0x5000).to_bytes(8,'little').hex()+bytes(8).hex()and ''.join(x['after_hex']for x in mode)==bytes(8).hex()and int(mode[0]['address'],16)==int(saved[0]['address'],16)+16
    counts['hidden_X8_context_records']+=1
  assert r['map_refs']==3 and r['current_map']==hex(P+0x3000 if c['same_map']else P+0x5000);assert r['copy_error_counter']==(8 if label=='copy_error'and not c['same_map']else 7)
 assert len(p['cases'])==42 and counts['payload_release_requests']==counts['copy_header_release_requests']==12 and counts['mapping_cleanup_requests']==8 and counts['paired_original_map_contexts']==counts['hidden_X8_context_records']==12 and counts['copied_payload_bytes']==262300
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_reply_copyout_source.json','kernel_reply_copyout_profiles.json','recover_kernel_reply_copyout.py','replay_kernel_reply_copyout.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py']},'verified_counts':{'cases':len(p['cases']),'functions':len(source['functions']),'captured_instructions':sum(len(f['instructions'])for f in source['functions']),'exact_instruction_roles':len(source['exact_instruction_roles']),**dict(counts)},'independent_A64_replay':dict(totals),'source_recapture_match':True,'all_checks_pass':True,'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'native_release_effects_executed':False,'native_copy_type_established':False,'native_map_switch_executed':False,'hardware_PAC_executed':False,'complete_FairPlay_round_trip_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'kernel_reply_copyout_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
