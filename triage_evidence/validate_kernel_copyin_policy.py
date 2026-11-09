#!/usr/bin/env python3
"""Fresh reference/source recovery, independent CPU replay and policy oracle.
O(text words+candidate paths+visits) time; O(source+profiles+private map) space.
Native runtime/global/boot/map state is not attested by these finite cases.
"""
from collections import Counter
import json
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
from recover_kernel_copyin_policy import recover,G
from replay_kernel_copyin_policy import Replay
def decision(c):
 if c['enforcement']==0:return 0
 if c['owner_present']and c['task_result']=='task'and c['associated_present']:return int(c['associated_bit']and not c['thread_bit'])
 return c['source_bit']
def main():
 source=json.loads((ROOT/'kernel_copyin_policy_source.json').read_text());assert source==recover();p=json.loads((ROOT/'kernel_copyin_policy_profiles.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_kernel_copyin_policy.py')
 for n,h in p['dependencies'].items():assert sha(ROOT/n)==h
 im=Image();counts=Counter();totals=Counter()
 for r in p['cases']:
  replay=Replay(im,r);totals.update(replay.run());c=r['configuration'];counts[r['kind']]+=1
  if r['kind']=='startup':
   want=1 if c['case']=='present1'else 2;assert r['final_policy_u32']==want and int.from_bytes(replay.u.mem_read(G,4),'little')==want
   stores=[x for x in r['source_writes']if int(x['address'],16)==G];assert len(stores)==int(c['case']!='absent')
   for x in stores:assert x['pc']=='0xfffffe000c5e4b38'and x['size_bytes']==4 and x['after_hex']==want.to_bytes(4,'little').hex();counts['startup_global_stores']+=1
   assert len(r['parser_entries'])==1 and not r['API_models'];continue
  need=decision(c);assert c['variant']<=18 or c['owner_present'];assert r['final_policy_u32']==c['enforcement']and not any(int(x['address'],16)==G for x in r['source_writes'])
  owner_calls=sum(x['pc']=='0xfffffe000bd7e9c4'for x in r['source_visits']);assert owner_calls==int(c['enforcement']!=0 and c['owner_present']);counts['original_owner_lookup_entries']+=owner_calls
  if r['kind']=='predicate':assert r['boundary']['kind']=='returned'and r['return_u32']==need
  else:
   expect='policy_range_validation'if need else'buffer_factory';assert r['boundary']['kind']==expect;counts[expect]+=1;assert len(r['API_models'])==need and all(x['symbol']=='map_read_lock_model'for x in r['API_models'])
   if c['enforcement']==2:counts['file_default_'+expect]+=1
 for pred,gate in p['predicate_gate_pairs']:
  a,b=p['cases'][pred],p['cases'][gate];assert a['kind']=='predicate'and b['kind']=='gate'and{n:v for n,v in a['configuration'].items()if n!='kind'}=={n:v for n,v in b['configuration'].items()if n!='kind'}and a['return_u32']==int(b['boundary']['kind']=='policy_range_validation');counts['matched_pairs']+=1
 refs=source['direct_references'];events=[e for r in refs['references']for e in r['events']];assert len(events)==7 and all(e['kind']=='memory'and e['operation']=='read'and e['width_bytes']==4 for e in events)
 assert source['policy_cell']['initial_u32']==2 and source['startup']['parameter_name']=='vm_map_cow_defeatured_enforce'and source['startup']['extent_bytes']==4
 expected={'predicate':54,'original_owner_lookup_entries':64,'gate':54,'buffer_factory':42,'policy_range_validation':12,'file_default_buffer_factory':12,'file_default_policy_range_validation':6,'startup':3,'startup_global_stores':2,'matched_pairs':54};assert counts==expected,dict(counts)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_copyin_policy_source.json','kernel_copyin_policy_profiles.json','recover_kernel_copyin_policy.py','replay_kernel_copyin_policy.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py']},'verified_counts':{'cases':len(p['cases']),'functions':len(source['functions']),'captured_instructions':sum(len(f['instructions'])for f in source['functions']),'instruction_words_scanned':refs['instruction_words'],'ADRP_page_candidates':refs['ADRP_page_candidates'],'direct_reference_groups':len(refs['references']),**dict(counts)},'independent_A64_replay':dict(totals),'source_recapture_match':True,'all_checks_pass':True,'native_target_executed':False,'native_boot_configuration_changed':False,'native_runtime_policy_value_attested':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'complete_FairPlay_round_trip_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'kernel_copyin_policy_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
