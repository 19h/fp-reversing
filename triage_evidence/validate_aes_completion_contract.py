#!/usr/bin/env python3
"""Original-source recapture, independent A64 replay and completion-contract oracles.
O(image+visits+effects+carriers), O(image+journals+private RAM); no native effects.
"""
import json
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_aes_completion_contract import Replay
from validate_aes_provider_queue import read,val
P='aes_completion_contract';R=0x6500000000;PROV=R+0x10000;GATE=R+0x11000;POOL=R+0x14000;PGATE=R+0x1c000;D0=R+0x20000;D1=R+0x21000;CTX=R+0x24000;CMD=R+0x31f00
def pool_count(row):
 sentinel=POOL+0x10;cur=val(row,sentinel);prev=sentinel;seen=set()
 while cur!=sentinel:
  assert cur not in seen and cur in range(R+0x30000,R+0x32000,0x100)
  seen.add(cur);assert val(row,cur+0x18)==prev;prev=cur;cur=val(row,cur+0x10)
 assert val(row,POOL+0x18)==prev
 return len(seen)
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());external=json.loads((ROOT/'aes_provider_queue_profiles.json').read_text());counts=Counter();totals=Counter();records=[]
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
  for k in ['hardware_origin_executed','authentic_completion_status_established','native_target_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','full_goal_complete']:assert obj[k]is False
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==43 and sum(len(r['instructions'])for r in src['functions'])==4256 and len(src['additional_slots'])==4
 ins={}
 for r in src['functions']:
  assert im.k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r.get('bytes_hex',r.get('bytes'))
  assert im.k.symbols([int(r['start'],16)])[r['start']]==r['exact_symbols']
  ins.update({i['ea']:(i['mnemonic'],i['operands'])for i in r['instructions']})
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']and s['exact_symbols']and p['format']==8 and p['auth']==1 and p['key']==0 and p['address_diversity']==1
 static=[('job_carrier_publication','str','x22, [x0, #0x30]'),('job_carrier_load','ldr','x22, [x21, #0x30]'),('job_backlink_clear','str','xzr, [x21, #0x30]'),('job_pool_return','blraa','x9, x17'),('framework_complete_quantum_call','blraa','x8, x16'),('IRQ_completion_branch','b','#0xfffffe0009d5153c')]
 for name,m,o in static:assert ins[src['origin_source_sites'][name]]==(m,o)
 counts['static_origin_sites_checked']=len(static)
 rows=prof['cases'];assert len(rows)==5
 for j,row in enumerate(rows):
  c=row['configuration'];models=row['API_models'];writes=row['source_writes'];visits=row['source_visits'];assert len(row['final_objects'])==49
  for k in ['hardware_origin_executed','authentic_completion_status_established','native_target_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','full_goal_complete']:assert row[k]is False
  origin=row['external_source_producer'];previous=external['cases'][origin['case']]if origin else rows[row['source_producer_case']]
  assert row['initial_private_fixtures'][:49]==previous['final_objects'];counts['source_object_transfers_checked']+=1
  assert val(row,PROV)==0xfffffe00082fd878 and val(row,PGATE+0x48)==0
  assert val(row,PROV+0x100)==PROV+0x100 and val(row,PROV+0x108)==PROV+0x100
  for mi,m in enumerate(models):
   args=[int(a,16)for a in m['arguments8']];result=int(m['return_value'],16);sym=m['symbol'];expected=[hex(((r+1)*0x123456789abcdef)^(mi+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(result)
   assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(mi+1)&1 else 0)and not m['memory_effects']and m['native_effects_executed']is False
   if sym in ['descriptor_prepare_model','descriptor_complete_no_effect_model']:assert args[:2]in [[D0,0],[D1,0]]and result==0
   elif sym=='descriptor_physical_address_model':assert args[0]==D0 and result==0x100000
   elif sym=='on_thread_model':assert args[0]==R+0x13000 and result==1
   elif sym in ['close_gate_no_effect_model','open_gate_no_effect_model']:assert args[0]==R+0x13000 and result==0
   elif sym=='opaque_submission_return_no_effect_model':assert j==0 and args[:2]==[PROV,CMD]and result==0x1122334455667788
   elif sym=='completion_callback_no_effect_model':assert j in [2,3]and args[:2]==[CTX,c['event_status']]and result==0
   else:raise AssertionError(sym)
   counts['API_'+sym]+=1
  if j==0:
   assert c['stage']=='admission'and row['declared_completion_event']is None and row['boundary']['kind']=='returned'and row['boundary']['registers31'][0]=='0x0'
   f=row['submission_return_frames'];assert len(f)==1 and f[0]['declared_return_register']=='0x1122334455667788'and f[0]['AES_result_supplied']is False and f[0]['arguments2']==[hex(PROV),hex(CMD)]
   assert val(row,CMD+0x68)==0 and val(row,CMD+0x70)==32768 and val(row,PROV+0x110,1)==1 and val(row,GATE+0x48)==0 and pool_count(row)==31
   assert not row['completion_callback_frames']and not row['completion_wakeup_frontiers'];counts['separate_admission_return_checked']=1
  else:
   status=c['event_status'];assert row['declared_completion_event']=={'status_u32':hex(status),'field_offset':0x78,'hardware_origin_established':False}and val(row,CMD+0x78,4)==status
   assert any(int(e['address'],16)==CMD+0x78 and e['bytes_hex']==status.to_bytes(4,'little').hex()for e in row['initial_private_fixtures'][49:])
   progress=32768 if j in [1,2]else 65536 if j==3 else 32;assert val(row,CMD+0x68)==progress
   busy=next(e for e in writes if e['pc']=='0xfffffe000abfd18c'and e['address']==hex(PROV+0x110));advance=next(e for e in writes if e['pc']=='0xfffffe000abfd1a0'and e['address']==hex(CMD+0x68));assert busy['source_visit_index']<advance['source_visit_index']and busy['after_hex']=='00'
   assert not any(int(e['address'],16)<=CMD+0x78<int(e['address'],16)+e['size_bytes']for e in writes);counts['declared_status_consumer_cases_checked']+=1
   if j==1:
    assert row['boundary']['kind']=='before_driver_quantum'and len(row['driver_quantum_frontiers'])==1 and not models and pool_count(row)==31 and val(row,PROV+0x110,1)==1
    assert any(e['pc']=='0xfffffe000abfd244'and e['address']==hex(CMD+0x10)for e in writes)and val(row,CMD+0x70)==32768;counts['partial_same_carrier_requeue_checked']=1
   else:
    complete=[m for m in models if m['symbol']=='descriptor_complete_no_effect_model'];assert len(complete)==2 and all(m['arguments8'][:2]==[hex(D0),'0x0']for m in complete)
    assert val(row,PROV+0x110,1)==0;counts['descriptor_completion_roles_checked']+=2
    if j in [2,3]:
     assert row['boundary']['kind']=='returned'and pool_count(row)==32 and val(row,GATE+0x48)==0
     f=row['completion_callback_frames'];assert len(f)==1 and f[0]['arguments2']==[hex(CTX),hex(status)]and f[0]['pool_head_hex']==CMD.to_bytes(8,'little').hex()
     pcs={e['pc']:e['index']if 'index'in e else k for k,e in enumerate(visits)}
     assert pcs['0xfffffe000abfd630']<pcs['0xfffffe000abfd664']<f[0]['before_source_visit_index'] and pcs['0xfffffe000abfd634']<pcs['0xfffffe000abfd664']and pcs['0xfffffe000abfd63c']<pcs['0xfffffe000abfd664']
     assert int(row['boundary']['registers31'][0],16)==PROV;counts['pool_return_before_saved_callback_checked']+=1
    else:
     assert row['boundary']['kind']=='before_completion_wakeup'and pool_count(row)==31 and val(row,GATE+0x48)==0x100 and not row['completion_callback_frames']
     f=row['completion_wakeup_frontiers'];assert len(f)==1 and f[0]['arguments3']==[hex(GATE),hex(CMD),'0x0'];counts['null_callback_deferred_pool_return_checked']=1
  assert not any(e['pc']=='0xfffffe0009d50a28'for e in visits)
  result=Replay(im,row).run();totals.update(result);records.append({'case':j,'configuration':c,'boundary':row['boundary']['kind'],'source_visits':len(visits),'API_models':len(models),'pool_count':pool_count(row),'progress_bytes':val(row,CMD+0x68),'raw_final_X0':row['boundary']['registers31'][0]});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=5,functions=43,captured_instructions=4256,additional_slots=4)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','aes_provider_queue_profiles.json','validate_aes_provider_queue.py','replay_'+P+'.py','replay_aes_provider_queue.py','replay_aes_command_pool.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'all_checks_pass':True,'hardware_origin_executed':False,'authentic_completion_status_established':False,'native_target_executed':False,'native_IPC_executed':False,'native_descriptor_or_DMA_executed':False,'native_workloop_or_lock_effects_executed':False,'native_hardware_AES_executed':False,'hardware_PAC_executed':False,'runtime_candidate_identity_established':False,'actual_kext_key_data_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
