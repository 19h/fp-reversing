#!/usr/bin/env python3
"""Fresh source recapture and independent saved-caller/status/ownership replay.
O(image+visits+effects+carriers), O(image+journals+private RAM); no native effects.
"""
import json
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_aes_synchronous_wait import Replay
from validate_aes_provider_queue import read,val
P='aes_synchronous_wait';R=0x6500000000;PROV=R+0x10000;GATE=R+0x11000;LOOP=R+0x13000;POOL=R+0x14000;LOCK=R+0x1a000;THREAD=R+0x1b000;PGATE=R+0x1c000;D0=R+0x20000;CMD=R+0x31f00;SP=R+0xf0000
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());external=json.loads((ROOT/'aes_carrier_initialization_profiles.json').read_text());counts=Counter();totals=Counter();records=[]
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
  for k in ['scheduler_effects_executed','authentic_completion_status_established','native_target_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','full_goal_complete']:assert obj[k]is False
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==50 and sum(len(r['instructions'])for r in src['functions'])==4629 and len(src['additional_slots'])==5
 for r in src['functions']:
  a=int(r['start'],16);assert im.k.read(a,int(r['end'],16)-a).hex()==r.get('bytes_hex',r.get('bytes'))and im.k.symbols([a])[r['start']]==r['exact_symbols']
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']and s['exact_symbols']and p['format']==8 and p['auth']==1 and p['key']==0 and p['address_diversity']==1
 rows=prof['cases'];assert len(rows)==12
 for j,row in enumerate(rows):
  c=row['configuration'];writes=row['source_writes'];models=row['API_models'];assert len(row['final_objects'])==49
  for k in ['scheduler_effects_executed','authentic_completion_status_established','native_target_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','full_goal_complete']:assert row[k]is False
  if j==0:assert row['initial_private_fixtures'][:44]==external['cases'][15]['final_objects']and row['external_source_producer']=={'path':'aes_carrier_initialization_profiles.json','case':15};counts['refreshed_source_seed_transfer_checked']=1
  else:assert row['initial_private_fixtures'][:49]==rows[row['source_producer_case']]['final_objects'];counts['source_object_transfers_checked']+=1
  assert all(val(row,R+0x30000+k*0x100+8,4)==1 for k in range(32));counts['source_constructed_base_words_preserved']+=32
  assert val(row,GATE+0x30)==LOOP and val(row,PGATE+0x48)==0
  for mi,m in enumerate(models):
   args=[int(a,16)for a in m['arguments8']];result=int(m['return_value'],16);sym=m['symbol'];expected=[hex(((r+1)*0x123456789abcdef)^(mi+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(result)
   assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(mi+1)&1 else 0)and not m['memory_effects']and m['native_effects_executed']is False
   if sym in ['descriptor_prepare_model','descriptor_complete_no_effect_model']:assert args[:2]==[D0,0]and result==0
   elif sym=='descriptor_physical_address_model':assert args[0]==D0 and result==0x100000
   elif sym=='on_thread_model':assert args[0]==LOOP and result==1
   elif sym in ['close_gate_no_effect_model','open_gate_no_effect_model']:assert args[0]==LOOP and result==0
   elif sym=='opaque_submission_return_no_effect_model':assert j==3 and args[:2]==[PROV,CMD]and result==0x1122334455667788
   elif sym=='kernel_wakeup_no_effect_model':assert j in [5,6]and args[:3]==[CMD,0,0]and result==0
   elif sym=='declared_scheduler_return_no_effect_model':assert j in [7,8,9]and args[:4]==[LOCK,0x10,CMD,0]and result==c['sleep_result']
   else:raise AssertionError(sym)
   counts['API_'+sym]+=1
  if j<3:
   assert not models and row['boundary']['kind']=='after_registration_component'and val(row,POOL+0x10)==CMD
  elif j==3:
   assert row['boundary']['kind']=='before_kernel_sleep'and row['kernel_sleep_frames'][0]['arguments']==[hex(LOCK),'0x10',hex(CMD),'0x0']and len(row['submission_frames'])==1
   assert val(row,LOCK+0x18)==0 and val(row,LOCK+0x20,4)==0 and val(row,GATE+0x48)==0x100 and val(row,POOL+0x10)==R+0x31e00 and val(row,PROV+0x110,1)==1
   clear_depth=next(e for e in writes if e['pc']=='0xfffffe000c519b1c'and e['address']==hex(LOCK+0x20));clear_owner=next(e for e in writes if e['pc']=='0xfffffe000c519b20'and e['address']==hex(LOCK+0x18));assert clear_depth['after_hex']=='00'*4 and clear_owner['after_hex']=='00'*8 and clear_depth['source_visit_index']<clear_owner['source_visit_index']
   ss=row['suspended_stack'];assert ss['address']==row['boundary']['SP']and int(ss['end_exclusive'],16)==SP+24 and len(ss['bytes_hex'])//2==280;counts['source_wait_stack_capture_checked']=1
  elif j in [4,5,6]:
   assert len(row['kernel_wakeup_frames'])==1 and row['kernel_wakeup_frames'][0]['arguments']==[hex(CMD),'0x0','0x0']and val(row,POOL+0x10)==R+0x31e00 and val(row,GATE+0x48)==0x100 and val(row,PROV+0x110,1)==0 and val(row,CMD+0x68)==32 and val(row,CMD+0x78,4)==c['event_status']
   assert sum(m['symbol']=='descriptor_complete_no_effect_model'for m in models)==2 and not row['kernel_sleep_frames'];counts['same_carrier_completion_event_prefixes_checked']+=1
   if j==4:assert row['boundary']['kind']=='before_waitqueue_lookup'and row['wake_count_frames'][0]['arguments'][4]=='0xffffffff';counts['false_wake_count_prefix_checked']=1
   else:assert row['boundary']['kind']=='returned'and row['boundary']['registers31'][0]==hex(PROV)
  elif j in [7,8,9]:
   a=rows[3];assert row['suspended_context_case']==3 and row['entry_registers31']==a['boundary']['registers31']and row['entry_NZCV']==a['boundary']['NZCV']and row['entry_SP']==a['boundary']['SP']and row['entry_PC']=='0xfffffe000bd0c8f4'
   ss=a['suspended_stack'];assert row['initial_private_fixtures'][-1]=={'address':ss['address'],'bytes_hex':ss['bytes_hex']};counts['exact_saved_context_and_stack_resumptions_checked']+=1
   owner=next(e for e in writes if e['pc']=='0xfffffe000c519b3c'and e['address']==hex(LOCK+0x18));depth=next(e for e in writes if e['pc']=='0xfffffe000c519b40'and e['address']==hex(LOCK+0x20));assert owner['after_hex']==THREAD.to_bytes(8,'little').hex()and depth['after_hex']=='03000000'and owner['source_visit_index']<depth['source_visit_index']and val(row,LOCK+0x18)==THREAD and val(row,LOCK+0x20,4)==3
   if j in [7,8]:
    status=0 if j==7 else 0xe00002bc;assert row['boundary']['kind']=='returned'and row['boundary']['registers31'][0]==hex(status)and row['boundary']['SP']==hex(SP)and val(row,CMD+0x78,4)==status and val(row,POOL+0x10)==CMD and val(row,GATE+0x48)==0
    r=next(e for e in row['source_reads']if e['pc']=='0xfffffe000abfd3fc'and e['address']==hex(CMD+0x78));h=next(e for e in writes if e['address']==hex(POOL+0x10));assert depth['source_visit_index']<r['source_visit_index']<h['source_visit_index']and r['size_bytes']==4
    assert not any(int(e['address'],16)<=CMD+0x78<int(e['address'],16)+e['size_bytes']for e in writes);counts['status_read_then_pool_return_then_public_result_checked']+=1
   else:
    assert row['boundary']['kind']=='before_nonzero_sleep_assertion'and val(row,POOL+0x10)==R+0x31e00 and val(row,GATE+0x48)==0x100 and not any(e['pc']=='0xfffffe000abfd3fc'for e in row['source_reads']);counts['nonzero_sleep_assertion_before_reclamation_checked']=1
  elif j==10:assert row['boundary']['kind']=='before_not_owner_assertion'and not row['kernel_sleep_frames']and not models;counts['actual_inGate_precondition_checked']=1
  else:assert j==11 and row['boundary']['kind']=='before_waitqueue_lookup'and row['kernel_wakeup_frames'][0]['arguments']==[hex(CMD),'0x1','0x0']and row['wake_count_frames'][0]['arguments'][4]=='0x1';counts['true_wake_count_prefix_checked']=1
  totals.update(Replay(im,row).run());records.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'raw_final_X0':row['boundary']['registers31'][0]});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=12,functions=50,captured_instructions=4629,additional_slots=5)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','aes_carrier_initialization_profiles.json','validate_aes_provider_queue.py','replay_'+P+'.py','replay_aes_provider_queue.py','replay_aes_command_pool.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'all_checks_pass':True,'scheduler_effects_executed':False,'authentic_completion_status_established':False,'native_target_executed':False,'native_IPC_executed':False,'native_hardware_AES_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
