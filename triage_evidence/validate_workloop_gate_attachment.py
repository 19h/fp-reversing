#!/usr/bin/env python3
"""Fresh A64 replay and independent two-gate/list/thread/predicate oracles.
O(image bytes+visits+effects), O(image+journals+private RAM); no target effects.
"""
import json,struct
from pathlib import Path
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_workloop_gate_attachment import Replay
P='workloop_gate_attachment';RAM=0x6500000000;PROV=RAM+0x10000;GATE=RAM+0x11000;EXP=RAM+0x12000;LOOP=RAM+0x13000;POOL=RAM+0x14000;CMD=RAM+0x15000;WLEXP=RAM+0x17000;IGATE=RAM+0x18000;IEXP=RAM+0x19000;WLLOCK=RAM+0x1a000;THREAD=RAM+0x1b000;MAINT=0xfffffe000c51a604;FLAG=0xfffffe000cb5b6e0
def value(row,a,n=8):
 e=next(e for e in row['final_objects']if int(e['address'],16)<=a<int(e['address'],16)+len(e['bytes_hex'])//2);b=bytes.fromhex(e['bytes_hex']);o=a-int(e['address'],16);return int.from_bytes(b[o:o+n],'little')
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());totals=Counter();counts=Counter();summaries=[];orders=[]
 for obj,n in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)
  for f,h in obj['dependencies'].items():assert sha(ROOT/f)==h
  assert all(obj[n]is False for n in ['native_target_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','full_goal_complete'])
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==25 and sum(len(f['instructions'])for f in src['functions'])==1786 and len(src['additional_slots'])==12
 for r in src['functions']:assert im.k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r.get('bytes_hex',r.get('bytes'))and im.k.symbols([int(r['start'],16)])[r['start']]==r['exact_symbols']
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']and s['exact_symbols']and p['format']==8 and p['auth']==1 and p['key']==0 and p['address_diversity']==1
 for s in src['diagnostic_role_strings']:assert im.k.read(int(s['address'],16),len(bytes.fromhex(s['bytes_hex']))).hex()==s['bytes_hex']and bytes.fromhex(s['bytes_hex']).decode()==s['text']
 for h in src['SDK_headers']:assert sha(Path(h['path']))==h['sha256']
 assert src['feature_flag']['file_byte_hex']=='00'and im.k.read(FLAG,1)==bytes(1)and src['feature_flag']['runtime_value_established']is False and src['gate_metaclass']['file_vptr_hex']=='00'*8 and im.k.read(0xfffffe000cb52db8,8)==bytes(8)
 rows=prof['cases'];assert len(rows)==10
 for j,row in enumerate(rows):
  c=row['configuration'];stage=c['stage'];models=row['API_models'];ret=int(row['boundary']['registers31'][0],16);obj={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in row['final_objects']};visits=row['source_visits'];reads=row['source_reads'];writes=row['source_writes']
  assert len(obj)==10 and row['initial_TPIDR_EL1']==hex(THREAD)and value(row,WLLOCK+0x18)==THREAD and value(row,LOOP+0x10)==WLLOCK
  if row['source_producer_case']is not None:
   producer=row['source_producer_case'];assert producer<j and row['initial_private_fixtures'][:10]==rows[producer]['final_objects'];counts['source_produced_object_transfers_checked']+=1
  for mi,m in enumerate(models):
   args=[int(a,16)for a in m['arguments8']];result=int(m['return_value'],16);effects=m['memory_effects'];sym=m['symbol'];assert sym not in ['attach_gate_model','owner_auxiliary_NULL_model','action_result_model'];expected=[hex(((r+1)*0x123456789abcdef)^(mi+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(result);assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(mi+1)&1 else 0)and m['native_effects_executed']is False;counts['API_'+sym]+=1
   if sym=='gate_extension_allocation_model':assert args[:2]==[0xfffffe0007e55c58,0x8004]and result==(EXP if j==0 else IEXP)and not effects
   elif sym=='internal_gate_allocation_model':assert j==1 and args[0]==0xfffffe000cb52db8 and result==IGATE and len(effects)==1 and effects[0]['address']==hex(IGATE)and effects[0]['after_hex']==struct.pack('<Q',0xfffffe0007f3fbb0).hex()
   elif sym=='source_initialized_gate_factory_model':assert j in [2,7]and args[:2]==[PROV,0]and result==GATE and not effects
   elif sym=='pool_factory_model':assert args[0]==LOOP and result==POOL and not effects
   elif sym in ['close_gate_no_effect_model','open_gate_no_effect_model']:assert args[0]==LOOP and result==0 and not effects
   elif sym=='on_thread_model':assert args[0]==LOOP and result==c['on_thread']and not effects
   else:assert sym in ['retain_no_effect_model','release_no_effect_model']and args[0]==GATE and result==0 and not effects
  if j==0:
   assert ret==1 and value(row,GATE+0x18)==PROV and value(row,GATE+0x20)==0 and value(row,GATE+0x28,1)==1 and value(row,GATE+0x30)==0 and value(row,EXP)==0;assert any(e['pc']=='0xfffffe000c57b2f0'for e in visits)and not any(m['pc']=='0xfffffe000c57b280'for m in models);counts['original_inactive_auxiliary_init_paths_checked']+=1
  elif j<=7:
   assert value(row,IGATE+0x18)==LOOP and value(row,IGATE+0x20)==MAINT and value(row,IGATE+0x28,1)==1 and value(row,IGATE+0x30)==LOOP and value(row,IGATE+0x40)==IEXP and value(row,IEXP)==0 and value(row,LOOP+0x20)==IGATE and value(row,LOOP+0x40)==WLEXP and value(row,LOOP+0x18)==0
   assert value(row,GATE+0x18)==PROV and value(row,GATE+0x20)==0 and value(row,GATE+0x30)==(0 if j in [1,4]else LOOP)and value(row,GATE+0x28,1)==(0 if j in [4,5]else 1)and value(row,WLEXP+8)==(0 if j in [1,4]else GATE)and value(row,GATE+0x10)==0
   assert value(row,IGATE+0x48)==0 and value(row,GATE+0x48)==(0x100 if j==3 else 0)
   if j==1:
    assert row['boundary']['pc']=='0xfffffe000c51b0a8'and any(e['pc']=='0xfffffe000c51b050'and e['address']==hex(LOOP+0x20)and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==IGATE for e in writes);counts['source_internal_gate_publications_checked']+=1
   elif j in [2,7]:assert row['boundary']['pc']=='0xfffffe000abfc70c'and value(row,PROV+0xf0)==0xfffffe000abfd2d8 and value(row,PROV+0xb8)==GATE and value(row,PROV+0xf8)==POOL
   elif j==3:assert row['boundary']['kind']=='before_queue_action'and len(row['action_frames'])==1 and[int(a,16)for a in row['action_frames'][0]['arguments8'][:5]]==[PROV,CMD,0,0,0];counts['source_attached_outer_dispatches_checked']+=1
   else:assert row['boundary']['kind']=='returned'and ret==0
   if j!=3:
    assert len(row['maintenance_frames'])==1;f=row['maintenance_frames'][0];assert[int(a,16)for a in f['arguments5']]==[LOOP,1 if j==4 else 0,IGATE if j==1 else GATE,0,0]and f['inner_gate48_hex']==struct.pack('<Q',0x100).hex();counts['two_gate_maintenance_handoffs_checked']+=1
   if j in [2,5,7]:
    retain=next(m for m in models if m['symbol']=='retain_no_effect_model');setloop=next(e for e in writes if e['address']==hex(GATE+0x30)and e['pc']=='0xfffffe000c51e868');publish=next(e for e in writes if e['address']==hex(WLEXP+8));assert retain['before_source_visit_index']<setloop['source_visit_index']<publish['source_visit_index']and int.from_bytes(bytes.fromhex(publish['after_hex']),'little')==GATE;orders.append({'case':j,'retain_before_source_visit':retain['before_source_visit_index'],'set_workloop_store':setloop,'list_store':publish});counts['retain_setloop_list_publication_orders_checked']+=1
   if j==4:
    unpublish=next(e for e in writes if e['address']==hex(WLEXP+8));clear=next(e for e in writes if e['address']==hex(GATE+0x30)and e['pc']=='0xfffffe000c51e9a4');release=next(m for m in models if m['symbol']=='release_no_effect_model');assert unpublish['source_visit_index']<clear['source_visit_index']<release['before_source_visit_index']and unpublish['after_hex']=='00'*8 and clear['after_hex']=='00'*8;assert row['system_context_reads']==[{'pc':'0xfffffe000c51a398','source_visit_index':row['system_context_reads'][0]['source_visit_index'],'TPIDR_EL1':hex(THREAD)}];assert any(e['address']==hex(WLLOCK+0x18)and int.from_bytes(bytes.fromhex(e['bytes_hex']),'little')==THREAD for e in reads);counts['unlink_clear_release_and_thread_checks']=1
  else:assert ret==0 and not models and not row['maintenance_frames']and any(e['address']==hex(FLAG)and e['bytes_hex']==format(c['feature_byte'],'02x')for e in reads);counts['inactive_nonzero_flag_cases_checked']+=1
  assert not any(e['pc']=='0xfffffe000abfd2d8'for e in visits)
  totals.update(Replay(im,row).run());summaries.append({'case':j,'configuration':c,'source_visits':len(visits),'API_models':len(models),'boundary':row['boundary']['pc'],'raw_X0':row['boundary']['registers31'][0]});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 assert rows[6]['final_objects']==rows[2]['final_objects']and not any(m['symbol']in ['retain_no_effect_model','release_no_effect_model']for m in rows[6]['API_models']);counts['duplicate_add_object_identity_checks']=1
 assert rows[7]['final_objects']==rows[2]['final_objects'];counts['on_thread_pair_final_object_checks']=1
 counts.update(cases=10,functions=25,captured_instructions=1786,additional_slots=12)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','replay_'+P+'.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':summaries,'attachment_publication_orders':orders,'all_checks_pass':True,'native_target_executed':False,'native_IPC_executed':False,'native_allocator_executed':False,'native_reference_effects_executed':False,'native_workloop_or_lock_effects_executed':False,'native_hardware_AES_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
