#!/usr/bin/env python3
"""Fresh source replay plus independent circular-list/lease/status/gate oracles.
O(image+visits+effects+cases*carriers), O(image+journals+private RAM); no target effects.
"""
import json,struct
from pathlib import Path
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_aes_command_pool import Replay
P='aes_command_pool';RAM=0x6500000000;PROV=RAM+0x10000;GATE=RAM+0x11000;LOOP=RAM+0x13000;POOL=RAM+0x14000;IGATE=RAM+0x18000;PGATE=RAM+0x1c000;PGEXP=RAM+0x1d000;SENTINEL=POOL+0x10;CARRIERS=[RAM+0x30000+0x100*j for j in range(32)]
def read(row,a,n=8):
 e=next(e for e in row['final_objects']if int(e['address'],16)<=a<int(e['address'],16)+len(e['bytes_hex'])//2);b=bytes.fromhex(e['bytes_hex']);o=a-int(e['address'],16);assert o+n<=len(b);return b[o:o+n]
def val(row,a,n=8):return int.from_bytes(read(row,a,n),'little')
def chain(row):
 at=val(row,POOL+0x10);prev=SENTINEL;out=[]
 while at!=SENTINEL:
  assert at in CARRIERS and at not in out and val(row,at+0x18)==prev;out.append(at);prev=at;at=val(row,at+0x10)
 assert val(row,POOL+0x18)==prev;return out
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());external=json.loads((ROOT/'workloop_gate_attachment_profiles.json').read_text());counts=Counter();totals=Counter();summaries=[]
 for obj,name in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  assert all(obj[k]is False for k in ['native_target_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','full_goal_complete'])
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==33 and sum(len(r['instructions'])for r in src['functions'])==2102 and len(src['additional_slots'])==11
 for r in src['functions']:assert im.k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r.get('bytes_hex',r.get('bytes'))and im.k.symbols([int(r['start'],16)])[r['start']]==r['exact_symbols']
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']and s['exact_symbols']and p['format']==8 and p['auth']==1 and p['key']==0 and p['address_diversity']==1
 for s in src['seed_stubs']:assert im.k.read(int(s['start'],16),16).hex()==s['bytes_hex']
 assert sha(Path(src['SDK_reference']['path']))==src['SDK_reference']['sha256']and src['pool_metaclass']['file_vptr_hex']=='00'*8 and im.k.read(0xfffffe000cb52de0,8)==bytes(8)
 rows=prof['cases'];assert len(rows)==38
 for j,row in enumerate(rows):
  c=row['configuration'];stage=c['stage'];models=row['API_models'];ret=int(row['boundary']['registers31'][0],16);free=chain(row);writes=row['source_writes']
  assert len(row['final_objects'])==44
  if j==0:assert row['external_source_producer']=={'path':'workloop_gate_attachment_profiles.json','case':2}and row['source_producer_case']is None and row['initial_private_fixtures'][:10]==external['cases'][2]['final_objects'];counts['external_object_producer_checked']=1
  else:assert row['external_source_producer']is None and row['source_producer_case']<j and row['initial_private_fixtures'][:44]==rows[row['source_producer_case']]['final_objects'];counts['exact_object_transfers_checked']+=1
  for mi,m in enumerate(models):
   args=[int(a,16)for a in m['arguments8']];result=int(m['return_value'],16);effects=m['memory_effects'];sym=m['symbol'];expected=[hex(((r+1)*0x123456789abcdef)^(mi+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(result);assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(mi+1)&1 else 0)and m['native_effects_executed']is False;counts['API_'+sym]+=1
   if sym in ['pool_allocation_model','pool_gate_allocation_model']:
    obj,meta,vptr=(POOL,0xfffffe000cb52de0,0xfffffe0007f40058)if sym=='pool_allocation_model'else(PGATE,0xfffffe000cb52db8,0xfffffe0007f3fbb0);assert j==0 and args[0]==meta and result==obj and len(effects)==1 and effects[0]['address']==hex(obj)and effects[0]['after_hex']==struct.pack('<Q',vptr).hex()
   elif sym=='pool_gate_extension_model':assert j==0 and args[:2]==[0xfffffe0007e55c58,0x8004]and result==PGEXP and not effects
   elif sym=='pool_gate_retain_no_effect_model':assert j==0 and args[0]==PGATE and result==0 and not effects
   elif sym=='command_allocation_model':assert j==1 and args[:2]==[0xfffffe000858a4a8,144]and result in CARRIERS and not effects
   elif sym=='command_base_constructor_model':assert j==1 and args[0]in CARRIERS and args[1]==0xfffffe000cce14e0 and result==args[0]and not effects
   elif sym=='command_class_bookkeeping_model':assert j==1 and args[0]==0xfffffe000cce14e0 and result==0 and not effects
   elif sym=='on_thread_model':assert args[0]==LOOP and result==1 and not effects
   else:assert sym in ['close_gate_no_effect_model','open_gate_no_effect_model']and args[0]==LOOP and result==0 and not effects
  assert val(row,POOL+0x28)==PGATE and val(row,PGATE+0x18)==POOL and val(row,PGATE+0x20)==0 and val(row,PGATE+0x28,1)==1 and val(row,PGATE+0x30)==LOOP and val(row,PGATE+0x40)==PGEXP and val(row,PGEXP)==0 and val(row,IGATE+0x18)==LOOP and val(row,GATE+0x18)==PROV
  assert val(row,GATE+0x10)==PGATE and val(row,PGATE+0x10)==0
  if j==0:
   assert ret==POOL and not free and len(row['maintenance_frames'])==1 and[int(a,16)for a in row['maintenance_frames'][0]['arguments5']]==[LOOP,0,PGATE,0,0];counts['third_gate_source_attachment_checked']=1
  elif j==1:
   assert free==list(reversed(CARRIERS))and len(row['command_allocations'])==32 and [int(e['address'],16)for e in row['command_allocations']]==CARRIERS and row['boundary']['pc']=='0xfffffe000abfc7ac';counts['source_seed_carriers_checked']=32
   for a in CARRIERS:
    assert val(row,a)==0xfffffe0008588d98 and any(e['pc']=='0xfffffe000abfc74c'and e['address']==hex(a)and e['after_hex']==struct.pack('<Q',0xfffffe0008588d98).hex()for e in writes)
  elif j in [2,4]:assert ret==CARRIERS[-1]and free==list(reversed(CARRIERS[:-1]))and read(row,ret+0x10,16)==bytes(16);counts['nonempty_bool_lease_cases_checked']+=1
  elif j==3:assert free==list(reversed(CARRIERS));counts['returned_carrier_cycle_checked']=1
  elif j<=35:
   used=c['ordinal']+1;assert ret==CARRIERS[32-used]and free==list(reversed(CARRIERS[:32-used]))and read(row,ret+0x10,16)==bytes(16);counts['additional_unique_drain_leases_checked']+=1
  elif j==36:assert ret==0 and not free and row['pool_action_statuses'][0]['raw_X0']=='0xe00002be';counts['empty_status_to_NULL_checked']=1
  else:
   assert not free and row['boundary']['kind']=='before_pool_sleep'and val(row,POOL+0x20,4)==1 and row['pool_sleep_frontiers']==[{'pc':'0xfffffe000c51e1d4','before_source_visit_index':len(row['source_visits']),'arguments3':[hex(PGATE),hex(POOL+0x20),'0x0'],'gate48_hex':struct.pack('<Q',0x100).hex()}]and not row['pool_action_statuses'];counts['empty_blocking_sleep_frontier_checked']=1
  assert val(row,POOL+0x20,4)==(1 if j==37 else 0)and val(row,PGATE+0x48)==(0x100 if j==37 else 0)
  for frame in row['pool_frames']:
   args=[int(a,16)for a in frame['arguments5']];assert args[0]==POOL and args[3:]==[0,0]and frame['gate48_hex']==struct.pack('<Q',0x100).hex()
   if frame['pc']=='0xfffffe000c51fcec':assert args[1]in CARRIERS and args[2]==0;counts['gated_return_frames_checked']+=1
   else:assert frame['pc']=='0xfffffe000c51fd90'and RAM<=args[1]<RAM+0x100000 and args[2]==c['block'];counts['gated_get_frames_checked']+=1
  if j!=36:assert all(e['raw_X0']=='0x0'for e in row['pool_action_statuses'])
  assert not row['action_frames']and not any(e['pc']in ['0xfffffe000abfd2d8','0xfffffe000abff358']for e in row['source_visits'])
  totals.update(Replay(im,row).run());summaries.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'free_count':len(free),'free_order':[hex(a)for a in free],'raw_X0':row['boundary']['registers31'][0],'boundary':row['boundary']['pc']});print(json.dumps({'case':j,'fresh_replay':'pass','visits':len(row['source_visits']),'free_count':len(free)}),flush=True)
 assert rows[3]['final_objects']==rows[1]['final_objects']and rows[4]['final_objects']==rows[2]['final_objects'];counts['complete_object_state_pairs_checked']=2
 leased=[int(rows[j]['boundary']['registers31'][0],16)for j in [4,*range(5,36)]];assert leased==list(reversed(CARRIERS))and len(set(leased))==32;counts['ordered_unique_drain_carriers_checked']=32
 counts.update(cases=38,functions=33,captured_instructions=2102,additional_slots=11)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','workloop_gate_attachment_profiles.json','replay_'+P+'.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':summaries,'all_checks_pass':True,'native_target_executed':False,'native_IPC_executed':False,'native_allocator_or_constructor_executed':False,'native_reference_effects_executed':False,'native_workloop_or_lock_effects_executed':False,'native_hardware_AES_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
