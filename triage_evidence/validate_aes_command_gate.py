#!/usr/bin/env python3
"""Original-byte recapture, fresh A64 replay and independent interface oracles.
O(image bytes+visits+effects), O(image+source journals+RAM); no native effects.
"""
import json,struct
from collections import Counter
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_aes_command_gate import Replay
P='aes_command_gate';RAM=0x6500000000;PROV=RAM+0x10000;GATE=RAM+0x11000;EXP=RAM+0x12000;LOOP=RAM+0x13000;POOL=RAM+0x14000;CMD=RAM+0x15000;ACTION=0xfffffe000abfd2d8
def value(row,a,n=8):
 e=next(e for e in row['final_objects']if int(e['address'],16)<=a<int(e['address'],16)+len(e['bytes_hex'])//2);b=bytes.fromhex(e['bytes_hex']);o=a-int(e['address'],16);return int.from_bytes(b[o:o+n],'little')
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());counts=Counter();totals=Counter();summaries=[]
 for obj,name in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
  assert all(obj[n]is False for n in ['native_target_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','full_goal_complete'])
 seed=src['pool_seed_context'];ptr=seed['new_pointer'];assert im.pointer(int(ptr['slot'],16))==ptr and im.k.symbols([int(ptr['target'],16)])[ptr['target']]==seed['new_exact_symbols']and im.k.read(0xfffffe000abff9e4,16).hex()==seed['new_stub_bytes_hex']and seed['initial_counter']==32 and seed['size_argument_bytes']==144 and seed['loop_executed']is False
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==10 and sum(len(r['instructions'])for r in src['functions'])==859 and len(src['slots'])==14
 for r in src['functions']:assert im.k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r.get('bytes_hex',r.get('bytes'))and im.k.symbols([int(r['start'],16)])[r['start']]==r['exact_symbols']
 words={int(i['ea'],16):(i['mnemonic'],i['operands'])for r in src['functions']for i in r['instructions']}
 for a,expected in {0xfffffe000abfc704:('mov','w25, #0x20'),0xfffffe000abfc720:('mov','w1, #0x90'),0xfffffe000abfc724:('bl','#0xfffffe000abff9e4'),0xfffffe000abfc798:('subs','w25, w25, #1'),0xfffffe000abfc79c:('b.ne','#0xfffffe000abfc71c')}.items():assert words[a]==expected
 counts['pool_seed_control_instructions_checked']=5
 for s in src['slots']:
  ptr=s['pointer'];assert im.pointer(int(ptr['slot'],16))==ptr and ptr['format']==8 and ptr['auth']==1 and ptr['key']==0 and ptr['address_diversity']==1 and im.k.symbols([int(ptr['target'],16)])[ptr['target']]==s['exact_symbols']and s['exact_symbols']
 assert im.k.read(0xfffffe000abffa94,0x50).hex()==src['import_stubs']['bytes_hex']and sha(Path(src['SDK_reference']['path']))==src['SDK_reference']['sha256']
 view=src['expansion_allocation_view'];assert im.k.read(int(view['address'],16),64).hex()==view['bytes64_hex']and struct.unpack_from('<I',bytes.fromhex(view['bytes64_hex']),44)[0]==8
 assert im.k.symbols([0xfffffe000bcfeb8c,0xfffffe000c57b280])==src['direct_API_symbols']and src['direct_API_symbols']['0xfffffe000c57b280']==[]
 rows=prof['cases'];assert len(rows)==9
 for j,row in enumerate(rows):
  c=row['configuration'];models=row['API_models'];stage=c['stage'];ret=int(row['boundary']['registers31'][0],16)
  if j:
   producer=0 if j==1 else 1;assert row['source_producer_case']==producer and row['initial_private_fixtures'][:6]==rows[producer]['final_objects'];counts['source_produced_object_transfers_checked']+=1
  else:assert row['source_producer_case']is None
  for mi,m in enumerate(models):
   args=[int(a,16)for a in m['arguments8']];result=int(m['return_value'],16);effects=m['memory_effects'];sym=m['symbol'];expected=[hex(((r+1)*0x123456789abcdef)^(mi+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(result);assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(mi+1)&1 else 0)and m['native_effects_executed']is False;counts['API_'+sym]+=1
   if sym=='expansion_allocation_model':assert args[:2]==[0xfffffe0007e55c58,0x8004]and result==EXP and not effects
   elif sym=='owner_auxiliary_NULL_model':assert args[0]==PROV and result==0 and not effects
   elif sym=='source_initialized_gate_factory_model':assert args[:2]==[PROV,0]and result==GATE and not effects and j==1
   elif sym=='attach_gate_model':assert args[:2]==[LOOP,GATE]and result==0 and len(effects)==1 and effects[0]['address']==hex(GATE+0x30)and effects[0]['before_hex']=='00'*8 and effects[0]['after_hex']==struct.pack('<Q',LOOP).hex()
   elif sym=='pool_factory_model':assert args[0]==LOOP and result==POOL and not effects
   elif sym in ['close_gate_no_effect_model','open_gate_no_effect_model']:assert args[0]==LOOP and result==0 and not effects
   elif sym=='on_thread_model':assert args[0]==LOOP and result==c['on_thread']and not effects
   else:assert sym=='action_result_model'and args[:5]==[PROV,CMD,0,0,0]and result==c['action_result']and not effects
  assert value(row,GATE+0x18)==PROV and value(row,GATE+0x20)==0 and value(row,GATE+0x28,1)==1 and value(row,GATE+0x40)==EXP and value(row,EXP)==0
  if j==0:
   assert ret==1 and value(row,GATE+0x30)==0 and any(e['pc']=='0xfffffe000c51bee0'and e['address']==hex(GATE+0x18)and e['after_hex']==struct.pack('<Q',PROV).hex()for e in row['source_writes'])and any(e['pc']=='0xfffffe000c51be3c'and e['address']==hex(GATE+0x20)and e['after_hex']=='00'*8 for e in row['source_writes'])
   assert any(e['pc']=='0xfffffe000c51bf10'and e['address']==hex(GATE+0x28)and e['after_hex']=='01'for e in row['source_writes']);counts['source_owner_default_enable_publications_checked']+=3
  else:
   assert value(row,PROV+0xf0)==ACTION and value(row,PROV+0xb8)==GATE and value(row,PROV+0xf8)==POOL and value(row,PROV+0xc0)==LOOP and value(row,GATE+0x30)==(0 if c.get('no_loop')else LOOP)
  if j==1:
   for pc,offset,result in [(0xfffffe000abfc640,0xf0,ACTION),(0xfffffe000abfc654,0xb8,GATE),(0xfffffe000abfc708,0xf8,POOL)]:assert any(e['pc']==hex(pc)and e['address']==hex(PROV+offset)and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==result for e in row['source_writes']);counts['source_provider_publications_checked']+=1
   assert row['boundary']['pc']=='0xfffffe000abfc70c'and not any(m['symbol']=='ptmf_conversion_model'for m in models)
   auth={e['pc']:e for e in row['logical_authentication']};assert int(auth['0xfffffe000abfc5c8']['registers18'][17],16)==(0xfffffe0008588c50&0x0000ffffffffffff)|(0x1430<<48);assert int(auth['0xfffffe000abfc5e4']['registers18'][17],16)==0xbd41;counts['virtual_to_action_domain_transitions_checked']+=1
  elif 2<=j<=5:
   assert len(row['action_frames'])==1;frame=row['action_frames'][0];assert[int(a,16)for a in frame['arguments8'][:5]]==[PROV,CMD,0,0,0]and frame['gate48_hex']==struct.pack('<Q',0x100).hex()and frame['return_pc']=='0xfffffe000c51e4fc';counts['owner_and_four_arguments_checked']+=1
   if j<=3:assert row['boundary']['kind']=='before_queue_action'and value(row,GATE+0x48)==0x100 and [m['symbol']for m in models]==['close_gate_no_effect_model','on_thread_model']
   else:assert row['boundary']['kind']=='returned'and ret==c['action_result']and value(row,GATE+0x48)==0 and [m['symbol']for m in models]==['close_gate_no_effect_model','on_thread_model','action_result_model','open_gate_no_effect_model'];counts['balanced_return_continuations_checked']+=1
  elif j>=6:assert ret==(0xe00002d8 if j==7 else 0xe00002c2)and not models and not row['action_frames']and value(row,GATE+0x48)==0;counts['default_or_missing_input_returns_checked']+=1
  # No source instruction from the queue action or hardware/provider AES body executes.
  assert not any(e['pc']in ['0xfffffe000abfd2d8','0xfffffe000abff358']for e in row['source_visits'])
  for e in row['source_reads']+row['source_writes']:
   a=int(e['address'],16)
   if EXP<=a<EXP+0x40:assert a+e['size_bytes']<=EXP+8
  totals.update(Replay(im,row).run());summaries.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'raw_X0':row['boundary']['registers31'][0]});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=9,functions=10,captured_instructions=859,slots=14,pool_seed_additional_exact_slot=1)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','replay_'+P+'.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':summaries,'all_checks_pass':True,'native_target_executed':False,'native_IPC_executed':False,'native_allocator_executed':False,'native_gate_or_workloop_executed':False,'native_hardware_AES_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
