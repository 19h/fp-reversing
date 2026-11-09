#!/usr/bin/env python3
"""Fresh source replay and independent configuration/carrier/queue oracles.
O(image+visits+effects+carriers), O(image+journals+private RAM); no target effects.
"""
import json,struct
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_aes_provider_queue import Replay
P='aes_provider_queue';RAM=0x6500000000;PROV=RAM+0x10000;GATE=RAM+0x11000;POOL=RAM+0x14000;PGATE=RAM+0x1c000;D0=RAM+0x20000;D1=RAM+0x21000;KEY=RAM+0x22000;IV=RAM+0x23000;CTX=RAM+0x24000;CALLBACK=RAM+0xe1000;CMD=RAM+0x31f00
def read(row,a,n=8):
 e=next(e for e in row['final_objects']if int(e['address'],16)<=a<int(e['address'],16)+len(e['bytes_hex'])//2);b=bytes.fromhex(e['bytes_hex']);o=a-int(e['address'],16);return b[o:o+n]
def val(row,a,n=8):return int.from_bytes(read(row,a,n),'little')
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());external=json.loads((ROOT/'aes_command_pool_profiles.json').read_text());counts=Counter();totals=Counter();records=[];orders=[]
 for obj,name in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  assert all(obj[k]is False for k in ['native_target_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','full_goal_complete'])
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==38 and sum(len(r['instructions'])for r in src['functions'])==3318 and len(src['additional_slots'])==7 and src['runtime_candidate_identity_established']is False
 for r in src['functions']:assert im.k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r.get('bytes_hex',r.get('bytes'))and im.k.symbols([int(r['start'],16)])[r['start']]==r['exact_symbols']
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']and s['exact_symbols']and p['format']==8 and p['auth']==1 and p['key']==0 and p['address_diversity']==1
 assert im.k.read(0xfffffe000abffaf4,16).hex()==src['physical_stub']['bytes_hex']
 rows=prof['cases'];assert len(rows)==7
 for j,row in enumerate(rows):
  c=row['configuration'];models=row['API_models'];writes=row['source_writes'];reads=row['source_reads'];assert len(row['final_objects'])==49 and val(row,PROV)==0xfffffe00082fd878 and val(row,PROV+0x128,4)==0
  if j==0:assert row['initial_private_fixtures'][:44]==external['cases'][1]['final_objects']and row['external_source_producer']=={'path':'aes_command_pool_profiles.json','case':1};counts['external_actor_producer_checked']=1
  else:assert row['initial_private_fixtures'][:49]==rows[row['source_producer_case']]['final_objects'];counts['source_object_transfers_checked']+=1
  assert val(row,PROV+0x88)==33554432 and val(row,PROV+0x90)==33554432 and val(row,PROV+0xb0,4)==1
  if j==0:assert len(row['source_visits'])==5 and not models and any(e['pc']=='0xfffffe0009d4f33c'and e['address']==hex(PROV+0xb0)and e['after_hex']=='01000000'for e in writes);counts['source_hardware_config_writers_checked']=3
  else:assert val(row,PROV+0xc8)==2097152 and val(row,PROV+0xe0)==32768 and val(row,PROV+0xe8)==32768
  if j in [1,2]:assert not models
  if j>=2:assert val(row,PROV+0xf0)==0xfffffe000abfd2d8
  for mi,m in enumerate(models):
   args=[int(a,16)for a in m['arguments8']];result=int(m['return_value'],16);sym=m['symbol'];expected=[hex(((r+1)*0x123456789abcdef)^(mi+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(result);assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(mi+1)&1 else 0)and not m['memory_effects']and m['native_effects_executed']is False;counts['API_'+sym]+=1
   if sym=='descriptor_prepare_model':assert args[:2]in [[D0,0],[D1,0]]and result==0
   elif sym=='descriptor_physical_address_model':assert args[0]in [D0,D1]and result==(0x100000 if args[0]==D0 else 0x200000)
   elif sym=='on_thread_model':assert args[0]==RAM+0x13000 and result==1
   else:assert sym in ['close_gate_no_effect_model','open_gate_no_effect_model']and args[0]==RAM+0x13000 and result==0
  if j<3:assert not row['driver_quantum_frontiers']
  else:
   assert row['boundary']['pc']=='0xfffffe0009d50a28'and len(row['driver_quantum_frontiers'])==1 and row['driver_quantum_frontiers'][0]['arguments2']==[hex(PROV),hex(CMD)]
   outdesc=D1 if c.get('separate')else D0;callback=CALLBACK if c.get('callback')else 0;context=CTX if c.get('callback')else 0;expected={0x10:0,0x18:0,0x20:D0,0x28:outdesc,0x30:c['length'],0x38:IV,0x48:KEY,0x50:c.get('offsetA',0),0x58:c.get('offsetB',0),0x60:32768,0x68:0,0x70:min(c['length'],32768),0x80:callback,0x88:context}
   assert all(val(row,CMD+o)==v for o,v in expected.items())and val(row,CMD+0x40,4)==c['operation'];assert row['driver_quantum_frontiers'][0]['carrier144_hex']==read(row,CMD,144).hex()
   assert val(row,PROV+0x100)==PROV+0x100 and val(row,PROV+0x108)==PROV+0x100 and val(row,PROV+0x110,1)==1 and val(row,GATE+0x48)==0x100 and val(row,PGATE+0x48)==0
   assert val(row,POOL+0x10)==RAM+0x31e00 and val(row,POOL+0x18)==RAM+0x30000
   expected_receivers=[D0,outdesc]
   for sym in ['descriptor_prepare_model','descriptor_physical_address_model']:assert[int(m['arguments8'][0],16)for m in models if m['symbol']==sym]==expected_receivers
   assert len(models)==9 and len(row['pool_frames'])==1 and row['pool_frames'][0]['arguments5'][2]=='0x1'and row['pool_action_statuses'][0]['raw_X0']=='0x0'and len(row['action_frames'])==1 and[int(a,16)for a in row['action_frames'][0]['arguments8'][:5]]==[PROV,CMD,0,0,0]
   key_reads=[e for e in reads if KEY<=int(e['address'],16)<KEY+0x60];assert{int(e['address'],16)-KEY for e in key_reads}=={0,0x24}and all(e['size_bytes']==4 for e in key_reads);assert not any(IV<=int(e['address'],16)<IV+16 for e in reads)
   clear=next(e for e in writes if e['pc']=='0xfffffe000c51fe50'and e['address']==hex(CMD+0x10));pack=next(e for e in writes if e['pc']=='0xfffffe000abff7f8'and e['address']==hex(CMD+0x20));enqueue=next(e for e in writes if e['pc']=='0xfffffe000abfd374'and e['address']==hex(CMD+0x10));dequeue=next(e for e in writes if e['pc']=='0xfffffe000abfd550'and e['address']==hex(CMD+0x10));quantum=next(e for e in writes if e['pc']=='0xfffffe000abfd554'and e['address']==hex(CMD+0x70));busy=next(e for e in writes if e['pc']=='0xfffffe000abfd55c'and e['address']==hex(PROV+0x110));indices=[e['source_visit_index']for e in [clear,pack,enqueue,dequeue,quantum,busy]];assert indices==sorted(indices)and len(set(indices))==6 and clear['after_hex']=='00'*8 and dequeue['after_hex']=='00'*8
   for pc in ['0xfffffe000c51fe50','0xfffffe000abfd550']:
    pair=[e for e in writes if e['pc']==pc and int(e['address'],16)in [CMD+0x10,CMD+0x18]];assert len(pair)==2 and all(e['size_bytes']==8 and e['after_hex']=='00'*8 for e in pair);counts['paired_link_clear_words_checked']+=2
   orders.append({'case':j,'pool_link_clear':clear,'packing':pack,'enqueue':enqueue,'dequeue':dequeue,'quantum_count_store':quantum,'busy_store':busy});counts['same_carrier_pool_pack_queue_handoffs_checked']+=1;counts['metadata_only_key_pointer_prefixes_checked']+=1
  assert not any(e['pc']=='0xfffffe0009d50a28'for e in row['source_visits'])
  totals.update(Replay(im,row).run());records.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['pc'],'carrier':hex(CMD)if j>=3 else None});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=7,functions=38,captured_instructions=3318,additional_slots=7)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','aes_command_pool_profiles.json','replay_'+P+'.py','replay_aes_command_pool.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'same_carrier_source_orders':orders,'all_checks_pass':True,'native_target_executed':False,'native_IPC_executed':False,'native_descriptor_or_DMA_executed':False,'native_workloop_or_lock_effects_executed':False,'native_hardware_AES_executed':False,'hardware_PAC_executed':False,'runtime_candidate_identity_established':False,'actual_kext_key_data_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
