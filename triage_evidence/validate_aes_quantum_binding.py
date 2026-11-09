#!/usr/bin/env python3
"""Fresh source/fixup and A64 replay with pool/binding/range/cleanup/segment oracles.
O(image+visits+effects+objects), O(image+journals+private RAM); no native effects.
"""
import json,struct
from pathlib import Path
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_aes_quantum_binding import Replay
from validate_aes_provider_queue import read,val
from validate_aes_hardware_job import pool_count,global_value
P='aes_quantum_binding';R=0x6500000000;PROV=R+0x10000;GATE=R+0x11000;LOOP=R+0x13000;POOL=R+0x14000;HPOOL=R+0x25000;HGATE=R+0x26000;D0=R+0x20000;D1=R+0x21000;CMD=R+0x31f00;JOBS=[R+0x40000+j*0x100 for j in range(32)];DMAS=[R+0x50000+j*0x100 for j in range(64)];CARRIERS=[R+0x30000+j*0x100 for j in range(32)]
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());external=json.loads((ROOT/'aes_hardware_job_profiles.json').read_text());counts=Counter();totals=Counter();records=[]
 flags=['native_target_executed','native_IPC_executed','native_DMA_or_cache_effects_executed','native_device_or_crypto_executed','hardware_PAC_executed','runtime_candidate_identity_established','idb_mutated','full_goal_complete']
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
  assert all(obj[k]is False for k in flags)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==61 and sum(len(r['instructions'])for r in src['functions'])==5892 and len(src['additional_slots'])==4
 for r in src['functions']:
  a=int(r['start'],16);assert im.k.read(a,int(r['end'],16)-a).hex()==r.get('bytes_hex',r.get('bytes'))and im.k.symbols([a])[r['start']]==r['exact_symbols']
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']and s['exact_symbols']and p['auth']==1 and p['key']==0 and p['format']==8 and p['address_diversity']==1
 for h in src['SDK_references']:assert sha(Path(h['path']))==h['sha256']and h['matched_collection_source_revision_established']is False
 rows=prof['cases'];assert len(rows)==13
 for j,row in enumerate(rows):
  c=row['configuration'];models=row['API_models'];writes=row['source_writes'];assert len(row['final_objects'])==150 and len(bytes.fromhex(row['final_objects'][0]['bytes_hex']))==0xa00 and all(row[k]is False for k in flags)
  origin=external['cases'][0]if row['external_source_producer']else rows[row['source_producer_case']];assert row['initial_private_fixtures'][:150]==origin['final_objects'];counts['source_object_transfers_checked']+=1
  assert row['final_source_globals']==external['cases'][0]['final_source_globals']and not row['job_allocations']and not row['DMA_allocations']and not row['driver_quantum_frontiers'];counts['source_global_snapshots_preserved']+=1
  assert pool_count(row,POOL,CARRIERS)==31 and pool_count(row,HPOOL,JOBS)==(32 if j==4 else 31)and val(row,PROV+0x110,1)==1 and val(row,GATE+0x48)==0x100
  assert val(row,JOBS[-1]+0x30)==(0 if j==4 else CMD)and val(row,CMD+0x78,4)==0 and val(row,JOBS[-1]+0x20)==DMAS[-2]and val(row,JOBS[-1]+0x28)==DMAS[-1]
  assert val(row,PROV+0x140)==PROV+0x140 and val(row,PROV+0x148)==PROV+0x140 and val(row,PROV+0x160,2)==0
  assert not any(e['pc']in ['0xfffffe0009d51e38','0xfffffe0009d4f650','0xfffffe0009d4fcf8']for e in row['source_visits']);counts['device_configuration_and_emitter_bodies_unexecuted_cases_checked']+=1
  for mi,m in enumerate(models):
   args=[int(a,16)for a in m['arguments8']];result=int(m['return_value'],16);sym=m['symbol'];expected=[hex(((r+1)*0x123456789abcdef)^(mi+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(result)
   assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(mi+1)&1 else 0)and m['native_effects_executed']is False
   if sym=='declared_segment_record_model':
    frame=next(e for e in row['segment_calls']if e['before_source_visit_index']==m['before_source_visit_index']);assert result==frame['declared_result'];effects=m['memory_effects']
    if result==0:
     rec=frame['declared_record'];expected_effects=[(args[1],struct.pack('<Q',frame['input_offset']+rec['length'])),(args[2],struct.pack('<QQ',rec['address'],rec['length'])),(args[3],struct.pack('<I',1))];assert len(effects)==3 and all(e['address']==hex(a)and e['after_hex']==b.hex()for e,(a,b)in zip(effects,expected_effects));counts['declared_segment_record_effects_checked']+=3
    else:assert not effects
   else:
    assert not m['memory_effects']
    if sym=='descriptor_prepare_model':assert args[:2]in [[D0,0],[D1,0]]and result==0
    elif sym=='descriptor_physical_address_model':assert args[0]in [D0,D1]and result==(0x100000 if args[0]==D0 else 0x200000)
    elif sym=='DMA_bind_no_effect_model':assert args[0]in DMAS[-2:]and args[1]in [D0,D1]and args[2]==1 and result==c.get('binding_result',0)
    elif sym=='descriptor_operation_no_effect_model':assert args[0]in [D0,D1]and args[1]in [1,2]and result==c.get('cache_result',0)
    elif sym=='DMA_clear_no_effect_model':assert j==4 and args[:2]in [[DMAS[-2],1],[DMAS[-1],1]]and result==0
    elif sym=='declared_configuration_error_no_effect_model':assert j==4 and args[:3]==[PROV,CMD,0]and result==0xe00002bc
    elif sym=='on_thread_model':assert args[0]==LOOP and result==1
    else:assert sym in ['close_gate_no_effect_model','open_gate_no_effect_model']and args[0]==LOOP and result==0
   counts['API_'+sym]+=1
  if c['stage']=='perform':
   q=min(c['length'],32768);assert val(row,CMD+0x30)==c['length']and val(row,CMD+0x68)==0 and val(row,CMD+0x70)==q and len(row['quantum_calls'])==1 and row['quantum_calls'][0]['arguments']==[hex(PROV),hex(CMD)]and row['inner_pool_frames'][0]['arguments5'][2]=='0x0'and row['pool_frames'][0]['arguments5'][2]=='0x1'
   assert row['enable_calls'][0]['arguments']==[hex(PROV),'0x1']
   if j==5:
    assert row['boundary']['kind']=='before_device_enable'and not row['binding_calls']and not row['cache_operation_calls']and not row['configuration_calls']and val(row,PROV+0x168,4)==0 and val(row,PROV+0x1f8,1)==0;counts['disabled_state_device_boundary_checked']=1
   else:
    dout=D0 if c.get('same_descriptor')else D1;first,second=(dout,D0)if c['operation']==1 else(D0,dout);oa,ob=c.get('offsetA',0),c.get('offsetB',0);first_offset,second_offset=(ob,oa)if c['operation']==1 else(oa,ob)
    assert[e['arguments']for e in row['binding_calls']]==[[hex(DMAS[-2]),hex(first),'0x1'],[hex(DMAS[-1]),hex(second),'0x1']]
    assert[e['arguments']for e in row['cache_operation_calls']]==[[hex(first),'0x2',hex(first_offset),hex(q)],[hex(second),'0x1',hex(second_offset),hex(q)]]and row['configuration_calls'][0]['arguments']==[hex(PROV),hex(CMD),'0x0'];counts['same_job_binding_cache_range_handoffs_checked']+=1
    assert val(row,PROV+0x1f8,1)==1
    if j==4:
     assert row['boundary']['kind']=='before_disable_register_base'and val(row,PROV+0x168,4)==0 and len(row['clear_calls'])==2 and row['enable_calls'][1]['arguments']==[hex(PROV),'0x0']and val(row,PROV+0x9fc,4)==1
     clear=next(e for e in writes if e['pc']=='0xfffffe0009d50dd0');head=next(e for e in writes if e['address']==hex(HPOOL+0x10)and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==JOBS[-1]);decrement=next(e for e in writes if e['pc']=='0xfffffe0009d50e0c');assert clear['source_visit_index']<head['source_visit_index']<decrement['source_visit_index'];counts['conditional_configuration_error_cleanup_order_checked']=1
    else:assert row['boundary']['kind']=='before_AES_configuration'and val(row,PROV+0x168,4)==1 and val(row,PROV+0x9fc,4)==0
    if j==3:assert row['source_visits']==rows[0]['source_visits']and row['final_objects']==rows[0]['final_objects'];counts['ignored_bind_and_cache_status_register_cases_checked']=1
  else:
   assert row['transfer_calls'][0]['arguments']==[hex(PROV),'0x0','0x0',hex(DMAS[-2]),hex(DMAS[-1]),hex(c['offsetA']),hex(c['offsetB']),hex(c['remaining'])]
   for k,e in enumerate(row['segment_calls']):assert e['arguments'][0]==hex(DMAS[-2+k])and e['input_count']==1 and e['input_offset']==[c['offsetA'],c['offsetB']][k]
   if j in [6,7,8]:
    assert row['boundary']['kind']=='before_transfer_register_base'and len(row['segment_calls'])==2 and int(row['boundary']['registers31'][26],16)==min(c['remaining'],*c['segment_lengths'])and int(row['boundary']['registers31'][28],16)==0x100000 and int(row['boundary']['registers31'][25],16)==0x200000;counts['unsigned_segment_minimum_consumer_cases_checked']+=1
   elif j==9:assert row['boundary']['kind']=='returned'and row['boundary']['registers31'][0]=='0x0'and not row['segment_calls']and not models;counts['empty_transfer_guard_checked']=1
   else:assert j in [10,11]and row['boundary']['kind']=='before_segment_error_assertion'and row['boundary']['pc']==('0xfffffe0009d513b4'if j==10 else'0xfffffe0009d51388')and len(row['segment_calls'])==(1 if j==10 else 2);counts['segment_error_assertion_frontiers_checked']+=1
  totals.update(Replay(im,row).run());records.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'outer_pool_count':31,'inner_pool_count':pool_count(row,HPOOL,JOBS)});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=13,functions=61,captured_instructions=5892,additional_slots=4)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','aes_hardware_job_profiles.json','validate_aes_provider_queue.py','validate_aes_hardware_job.py','replay_'+P+'.py','replay_aes_hardware_job.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'all_checks_pass':True,**{k:False for k in flags}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
