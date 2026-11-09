#!/usr/bin/env python3
"""Independent source/fixup recapture and job/pool/specification/segment oracles.
O(image+visits+effects+objects), O(image+journals+private RAM); no native effects.
"""
import json,struct
from pathlib import Path
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_aes_hardware_job import Replay
from validate_aes_provider_queue import read,val
P='aes_hardware_job';R=0x6500000000;PROV=R+0x10000;GATE=R+0x11000;LOOP=R+0x13000;POOL=R+0x14000;WLEXP=R+0x17000;PGATE=R+0x1c000;HPOOL=R+0x25000;HGATE=R+0x26000;HEXP=R+0x27000;MAPPER=R+0x28000;SEGS=R+0x29000;JOBS=[R+0x40000+j*0x100 for j in range(32)];DMAS=[R+0x50000+j*0x100 for j in range(64)];OUTPUT=0xfffffe000c529dd8;DV=0xfffffe0007f411f8;DMETA=0xfffffe000cb52ea8;COUNTER=0xfffffe000cb5b638
def global_value(row,a,n):
 e=next(e for e in row['final_source_globals']if int(e['address'],16)<=a<a+n<=int(e['address'],16)+len(e['bytes_hex'])//2);off=a-int(e['address'],16);return int.from_bytes(bytes.fromhex(e['bytes_hex'])[off:off+n],'little')
def pool_count(row,pool,objects):
 sentinel=pool+0x10;cur=val(row,sentinel);prev=sentinel;seen=set()
 while cur!=sentinel:
  assert cur in objects and cur not in seen and val(row,cur+0x18)==prev;seen.add(cur);prev=cur;cur=val(row,cur+0x10)
 assert val(row,pool+0x18)==prev;return len(seen)
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());external=json.loads((ROOT/'aes_synchronous_wait_profiles.json').read_text());counts=Counter();totals=Counter();records=[]
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
  for k in ['native_target_executed','native_IPC_executed','native_allocation_or_DMA_executed','hardware_PAC_executed','runtime_candidate_identity_established','idb_mutated','full_goal_complete']:assert obj[k]is False
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==58 and sum(len(r['instructions'])for r in src['functions'])==4882 and len(src['additional_slots'])==11 and len(src['driver_stubs'])==5
 for r in src['functions']:
  a=int(r['start'],16);assert im.k.read(a,int(r['end'],16)-a).hex()==r.get('bytes_hex',r.get('bytes'))and im.k.symbols([a])[r['start']]==r['exact_symbols']
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']and s['exact_symbols']and p['format']==8
 assert sum(s['pointer']['auth']==0 for s in src['additional_slots'])==1 and next(s for s in src['additional_slots']if s['name']=='segment_output')['pointer']['target']==hex(OUTPUT)
 for s in src['driver_stubs']:assert im.k.read(int(s['start'],16),16).hex()==s['bytes_hex']
 view=src['job_type_view'];assert view['bytes_hex']==im.k.read(0xfffffe00082fe528,64).hex()and(int.from_bytes(bytes.fromhex(view['bytes_hex'])[0x2c:0x30],'little')&0xffffff)==64
 assert src['DMA_zone_cache']['file_hex']==im.k.read(0xfffffe0007f41438,8).hex()=='00'*8 and src['DMA_metaclass']['file64_hex']==im.k.read(DMETA,64).hex()=='00'*64
 h=src['SDK_reference'];assert sha(Path(h['path']))==h['sha256']and h['matched_collection_source_revision_established']is False and h['compile_executed']is False
 options=bytearray(40);options[0]=40;struct.pack_into('<III',options,24,1,1,1)
 rows=prof['cases'];assert len(rows)==10
 for j,row in enumerate(rows):
  c=row['configuration'];models=row['API_models'];assert len(row['final_objects'])==150 and not row['pool_frames']and not row['pool_action_statuses']
  for k in ['native_target_executed','native_IPC_executed','native_allocation_or_DMA_executed','hardware_PAC_executed','runtime_candidate_identity_established','idb_mutated','full_goal_complete']:assert row[k]is False
  if j in [1,2]:
   prior=rows[j-1];assert row['initial_private_fixtures'][:150]==prior['final_objects']and row['initial_image_fixtures'][-2:]==[{**e,'provenance':'Exact source-produced global snapshot; native epoch unestablished'}for e in prior['final_source_globals']];counts['object_and_global_snapshot_transfers_checked']+=1
  else:assert row['initial_private_fixtures'][:49]==external['cases'][2]['final_objects'];counts['external_source_actor_transfers_checked']+=1
  assert read(row,POOL,0x100)==read(external['cases'][2],POOL,0x100)
  for k in range(32):assert read(row,R+0x30000+k*0x100,144)==read(external['cases'][2],R+0x30000+k*0x100,144)
  counts['outer_pool_and_carrier_images_preserved']+=33
  for e in row['DMA_factory_frames']:assert e['arguments8']==[hex(OUTPUT),'0x0','0x0','0x0','0x0','0x1',hex(MAPPER),'0x0'];counts['factory_scalar_ABI_frames_checked']+=1
  for e in row['DMA_options_frames']:
   args=[int(x,16)for x in e['arguments6']];assert args[0]in DMAS and args[1]==OUTPUT and args[3:]==[0,MAPPER,0]and e['options40_hex']==options.hex();counts['source_options40_frames_checked']+=1
  for mi,m in enumerate(models):
   args=[int(a,16)for a in m['arguments8']];result=int(m['return_value'],16);sym=m['symbol'];expected=[hex(((r+1)*0x123456789abcdef)^(mi+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(result)
   assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(mi+1)&1 else 0)and m['native_effects_executed']is False
   effects=m['memory_effects']
   if sym in ['job_zeroed_backend_model','DMA_zeroed_backend_model']:
    n=64 if sym=='job_zeroed_backend_model'else 120;assert len(effects)==1 and effects[0]['address']==hex(result)and effects[0]['before_hex']=='5a'*n and effects[0]['after_hex']=='00'*n
    if n==64:assert args[:2]==[0xfffffe00082fe528,4]and result in JOBS
    else:assert args[:4]==[0xfffffe0007f36938,120,0x41004,0]and result in DMAS
   elif sym in ['inner_pool_allocation_model','inner_gate_allocation_model']:
    address=HPOOL if sym=='inner_pool_allocation_model'else HGATE;vptr=0xfffffe0007f40058 if address==HPOOL else 0xfffffe0007f3fbb0;assert len(effects)==1 and effects[0]['address']==hex(address)and effects[0]['after_hex']==vptr.to_bytes(8,'little').hex()and result==address
   else:
    assert not effects
    if sym=='inner_gate_extension_model':assert args[0]==0xfffffe0007e55c58 and result==HEXP
    elif sym=='job_class_bookkeeping_model':assert args[0]==0xfffffe000cc68c88 and result==0
    elif sym=='inner_gate_retain_model':assert args[0]==HGATE and result==0
    elif sym=='DMA_options_init_no_effect_model':assert args[0]in DMAS and result==c.get('init_result',1)
    elif sym=='DMA_release_no_effect_model':assert j==4 and args[0]==DMAS[0]and result==0
    elif sym=='DMA_meta_NULL_model':assert j==5 and args[0]==DMETA and result==0
    elif sym=='on_thread_model':assert args[0]==LOOP and result==1
    else:assert sym in ['close_gate_no_effect_model','open_gate_no_effect_model']and args[0]==LOOP and result==0
   counts['API_'+sym]+=1
  counter=global_value(row,COUNTER,8);meta_count=global_value(row,DMETA+0x24,4)
  if j<3:
   assert val(row,PROV+0xf8)==POOL and val(row,PROV+0x158)==HPOOL and POOL!=HPOOL and val(row,HPOOL+0x28)==HGATE and val(row,HGATE+0x18)==HPOOL and val(row,HGATE+0x20)==0 and val(row,HGATE+0x30)==LOOP and val(row,HGATE+0x48)==0
   assert val(row,WLEXP+8)==GATE and val(row,GATE+0x10)==PGATE and val(row,PGATE+0x10)==HGATE and val(row,HGATE+0x10)==0
   assert val(row,PROV+0x140)==PROV+0x140 and val(row,PROV+0x148)==PROV+0x140 and val(row,PROV+0x160,2)==0 and val(row,PROV+0x164,4)==0xffffffff and val(row,PROV+0x168,4)==0 and counter==32*64+64*120 and meta_count==64
   for k,a in enumerate(JOBS):assert val(row,a)==0xfffffe00082fe2a0 and val(row,a+8,4)==1 and val(row,a+0x20)==DMAS[2*k]and val(row,a+0x28)==DMAS[2*k+1]and val(row,a+0x30)==0 and val(row,a+0x38,2)==0xffff
   for a in DMAS:assert val(row,a)==DV and val(row,a+8,4)==1 and val(row,a+0x40)==0 and val(row,a+0x48)==0
   assert pool_count(row,HPOOL,JOBS)==(31 if j==1 else 32)
   if j==0:
    assert len(row['job_allocations'])==32 and len(row['DMA_allocations'])==64 and len(row['job_base_frames'])==32 and len(row['DMA_options_frames'])==64 and row['boundary']['pc']=='0xfffffe0009d4f360'
    assert[int(e['address'],16)for e in row['job_allocations']]==JOBS and[int(e['address'],16)for e in row['DMA_allocations']]==DMAS;counts['source_seeded_jobs_checked']=32;counts['source_constructed_DMA_objects_checked']=64;counts['distinct_pool_and_fourth_gate_topology_checked']=1
   elif j==1:assert row['boundary']['registers31'][0]==hex(JOBS[-1])and val(row,JOBS[-1]+0x10)==0 and val(row,JOBS[-1]+0x18)==0;counts['source_job_lease_checked']=1
   else:assert row['final_objects']==rows[0]['final_objects']and row['final_source_globals']==rows[0]['final_source_globals'];counts['complete_lease_return_state_restoration_checked']=1
  elif j in [3,4]:
   assert len(row['DMA_allocations'])==1 and len(row['DMA_options_frames'])==1 and counter==120 and meta_count==1 and val(row,DMAS[0])==DV and val(row,DMAS[0]+8,4)==1 and row['boundary']['registers31'][0]==(hex(DMAS[0])if j==3 else'0x0');counts['factory_result_branches_checked']+=1
  elif j==5:assert not row['DMA_allocations']and not row['DMA_options_frames']and counter==meta_count==0 and row['boundary']['registers31'][0]=='0x0';counts['conditional_NULL_meta_factory_branch_checked']=1
  else:
   assert not models and row['boundary']['registers31'][0]=='0x1'and counter==meta_count==0;expected=bytearray([0xa5])*64;struct.pack_into('<QQ',expected,c['index']*16,c['address'],c['length']);assert read(row,SEGS,64)==expected and len(row['source_writes'])==2 and all(e['size_bytes']==8 for e in row['source_writes']);counts['original_little64_segment_cases_checked']+=1
  totals.update(Replay(im,row).run());records.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'requested_byte_counter':counter,'private_DMA_meta_count':meta_count});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=10,functions=58,captured_instructions=4882,additional_slots=11,driver_stubs=5)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','aes_synchronous_wait_profiles.json','validate_aes_provider_queue.py','replay_'+P+'.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'all_checks_pass':True,'native_target_executed':False,'native_IPC_executed':False,'native_allocation_or_DMA_executed':False,'hardware_PAC_executed':False,'runtime_candidate_identity_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
