#!/usr/bin/env python3
"""Original cast/property/platform bindings and independently replayed ABI oracles.
O(image+visits+effects+objects), O(image+journals+private RAM); no native effects.
"""
import json
from pathlib import Path
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import definitions
from replay_aes_platform_gate import Replay
from validate_aes_provider_queue import read,val
P='aes_platform_gate';R=0x6500000000;PROV=R+0x10000;DEV=R+0x2a000;DATA=R+0x2b000;STRING=R+0x2b100;CTRL=R+0x2d000;CONTEXT=R+0x2e000;UNSUPPORTED=0xe00002c7
FLAGS=['native_target_executed','native_IPC_executed','native_registry_or_platform_effects_executed','hardware_PAC_executed','runtime_device_or_controller_identity_established','idb_mutated','full_goal_complete']
def args(row,key):return[[int(a,16)for a in e['arguments']]for e in row[key]]
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());external=json.loads((ROOT/'aes_hardware_job_profiles.json').read_text())['cases'][0];counts=Counter();totals=Counter();records=[]
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
  assert all(obj[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==76 and sum(len(r['instructions'])for r in src['functions'])==6726 and len(src['additional_slots'])==22
 for r in src['functions']:
  a=int(r['start'],16);assert im.k.read(a,int(r['end'],16)-a).hex()==r.get('bytes_hex',r.get('bytes'))and im.k.symbols([a])[r['start']]==r['exact_symbols']
  assert[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(im.k.read(a,int(r['end'],16)-a),a)]==r['instructions']
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']and s['exact_symbols']and p['format']==8
  if p['auth']:assert p['key']==0 and p['address_diversity']==1
 slots={s['name']:s['pointer']for s in src['additional_slots']};assert sum(p['auth']==1 for p in slots.values())==15
 assert definitions(im.k,list(src['named_definitions']))==src['named_definitions']
 for name,address in [('__ZTV16AppleARMIODevice',0xfffffe0007ff24d0),('__ZTV10AppleARMIO',0xfffffe0007ff1a58),('__ZTV17AppleH16GFamilyIO',0xfffffe000838c4d0),('__ZN17AppleH16GFamilyIO10superClassE',0xfffffe000838c4c8),('__ZN10AppleARMIO10gMetaClassE',0xfffffe000cc08960)]:assert len(src['named_definitions'][name])==1 and int(src['named_definitions'][name][0]['address'],16)==address
 assert slots['candidate_super']['target']=='0xfffffe000cc08960'and slots['candidate_psd']['target']==slots['controller_psd']['target']and slots['candidate_clock']['target']=='0xfffffe0009f764ac'and slots['candidate_power']['target']=='0xfffffe0009f76580'
 for s in src['seed_stubs']+src['driver_stubs']+src['platform_stubs']:assert im.k.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 key=src['property_key'];assert im.k.read(int(key['address'],16),14).hex()==key['bytes_hex']==b'service-gates\0'.hex()
 meta=src['metaclasses'];assert meta['runtime_hierarchy_established']is False
 for name in ['data','string']:assert im.k.read(int(meta[name],16)+0x10,8).hex()==meta[name+'_file_super_hex']=='00'*8
 for g in src['debug_globals']:assert im.k.read(int(g['address'],16),g['size_bytes']).hex()==g['file_hex']and g['runtime_value_established']is False
 assert im.k.symbols([int(a,16)for a in src['adjacent_IORPC_symbol_inventory']])==src['adjacent_IORPC_symbol_inventory']and len(src['adjacent_IORPC_symbol_inventory'])==6
 for h in src['SDK_references']:assert sha(Path(h['path']))==h['sha256']and h['matched_collection_source_revision_established']is False and 'iokit_common_err(0x2c7)'in Path(h['path']).read_text()
 # The three real base methods contain exactly the same unsupported return.
 for name in ['controller_clock','controller_power','controller_psd']:
  f=next(f for f in src['functions']if f['start']==slots[name]['target']);assert[(i['mnemonic'],i['operands'])for i in f['instructions']]==[('bti','c'),('mov','w0, #0x2c7'),('movk','w0, #0xe000, lsl #16'),('ret','')]
 init=next(f for f in src['functions']if f['start']=='0xfffffe0008cb3f80');assert{'ea':'0xfffffe0008cb3fdc','mnemonic':'str','operands':'x21, [x20, #0x88]'}in init['instructions']
 rows=prof['cases'];assert len(rows)==15
 for j,row in enumerate(rows):
  c=row['configuration'];models=row['API_models'];assert len(row['final_objects'])==158 and len(bytes.fromhex(row['final_objects'][0]['bytes_hex']))==0xa00 and all(row[k]is False for k in FLAGS)
  origin=external if row['external_source_producer']else rows[row['source_producer_case']];n=150 if row['external_source_producer']else 158;assert row['initial_private_fixtures'][:n]==origin['final_objects'];counts['source_object_transfers_checked']+=1
  assert row['final_source_globals']==external['final_source_globals'];counts['source_global_snapshots_preserved']+=1
  # Original outer/inner pools, carriers/jobs/adapters remain byte-identical.
  for e in external['final_objects'][1:]:assert read(row,int(e['address'],16),len(e['bytes_hex'])//2).hex()==e['bytes_hex'];counts['prior_nonprovider_objects_preserved']+=1
  assert not any(row[k]for k in ['job_allocations','DMA_allocations','pool_frames','pool_action_statuses','driver_quantum_frontiers','inner_pool_frames','job_base_frames','DMA_factory_frames','DMA_options_frames'])
  assert not any(e['pc']=='0xfffffe0009d4fbc0'for e in row['source_visits'])and val(row,PROV+0x1f8,1)==0
  env={int(e['address'],16):e['bytes_hex']for e in row['final_environment_globals']};assert env[int(meta['data'],16)+0x10]==env[int(meta['string'],16)+0x10]=='00'*8 and env[0xfffffe000caac518]==('0004800000000000'if j==14 else'0000800000000000')and env[0xfffffe000cb5c400]==('01000000'if j==14 else'00000000')
  for mi,m in enumerate(models):
   aa=[int(a,16)for a in m['arguments8']];result=int(m['return_value'],16);sym=m['symbol'];expected=[hex(((r+1)*0x123456789abcdef)^(mi+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(result)
   assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(mi+1)&1 else 0)and m['native_effects_executed']is False and not m['memory_effects']
   if sym=='declared_registry_property_model':assert j in range(2,6)and aa[:2]==[DEV,int(key['address'],16)]and result=={'absent':0,'data':DATA,'string':STRING}[c['property_kind']]
   else:assert sym=='kernel_trace_no_effect_model'and j==14 and result==0
   counts['API_'+sym]+=1
  if j<2:
   expected=0 if j else DEV;assert val(row,PROV+0x138)==expected and int(row['boundary']['registers31'][0],16)==expected and args(row,'cast_frames')==[[DATA if j else DEV,int(meta['ARM'],16)]]
   assert any(e['pc']=='0xfffffe0009d4eb28'and e['address']==hex(PROV+0x138)and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==expected for e in row['source_writes']);counts['provider_typed_publication_cases_checked']+=1
  elif j<6:
   flag=[0,1,0,1][j-2];assert val(row,PROV+0x138)==DEV and val(row,PROV+0x1d2,1)==flag and len(row['property_frames'])==len(row['cast_frames'])==1 and row['property_frames'][0]['key14_hex']==key['bytes_hex']
   assert args(row,'cast_frames')==[[{'absent':0,'data':DATA,'string':STRING}[c['property_kind']],int(meta['data'],16)]]
   assert any(e['pc']=='0xfffffe0009d4ef8c'and e['address']==hex(PROV+0x1d2)and e['after_hex']==bytes([flag]).hex()for e in row['source_writes']);counts['typed_presence_flag_cases_checked']+=1
   if j in [3,5]:assert[(int(e['address'],16),e['size_bytes'])for e in row['source_reads']if DATA<=int(e['address'],16)<DATA+128]==[(DATA,8)];counts['typed_object_tail_unread_cases_checked']+=1
   if j==5:assert row['source_visits']==rows[3]['source_visits']and read(row,DATA+8,120)==bytes([0x5a])*120 and read(rows[3],DATA+8,120)==bytes(120);counts['tail_pattern_pair_checked']=1
  else:
   enable=c.get('enable',1);combined=j in [8,9,11,13];assert val(row,PROV+0x138)==DEV and val(row,PROV+0x1d2,1)==int(combined)and args(row,'device_enable_frames')==[[PROV,enable]]
   if combined:
    assert args(row,'device_method_frames')==[[DEV,enable,0,0xffffffff,0xffffffff]]
    assert args(row,'controller_method_frames')==([]if j==11 else[[CTRL,0x789,0xffffffff if enable else 0x7fffffff,CONTEXT,0xa]])and not row['clock_return_frames'];counts['PSD_argument_or_guard_cases_checked']+=1
   else:
    assert args(row,'device_method_frames')==[[DEV,enable,0],[DEV,enable,0,0]]and args(row,'controller_method_frames')==([]if j==10 else[[CTRL,0x123,enable]])+[[CTRL,0x456,enable,0]]and len(row['clock_return_frames'])==1 and row['clock_return_frames'][0]['raw_X0']==hex(UNSUPPORTED);counts['clock_then_power_or_guard_cases_checked']+=1
   if j in [12,13]:assert row['boundary']['kind']=='before_activation_register_base'and row['boundary']['pc']=='0xfffffe0009d4fa20'and args(row,'AES_enable_frames')==[[PROV,1]]and val(row,PROV+0x168,4)==0;counts['AES_activation_frontiers_checked']+=1
   else:assert row['boundary']['kind']=='returned'and int(row['boundary']['registers31'][0],16)==UNSUPPORTED and row['boundary']['SP']==row['entry_SP'];counts['real_base_unsupported_returns_checked']+=1
   assert all(R<=int(e['address'],16)<R+0x100000 for e in row['source_writes']);counts['no_MMIO_write_cases_checked']+=1
  assert args(row,'trace_frames')==([[0x5070000,DEV,0,0x123,1,0],[0x5070004,DEV,0,0x456,1,0]]if j==14 else[])
  totals.update(Replay(im,row).run());records.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind']});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=15,functions=76,captured_instructions=6726,additional_slots=22,authenticated_slots=15,adjacent_IORPC_symbols=6,static_controller_field_writer=1)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','aes_hardware_job_profiles.json','validate_aes_provider_queue.py','replay_'+P+'.py','replay_aes_hardware_job.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
