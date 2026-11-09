#!/usr/bin/env python3
"""Original parser/collection field round trips and source consumer/filter ABI.
Finite valid-input semantic oracles plus fresh A64 replay, not native parsing,
interning, ownership, malformed-input or arbitrary-graph validation.
O(image+visits+effects+objects), O(image+journals+private RAM).
"""
import json,struct
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import definitions
from replay_iorpc_binary_parser import Replay
from validate_aes_provider_queue import read,val
P='iorpc_binary_parser';R=0x6500000000;DEV=R+0x2a000;D=R+0x90000;V=R+0x90100;K=R+0x90200;KB=R+0x90300;PAIRS=R+0x91000;BYTES=R+0x92000;TABLE=R+0x93000;NEST=R+0x94000;COOKIE=R+0x95000;ERROR=R+0x95080;FILTER=R+0xe4200;MAPPED=R+0x77000;PARSER=0xfffffe000c489b18;VMCOUNT=0xfffffe000cb5b630;MID=0xd8a753ea156f9162
FLAGS=['native_target_executed','native_IPC_executed','native_registry_or_platform_effects_executed','native_remote_transport_executed','native_port_objects_observed','native_object_port_registry_effects_executed','native_serialized_VM_or_parser_effects_executed','native_binary_parser_executed','runtime_metaclass_hierarchy_established','runtime_device_or_controller_identity_established','hardware_PAC_executed','idb_mutated','full_goal_complete']
def u32(b,o):return int.from_bytes(b[o:o+4],'little')
def u64(b,o):return int.from_bytes(b[o:o+8],'little')
def glob(row,a):return next(int.from_bytes(bytes.fromhex(e['bytes_hex']),'little')for e in row['final_serialization_globals']if int(e['address'],16)==a)
def has_pc(row,a):return any(e['pc']==hex(a)for e in row['source_visits'])
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());old=json.loads((ROOT/'iorpc_ool_serialization_profiles.json').read_text())['cases'];origin=json.loads((ROOT/'iorpc_object_conversion_profiles.json').read_text())['cases'][0];counts=Counter();totals=Counter();records=[]
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
  assert all(obj[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==191 and sum(len(f['instructions'])for f in src['functions'])==17506
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f.get('bytes_hex',f.get('bytes'))and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 slots=sum((src[k]for k in ['additional_slots','iorpc_slots','remote_slots','object_conversion_slots','serialization_slots','binary_parser_slots']),[])
 for s in slots:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 assert definitions(im.k,list(src['binary_parser_definitions']))==src['binary_parser_definitions']
 assert len(next(f for f in src['functions']if f['start']==hex(PARSER))['instructions'])==882
 rows=prof['cases'];assert len(rows)==19
 for j,row in enumerate(rows):
  c=row['configuration'];stage=c['stage'];producer=old[c['packet_case']];source_config=producer['configuration'];data=bytes.fromhex(producer['serialization_records'][0]['bytes_hex']);populated='payload_length'in source_config;n=source_config.get('payload_length',0);payload=bytes((i*37+11)&255 for i in range(n));models=row['API_models'];assert all(row[k]is False for k in FLAGS)and len(row['final_objects'])==203 and row['initial_private_fixtures'][:173]==origin['final_objects'];counts['exact_prior_actor_transfers_checked']+=1
  assert row['exact_packet_producer']=={'path':'iorpc_ool_serialization_profiles.json','case':c['packet_case']}and not any(m['symbol']=='declared_binary_parser_object'for m in models);counts['whole_parser_result_model_removed_cases_checked']+=1
  assert val(row,D)==0xfffffe0007f318a8 and val(row,D+0xc,4)==int(populated)and val(row,D+0x10,4)==0 and val(row,D+0x14,4)==int(populated)and val(row,D+0x18,4)==1 and val(row,D+0x1c,4)==1 and val(row,D+0x20)==PAIRS
  data_capacity=max(n,16)if n else 0;assert glob(row,VMCOUNT)==16+data_capacity;counts['source_dictionary_fields_and_buffer_accounting_checked']+=1
  if populated:
   assert read(row,PAIRS,16)==struct.pack('<QQ',K,V)and val(row,K)==0xfffffe0007f343f0 and val(row,K+0xc,4)==4<<14 and val(row,K+0x10)==KB and read(row,KB,4)==b'key\0'and val(row,V)==0xfffffe0007f31568 and val(row,V+0xc,4)==n and val(row,V+0x10,4)==data_capacity and val(row,V+0x14,4)==max(n,16)and val(row,V+0x18)==(BYTES if n else 0)and read(row,BYTES,n)==payload;counts['semantic_key_payload_and_source_dictionary_pair_round_trips_checked']+=1
  else:assert read(row,PAIRS,16)==bytes(16)and read(row,V,64)==bytes(64);counts['empty_dictionary_round_trips_checked']+=1
  if stage=='adapter':
   p=rows[c['parser_producer_case']];assert c['parser_producer_case']in[5,8]and row['initial_private_fixtures'][-203:]==p['final_objects'];counts['exact_reconstructed_object_snapshot_transfers_checked']+=1
   for key in ['final_source_globals','final_environment_globals','final_registry_globals','final_serialization_globals']:
    for e in p[key]:assert any(f['address']==e['address']and f['bytes_hex']==e['bytes_hex']for f in row['initial_image_fixtures']);counts['reconstructed_global_snapshot_transfers_checked']+=1
   assert not has_pc(row,PARSER)and not row['binary_parser_return_frames']and not row['binary_parser_allocation_frames']and row['SetProperties_handler_frames'][0]['arguments']==[hex(DEV),hex(D)]and row['binary_parser_handler_frames'][0]['payload_hex']==payload.hex();b=bytes.fromhex(row['final_rpc_buffers'][0]['bytes_hex']);assert u32(b,0)==0x80001513 and u32(b,4)==60 and u32(b,0x1c)==0x4da2b68d and u32(b,0x20)==0 and u64(b,0x24)==MID and u64(b,0x2c)==8 and u64(b,0x34)==0 and row['boundary']['registers31'][0]=='0x0';counts['original_adapter_accepts_source_reconstructed_dictionary_checked']+=1
  else:
   assert stage in['inverse','parser_component']and has_pc(row,PARSER)and all(not any(m['pc']==hex(a)for m in models)for a in[PARSER,0xfffffe000c44d70c,0xfffffe000c44cd64,0xfffffe000c44cd70,0xfffffe000c44ab74,0xfffffe000c44ac2c]);counts['original_parser_and_collection_bodies_executed_cases_checked']+=1
   assert row['serialization_parser_frames'][1]['bytes_hex']==data.hex()and row['binary_parser_return_frames'][0]['arguments']==[hex(D)]and read(row,TABLE,8*(3 if populated else 1))==(struct.pack('<QQQ',D,K,V)if populated else struct.pack('<Q',D))
   assert len(row['binary_parser_allocation_frames'])==(8 if populated and n else 7 if populated else 4);counts['source_reference_table_and_root_return_checked']+=1
   if data[0]==0xd4:
    assert has_pc(row,0xfffffe000c48a0f8)and not any(PARSER<=int(e['pc'],16)<0xfffffe000c48a8e0 and max(int(e['address'],16),MAPPED+8)<min(int(e['address'],16)+e['size_bytes'],MAPPED+12)for e in row['source_reads']);counts['source_D4_dictionary_index_skip_without_value_read_checked']+=1
   assert any(w['pc']=='0xfffffe000c48a198'and w['address']==hex(TABLE)and w['after_hex']==struct.pack('<Q',D).hex()for w in row['source_writes'])
   if populated:
    assert any(w['pc']=='0xfffffe000c44d09c'and w['address']==hex(PAIRS)and w['after_hex']==struct.pack('<Q',K).hex()for w in row['source_writes'])and any(w['pc']=='0xfffffe000c44d120'and w['address']==hex(PAIRS+8)and w['after_hex']==struct.pack('<Q',V).hex()for w in row['source_writes'])and any(w['pc']=='0xfffffe000c44d180'and w['address']==hex(D+0x14)and w['after_hex']=='01000000'for w in row['source_writes']);counts['original_dictionary_key_value_and_count_stores_checked']+=1
   if stage=='inverse':
    assert row['serialization_parser_frames'][1]['arguments'][2:]==['0x0']*4 and any(f['address']==hex(R+0x7c100)and f['bytes_hex']==producer['transport_frames'][0]['packet_hex']for f in row['initial_private_fixtures']);b=bytes.fromhex(row['final_rpc_buffers'][0]['bytes_hex']);assert u64(b,0x24)==0 and u64(b,0x34)==0 and u32(b,0x40)==0 and u64(b,0x5c)==DEV and u64(b,0x64)==D and row['boundary']['registers31'][0]=='0x0'and len(row['serialization_VM_frames'])==2;counts['original_inverse_publishes_actual_parser_root_and_clears_descriptors_checked']+=1
   else:
    assert c['options']==j-11 and row['serialization_parser_frames'][1]['arguments']==[hex(MAPPED),hex(len(data)),hex(FILTER),hex(COOKIE),hex(c['options']),hex(ERROR)]and not row['serialization_VM_frames']and row['boundary']['registers31'][0]==hex(D)and val(row,ERROR)==0;counts['separate_parser_component_options_and_error_slot_checked']+=1
    assert len(row['binary_parser_filter_frames'])==int(bool(c['options']&1))
    for f in row['binary_parser_filter_frames']:assert f['arguments']==[hex(COOKIE),hex(D),hex(K),hex(V)]and f['payload_hex']==payload.hex()
    counts['dictionary_filter_low_three_bit_options_checked']+=1
    if c['options']&1:assert any(e['modifier']=='0xfa46'and e['target']==hex(FILTER)for e in row['indirect_edges']);counts['source_authenticated_filter_ABI_edges_checked']+=1
  for k,m in enumerate(models):
   args=[int(v,16)for v in m['arguments8']];ret=int(m['return_value'],16);sym=m['symbol'];expected=[hex(((i+1)*0x123456789abcdef)^(k+1)*0x8b3dc651)for i in range(18)];expected[0]=hex(ret)
   if sym in['declared_parser_typed_buffer_allocation','declared_parser_bookkeeping_allocation']:expected[1]=m['return_register_X1'];assert int(expected[1],16)==(512 if sym.endswith('bookkeeping_allocation')else max(args[1],16))
   assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False
   if sym=='declared_parser_dictionary_allocation':assert args[0]==0xfffffe000cb51ab8 and ret==D
   elif sym=='declared_parser_data_allocation':assert args[0]==0xfffffe000cb51a90 and ret==V
   elif sym=='declared_parser_typed_buffer_allocation':assert(args[:4]==[0xfffffe0007f941d9,16*int(populated),0x41244,0]and ret==PAIRS)or(args[:4]==[0xfffffe0007f8bfb0,n,0x41a04,V+0x18]and ret==BYTES)
   elif sym=='declared_parser_bookkeeping_allocation':assert args[:6]==[0xfffffe0007f94549 if ret==TABLE else 0xfffffe0007f94599,0,0,512,0x41244,0]and ret in[TABLE,NEST]
   elif sym=='declared_parser_bookkeeping_free':assert args[:3]==[0xfffffe0007f945e9 if args[1]==TABLE else 0xfffffe0007f94639,args[1],512]and args[1]in[TABLE,NEST]and not m['memory_effects']
   elif sym=='declared_parser_symbol_intern':assert ret==K and row['binary_parser_symbol_frames'][0]['string_hex']=='6b6579'
   elif sym=='declared_parser_filter_passthrough':assert args[:4]==[COOKIE,D,K,V]and ret==V and not m['memory_effects']
   elif sym=='declared_parser_zero_byte_copy':assert n==0 and populated and args[0]==0 and args[2]==0 and ret==0 and not m['memory_effects']
   elif sym=='declared_private_memory_copy':assert args[:3]==[BYTES,MAPPED+(24 if data[0]==0xd4 else 20),n]and n>0 and ret==BYTES and m['memory_effects'][0]['after_hex']==payload.hex()
   elif sym=='declared_strcmp_result':assert args[0]==0xfffffe0007045578 and args[1]==MAPPED and ret==(0 if data[0]==0xd3 else 1)
   counts['API_'+sym]+=1
  totals.update(Replay(im,row).run());records.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'raw_X0':row['boundary']['registers31'][0],'root_identity':hex(D),'dictionary_entries':int(populated),'payload_bytes':n});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=19,functions=191,captured_instructions=17506,parser_instructions=882,binary_parser_binding_records=18,recaptured_binding_records=len(slots),unique_binding_slots=len({s['pointer']['slot']for s in slots}))
 deps=[P+'_source.json',P+'_profiles.json','iorpc_ool_serialization_profiles.json','iorpc_object_conversion_profiles.json','validate_aes_provider_queue.py','replay_'+P+'.py','replay_iorpc_ool_serialization.py','replay_iorpc_object_conversion.py','replay_iorpc_remote.py','replay_platform_iorpc.py','replay_aes_platform_gate.py','replay_aes_hardware_job.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
