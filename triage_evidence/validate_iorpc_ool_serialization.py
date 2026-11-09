#!/usr/bin/env python3
"""Recapture source/fixups and independently replay original OOL producer/consumer.
Finite byte/layout/ABI oracles, not native serialization or parser validation.
O(image+visits+effects+objects), O(image+journals+private RAM).
"""
import json,struct
from collections import Counter
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import definitions
from replay_iorpc_ool_serialization import Replay
from validate_aes_provider_queue import read,val
P='iorpc_ool_serialization';R=0x6500000000;DEV=R+0x2a000;DIC=R+0x70000;SER=R+0x71000;MD=R+0x74000;KEY=R+0x75000;VALUE=R+0x75100;COPY=R+0x76000;MAPPED=R+0x77000;RESTORED=R+0x7b000;TEXT=R+0x80000;MAP=R+0x7d000;VMCOUNT=0xfffffe000cb5b630;PARSER=0xfffffe000c489b18;MID=0xd8a753ea156f9162
FLAGS=['native_target_executed','native_IPC_executed','native_registry_or_platform_effects_executed','native_remote_transport_executed','native_port_objects_observed','native_object_port_registry_effects_executed','native_serialized_VM_or_parser_effects_executed','runtime_metaclass_hierarchy_established','runtime_device_or_controller_identity_established','hardware_PAC_executed','idb_mutated','full_goal_complete']
def u32(b,o):return int.from_bytes(b[o:o+4],'little')
def u64(b,o):return int.from_bytes(b[o:o+8],'little')
def globalscalar(row,a):return next(int.from_bytes(bytes.fromhex(e['bytes_hex']),'little')for e in row['final_serialization_globals']if int(e['address'],16)==a)
def expected_wire(c):
 index=not c.get('no_index_data');magic=0xd4 if index else 0xd3
 if 'payload_length'not in c:return struct.pack('<II',magic|(4<<6)if index else magic,0x81000000)+(struct.pack('<I',2)if index else b'')
 n=c['payload_length'];data=bytes((j*37+11)&255 for j in range(n));aligned=(n+3)&~3
 return struct.pack('<II',magic|(12<<6)if index else magic,0x81000001)+(struct.pack('<I',5+aligned//4)if index else b'')+struct.pack('<I',0x08000004)+b'key\0'+struct.pack('<I',0x8a000000|n)+data+bytes(aligned-n)
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());origin=json.loads((ROOT/'iorpc_object_conversion_profiles.json').read_text())['cases'][0];counts=Counter();totals=Counter();records=[]
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  assert all(obj[k]is False for k in FLAGS)
 assert len(src['functions'])==168 and sum(len(f['instructions'])for f in src['functions'])==14631 and src['kernel_sha256']==im.k.sha256
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f.get('bytes_hex',f.get('bytes'))and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 slots=sum((src[k]for k in ['additional_slots','iorpc_slots','remote_slots','object_conversion_slots','serialization_slots']),[])
 for s in slots:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 assert definitions(im.k,list(src['serialization_definitions']))==src['serialization_definitions']
 for c in src['SetProperties_constants']:assert im.k.read(int(c['address'],16),len(c['bytes_hex'])//2).hex()==c['bytes_hex']
 for h in src['SDK_serialization_headers']:assert sha(Path(h['path']))==h['sha256']and h['matched_collection_source_revision_established']is False
 g=src['kernel_map_file'];assert im.k.read(int(g['address'],16),8).hex()==g['bytes_hex']and g['runtime_identity_established']is False
 magic=src['binary_magic'];assert im.k.read(int(magic['address'],16),4).hex()==magic['bytes_hex']=='d3000000'
 assert PARSER not in [int(f['start'],16)for f in src['functions']]
 rows=prof['cases'];assert len(rows)==20
 reply=bytes.fromhex(rows[1]['final_rpc_buffers'][0]['bytes_hex']);assert u32(reply,4)==60 and u32(reply,0x1c)==0x4da2b68d and u32(reply,0x20)==0 and u64(reply,0x24)==MID and u64(reply,0x2c)==8 and u64(reply,0x34)==0
 for j,row in enumerate(rows):
  c=row['configuration'];stage=c['stage'];models=row['API_models'];assert row['initial_private_fixtures'][:173]==origin['final_objects']and len(row['final_objects'])==193 and all(row[k]is False for k in FLAGS);counts['exact_prior_actor_transfers_checked']+=1
  assert row['external_source_producer']=={'path':'iorpc_object_conversion_profiles.json','case':0}and row['source_producer_case']is None
  assert globalscalar(row,0xfffffe0007f860a8)==MAP and globalscalar(row,VMCOUNT)==(16384 if row['serialization_records']else 0)
  assert not any(int(v['pc'],16)==PARSER for v in row['source_visits']);counts['parser_body_unexecuted_cases_checked']+=1
  if stage=='build':
   f=row['rpc_frames'][0];b=bytes.fromhex(f['packet_hex']);assert[f['send_size'],f['reply_capacity']]==[108,128]and u32(b,4)==108 and u32(b,0x1c)==0x4da2b68c and u32(b,0x20)==2 and u64(b,0x34)==0x20 and u32(b,0x3c)==0x01000100 and u32(b,0x40)==0 and u64(b,0x44)==MID and u64(b,0x4c)==0 and u64(b,0x54)==2 and u64(b,0x5c)==DEV and u64(b,0x64)==DIC;assert not models and row['boundary']['kind']=='before_custom_dispatch';counts['original_two_descriptor_builder_checked']=1
  elif stage=='invoke':
   assert row['SetProperties_handler_frames'][0]['arguments']==[hex(DEV),hex(DIC)]and row['boundary']['registers31'][0]=='0x0';counts['original_nullable_dictionary_type_adapter_reply_checked']=1
  elif stage=='full':
   packet=bytes.fromhex(row['transport_frames'][0]['packet_hex']);assert u32(packet,0)==0x80001513 and u32(packet,4)==108 and u64(packet,0x44)==MID and u64(packet,0x4c)==5 and u64(packet,0x54)==2 and packet[0x5c:0x6c]==bytes(16)and u64(packet,0x24)==R+0x66000 and u32(packet,0x2c)==0x00110000
   assert row['transport_frames'][0]['arguments'][1:5]==['0x6c','0x80','0x0','0x0'];counts['original_remote_two_descriptor_frames_checked']+=1
   if c.get('null_dictionary'):assert not row['serialization_records']and u64(packet,0x34)==0 and u32(packet,0x40)==0;counts['nullable_OOL_without_serializer_checked']=1
   else:
    data=bytes.fromhex(row['serialization_records'][0]['bytes_hex']);assert data==expected_wire(c)and u64(packet,0x34)==COPY and u32(packet,0x3c)==0x01000000 and u32(packet,0x40)==len(data)and val(row,SER+0x10)==TEXT and val(row,SER+0x1c,4)==16384 and val(row,SER+0x18,4)==len(data)and val(row,MD+0xc,4)==(0 if c.get('no_index_data')else 12 if 'payload_length'in c else 4)
    assert row['serialization_records'][0]['arguments'][0:4]==[hex(MAP),hex(TEXT),hex(len(data)),'0x0'];counts['independent_binary_byte_and_OOL_extent_oracles_checked']+=1
    if c.get('no_index_data'):assert val(row,SER+0x50)==0;counts['optional_index_NULL_D3_cases_checked']+=1
    else:assert val(row,SER+0x50)==MD;counts['index_data_D4_cases_checked']+=1
   final=bytes.fromhex(row['final_rpc_buffers'][0]['bytes_hex'])
   if c.get('frontier'):assert row['boundary']['kind']=='before_kernel_transport_body'
   else:
    result=c.get('transport_result',0);assert row['boundary']['kind']=='returned'and int(row['boundary']['registers31'][0],16)==result
    if result:assert u64(final,0x24)==(R+0x66000 if c.get('message_moved')else 0)and u64(final,0x34)==COPY and u32(final,0x40)==32;counts['source_error_and_moved_cleanup_field_cases_checked']+=1
    else:assert final==reply;counts['source_adapter_reply_transfers_and_validation_checked']+=1
  else:
   assert stage=='inverse';producer=rows[c['packet_case']];data=bytes.fromhex(producer['serialization_records'][0]['bytes_hex']);initial=producer['transport_frames'][0]['packet_hex'];assert any(f['address']==hex(R+0x7c100)and f['bytes_hex']==initial for f in row['initial_private_fixtures']);counts['exact_packet_and_emitted_byte_consumer_transfers_checked']+=1
   fs=row['serialization_parser_frames'];assert len(fs)==2 and all(f['arguments'][:5]==[hex(MAPPED),hex(len(data)),'0x0','0x0','0x0']for f in fs)and fs[1]['pc']==hex(PARSER)and fs[1]['bytes_hex']==data.hex();counts['original_wrapper_D3_D4_parser_dispatch_checked']+=1
   assert row['serialization_VM_frames'][0]['arguments'][:5]==[hex(MAP),hex(int(row['serialization_VM_frames'][0]['arguments'][1],16)),hex(COPY),hex(len(data)),'0x1']
   b=bytes.fromhex(row['final_rpc_buffers'][0]['bytes_hex']);assert u64(b,0x24)==0 and u64(b,0x5c)==DEV
   if c.get('parser_frontier'):assert row['boundary']['kind']=='before_binary_parser_body'and u64(b,0x34)==COPY and u32(b,0x40)==len(data)and u64(b,0x64)==0;counts['unexecuted_parser_frontiers_checked']+=1
   else:assert row['boundary']['registers31'][0]=='0x0'and u64(b,0x34)==0 and u32(b,0x40)==0 and u64(b,0x64)==RESTORED and row['serialization_VM_frames'][1]['arguments']==[hex(MAP),hex(MAPPED),hex(len(data))];counts['source_consumer_deallocation_and_slot_clearing_checked']+=1
  for k,m in enumerate(models):
   args=[int(x,16)for x in m['arguments8']];ret=int(m['return_value'],16);sym=m['symbol'];expected=[hex(((i+1)*0x123456789abcdef)^(k+1)*0x8b3dc651)for i in range(18)];expected[0]=hex(ret)
   if sym=='declared_serializer_VM_allocation':expected[1]=hex(TEXT);assert m['return_register_X1']==hex(TEXT)and ret==0
   assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False
   if sym=='declared_private_memory_copy':assert m['memory_effects']==[]if args[2]==0 else len(m['memory_effects'])==1
   if sym=='declared_binary_parser_object':assert stage=='inverse'and not c.get('parser_frontier')and ret==RESTORED and not m['memory_effects']
   if sym=='declared_strcmp_result':assert args[0]==0xfffffe0007045578 and args[1]==MAPPED and ret==(0 if data[0]==0xd3 else 1)
   if sym=='declared_optional_index_allocation_NULL':assert c.get('no_index_data')and ret==0
   counts['API_'+sym]+=1
  totals.update(Replay(im,row).run());records.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'raw_X0':row['boundary']['registers31'][0],'serialized_extent_bytes':len(bytes.fromhex(row['serialization_records'][0]['bytes_hex']))if row['serialization_records']else None});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=20,functions=len(src['functions']),captured_instructions=sum(len(f['instructions'])for f in src['functions']),serialization_slots=57,recaptured_binding_records=len(slots),unique_binding_slots=len({s['pointer']['slot']for s in slots}))
 deps=[P+'_source.json',P+'_profiles.json','iorpc_object_conversion_profiles.json','validate_aes_provider_queue.py','replay_'+P+'.py','replay_iorpc_object_conversion.py','replay_iorpc_remote.py','replay_platform_iorpc.py','replay_aes_platform_gate.py','replay_aes_hardware_job.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
