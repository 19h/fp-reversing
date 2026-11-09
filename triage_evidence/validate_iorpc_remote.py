#!/usr/bin/env python3
"""Original remote IORPC route/header/transport/reply and cleanup ABI oracles.
O(image+visits+effects+objects), O(image+journals+private RAM); no native effects.
"""
import json,struct
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import definitions
from replay_iorpc_remote import Replay
from validate_aes_provider_queue import read,val
P='iorpc_remote';R=0x6500000000;DEV=R+0x2a000;OUT=R+0x2f000;THREAD=R+0x1b000;EXP=R+0x60000;LINK=R+0x61000;SERVER=R+0x62000;QUEUE=R+0x63000;QDATA=R+0x64000;PORT=R+0x65000;REMOTE=0xfffffe000c595bf8;RPC=0xfffffe000bcf59e0;SEND=0xfffffe000bcf55dc;REQ=0xfffffe000c5962c0;CONVERT=0xfffffe000c5968d8;RELEASE=0xfffffe000bcd0448
FLAGS=['native_target_executed','native_IPC_executed','native_registry_or_platform_effects_executed','native_remote_transport_executed','native_port_objects_observed','runtime_metaclass_hierarchy_established','runtime_device_or_controller_identity_established','hardware_PAC_executed','idb_mutated','full_goal_complete']
def ints(e):return[int(x,16)for x in e['arguments']]
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());origin=json.loads((ROOT/'aes_platform_gate_profiles.json').read_text())['cases'][0];old=json.loads((ROOT/'platform_iorpc_profiles.json').read_text())['cases'];counts=Counter();totals=Counter();records=[]
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
  assert all(obj[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==100 and sum(len(f['instructions'])for f in src['functions'])==9148
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f.get('bytes_hex',f.get('bytes'))and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 for s in src['additional_slots']+src['iorpc_slots']+src['remote_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 assert len(src['remote_slots'])==7 and all(s['pointer']['auth']==1 and s['pointer']['address_diversity']==1 and s['pointer']['key']==0 for s in src['remote_slots'])and definitions(im.k,list(src['remote_definitions']))==src['remote_definitions']
 assert im.k.symbols([int(a,16)for a in src['route_anchors']])==src['route_anchors']
 co=src['remote_header_constant'];assert im.k.read(int(co['address'],16),8).hex()==co['bytes_hex']=='000000008cb6a24d'
 prior=json.loads((ROOT/'kernel_rpc_transport_contracts.json').read_text());a=next(f for f in src['functions']if f['start']==hex(RPC));b=next(f for f in prior['native_ranges']if f['start']==hex(RPC));assert a['bytes']==b['bytes']and a['instructions']==b['instructions'];counts['same_FairPlay_common_transport_source_join_checked']=1
 priorcopy=json.loads((ROOT/'rpc700_namespace_contracts.json').read_text());a=next(f for f in src['functions']if f['start']=='0xfffffe000bcd00bc');b=next(f for f in priorcopy['kernel_functions']if f['start']==a['start']);assert a['bytes']==b['bytes'];counts['same_prior_port_reference_copy_source_join_checked']=1
 rows=prof['cases'];assert len(rows)==16
 for j,row in enumerate(rows):
  cfg=row['configuration'];method=cfg['method'];mi={'clock':0,'power':1,'psd':2}[method];previous=old[mi]['rpc_frames'][0];reply=old[mi+3]['final_rpc_buffers'][0];oneway=cfg.get('oneway_component',False);frontier=cfg.get('frontier',False);models=row['API_models'];writes=row['source_writes'];assert all(row[k]is False for k in FLAGS)and len(row['final_objects'])==166 and row['initial_private_fixtures'][:158]==origin['final_objects']and row['final_source_globals']==origin['final_source_globals'];counts['exact_actor_and_global_transfers_checked']+=1
  for e in origin['final_objects']:
   addr=int(e['address'],16);expected=bytearray.fromhex(e['bytes_hex'])
   if addr==DEV:struct.pack_into('<Q',expected,0x28,EXP)
   assert read(row,addr,len(expected))==expected;counts['prior_object_images_with_declared_device_link_checked']+=1
  assert val(row,DEV+0x28)==EXP and val(row,EXP+0x28)==LINK and val(row,LINK)==SERVER and val(row,SERVER)==0xfffffe0007f56050 and val(row,QUEUE)==0xfffffe0007f354a8 and val(row,QUEUE+0x10)==QDATA and val(row,QDATA+0x28)==PORT and val(row,THREAD+0x378)==0x1122334455667788 and not any(e['address']==hex(THREAD+0x378)for e in writes)
  assert not any(row[k]for k in ['dispatch_frames','invoke_frames','thunk_frames','thread_frames','device_method_frames','controller_method_frames','job_allocations','DMA_allocations']);counts['remote_without_local_dispatch_or_thread_clear_checked']+=1
  env={e['address']:e['bytes_hex']for e in row['final_environment_globals']};assert env['0xfffffe000cc08998']==struct.pack('<Q',0xfffffe000cb5c060).hex()and env['0xfffffe000cb5c070']=='00'*8
  assert len(row['rpc_frames'])==len(row['remote_frames'])==1;f=row['rpc_frames'][0];remote=row['remote_frames'][0];a=int(f['message_address'],16);content=a+0x34;send=previous['send_size'];capacity=previous['reply_capacity'];request=bytearray.fromhex(previous['packet_hex']);struct.pack_into('<Q',request,0x3c,0x8d if oneway else 0x85)
  assert remote['pc']==hex(REMOTE)and ints(remote)==[SERVER,int(remote['rpc_address'],16)]and remote['packet_hex']==request.hex()and remote['rpc32_hex']==f['rpc32_hex']and remote['send_size']==send and remote['reply_capacity']==capacity
  if oneway:
   assert f['packet_hex']==request.hex()and row['external_request_packet_producer']=={'path':'platform_iorpc_profiles.json','case':mi}and row['entry_SP']==hex(R+0xef800)
   assert any(e['address']==previous['rpc_address']and e['bytes_hex']==previous['rpc32_hex']for e in row['initial_private_fixtures'])and any(e['address']==previous['message_address']and e['bytes_hex']==request.hex()for e in row['initial_private_fixtures']);counts['source_request_component_transfers_checked']+=1
  else:assert f['packet_hex']==previous['packet_hex'];counts['original_builder_to_server_routes_checked']+=1
  assert row['external_reply_packet_producer']=={'path':'platform_iorpc_profiles.json','case':mi+3}
  if j==10:assert not row['queue_lookup_frames']
  else:assert len(row['queue_lookup_frames'])==1 and ints(row['queue_lookup_frames'][0])==[0xfffffe000cb5c060,DEV,struct.unpack_from('<Q',request,0x34)[0]]
  if row['port_copy_frames']:assert len(row['port_copy_frames'])==1 and ints(row['port_copy_frames'][0])==[PORT]
  transport=row['transport_frames'];converted=row['conversion_frames'];releases=row['release_frames']
  if j in [9,10,11]:assert not transport and not converted
  else:
   assert len(transport)==1 and transport[0]['pc']==hex(SEND if oneway else RPC);ta=ints(transport[0]);assert ta[:2]==[a,send]and(ta[2:4]==[0x50001,0]if oneway else ta[2:5]==[capacity,0,0]);counts['transport_argument_frames_checked']+=1
   outgoing=bytearray(request);struct.pack_into('<I',outgoing,0,0x80000013 if oneway else 0x80001513);struct.pack_into('<QQ',outgoing,8,PORT,0);outgoing[0x18:0x20]=bytes.fromhex(co['bytes_hex']);assert transport[0]['packet_hex']==outgoing.hex();counts['source_outgoing_header_oracles_checked']+=1
   for pc,addr,n,value in [('0xfffffe000c595d70',a,4,0x80000013 if oneway else 0x80001513),('0xfffffe000c595d74',a+8,8,PORT),('0xfffffe000c595d74',a+0x10,8,0)]:assert any(e['pc']==pc and e['address']==hex(addr)and e['size_bytes']==n and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==value and e['source_visit_index']<transport[0]['before_source_visit_index']for e in writes)
   assert converted[0]['pc']==hex(REQ)and ints(converted[0])[:5]==[SERVER,a,content,send,0]
   if frontier:assert row['boundary']['kind']=='before_kernel_transport_body'and row['boundary']['pc']==hex(RPC)and not any(m['symbol']=='declared_kernel_transport_model'for m in models)
   else:
    assert row['boundary']['kind']=='returned'and row['boundary']['SP']==row['entry_SP'];assert[(e['pc'],ints(e)[0])for e in releases]==[(hex(RELEASE),PORT),('0xfffffe000c4451d0',QUEUE)]
    assert transport[0]['before_source_visit_index']<releases[0]['before_source_visit_index']<releases[1]['before_source_visit_index'];counts['port_then_queue_release_order_checked']+=1
    if j in [6,15]:assert len(converted)==2 and ints(converted[1])==[SERVER,a,content,send,0,1];counts['unmoved_request_cleanup_cases_checked']+=1
    elif j==7:assert len(converted)==1;counts['moved_request_cleanup_skip_checked']=1
    elif not oneway:
     assert ints(converted[1])==[SERVER,a,a+0x24,68 if j==12 else [60,64,60][mi],0 if j==12 else 1,1]
     if j==13:assert len(converted)==3 and ints(converted[2])==[SERVER,a,a+0x24,60,0,1]and len(row['reply_cleanup_frames'])==1;counts['conditional_reply_conversion_cleanup_checked']=1
     else:assert len(converted)==2
     counts['reply_content_and_conversion_modes_checked']+=1
  if j==8:assert[(e['pc'],ints(e)[0])for e in releases]==[('0xfffffe000c445200',QUEUE)];counts['fallback_queue_retain_frontier_checked']=1
  if j in [9,10]:assert not releases
  if j==11:assert[(e['pc'],ints(e)[0])for e in releases]==[('0xfffffe000c4451d0',QUEUE)]
  if not frontier:
   expected={9:0xe00002d8,10:0xe00002d7,11:0xe00002d8,12:0xe00002bc,13:0x2e}.get(j,cfg.get('transport_result',0));assert int(row['boundary']['registers31'][0],16)==expected;counts['returned_status_cases_checked']+=1
  assert val(row,OUT,4)==(0x12345678 if j==4 else 0xa5a5a5a5)and read(row,OUT+4,12)==b'\xa5'*12
  for k,m in enumerate(models):
   aa=[int(x,16)for x in m['arguments8']];ret=int(m['return_value'],16);sym=m['symbol'];expected=[hex(((r+1)*0x123456789abcdef)^(k+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(ret);assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False
   if sym=='declared_kernel_transport_model':
    effects=m['memory_effects'];assert effects[0]['address']==hex(aa[4 if oneway else 5])and effects[0]['after_hex']==struct.pack('<I',cfg.get('message_moved',1 if ret==0 else 0)).hex()
    if not oneway and ret==0:
     b=bytearray.fromhex(reply['bytes_hex'])
     if j==12:struct.pack_into('<I',b,4,68);struct.pack_into('<Q',b,0x2c,0x48);struct.pack_into('<I',b,0x3c,0xe00002bc)
     assert len(effects)==2 and effects[1]['address']==hex(a)and effects[1]['after_hex']==b.hex();counts['declared_source_reply_transfers_checked']+=1
    else:assert len(effects)==1
   else:
    assert not m['memory_effects']
    if sym=='declared_queue_lookup_model':assert aa[1:3]==[DEV,struct.unpack_from('<Q',request,0x34)[0]]and ret==(0 if cfg.get('lookup_NULL')else QUEUE)
    elif sym=='declared_port_reference_copy_model':assert aa[0]==PORT and ret==(0 if cfg.get('port_NULL')else PORT)
    else:assert sym in ['declared_request_object_conversion_model','declared_reply_or_cleanup_conversion_model','declared_reply_cleanup_model','declared_port_send_release_model','declared_queue_retain_model','declared_queue_release_model']
   counts['API_'+sym]+=1
  assert all(R<=int(e['address'],16)<R+0x100000 for e in writes)and not any(e['pc']in [hex(RPC),hex(SEND)]for e in row['source_visits']);counts['native_transport_bodies_unexecuted_checked']+=1
  totals.update(Replay(im,row).run());records.append({'case':j,'configuration':cfg,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'raw_X0':row['boundary']['registers31'][0]});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=16,functions=100,captured_instructions=9148,remote_slots=7,recaptured_bindings=31)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','platform_iorpc_profiles.json','aes_platform_gate_profiles.json','kernel_rpc_transport_contracts.json','rpc700_namespace_contracts.json','validate_aes_provider_queue.py','replay_'+P+'.py','replay_platform_iorpc.py','replay_aes_platform_gate.py','replay_aes_hardware_job.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
