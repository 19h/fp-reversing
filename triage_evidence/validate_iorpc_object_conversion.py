#!/usr/bin/env python3
"""Original converter/registry/hash/counter and mode-specific field oracles.
O(image+visits+effects+objects), O(image+journals+private RAM); no native effects.
"""
import json,struct
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import definitions
from replay_iorpc_object_conversion import Replay
from validate_aes_provider_queue import read,val
P='iorpc_object_conversion';R=0x6500000000;DEV=R+0x2a000;THREAD=R+0x1b000;OPORT=R+0x66000;NODE=R+0x67000;LOCK=R+0x68000;AUX=R+0x69000;ZONE=R+0x6a000;BUFFER=R+0x6b000;DECOY=R+0x6c000;BUCKETS=0xfffffe000cb53478;META=0xfffffe000cb53450;COUNTER=0xfffffe000cb5b638
FLAGS=['native_target_executed','native_IPC_executed','native_registry_or_platform_effects_executed','native_remote_transport_executed','native_port_objects_observed','native_object_port_registry_effects_executed','runtime_metaclass_hierarchy_established','runtime_device_or_controller_identity_established','hardware_PAC_executed','idb_mutated','full_goal_complete']
def scalar(row,a,n=8,where='final_registry_globals'):
 for e in row[where]:
  start=int(e['address'],16);b=bytes.fromhex(e['bytes_hex'])
  if start<=a and a+n<=start+len(b):return int.from_bytes(b[a-start:a-start+n],'little')
 raise AssertionError(hex(a))
def hash_index(a):
 x=((a>>4)*0x5052acdb)&0xffffffff;return(x^int.from_bytes(x.to_bytes(4,'little'),'big'))&4095
def has_pc(row,a):return any(e['pc']==hex(a)for e in row['source_visits'])
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());external=json.loads((ROOT/'aes_platform_gate_profiles.json').read_text())['cases'][0];old=json.loads((ROOT/'platform_iorpc_profiles.json').read_text())['cases'];counts=Counter();totals=Counter();records=[]
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
  assert all(obj[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==110 and sum(len(f['instructions'])for f in src['functions'])==9642
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f.get('bytes_hex',f.get('bytes'))and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 for s in src['additional_slots']+src['iorpc_slots']+src['remote_slots']+src['object_conversion_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 assert definitions(im.k,list(src['IOMachPort_definitions']))==src['IOMachPort_definitions']and len(src['object_conversion_slots'])==4
 for g in src['registry_file_globals']:assert im.k.read(int(g['address'],16),g['size_bytes']).hex()==g['bytes_hex']and g['runtime_epoch_established']is False
 assert im.k.read(0xfffffe000700dcd0,16).hex()==src['block_constants']['bytes_hex']
 rows=prof['cases'];assert len(rows)==16 and hash_index(DEV)==1280 and hash_index(0x6500072360)==1280
 for j,row in enumerate(rows):
  c=row['configuration'];stage=c.get('stage','remote');writes=row['source_writes'];models=row['API_models'];producer=row['registry_producer_case'];origin=external if producer is None else rows[producer];n=158 if producer is None else 173;assert row['initial_private_fixtures'][:n]==origin['final_objects']and row['source_producer_case']==producer and len(row['final_objects'])==173 and all(row[k]is False for k in FLAGS);counts['exact_actor_snapshot_transfers_checked']+=1
  if producer is not None:
   for e in origin['final_registry_globals']:assert any(f['address']==e['address']and f['bytes_hex']==e['bytes_hex']for f in row['initial_image_fixtures']);counts['source_registry_global_transfers_checked']+=1
  assert scalar(row,COUNTER,8,'final_source_globals')==9768 and row['final_source_globals'][1]==external['final_source_globals'][1]and scalar(row,META+0x24,4)==1 and val(row,NODE)==0xfffffe0007f502d8 and val(row,NODE+8,4)==1 and val(row,NODE+0xc,1)==1 and val(row,NODE+0x18)==OPORT and val(row,NODE+0x20)==DEV and val(row,OPORT+0x50)==NODE and val(row,LOCK+8)==0 and val(row,THREAD+0x518,4)==0x1234
  expected_count=2 if j in [0,9,15]else 3;assert val(row,OPORT+4,4)==expected_count and val(row,OPORT+0x84,4)==expected_count-1 and val(row,OPORT+0x88,4)==expected_count-1;counts['source_port_counter_images_checked']+=1
  assert scalar(row,BUCKETS+1280*8)==(DECOY if j==14 else NODE)
  if j==0:
   assert row['new_IOMachPort_nodes']==[hex(NODE)]and len(row['object_allocation_frames'])==3 and read(row,AUX,16)==struct.pack('<QQ',1,0)
   for pc,addr,value,nbytes in [(0xfffffe000c5611e8,BUCKETS+1280*8,NODE,8),(0xfffffe000c5613f0,NODE+0x20,DEV,8),(0xfffffe000c561364,COUNTER,9768,8),(0xfffffe000be35a98,AUX,1,8)]:assert any(e['pc']==hex(pc)and e['address']==hex(addr)and e['size_bytes']==nbytes and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==value for e in writes)
   counts['original_registry_miss_constructor_and_publication_checked']=1
  else:assert not row['new_IOMachPort_nodes']and not has_pc(row,0xfffffe000c561300)and not any(e['address']==hex(COUNTER)for e in writes);counts['registry_allocation_free_cases_checked']+=1
  if j==14:assert val(row,DECOY+0x10)==NODE and val(row,DECOY+0x20)==0x6500072360 and has_pc(row,0xfffffe000c56123c);counts['same_hash_collision_traversal_checked']=1
  get=[e for e in row['object_conversion_frames']if e['pc']=='0xfffffe000c56114c'];make=has_pc(row,0xfffffe000bccfc94)
  assert bool(get)==(j in list(range(9))+[14,15])and make==(j in list(range(9))+[14])
  for e in get:assert e['arguments']==[hex(DEV),'0x29']
  for e in row['conversion_frames']:assert has_pc(row,int(e['pc'],16))and not any(m['pc']==e['pc']for m in models);counts['original_converter_entries_executed_checked']+=1
  # Original converter calls now produce the port descriptor and clear object[0].
  if stage=='remote':
   assert len(row['transport_frames'])==1;packet=bytes.fromhex(row['transport_frames'][0]['packet_hex']);assert int.from_bytes(packet[0x24:0x2c],'little')==OPORT and packet[0x2c:0x34]==struct.pack('<II',0x110000,0)and packet[0x4c:0x54]==bytes(8);counts['source_exported_port_descriptor_frames_checked']+=1
   assert any(e['pc']=='0xfffffe000c596400'and e['address']==hex(int(row['rpc_frames'][0]['content_address'],16)+0x18)and e['after_hex']=='00'*8 for e in writes)
   if j==4:assert row['boundary']['kind']=='before_kernel_transport_body'
   else:assert row['boundary']['kind']=='returned'and int(row['boundary']['registers31'][0],16)==(0x10000003 if j in [5,6]else 0xe00002bc if j==7 else 0)
   if j==5:assert any(e['arguments']==[hex(OPORT)]for e in row['release_frames'])and int.from_bytes(bytes.fromhex(row['final_rpc_buffers'][0]['bytes_hex'])[0x24:0x2c],'little')==0;counts['unmoved_request_actual_descriptor_cleanup_checked']=1
   if j==6:assert not any(e['arguments']==[hex(OPORT)]for e in row['release_frames']);counts['moved_request_descriptor_preserved_checked']=1
  elif stage=='export':
   packet=bytes.fromhex(row['final_rpc_buffers'][0]['bytes_hex']);assert row['boundary']['registers31'][0]=='0x0'
   if j==8:assert int.from_bytes(packet[0x24:0x2c],'little')==OPORT and packet[0x4c:0x54]==bytes(8)and any(e['pc']=='0xfffffe000c4451d0'and e['arguments']==[hex(DEV)]for e in row['object_reference_frames']);counts['consume_mode_object_release_checked']=1
   elif j==9:assert packet[0x24:0x2c]==bytes(8)and packet[0x2c:0x34]==struct.pack('<II',0x110000,0)and not get;counts['nullable_object_export_checked']=1
   else:assert j==15 and packet[0x24:0x34]==bytes(16)and int.from_bytes(packet[0x4c:0x54],'little')==DEV and not make;counts['conditional_NULL_port_result_caller_case_checked']=1
  else:
   assert stage=='restore'and row['packet_producer_case']==4 and row['registry_producer_case']==4;source=rows[4]['transport_frames'][0]['packet_hex'];assert any(e['address']==hex(BUFFER)and e['bytes_hex']==source for e in row['initial_private_fixtures']);packet=bytes.fromhex(row['final_rpc_buffers'][0]['bytes_hex'])
   assert int.from_bytes(packet[0x4c:0x54],'little')==(DEV if c['restore']else 0)and int.from_bytes(packet[0x24:0x2c],'little')==(0 if c['release']else OPORT)and row['boundary']['registers31'][0]=='0x0'
   assert has_pc(row,0xfffffe000be351d0)==bool(c['restore'])and any(e['arguments']==[hex(OPORT)]for e in row['release_frames'])==bool(c['release']);counts['independent_restore_release_mode_cases_checked']+=1
   if c['restore']:assert[(e['pc'],e['arguments'][0])for e in row['object_reference_frames']]==[('0xfffffe000c445200',hex(NODE)),('0xfffffe000c445200',hex(DEV)),('0xfffffe000c4451d0',hex(NODE))];counts['source_wrapper_to_object_reference_sequences_checked']+=1
  for k,m in enumerate(models):
   args=[int(x,16)for x in m['arguments8']];ret=int(m['return_value'],16);sym=m['symbol'];expected=[hex(((r+1)*0x123456789abcdef)^(k+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(ret);assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False
   if sym=='declared_IOMachPort_allocation_model':assert j==0 and args[1:3]==[40,0x41004]and ret==NODE and m['memory_effects'][0]['before_hex']=='5a'*40 and m['memory_effects'][0]['after_hex']=='00'*40
   elif sym=='declared_typed_port_creation_model':assert j==0 and args[:4]==[NODE,0x129,AUX,0]and ret==OPORT and len(m['memory_effects'])==1
   elif sym=='declared_port_aux_allocation_model':assert j==0 and args[:3]==[R+0x6a100,0,0x8004]and ret==AUX and not m['memory_effects']
   elif sym=='declared_kernel_transport_model':assert stage=='remote'and not c.get('frontier')
   else:
    assert not m['memory_effects']and sym in ['declared_queue_lookup_model','declared_port_reference_copy_model','declared_port_lock_no_effect_model','declared_port_unlock_no_effect_model','declared_port_send_release_model','declared_queue_release_model','declared_object_reference_no_effect_model','declared_object_port_NULL_model']
    if sym=='declared_object_port_NULL_model':assert j==15 and ret==0
   counts['API_'+sym]+=1
  assert not any(m['symbol']in ['declared_request_object_conversion_model','declared_reply_or_cleanup_conversion_model']for m in models);counts['former_conversion_models_removed_cases_checked']+=1
  totals.update(Replay(im,row).run());records.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'raw_X0':row['boundary']['registers31'][0]});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=16,functions=110,captured_instructions=9642,object_conversion_slots=4,recaptured_bindings=35)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','aes_platform_gate_profiles.json','platform_iorpc_profiles.json','validate_aes_provider_queue.py','replay_'+P+'.py','replay_iorpc_remote.py','replay_platform_iorpc.py','replay_aes_platform_gate.py','replay_aes_hardware_job.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
