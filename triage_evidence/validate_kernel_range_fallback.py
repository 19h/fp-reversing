#!/usr/bin/env python3
"""Original fallback marker and reservation-abort bitmap/store/record contracts.
O(image+visits+RAM+effects), O(image+RAM+journals). Separate calls and modeled
primitives do not prove a live validation error, native ownership or VM effects.
"""
import json,struct
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_rpc502_vm_handoff import decode
from replay_kernel_vm_entry_copy import Replay as FactoryReplay
from replay_kernel_map_store_init import Replay as ConstructReplay
from replay_kernel_range_fallback import Replay
P='kernel_range_fallback';R=0x6500000000;SIZE=0x100000;KMAP=R+0x2e000;COPY=R+0x68000;NEW=0xfffffe0001000040;REC=0xfffffe00010000c0;ROOTPAGE=0xfffffe0003000000;STATE=0xfffffe000cb80d60;RZ=R+0xb6000;RA=R+0xb6100
FLAGS=['native_target_executed','native_VM_effects_executed','native_retirement_executed','native_namespace_conversion_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']
def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());factory=json.loads((ROOT/'kernel_vm_entry_copy_profiles.json').read_text())['cases'][4];constructed=json.loads((ROOT/'kernel_map_store_init_profiles.json').read_text())['cases'][0];counts=Counter();totals=Counter();summaries=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  assert all(obj[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==76 and sum(len(f['instructions'])for f in src['functions'])==13296
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 factory_replay=FactoryReplay(im,factory).run();constructor_replay=ConstructReplay(im,constructed).run();counts['fresh_copy_and_map_producer_reconstructions_checked']=2;rows=prof['cases'];assert len(rows)==19
 for j,row in enumerate(rows):
  c=row['configuration'];phase=c['phase'];ram=decode(row['final_private_RAM']);mapbytes=bytes.fromhex(row['destination_map256_hex']);rootbytes=bytes.fromhex(row['root256_hex']);record=bytes.fromhex(row['range_record64_hex']);node=bytes.fromhex(row['new_entry64_hex']);header=bytes.fromhex(row['working_copy_header48_hex']);bucket=bytes.fromhex(row['range_bucket448_hex']);models=row['API_models'];names=[m['symbol']for m in models];assert all(row[k]is False for k in FLAGS)and row['thread_active_cursor']=='0x0'and row['thread_entry_nesting']==0;counts['zero_cursor_nesting_at_components_checked']+=1
  transfer=row['initial_state_transfer'];parent=constructed if j<3 else rows[transfer['case']];assert transfer['path']==('kernel_map_store_init_profiles.json'if j<3 else P+'_profiles.json')and decode(transfer)==decode(parent['final_private_RAM'])and row['initial_private_fixtures'][:3]==parent['final_auxiliary_regions'];counts['exact_primary_auxiliary_component_transfers_checked']+=1
  inherited=[{**e,'provenance':'Exact original map-constructor/component final-global transfer'}for e in parent['final_image_globals']];assert row['initial_image_fixtures'][:len(inherited)]==inherited;counts['exact_inherited_global_transfers_checked']+=1
  assert 'declared_type2_destination_resolver'not in names and 'declared_packed_store_position_model'not in names;counts['no_whole_range_or_position_model_checked']+=1
  if j<3:
   assert transfer['case']==0 and row['initial_private_fixtures'][-1]=={'address':hex(KMAP+0xb0),'bytes_hex':struct.pack('<I',c['map_flags']).hex()}and ram[0x18040:0x18040+392]==decode(constructed['final_private_RAM'])[0x18040:0x18040+392]and ram[0x69000:0x69030]==decode(constructed['final_private_RAM'])[0x69000:0x69030];counts['declared_map_flag_epoch_and_other_descriptor_preservation_checked']+=1
  else:assert row['initial_private_fixtures']==parent['final_auxiliary_regions']and row['initial_image_fixtures']==inherited
  if phase=='fallback':
   destination=R+0x4000 if c['map_flags']==8 else R;end=destination+49152;wantmap=bytearray.fromhex(constructed['destination_map256_hex']);struct.pack_into('<QQ',wantmap,0,NEW,NEW);struct.pack_into('<Q',wantmap,0x20,49152);struct.pack_into('<I',wantmap,0x28,1);struct.pack_into('<Q',wantmap,0x50,ROOTPAGE);struct.pack_into('<I',wantmap,0xb0,c['map_flags']);struct.pack_into('<Q',wantmap,0xa0,end if c['map_flags']==8 else 0);wantroot=bytearray(256);struct.pack_into('<I',wantroot,0,0x10003);struct.pack_into('<QQQ',wantroot,0x10,destination,end,(1<<64)-1);struct.pack_into('<I',wantroot,0xac,0x40001);wantnode=bytearray(64);struct.pack_into('<I',wantnode,0,0x10000);struct.pack_into('<QQ',wantnode,0x10,destination,end);struct.pack_into('<I',wantnode,0x38,0x5730)
   assert row['boundary']['kind']=='returned'and row['raw_return_u32']==0 and mapbytes==bytes(wantmap)and rootbytes==bytes(wantroot)and node==bytes(wantnode)and header==bytes(48)and record==bytes(64)and bucket==bytes(448)and row['cached_rng_u64']==0x12345678 and row['output16_hex']==struct.pack('<Q',destination).hex()+'a5'*8;counts['original_complete_fallback_direct_store_oracles_checked']+=1
   assert row['lower_allocator_return_frames'][0]['arguments']==['0x2e']and row['range_result_frames'][0]['arguments']==['0x0']and row['range_result_frames'][0]['out_pair16_hex']==struct.pack('<QQ',destination|(1<<63),0).hex()and any(e['pc']=='0xfffffe000bdc7564'for e in row['source_visits']);counts['original_2e_fallback_marked_address_null_token_join_checked']+=1
   gap=next(f for f in row['fallback_frames']if f['pc']=='0xfffffe000bdde280');assert gap['arguments'][:6]==[hex(KMAP),hex(R),hex(R+SIZE),'0x6000000000000000','0xc000','0x3fff']and names==['map_lock_model','declared_store_memmove','declared_store_memmove','header_bzero_model','copy_header_release_request','map_unlock_model'];counts['original_generic_search_ABI_and_no_record_or_rng_consumption_checked']+=1
  elif phase=='reserve':
   wantroot=bytearray(256);struct.pack_into('<I',wantroot,0,0x10003);struct.pack_into('<QQQ',wantroot,0x10,R,R+SIZE,(1<<64)-1);struct.pack_into('<I',wantroot,0xac,0x80040003);wantmap=bytearray.fromhex(constructed['destination_map256_hex']);struct.pack_into('<Q',wantmap,0x50,ROOTPAGE);wantrecord=bytearray(64);struct.pack_into('<Q',wantrecord,0,STATE);struct.pack_into('<I',wantrecord,8,R>>16);wantrecord[12:16]=bytes([16,16,4,11]);struct.pack_into('<Q',wantrecord,16,0xfeff);struct.pack_into('<II',wantrecord,24,0x80040003,0x80040003);wantbucket=bytearray(448);struct.pack_into('<Q',wantbucket,16,REC)
   assert row['boundary']['kind']=='before_post_reservation_validation'and row['boundary']['pc']=='0xfffffe000bdcb570'and mapbytes==bytes(wantmap)and rootbytes==bytes(wantroot)and record==bytes(wantrecord)and bucket==bytes(wantbucket)and node==bytes.fromhex(factory['new_entry64_hex'])and header==bytes.fromhex(factory['working_copy_header48_hex'])and row['output16_hex']=='a5'*16 and row['cached_rng_u64']==0 and row['range_result_frames'][0]['out_pair16_hex']==struct.pack('<QQ',R+0x80000,REC).hex();counts['exact_source_produced_pre_insertion_reservation_frontier_checked']=1
  elif phase=='rollback':
   assert transfer['case']==2 and row['entry_PC']=='0xfffffe000bde01b0'and row['boundary']['kind']=='returned'and node==bytes.fromhex(factory['new_entry64_hex'])and header==bytes.fromhex(factory['working_copy_header48_hex'])and row['output16_hex']=='a5'*16 and row['cached_rng_u64']==0;counts['standalone_abort_call_without_insertion_or_return_status_claim_checked']+=1
   address=R+0x80000|(1<<63 if c['token_kind']=='signed_address'else 0);token=0 if c['token_kind']=='zero'else REC;assert row['fallback_frames'][0]['arguments']==[hex(KMAP),hex(address),hex(token)];counts['rollback_argument_ABI_checked']+=1
   if c['token_kind']!='record':
    assert not models and mapbytes==bytes.fromhex(parent['destination_map256_hex'])and rootbytes==bytes.fromhex(parent['root256_hex'])and record==bytes.fromhex(parent['range_record64_hex'])and bucket==bytes.fromhex(parent['range_bucket448_hex'])and len(row['fallback_frames'])==1;counts['original_zero_token_or_bit63_data_state_noop_checked']+=1
   else:
    wantroot=bytearray.fromhex(parent['root256_hex']);struct.pack_into('<I',wantroot,0,0x10001);struct.pack_into('<Q',wantroot,0x10,(1<<64)-1);assert rootbytes==bytes(wantroot)and mapbytes==bytes.fromhex(parent['destination_map256_hex'])and record==bytes(64)and bucket==bytes(448)and names==['declared_store_or_record_zeroing','copy_header_release_request'];counts['original_bucket_unlink_pool_coalescing_and_record_retirement_checked']=1
    assert any(w['pc']=='0xfffffe000bde0348'and w['address']==hex(REC+16)and w['after_hex']=='ffff000000000000'for w in row['source_writes'])and any(f['pc']=='0xfffffe000bde0334'and f['arguments']==[hex(REC),'0x100']for f in row['fallback_frames'])and any(f['pc']=='0xfffffe000bde0578'and f['arguments']==[hex(KMAP+0x48),'0x0','0xffffffffffffffff']for f in row['fallback_frames']);counts['last_slot_return_to_entire_pool_removal_join_checked']=1
    assert models[-1]['arguments8'][:4]==[hex(RZ),hex(RA),hex(REC),'0x40']and val(rootbytes,0xac,4)==0x80040003 and val(mapbytes,0x50)==ROOTPAGE;counts['inactive_root_bits_and_hint_distinguished_from_live_record_checked']=1
  else:
   assert phase=='lookup'and row['boundary']['kind']=='returned'and not models and not row['declared_effects']and mapbytes==bytes.fromhex(parent['destination_map256_hex'])and rootbytes==bytes.fromhex(parent['root256_hex'])and record==bytes.fromhex(parent['range_record64_hex'])and bucket==bytes.fromhex(parent['range_bucket448_hex']);parent_index=transfer['case']
   if parent_index in[0,1]:destination=val(bytes.fromhex(parent['output16_hex']),0);inside=destination<=c['query']<destination+49152;assert row['raw_return_u32']==int(inside)and row['lookup_output']==hex(NEW if c['query']<destination+49152 else 0);counts['real_lookup_after_original_fallback_checked']+=1
   else:assert parent_index in[3,4,5]and row['raw_return_u32']==0 and row['lookup_output']=='0x0';counts['real_lookup_with_retained_or_removed_pool_without_entry_checked']+=1
  for k,m in enumerate(models):
   want=[hex(((i+1)*0x123456789abcdef)^(k+1)*0x8b3dc651)for i in range(18)];want[0]=m['return_value'];assert m['after_registers31'][:18]==want and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False
  totals.update(Replay(im,row).run());summaries.append({'case':j,'phase':phase,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'copyout_or_lookup_result':row['raw_return_u32']if phase in['fallback','lookup']else None});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=19,functions=76,captured_instructions=13296)
 deps=[P+'_source.json',P+'_profiles.json','kernel_map_store_init_profiles.json','kernel_vm_entry_copy_profiles.json','replay_'+P+'.py','replay_kernel_range_resolver.py','replay_kernel_map_store_init.py','replay_kernel_type2_copyout.py','replay_kernel_vm_entry_copy.py','replay_kernel_vm_range_cursor.py','replay_rpc502_vm_handoff.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_factory_replay':factory_replay,'fresh_constructor_replay':constructor_replay,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
