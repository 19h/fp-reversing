#!/usr/bin/env python3
"""Original range reservation, cached-random slot selection and tagged-record ABI.
O(image+visits+RAM+effects), O(image+RAM+journals). Declared bounds/cache/zone epochs;
no native boot-state, mapping, entropy, rights, retirement or FairPlay IPC proof.
"""
import json,struct
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_rpc502_vm_handoff import decode
from replay_kernel_vm_entry_copy import Replay as FactoryReplay
from replay_kernel_map_store_init import Replay as ConstructReplay
from replay_kernel_range_resolver import Replay
P='kernel_range_resolver';R=0x6500000000;SIZE=0x100000;KMAP=R+0x2e000;COPY=R+0x68000;NEW=0xfffffe0001000040;REC=NEW+128;ROOTPAGE=0xfffffe0003000000;STATE=0xfffffe000cb80d60;RNG=0xfffffe000cb810e0;BOUNDS=0xfffffe0007e69fe0;RZ=R+0xb6000;RA=R+0xb6100;TAG=0x80040003
FLAGS=['native_target_executed','native_VM_effects_executed','native_retirement_executed','native_namespace_conversion_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']
def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());factory=json.loads((ROOT/'kernel_vm_entry_copy_profiles.json').read_text())['cases'][4];constructed=json.loads((ROOT/'kernel_map_store_init_profiles.json').read_text())['cases'][0];counts=Counter();totals=Counter();summaries=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  assert all(obj[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==72 and sum(len(f['instructions'])for f in src['functions'])==12376
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 for e in src['range_file_cells']:assert im.k.read(int(e['address'],16),len(e['bytes_hex'])//2).hex()==e['bytes_hex']
 factory_replay=FactoryReplay(im,factory).run();constructor_replay=ConstructReplay(im,constructed).run();counts['fresh_copy_and_map_producer_reconstructions_checked']=2;rows=prof['cases'];assert len(rows)==25
 for j,row in enumerate(rows):
  c=row['configuration'];lookup=c.get('phase')=='lookup';ram=decode(row['final_private_RAM']);mapbytes=bytes.fromhex(row['destination_map256_hex']);rootbytes=bytes.fromhex(row['root256_hex']);record=bytes.fromhex(row['range_record64_hex']);node=bytes.fromhex(row['new_entry64_hex']);bucket=bytes.fromhex(row['range_bucket448_hex']);models=row['API_models'];names=[m['symbol']for m in models];assert all(row[k]is False for k in FLAGS)and row['boundary']['kind']=='returned'and row['thread_active_cursor']=='0x0'and row['thread_entry_nesting']==0;counts['completed_zero_cursor_nesting_components_checked']+=1
  transfer=row['initial_state_transfer'];parent=rows[transfer['case']]if lookup else constructed;assert transfer['path']==(P+'_profiles.json'if lookup else'kernel_map_store_init_profiles.json')and decode(transfer)==decode(parent['final_private_RAM'])and row['initial_private_fixtures'][:3]==parent['final_auxiliary_regions'];counts['exact_primary_and_auxiliary_component_transfers_checked']+=1
  expected_globals=[{**e,'provenance':'Exact original map-constructor/component final-global transfer'}for e in parent['final_image_globals']];assert row['initial_image_fixtures'][:len(expected_globals)]==expected_globals;counts['exact_inherited_global_transfers_checked']+=1
  assert 'declared_type2_destination_resolver'not in names and 'declared_packed_store_position_model'not in names;counts['absence_of_whole_resolver_and_position_models_checked']+=1
  if not lookup:
   assert transfer['case']==0 and row['entry_PC']=='0xfffffe000bdd1574'and ram[0x18040:0x18040+392]==decode(constructed['final_private_RAM'])[0x18040:0x18040+392]and ram[0x69000:0x69030]==decode(constructed['final_private_RAM'])[0x69000:0x69030];counts['other_descriptor_and_message_preservation_checked']+=1
   frames=row['range_allocator_frames'];main=next(f for f in frames if f['pc']=='0xfffffe000bdde9ac');producer=next(f for f in frames if f['pc']=='0xfffffe000bddee0c');gap=next(f for f in frames if f['pc']=='0xfffffe000bdde280');expected_bounds=[hex(R),hex(R+SIZE)]if c['environment']=='declared'else['0x0','0x0'];assert main['arguments'][:7]==[hex(KMAP),hex(STATE),*expected_bounds,'0x6000000000000000','0xc000','0x0']and producer['arguments']==[hex(KMAP),hex(STATE),*expected_bounds,'0x6000000000000000','0x10','0x3fff']and gap['arguments'][:6]==[hex(KMAP),*expected_bounds,'0x0','0x100000','0xfffff'];counts['original_size_class_pool_alignment_and_forward_search_ABIs_checked']+=1
   assert len(row['range_result_frames'])==1;result=row['range_result_frames'][0];pair=bytes.fromhex(result['out_pair16_hex'])
   if c['environment']=='file':
    assert row['raw_return_u32']==3 and result['arguments']==['0x3']and pair==bytes(16)and record==bytes(64)and bucket==bytes(448)and row['output16_hex']=='a5'*16 and rootbytes==bytes.fromhex(constructed['root256_hex'])and mapbytes==bytes.fromhex(constructed['destination_map256_hex'])and node==bytes.fromhex(factory['new_entry64_hex'])and names==['map_lock_model','VM_error_observer_model','map_unlock_model'];counts['original_file_bounds_failure_without_range_model_checked']=1
   else:
    additions=row['initial_image_fixtures'][len(expected_globals):];assert[(e['address'],e['bytes_hex'])for e in additions]==[(hex(BOUNDS),struct.pack('<QQ',R,R+SIZE).hex()),(hex(STATE),'00'*448),(hex(RNG),struct.pack('<Q',c['rng_seed']).hex()),('0xfffffe000caec380',struct.pack('<QQ',RZ,RA).hex())];counts['declared_bound_bucket_rng_zone_epochs_checked']+=1
    slot=(c['rng_seed']&0xffffffff)%16;destination=R+(slot<<16);end=destination+49152;wantrecord=bytearray(64);struct.pack_into('<Q',wantrecord,0,STATE);struct.pack_into('<I',wantrecord,8,R>>16);wantrecord[12:16]=bytes([16,16,4,11]);struct.pack_into('<Q',wantrecord,16,0xffff&~(1<<slot));struct.pack_into('<II',wantrecord,24,TAG,TAG);
    for index in range((slot>>1)+1):struct.pack_into('<I',wantrecord,32+4*index,0x40001)
    wantbucket=bytearray(448);struct.pack_into('<Q',wantbucket,16,REC);wantroot=bytearray(256);struct.pack_into('<I',wantroot,0,0x10003);struct.pack_into('<QQQ',wantroot,16,R,R+SIZE,(1<<64)-1);struct.pack_into('<I',wantroot,0xac,TAG);wantnode=bytearray(64);struct.pack_into('<I',wantnode,0,0x10000);struct.pack_into('<QQ',wantnode,16,destination,end);struct.pack_into('<I',wantnode,32,TAG);struct.pack_into('<I',wantnode,56,0x5730);wantmap=bytearray.fromhex(constructed['destination_map256_hex']);struct.pack_into('<QQ',wantmap,0,NEW,NEW);struct.pack_into('<Q',wantmap,32,49152);struct.pack_into('<I',wantmap,40,1);struct.pack_into('<Q',wantmap,80,ROOTPAGE)
    assert row['raw_return_u32']==0 and row['output16_hex']==struct.pack('<Q',destination).hex()+'a5'*8 and result['arguments']==['0x0']and pair==struct.pack('<QQ',destination,REC)and record==bytes(wantrecord)and bytes.fromhex(row['range_record32_hex'])==bytes(wantrecord[:32])and bytes.fromhex(result['record32_hex'])==bytes(wantrecord[:32])and bucket==bytes(wantbucket)and rootbytes==bytes(wantroot)and node==bytes(wantnode)and mapbytes==bytes(wantmap)and row['cached_rng_u64']==c['rng_seed']>>32;counts['original_16byte_address_record_result_checked']+=1;counts['original_record_header_bitmap_budget_and_self_links_checked']+=1;counts['original_cached_rng_slot_and_next_word_checked']+=1;counts['original_tagged_pool_root_and_secondary_index_oracles_checked']+=1;counts['original_completed_copyout_with_record_tagged_entry_checked']+=1
    assert names==['map_lock_model','declared_zeroed_range_record_allocation','declared_store_memmove','declared_store_memmove','header_bzero_model','copy_header_release_request','map_unlock_model'];allocation=next(m for m in models if m['symbol']=='declared_zeroed_range_record_allocation');assert allocation['arguments8'][:3]==[hex(RZ),hex(RA),'0x8004']and allocation['return_pc']=='0xfffffe000bddef60'and allocation['return_value']==hex(REC);counts['record_zone_ABI_and_explicit_primitive_models_checked']+=1
    insert=next(f for f in frames if f['pc']=='0xfffffe000bde1300');assert insert['arguments']==[hex(KMAP),hex(NEW),hex(destination),hex(REC),'0x6000000000000000'];counts['nonzero_record_output_to_map_insertion_join_checked']+=1
    assert any(w['address']==hex(REC+32+4*(slot>>1))and w['after_hex']=='01000400'for w in row['source_writes'])and val(ram,0x68000)==0 and ram[0x68000:0x68030]==bytes(48);counts['secondary_index_store_and_wrapper_only_retirement_checked']+=1
  else:
   destination=val(bytes.fromhex(parent['output16_hex']),0);query=c['query'];inside=destination<=query<destination+49152;assert row['raw_return_u32']==int(inside)and row['lookup_output']==hex(NEW if query<destination+49152 else 0)and not models and not row['declared_effects']and mapbytes==bytes.fromhex(parent['destination_map256_hex'])and rootbytes==bytes.fromhex(parent['root256_hex'])and record==bytes.fromhex(parent['range_record64_hex'])and bucket==bytes.fromhex(parent['range_bucket448_hex'])and any(e['pc']in['0xfffffe000bdc738c','0xfffffe000bdc7358']for e in row['source_visits']);counts['real_tagged_record_lookup_components_checked']+=1
   if query<destination:counts['false_before_start_with_nonnull_candidate_checked']+=1
   if query==destination+49152:counts['end_exclusive_null_lookup_checked']+=1
  for k,m in enumerate(models):
   want=[hex(((i+1)*0x123456789abcdef)^(k+1)*0x8b3dc651)for i in range(18)];want[0]=m['return_value'];assert m['after_registers31'][:18]==want and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False
  totals.update(Replay(im,row).run());summaries.append({'case':j,'environment':c['environment'],'phase':c.get('phase','copyout'),'source_visits':len(row['source_visits']),'API_models':len(models),'returned_u32':row['raw_return_u32']});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=25,functions=72,captured_instructions=12376)
 deps=[P+'_source.json',P+'_profiles.json','kernel_map_store_init_profiles.json','kernel_vm_entry_copy_profiles.json','replay_'+P+'.py','replay_kernel_map_store_init.py','replay_kernel_type2_copyout.py','replay_kernel_vm_entry_copy.py','replay_kernel_vm_range_cursor.py','replay_rpc502_vm_handoff.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_factory_replay':factory_replay,'fresh_constructor_replay':constructor_replay,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
