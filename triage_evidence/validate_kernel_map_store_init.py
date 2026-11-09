#!/usr/bin/env python3
"""Map constructor/root oracles, original insertion/release and real resolver joins.
O(image+instruction words+visits+RAM+effects), O(image+RAM+journals+reference windows).
Structural NULL-object tests only; no native mapping, rights or retirement proof.
"""
import json,struct
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_rpc502_vm_handoff import decode
from replay_kernel_vm_entry_copy import Replay as FactoryReplay
from replay_kernel_map_store_init import Replay
P='kernel_map_store_init';R=0x6500000000;KMAP=R+0x2e000;COPY=R+0x68000;CLONE=R+0x6a000;NEW=0xfffffe0001000040;ROOTPAGE=0xfffffe0003000000;DEST=R+0x30000;END=DEST+49152;COUNTER=0xfffffe000cb810e8;MZ=R+0xb2000;MA=R+0xb2100;RZ=R+0xb2200;RA=R+0xb2300;EXTSTORE=R+0xb4000
FLAGS=['native_target_executed','native_VM_effects_executed','native_retirement_executed','native_namespace_conversion_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']
def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def aux(row,a,n):
 for e in row['final_auxiliary_regions']:
  lo=int(e['address'],16);b=bytes.fromhex(e['bytes_hex'])
  if lo<=a and a+n<=lo+len(b):return b[a-lo:a-lo+n]
 raise AssertionError(hex(a))
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());factory=json.loads((ROOT/'kernel_vm_entry_copy_profiles.json').read_text())['cases'][4];counts=Counter();totals=Counter();summaries=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  assert all(obj[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==69 and sum(len(f['instructions'])for f in src['functions'])==11322
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 wrapper=next(f for f in src['functions']if f['start']=='0xfffffe000bdc6eac');assert {'_vm_map_create','_vm_map_create_external'}<={e['name']for e in wrapper['exact_symbols']};move=src['store_move_primitive'];assert im.k.read(int(move['address'],16),32).hex()==move['bytes_hex']and im.k.symbols([int(move['address'],16)])[move['address']]==move['exact_symbols']and {'_memcpy','_memmove'}=={e['name']for e in move['exact_symbols']};counts['original_constructor_alias_and_move_symbols_checked']=1
 for e in src['map_constructor_file_cells']:assert im.k.read(int(e['address'],16),len(e['bytes_hex'])//2).hex()==e['bytes_hex']
 assert next(im.k.cs.disasm(im.k.read(0xfffffe000bdc7034,4),0xfffffe000bdc7034)).op_str=='x9, #0xfffffe000cb81000'and next(im.k.cs.disasm(im.k.read(0xfffffe000bdc7038,4),0xfffffe000bdc7038)).op_str=='x9, x9, #0xe8';counts['exact_counter_address_ADRP_ADD_join_checked']=1
 actual=[];words=0
 for sec in im.k.kernel['sections']:
  if not sec['flags']&0x80000400:continue
  raw=im.k.read(sec['address'],sec['size']&~3);words+=len(raw)//4
  for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
   if w&0x9f000000!=0x90000000:continue
   x=(((w>>5)&0x7ffff)<<2)|((w>>29)&3);signed=x if x<(1<<20)else x-(1<<21);pc=sec['address']+4*j
   if((pc&~4095)+(signed<<12))&((1<<64)-1)==0xfffffe0007e69000:actual.append(hex(pc))
 scan=src['class_bounds_page_ADRP_scan'];assert words==scan['instruction_words']==2558560 and actual==[e['pc']for e in scan['hits']]and len(actual)==116 and scan['direct_indirect_writer_completeness_established']is False
 for e in scan['hits']:
  a=int(e['pc'],16);b=im.k.read(a,96);assert b.hex()==e['bytes_hex']and im.k.function(a,exact=False)['start']==e['function']and[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==e['instructions']
 counts.update(syntactic_class_bounds_page_references_checked=116,instruction_words_scanned=words);factory_replay=FactoryReplay(im,factory).run();counts['fresh_source_copy_producer_reconstruction_checked']=1
 rows=prof['cases'];assert len(rows)==17;emptyroot=bytearray(256);struct.pack_into('<I',emptyroot,0,0x10001);struct.pack_into('<Q',emptyroot,0x10,(1<<64)-1)
 for j,row in enumerate(rows):
  c=row['configuration'];phase=c['phase'];ram=decode(row['final_private_RAM']);mapbytes=bytes.fromhex(row['destination_map256_hex']);rootbytes=bytes.fromhex(row['root256_hex']);node=bytes.fromhex(row['new_entry64_hex']);header=bytes.fromhex(row['working_copy_header48_hex']);models=row['API_models'];names=[m['symbol']for m in models];assert all(row[k]is False for k in FLAGS)and row['thread_active_cursor']=='0x0'and row['thread_entry_nesting']==0;counts['final_zero_cursor_nesting_checked']+=1
  transfer=row['initial_state_transfer']
  if phase=='create':
   assert transfer['path']=='kernel_vm_entry_copy_profiles.json'and transfer['case']==4 and decode(transfer)==decode(factory['final_private_RAM'])and row['initial_private_fixtures'][:2]==factory['final_auxiliary_regions'];counts['exact_factory_to_constructor_RAM_aux_transfer_checked']+=1
   mask=(1<<c['page_shift'])-1;minimum=(c['minimum']+mask)&~mask;maximum=c['maximum']&~mask;want=bytearray(256);struct.pack_into('<QQ',want,0x10,minimum,maximum);want[0x2c:0x2e]=bytes([c['page_shift'],1]);struct.pack_into('<I',want,0x48,(ROOTPAGE>>8)&0xffffffff);struct.pack_into('<QQQ',want,0x68,0x7fffffffffffffff,0x7fffffffffffffff,0x7ffffe000000);struct.pack_into('<I',want,0x88,1);struct.pack_into('<Q',want,0x90,EXTSTORE if c['flags']&16 else 0);struct.pack_into('<I',want,0xb0,(int(bool(c['global_flag']))<<24)|((c['flags']&1)<<7)|((c['flags']&2)<<13));identifier=0 if c['flags']&12 else 8;struct.pack_into('<Q',want,0xc0,identifier)
   assert mapbytes==bytes(want)and rootbytes==bytes(emptyroot)and aux(row,ROOTPAGE,256)==rootbytes and row['map_constructor_counter']==(7 if c['flags']&12 else 8)and row['boundary']['kind']=='returned'and row['boundary']['registers31'][0]==hex(KMAP)and node==bytes.fromhex(factory['new_entry64_hex'])and header==bytes.fromhex(factory['working_copy_header48_hex']);counts['exact_256byte_original_map_and_root_oracles_checked']+=1;counts['rounding_flags_reference_identifier_oracles_checked']+=1
   alloc=[m for m in models if m['symbol']=='declared_zeroed_map_or_root_allocation'];assert len(alloc)==2 and alloc[0]['arguments8'][:3]==[hex(MZ),hex(MA),'0x8004']and alloc[0]['return_value']==hex(KMAP)and alloc[1]['arguments8'][:3]==[hex(RZ),hex(RA),'0x8004']and alloc[1]['return_value']==hex(ROOTPAGE);counts['distinct_map_root_allocator_ABIs_checked']+=1
   if c['wrapper']:assert row['entry_PC']=='0xfffffe000bdc6eac'and row['map_constructor_frames'][1]['arguments']==['0x0',hex(c['minimum']),hex(c['maximum']),'0xe','0x0'];counts['exported_map_constructor_defaults_checked']+=1
   if c['flags']&16:assert names.count('declared_auxiliary_store_allocation')==1 and any(f['pc']=='0xfffffe000bddd56c'and f['arguments']==[hex(KMAP)]for f in row['map_constructor_frames']);counts['original_optional_aux_store_path_checked']+=1
  else:
   assert transfer['path']==P+'_profiles.json';parent=rows[transfer['case']];assert decode(transfer)==decode(parent['final_private_RAM'])and row['initial_private_fixtures']==parent['final_auxiliary_regions']and row['initial_image_fixtures']==[{**e,'provenance':'Exact original map-constructor/component final-global transfer'}for e in parent['final_image_globals']];counts['exact_constructed_component_RAM_aux_global_handoffs_checked']+=1
   if phase=='copyout':
    if c['resolver_result']is None:assert row['boundary']['kind']=='before_lower_VM_resolver'and rootbytes==bytes(emptyroot)and mapbytes==bytes.fromhex(rows[0]['destination_map256_hex']);counts['constructed_map_unmodeled_resolver_frontier_checked']=1
    elif c['resolver_result']:
     assert row['boundary']['kind']=='returned'and row['raw_return_u32']==3 and rootbytes==bytes(emptyroot)and mapbytes==bytes.fromhex(rows[0]['destination_map256_hex'])and node==bytes.fromhex(factory['new_entry64_hex'])and header==bytes.fromhex(factory['working_copy_header48_hex']);counts['constructed_map_resolver_failure_preservation_checked']=1
    else:
     consumed=c.get('consume',1)&1;linked=NEW if consumed else NEW+64;wantroot=bytearray(256);struct.pack_into('<I',wantroot,0,0x10003);struct.pack_into('<QQQ',wantroot,0x10,DEST,END,(1<<64)-1);struct.pack_into('<I',wantroot,0xac,(linked-0xfffffe0000000000)>>6);wantmap=bytearray.fromhex(rows[0]['destination_map256_hex']);struct.pack_into('<QQ',wantmap,0,linked,linked);struct.pack_into('<Q',wantmap,0x20,49152);struct.pack_into('<I',wantmap,0x28,1);struct.pack_into('<Q',wantmap,0x50,ROOTPAGE);wantnode=bytearray(64);struct.pack_into('<I',wantnode,0,0x10000);struct.pack_into('<QQ',wantnode,0x10,DEST,END);struct.pack_into('<I',wantnode,0x38,0x5730)
     assert row['boundary']['kind']=='returned'and row['raw_return_u32']==0 and row['output16_hex']==struct.pack('<Q',DEST).hex()+'a5'*8 and mapbytes==bytes(wantmap)and rootbytes==bytes(wantroot)and aux(row,linked,64)==bytes(wantnode);counts['completed_original_root_keys_records_map_links_and_entry_oracles_checked']+=1;counts['completed_original_exclusive_release_and_zero_return_checked']+=1
     released=COPY if consumed else CLONE;assert ram[released-R:released-R+48]==bytes(48)and names.count('header_bzero_model')==names.count('copy_header_release_request')==1 and names.count('declared_store_memmove')==2 and names.count('map_lock_model')==names.count('map_unlock_model')==1;counts['wrapper_only_retirement_protocol_and_persistent_mapped_entry_checked']+=1
     if not consumed:assert node==bytes.fromhex(factory['new_entry64_hex'])and header==bytes.fromhex(factory['working_copy_header48_hex']);counts['completed_nonconsuming_clone_preserves_source_copy_checked']=1
     else:assert header==bytes(48);counts['completed_consuming_copyout_checked']=1
     assert any(f['pc']=='0xfffffe000be2fac0'and f['arguments'][1]==hex(linked)for f in row['map_constructor_frames'])and any(f['pc']=='0xfffffe000bddf2c8'and f['arguments']==[hex(KMAP+0x48),f['arguments'][1],hex(DEST),hex(END),hex((linked-0xfffffe0000000000)>>6)]for f in row['map_constructor_frames']);counts['original_store_insert_to_entry_release_argument_join_checked']+=1
   elif phase=='discard':
    assert row['boundary']['kind']=='returned'and row['raw_return_u32']==0 and mapbytes==bytes.fromhex(parent['destination_map256_hex'])and rootbytes==bytes.fromhex(parent['root256_hex']);counts['post_copyout_discard_preserves_constructed_map_store_checked']+=1
    if c['descriptor_index']==0:assert node==bytes(64)and header==bytes(48)and aux(row,NEW+64,64)==aux(parent,NEW+64,64);counts['source_copy_retirement_keeps_distinct_mapped_clone_checked']=1
    else:assert ram[0x69000:0x69030]==bytes(48)and aux(row,NEW,64)==aux(parent,NEW,64);counts['other_descriptor_retirement_keeps_mapped_entry_checked']=1
   else:
    assert phase=='lookup'and row['boundary']['kind']=='returned'and not models and not row['declared_effects']and mapbytes==bytes.fromhex(parent['destination_map256_hex'])and rootbytes==bytes.fromhex(parent['root256_hex']);query=c['query'];inside=DEST<=query<END;linked=NEW+64 if transfer['case']==8 else NEW;expected_pointer=linked if query<END else 0;assert row['raw_return_u32']==int(inside)and row['lookup_output']==hex(expected_pointer)and any(f['pc']=='0xfffffe000bddd5dc'and f['arguments']==[hex(KMAP),hex(query)]for f in row['map_constructor_frames']);counts['original_real_resolver_and_candidate_membership_cases_checked']+=1
    if query<DEST:counts['false_lookup_with_nonnull_candidate_checked']=1
    if query==END:counts['end_exclusive_null_lookup_checked']+=1
    if transfer['case']==8:counts['real_lookup_after_source_retirement_checked']+=1
  for k,m in enumerate(models):
   want=[hex(((i+1)*0x123456789abcdef)^(k+1)*0x8b3dc651)for i in range(18)];want[0]=m['return_value'];assert m['after_registers31'][:18]==want and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False
  totals.update(Replay(im,row).run());summaries.append({'case':j,'phase':phase,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'returned_X0':row['boundary']['registers31'][0]if row['boundary']['kind']=='returned'else None});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=17,functions=69,captured_instructions=11322)
 deps=[P+'_source.json',P+'_profiles.json','kernel_vm_entry_copy_profiles.json','replay_'+P+'.py','replay_kernel_type2_copyout.py','replay_kernel_vm_entry_copy.py','replay_kernel_vm_range_cursor.py','replay_rpc502_vm_handoff.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_copy_producer_replay':factory_replay,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
