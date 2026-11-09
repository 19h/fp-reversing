#!/usr/bin/env python3
"""Original cursor field/guard, candidate, callback and type2 frontier oracles.
O(image+visits+RAM+effects), O(image+RAM+journals). No native membership/rights.
"""
import json,struct
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_rpc502_vm_handoff import decode
from replay_kernel_vm_range_cursor import Replay
P='kernel_vm_range_cursor';R=0x6500000000;SIZE=0x100000;MAP=R+0x2a000;THREAD=R+0x2c000;CUR=R+0xa0000;LOOKOUT=R+0xa1000;SENTINEL=R+0xa2000;VMOBJ=R+0xa4000;START=R+0x50000;END=R+0x5c000;ENTRY=0xfffffe0001000000;PAGE=0xfffffe0002000000;CALLBACK=0xfffffe000bdd2750;SLOT=0xfffffe0007e6a150;OPS=SLOT-16;MARKER=0xfffffe000cb0bf18
FLAGS=['native_target_executed','native_VM_effects_executed','native_retirement_executed','native_namespace_conversion_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']
def scalar(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());counts=Counter();totals=Counter();summary=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  assert all(obj[k]is False for k in FLAGS)
 assert len(src['functions'])==41 and sum(len(f['instructions'])for f in src['functions'])==7474 and src['kernel_sha256']==im.k.sha256
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 assert im.pointer(SLOT)==src['range_callback']['pointer']and src['range_callback']['pointer']['target']==hex(CALLBACK)and src['range_callback']['pointer']['diversity']=='0x0'and src['range_callback']['pointer']['address_diversity']==1 and src['range_callback']['pointer']['auth']==1
 g=src['callback_global'];assert im.k.read(int(g['address'],16),4).hex()==g['bytes_hex']
 rows=prof['cases'];assert len(rows)==38
 for j,row in enumerate(rows):
  c=row['configuration'];stage=c['stage'];ram=decode(row['final_private_RAM']);cur=bytes.fromhex(row['cursor128_hex']);raw=row['raw_return_u32'];models=row['API_models'];names=[m['symbol']for m in models];assert all(row[k]is False for k in FLAGS);counts['cases_with_explicit_non_native_boundaries_checked']+=1
  assert cur==ram[int(row['cursor_address'],16)-R:int(row['cursor_address'],16)-R+128]and row['thread_active_cursor']==hex(scalar(ram,THREAD-R+0x238))and row['thread_entry_nesting']==scalar(ram,THREAD-R+0x22c,4)
  if stage=='init':
   a,b,f=c['start'],c['end'],c['flags'];associated=c.get('associated','null');f|=0x80000000 if associated=='marker'else 0
   if f&0x1000:assert a==b==0;a,b=0,((1<<64)-1)<<c.get('page_shift',14)&((1<<64)-1)
   valid=a<b and(bool(f&0x3000)or R<=a and b<=R+SIZE);want=bytearray(b'\xa5'*128);struct.pack_into('<QQQQ',want,0,a,b,MAP,0);struct.pack_into('<IH',want,0x28,f,3);want[0x2e:0x48]=bytes(26)
   if f&4:struct.pack_into('<Q',want,0x30,a)
   struct.pack_into('<QQQ',want,0x48,a,b,MAP);want[0x60:0x70]=bytes(16);assert cur==bytes(want)and raw==int(not valid)and row['thread_active_cursor']==hex(CUR if valid else SENTINEL)and not models;counts['exact_initializer_128byte_and_guard_oracles_checked']+=1;counts['initializer_success'if valid else'initializer_range_rejection']+=1
   assert cur[0x20:0x28]==b'\xa5'*8 and cur[0x70:]==b'\xa5'*16;counts['caller_word_and_outside_touched_extent_preservation_checked']+=1
  elif stage=='lookup':
   result=not c.get('empty_store')and START<=c['address'];assert raw==int(result)and row['lookup_output']==hex(0 if c.get('empty_store')else ENTRY)and row['thread_active_cursor']==hex(SENTINEL)and names==['declared_packed_store_position_model'];counts['packed_candidate_decode_and_local_start_predicate_checked']+=1
   assert row['position_frames'][0]['arguments']==[hex(MAP),hex(c['address'])]
  elif stage=='callback':
   rejected=not c.get('null_object')and c['object_class']==4 and not(c['global_flag']and c['map_kind']=='page12')and not c['entry_bit3'];assert raw==(0x20008002 if rejected else 0)and not models and not row['source_writes']and row['thread_active_cursor']==hex(SENTINEL)and row['callback_frames'][0]['arguments']==[hex(OPS),hex(CUR),hex(ENTRY)];counts['callback_class_global_page_bit_oracles_checked']+=1;counts['callback_rejection'if rejected else'callback_zero_result']+=1
  else:
   assert stage=='type2'and row['VM_copyin_entries'][0]['arguments5'][:4]==[hex(MAP),hex(START),'0x8001','0x1']and len(row['VM_copyin_entries'])==1
   before=next(e for e in row['cursor_frames']if e['pc']=='0xfffffe000be31808');assert scalar(bytes.fromhex(before['cursor128_hex']),0x20)==OPS;counts['factory_callback_word_survives_initializer_checked']+=1
   first=row['cursor_return_frames'][0];firstcur=bytes.fromhex(first['cursor128_hex']);assert first['pc']=='0xfffffe000bdd17a4'and scalar(firstcur,0)==START and scalar(firstcur,8)==END and scalar(firstcur,0x20)==OPS and scalar(firstcur,0x28,4)==0x42015
   if c['empty_store']:
    assert row['boundary']['kind']=='returned'and raw==0x1000000c and first['arguments']==['0x1']and len(row['cursor_return_frames'])==1 and row['thread_active_cursor']=='0x0'and row['entry_lock_word']==0x10000 and row['thread_entry_nesting']==0 and ram[0x68000:0x68030]==bytes(48)and scalar(ram,0x18040+36)==START and names.count('header_bzero_model')==names.count('copy_header_release_request')==1 and 'source_region_remove_request'not in names;counts['original_empty_type2_failure_header_cleanup_checked']+=1
   else:
    assert row['boundary']['kind']=='before_entry_clone_body'and row['boundary']['pc']=='0xfffffe000bdd21fc'and row['boundary']['registers31'][:3]==[row['cursor_address'],hex(ENTRY),'0x1']and first['arguments']==['0x0']and row['cursor_return_frames'][1]['arguments']==[hex(ENTRY)]and scalar(firstcur,0x2c,2)==3 and scalar(cur,0x2c,2)==1 and scalar(cur,0x18)==ENTRY and scalar(cur,0x30)==END and row['thread_active_cursor']==row['cursor_address']and row['entry_lock_word']==0x50000 and row['thread_entry_nesting']==1 and scalar(ram,0x68000+0x20)==32769 and ram[0x68000+0x2d]==2 and scalar(ram,0x18040+36)==START and not any(m['symbol']=='copy_header_release_request'for m in models);counts['original_range_iterator_entry_held_clone_frontier_checked']+=1
    assert len(row['logical_indirect_edges'])==1 and row['logical_indirect_edges'][0]['target']==hex(CALLBACK)and row['logical_indirect_edges'][0]['modifier']==hex(SLOT)and row['callback_frames'][0]['arguments']==[hex(OPS),row['cursor_address'],hex(ENTRY)];counts['exact_original_callback_slot_to_body_join_checked']+=1
   assert names.count('map_read_lock_model')==names.count('declared_range_read_unlock_no_effect')==1
  for k,m in enumerate(models):
   expected=[hex(((i+1)*0x123456789abcdef)^(k+1)*0x8b3dc651)for i in range(18)];expected[0]=m['return_value'];assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False
   if m['symbol']=='declared_packed_store_position_model':assert m['return_value']=='0x20000'and m['arguments8'][0]==hex(MAP)
   if m['symbol']=='declared_range_read_unlock_no_effect':assert m['arguments8'][0]==hex(MAP+0x30)and m['return_value']=='0x0'
  totals.update(Replay(im,row).run());summary.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'raw_X0':row['boundary']['registers31'][0]});print(json.dumps({**summary[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=38,functions=41,captured_instructions=7474,callback_binding_records=1)
 deps=[P+'_source.json',P+'_profiles.json','replay_'+P+'.py','replay_rpc502_vm_handoff.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':summary,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
