#!/usr/bin/env python3
"""Original bit gates, held-state unwind, type2 linkage/publication and discard.
O(image+visits+RAM+effects), O(image+RAM+journals). Structural NULL-object fixture,
not native mapping bytes, source removal, allocator retirement or IPC proof.
"""
import json,struct
from collections import Counter
from unicorn import arm64_const as ar
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_rpc502_vm_handoff import decode
from replay_kernel_vm_range_cursor import Replay as HeldReplay
from replay_kernel_vm_entry_copy import Replay
P='kernel_vm_entry_copy';R=0x6500000000;ENTRY=0xfffffe0001000000;NEW=ENTRY+64;MAP=R+0x2a000;THREAD=R+0x2c000;COPY=R+0x68000;OTHER=R+0x69000;EZ=R+0xb0000;EA=R+0xb0100;START=R+0x50000;END=R+0x5c000
FLAGS=['native_target_executed','native_VM_effects_executed','native_retirement_executed','native_namespace_conversion_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']
def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def aux(row,a,n):
 for e in row['final_auxiliary_regions']:
  lo=int(e['address'],16);b=bytes.fromhex(e['bytes_hex'])
  if lo<=a and a+n<=lo+len(b):return b[a-lo:a-lo+n]
 raise AssertionError(hex(a))
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());held=json.loads((ROOT/'kernel_vm_range_cursor_profiles.json').read_text())['cases'][23];counts=Counter();totals=Counter();summaries=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  assert all(obj[k]is False for k in FLAGS)
 assert len(src['functions'])==50 and sum(len(f['instructions'])for f in src['functions'])==8224 and src['kernel_sha256']==im.k.sha256
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 for k in ['entry_initializer_constant','entry_zone_file']:
  e=src[k];assert im.k.read(int(e['address'],16),len(e['bytes_hex'])//2).hex()==e['bytes_hex']
 old=HeldReplay(im,held);assert old.run()==prof['held_prefix_fresh_replay'];simd=[hex(old.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)];assert simd==prof['held_Q_registers32'];counts['fresh_held_prefix_reconstructions_checked']=1
 rows=prof['cases'];assert len(rows)==7
 for j,row in enumerate(rows):
  c=row['configuration'];mode=c['mode'];ram=decode(row['final_private_RAM']);header=bytes.fromhex(row['working_copy_header48_hex']);node=bytes.fromhex(row['new_entry64_hex']);names=[m['symbol']for m in row['API_models']];assert all(row[k]is False for k in FLAGS)and row['boundary']['kind']=='returned'and row['thread_active_cursor']=='0x0'and row['thread_entry_nesting']==0 and row['entry_lock_word']==0x10000 and val(ram,THREAD-R+0x238)==0 and val(aux(row,ENTRY,4),0,4)==0x10000;counts['completed_original_cursor_reader_unwinds_checked']+=1
  if mode=='resume':
   assert row['entry_PC']==held['boundary']['pc']and row['entry_registers31']==held['boundary']['registers31']and row['entry_SP']==held['boundary']['SP']and row['entry_NZCV']==held['boundary']['NZCV']and row['entry_Q_registers32']==simd and decode(row['initial_state_transfer'])==decode(held['final_private_RAM'])and row['initial_private_fixtures']==held['final_auxiliary_regions']and row['initial_image_fixtures']==[{**e,'provenance':'Exact held-prefix final-global transfer'}for e in held['final_image_globals']];counts['exact_held_RAM_aux_globals_GP_SP_NZCV_SIMD_transfers_checked']=1
  if mode in['resume','factory']:
   eligible=mode=='factory'and bool(c['entry_flags']&0x100)and bool(c['entry_flags']&0x10);assert len(row['new_entry_allocations'])==int(eligible)and row['entry_copy_return_frames'][0]['arguments']==['0x0'if eligible else'0x2'];counts['original_entry_bit8_bit4_gate_and_status_checked']+=1
   if eligible:
    assert row['raw_return_u32']==0 and val(header,0)==val(header,8)==NEW and val(header,0x10)==START and val(header,0x20)==32769 and val(header,0x28,4)==1 and header[0x2c:0x30]==bytes([14,2,0,0]);want=bytearray(64);struct.pack_into('<Q',want,0,1);struct.pack_into('<QQ',want,0x10,START,END);struct.pack_into('<I',want,0x38,0x4110);assert node==bytes(want)and node==aux(row,NEW,64)and val(ram,0x18040+36)==COPY and val(ram,0x18040+52)==OTHER and ram[0x69000+0x2d]==3 and val(ram,0x69000+0x20)==1;counts['original_64byte_entry_copy_adjustments_checked']+=1;counts['original_type2_single_entry_header_and_two_descriptor_publication_checked']+=1
    assert len(row['new_entry_allocations'])==1 and row['new_entry_allocations'][0]['arguments']==[hex(EZ),hex(EA),'0x8004']and names.count('declared_type2_source_removal')==1;counts['distinct_entry_allocator_and_source_removal_ABIs_checked']+=1
    source_remove=next(m for m in row['API_models']if m['symbol']=='declared_type2_source_removal');assert source_remove['arguments8'][:5]==[hex(MAP),hex(START),hex(END),'0x0','0x0'];pub=next(w for w in row['source_writes']if w['pc']=='0xfffffe000bdd1f38'and w['after_hex']==struct.pack('<Q',COPY).hex());assert source_remove['before_source_visit_index']<pub['source_visit_index'];counts['type2_source_removal_before_copy_publication_checked']+=1
    assert any(w['pc']=='0xfffffe000bde122c'and w['address']==hex(COPY)and w['after_hex']==struct.pack('<Q',NEW).hex()for w in row['source_writes'])and any(w['pc']=='0xfffffe000bde1228'and w['address']==hex(COPY+0x28)and w['after_hex']=='01000000'for w in row['source_writes']);counts['original_copy_list_head_tail_and_count_stores_checked']+=1
   else:assert row['raw_return_u32']==0x1000000c and header==bytes(48)and val(ram,0x18040+36)==START and 'declared_entry_zone_allocation'not in names and names.count('copy_header_release_request')==1;counts['original_rejected_entry_working_header_cleanup_checked']+=1
  else:
   assert mode=='discard';p=rows[row['initial_state_transfer']['producer_case']];assert decode(row['initial_state_transfer'])==decode(p['final_private_RAM'])and row['initial_private_fixtures']==p['final_auxiliary_regions']and row['initial_image_fixtures']==[{**e,'provenance':'Exact produced-list component global transfer'}for e in p['final_image_globals']];counts['exact_produced_RAM_aux_global_handoffs_checked']+=1
   assert header==bytes(48)and node==bytes(64)
   if c['descriptor_index']==0:
    assert names.count('header_bzero_model')==2 and names.count('copy_header_release_request')==2 and 'backing_release_request'not in names and any(f['pc']=='0xfffffe000bde1248'and f['arguments']==[hex(COPY),hex(NEW)]for f in row['entry_copy_frames']);counts['original_type2_unlink_64byte_entry_and_48byte_header_release_checked']=1
   else:assert names.count('backing_release_request')==names.count('copy_header_release_request')==1 and ram[0x69000:0x69030]==bytes(48);counts['separate_produced_type3_discard_checked']=1
   assert val(ram,0x18040+36)==COPY and val(ram,0x18040+52)==OTHER;counts['stale_descriptor_bits_after_release_protocol_checked']+=1
  for k,m in enumerate(row['API_models']):
   want=[hex(((i+1)*0x123456789abcdef)^(k+1)*0x8b3dc651)for i in range(18)];want[0]=m['return_value'];assert m['after_registers31'][:18]==want and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False
   if m['symbol']=='declared_entry_zone_allocation':assert m['arguments8'][:3]==[hex(EZ),hex(EA),'0x8004']and m['return_value']==hex(NEW)
   if m['symbol']=='copy_header_release_request'and m['arguments8'][2]==hex(NEW):assert m['arguments8'][:4]==[hex(EZ),hex(EA),hex(NEW),'0x40']
  totals.update(Replay(im,row).run());summaries.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(row['API_models']),'raw_X0':row['boundary']['registers31'][0],'new_entries':len(row['new_entry_allocations'])});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=7,functions=50,captured_instructions=8224)
 deps=[P+'_source.json',P+'_profiles.json','kernel_vm_range_cursor_profiles.json','replay_'+P+'.py','replay_kernel_vm_range_cursor.py','replay_rpc502_vm_handoff.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'held_prefix_replay':prof['held_prefix_fresh_replay'],'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
