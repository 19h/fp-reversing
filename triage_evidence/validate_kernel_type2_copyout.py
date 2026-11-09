#!/usr/bin/env python3
"""Original type2 consumer guards, relocation, cloning and held insertion ABI.
O(image+visits+RAM+effects), O(image+RAM+journals). No native mapping/lifetime proof.
"""
import json,struct
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_rpc502_vm_handoff import decode
from replay_kernel_vm_entry_copy import Replay as ProducerReplay
from replay_kernel_type2_copyout import Replay
P='kernel_type2_copyout';R=0x6500000000;COPY=R+0x68000;CLONE=R+0x6a000;NEW=0xfffffe0001000040;THREAD=R+0x2c000;KMAP=R+0x2e000;DEST=R+0x30000;OUT=R+0x16000;SP=R+0xf0000
FLAGS=['native_target_executed','native_VM_effects_executed','native_retirement_executed','native_namespace_conversion_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']
def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());producer=json.loads((ROOT/'kernel_vm_entry_copy_profiles.json').read_text())['cases'][4];counts=Counter();totals=Counter();summaries=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  assert all(obj[k]is False for k in FLAGS)
 assert len(src['functions'])==64 and sum(len(f['instructions'])for f in src['functions'])==11047 and src['kernel_sha256']==im.k.sha256
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 for e in [src['entry_initializer_constant'],src['entry_zone_file'],src['copyout_entry_initializer_constant'],*src['type2_copyout_globals']]:assert im.k.read(int(e['address'],16),len(e['bytes_hex'])//2).hex()==e['bytes_hex']
 assert src['copyout_entry_initializer_constant']['bytes_hex']=='0800000000000000';producer_replay=ProducerReplay(im,producer).run();counts['fresh_produced_type2_reconstruction_checked']=1
 initial=decode(producer['final_private_RAM']);initialnode=bytes.fromhex(producer['new_entry64_hex']);initialheader=bytes.fromhex(producer['working_copy_header48_hex']);rows=prof['cases'];assert len(rows)==14
 for j,row in enumerate(rows):
  c=row['configuration'];ram=decode(row['final_private_RAM']);node=bytes.fromhex(row['new_entry64_hex']);header=bytes.fromhex(row['working_copy_header48_hex']);cn=bytes.fromhex(row['cloned_entry64_hex']);ch=bytes.fromhex(row['cloned_header48_hex']);frames=row['type2_consumer_frames'];models=row['API_models'];names=[e['symbol']for e in models];by={pc:[f for f in frames if f['pc']==hex(pc)]for pc in[0xfffffe000bdcb374,0xfffffe000bdc7434,0xfffffe000bdde9ac,0xfffffe000bdcbfcc,0xfffffe000bdc8760,0xfffffe000bdc8ba4,0xfffffe000bdcc14c,0xfffffe000bde1300,0xfffffe000bddf0b0]}
  assert all(row[k]is False for k in FLAGS)and row['initial_state_transfer']['path']=='kernel_vm_entry_copy_profiles.json'and row['initial_state_transfer']['case']==4 and decode(row['initial_state_transfer'])==initial and row['initial_private_fixtures']==producer['final_auxiliary_regions']and row['initial_image_fixtures']==[{**e,'provenance':'Exact produced-type2 final-global transfer'}for e in producer['final_image_globals']];counts['exact_produced_RAM_aux_global_transfers_checked']+=1
  assert row['entry_SP']==hex(SP)and row['entry_registers31'][30]==hex(R+0xe0000)and row['thread_active_cursor']=='0x0'and ram[0x69000:0x69030]==initial[0x69000:0x69030]and ram[0x18040:0x18040+392]==initial[0x18040:0x18040+392];counts['other_copy_and_message_preserved_checked']+=1
  args=by[0xfffffe000bdcb374][0]['arguments'];extent=c.get('extent',32769);consume=c.get('consume',1);assert args==[hex(KMAP),hex(OUT),hex(COPY),hex(extent),hex(consume)]
  if c.get('wrapper',True):assert row['entry_PC']=='0xfffffe000bdd1574'and len(frames)>1;counts['exported_wrapper_extent_and_flag_forwarding_checked']+=1
  else:assert row['entry_PC']=='0xfffffe000bdcb374'
  if c['test']=='extent_mismatch':
   assert extent!=32769 and not by[0xfffffe000bdc7434]and row['boundary']['kind']=='returned'and row['raw_return_u32']==5 and row['output16_hex']=='00'*8+'a5'*8 and node==initialnode and header==initialheader and names==['VM_error_observer_model']and row['thread_entry_nesting']==0;counts['exact_extent_mismatch_zero_output_preservation_checked']+=1
  else:
   assert by[0xfffffe000bdc7434][0]['arguments'][:5]==[hex(KMAP),'0x0','0xc000','0x0','0x6000000000000000'];rr=by[0xfffffe000bdde9ac][0];assert rr['arguments'][:7]==[hex(KMAP),'0xfffffe000cb80d60','0x0','0x0','0x6000000000000000','0xc000','0x0'];counts['original_destination_interval_class_and_lower_ABI_checked']+=1
   if c['test']=='exact_produced_copy':assert row['boundary']['kind']=='before_lower_VM_resolver'and row['boundary']['pc']==rr['pc']and names==['map_lock_model']and row['output16_hex']=='a5'*16 and node==initialnode and header==initialheader;counts['unmodeled_original_resolver_frontier_checked']=1
   elif c['resolver_result']:
    assert row['boundary']['kind']=='returned'and row['raw_return_u32']==(3 if c['resolver_result']==0x2e else c['resolver_result'])and row['output16_hex']=='a5'*16 and names==['map_lock_model','declared_type2_destination_resolver','VM_error_observer_model','map_unlock_model']and node==initialnode and header==initialheader and row['thread_entry_nesting']==0
    if c['resolver_result']==0x2e:assert any(v['pc']=='0xfffffe000bdc7564'for v in row['source_visits'])and any(v['pc']=='0xfffffe000bdc7688'for v in row['source_visits']);counts['special_resolver_fallback_original_file_bounds_rejection_checked']+=1
    else:counts['resolver_error_return_copy_and_output_preservation_checked']+=1
   else:
    assert row['boundary']['kind']=='before_destination_store_search'and row['boundary']['pc']=='0xfffffe000bddf0b0'and row['thread_entry_nesting']==1 and val(ram,THREAD-R+0x22c,4)==1 and row['output16_hex']==struct.pack('<Q',DEST).hex()+'a5'*8;counts['held_store_frontier_output_and_exclusive_nesting_checked']+=1
    source_node=NEW if consume&1 else NEW+64;source_header=COPY if consume&1 else CLONE;wanted=bytearray(64);struct.pack_into('<I',wanted,0,0x30000);struct.pack_into('<QQ',wanted,0x10,DEST,DEST+49152);flags=((0x4110|0x1000)&((-0x2ff1)&0xffffffff)|0x730)&0xfffffff9;assert flags==0x5730;struct.pack_into('<I',wanted,0x38,flags);assert(node if consume&1 else cn)==bytes(wanted);counts['original_relocation_flag_normalization_and_exclusive_entry_checked']+=1
    hh=header if consume&1 else ch;assert val(hh,0)==val(hh,8)==0 and val(hh,0x28,4)==0 and val(hh,0x20)==32769 and hh[0x2d]==2;counts['original_copy_list_unlink_without_wrapper_release_checked']+=1
    if consume&1:assert names==['map_lock_model','declared_type2_destination_resolver']and cn==bytes(64)and ch==bytes(48);counts['consuming_in_place_path_checked']+=1
    else:
     assert node==initialnode and header==initialheader and names==['map_lock_model','declared_type2_destination_resolver','declared_type2_copyout_clone_allocation','declared_type2_copyout_clone_allocation'];alloc=[m for m in models if m['symbol']=='declared_type2_copyout_clone_allocation'];assert alloc[0]['return_pc']=='0xfffffe000bdcb840'and alloc[0]['arguments8'][:3]==[hex(R+0x86000),hex(R+0x88000),'0x4']and alloc[0]['return_value']==hex(CLONE)and alloc[1]['return_pc']=='0xfffffe000bdcb8b4'and alloc[1]['arguments8'][:3]==[hex(R+0xb0000),hex(R+0xb0100),'0x8004']and alloc[1]['return_value']==hex(NEW+64);counts['nonconsuming_original_clone_and_allocator_ABIs_checked']+=1
    assert by[0xfffffe000bdcbfcc][0]['arguments'][:3]==[hex(KMAP),hex(source_header),'0x0']and by[0xfffffe000bdcbfcc][0]['arguments'][4]=='0x1000'and len(by[0xfffffe000bdc8760])==len(by[0xfffffe000bdc8ba4])==1;counts['original_entry_and_map_validation_pipeline_checked']+=1
    assert by[0xfffffe000bdcc14c][0]['arguments']==[hex(KMAP),hex(source_header),hex(DEST),'0x0','0x6000000000000000']and by[0xfffffe000bde1300][0]['arguments']==[hex(KMAP),hex(source_node),hex(DEST),'0x0','0x6000000000000000'];counts['original_unlink_to_map_insertion_argument_join_checked']+=1
    assert val(ram,KMAP-R+0x20)==49152 and val(ram,KMAP-R+0x48)==0 and val(ram,KMAP-R+0x60)==0 and bytes.fromhex(row['boundary']['detail']['store_context24_hex'])[:16]==bytes(16);counts['pre_search_map_accounting_and_absent_root_checked']+=1
    pub=next(w for w in row['source_writes']if w['pc']=='0xfffffe000bdcbb04'and w['address']==hex(OUT));assert pub['after_hex']==struct.pack('<Q',DEST).hex()and pub['source_visit_index']<by[0xfffffe000bdcc14c][0]['before_source_visit_index'];counts['output_written_before_insertion_frontier_checked']+=1
  for k,m in enumerate(models):
   want=[hex(((i+1)*0x123456789abcdef)^(k+1)*0x8b3dc651)for i in range(18)];want[0]=m['return_value'];assert m['after_registers31'][:18]==want and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False
  totals.update(Replay(im,row).run());summaries.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'returned_u32':row['raw_return_u32']if row['boundary']['kind']=='returned'else None});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=14,functions=64,captured_instructions=11047)
 deps=[P+'_source.json',P+'_profiles.json','kernel_vm_entry_copy_profiles.json','replay_'+P+'.py','replay_kernel_vm_entry_copy.py','replay_kernel_vm_range_cursor.py','replay_rpc502_vm_handoff.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_producer_replay':producer_replay,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
