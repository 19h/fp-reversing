#!/usr/bin/env python3
"""Source factory-to-consumer snapshots, ownership channels and fresh replay.
O(image+visits+RAM+effects), O(image+RAM+journals). No native ownership proof.
"""
import json,struct
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_rpc502_vm_handoff import Replay,decode,P,SIZE,MAP,KMAP,THREAD,SOURCES,BACKS,COPIES,ZONE,AUX,OUT,DEST
PREFIX='rpc502_vm_handoff';FLAGS=['native_target_executed','native_VM_effects_executed','native_IPC_executed','native_retirement_executed','native_namespace_conversion_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']
def u64(b,o):return int.from_bytes(b[o:o+8],'little')
def main():
 im=Image();source=json.loads((ROOT/(PREFIX+'_source.json')).read_text());profiles=json.loads((ROOT/(PREFIX+'_profiles.json')).read_text());legacy=json.loads((ROOT/'rpc502_reply_copyin_profiles.json').read_text())['cases'];counts=Counter();totals=Counter();summary=[]
 for obj,script in[(source,'recover_'+PREFIX+'.py'),(profiles,'probe_'+PREFIX+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  assert all(obj[k]is False for k in FLAGS)
 assert source['kernel_sha256']==im.k.sha256 and len(source['functions'])==23 and sum(len(f['instructions'])for f in source['functions'])==4492
 for f in source['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f['bytes']and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 for e in source['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 assert source['file_environment']==[{'address':'0xfffffe0007e6a01c','bytes_hex':'02000000'},{'address':'0xfffffe0007f8b5f0','bytes_hex':'00000000'}]
 rows=profiles['cases'];assert len(rows)==18
 for j,row in enumerate(rows):
  c=row['configuration'];stage=c['stage'];lens=c['lengths'];ram=decode(row['final_private_RAM']);h=int(row['message_header_address'],16)-P;models=row['API_models'];names=[m['symbol']for m in models];assert all(row[k]is False for k in FLAGS)and row['source_policy']==2 and row['source_policy_V']==0 and row['current_map']==hex(MAP)and row['destination_map_refs']==3;counts['original_file_policy2_and_restored_map_state_checked']+=1
  assert u64(ram,THREAD-P+0x428)==MAP and int.from_bytes(ram[KMAP-P+0x88:KMAP-P+0x8c],'little')==3
  counter=(7 if row['source_producer_case']is None else rows[row['source_producer_case']]['copy_error_counter'])+int(stage=='copyout'and c.get('copy_result',0)==5);assert row['copy_error_counter']==counter and next(e['bytes_hex']for e in row['final_image_globals']if e['address']=='0xfffffe000cb810f0')==struct.pack('<I',counter).hex();counts['source_error_counter_epoch_transfers_checked']+=1
  for v in row['source_visits']:assert any(int(f['start'],16)<=int(v['pc'],16)<int(f['end'],16)for f in source['functions'])
  if row['source_producer_case']is None:
   assert stage=='copyin'and row['initial_private_RAM_transfer']is None;seed=legacy[c['legacy_fixture_case']];original=next(e for e in seed['initial_private_fixtures']if e['address']==row['message_header_address']);assert original in row['initial_private_fixtures'];counts['exact_normalized_reply_seed_frames_checked']+=1
   assert row['return_u32']==0 and len(row['VM_copyin_entries'])==sum(n>0 for n in lens)
   for idx,n in enumerate(lens):
    ptr=u64(ram,h+36+16*idx);assert ptr==(COPIES[idx]if n else 0)
    if n:
     copy=ram[COPIES[idx]-P:COPIES[idx]-P+48];payload=bytes((idx*71+k*37+17)&255 for k in range(n));assert u64(copy,0)==BACKS[idx]and u64(copy,0x10)==0 and u64(copy,0x20)==n and copy[0x2d]==3 and ram[BACKS[idx]-P:BACKS[idx]-P+n]==payload;counts['source_constructed_type3_objects_checked']+=1
     removal=next(m for m in models if m['symbol']=='source_region_remove_request'and m['descriptor_index']==idx);published=next(w for w in row['source_writes']if w['pc']=='0xfffffe000bdd1f38'and int(w['address'],16)==int(row['VM_copyin_entries'][idx]['arguments5'][4],16)and w['after_hex']==struct.pack('<Q',COPIES[idx]).hex());descriptor=next(w for w in row['source_writes']if int(w['address'],16)==P+h+36+16*idx and w['after_hex']==struct.pack('<Q',COPIES[idx]).hex());assert removal['before_source_visit_index']<published['source_visit_index']<descriptor['source_visit_index'];counts['source_removal_publication_descriptor_order_checked']+=1
   counts['source_factory_components_checked']+=1
  else:
   producer=rows[row['source_producer_case']];initial=decode(row['initial_private_RAM_transfer']);assert initial==decode(producer['final_private_RAM'])and row['initial_private_RAM_transfer']['producer_case']==row['source_producer_case']and not row['initial_private_fixtures'];counts['exact_whole_RAM_snapshot_transfers_checked']+=1;counts['exact_whole_RAM_bytes_transferred_checked']+=SIZE
   assert row['initial_image_fixtures']==[{**e,'provenance':'Exact producer final image-global transfer'}for e in producer['final_image_globals']];counts['exact_image_global_snapshot_transfers_checked']+=1
   idx=c['descriptor_index'];ptr=u64(initial,h+36+idx*16);before=initial[COPIES[idx]-P:COPIES[idx]-P+48];after=ram[COPIES[idx]-P:COPIES[idx]-P+48];n=lens[idx];assert row['VM_handoff_frames'][0]['arguments']==([hex(KMAP),hex(OUT),hex(ptr)]if stage=='copyout'else[hex(ptr)])
   if stage=='copyout':
    result=c.get('allocation_result',0)or(1 if c.get('copy_result',0)else 0);assert row['return_u32']==result and row['mapped_address']==(DEST if n and not result else 0)
    assert after==(bytes(48)if n and result==0 else before);counts['source_consume_or_preserve_outcomes_checked']+=1
    if n and result==0:assert ram[DEST-P:DEST-P+n]==initial[BACKS[idx]-P:BACKS[idx]-P+n];counts['exact_produced_payload_copyouts_checked']+=1;counts['exact_produced_payload_bytes_checked']+=n
    else:assert ram[DEST-P:DEST-P+32768]==initial[DEST-P:DEST-P+32768]
    contexts=bool(n and not c.get('allocation_result',0));assert len(row['map_context_frames'])==2*int(contexts)
    if contexts:assert row['map_context_frames'][1]['record24_hex']==struct.pack('<QQII',MAP,0,0,0).hex();counts['original_X8_map_context_save_restore_pairs_checked']+=1
    assert names.count('source_region_remove_request')==int(bool(c.get('copy_result',0)))
   else:assert stage=='discard'and after==(bytes(48)if ptr else before);counts['source_discarded_produced_objects_checked']+=int(bool(ptr));counts['source_NULL_discard_checked']+=int(not ptr)
   consumes=bool(ptr)and(stage=='discard'or not c.get('allocation_result',0)and not c.get('copy_result',0));assert names.count('backing_release_request')==names.count('copy_header_release_request')==int(consumes)
   if consumes:
    b=next(m for m in models if m['symbol']=='backing_release_request');end=next(m for m in models if m['symbol']=='copy_header_release_request');assert b['arguments8'][:3]==[hex(0xfffffe0007f8bfb0),hex(BACKS[idx]),hex(n)]and end['arguments8'][:4]==[hex(ZONE),hex(AUX),hex(COPIES[idx]),'0x30'];clear=next(w for w in row['source_writes']if w['pc']==('0xfffffe000bdc64e8'if stage=='discard'else'0xfffffe000bdcbf0c'));assert clear['address']==hex(COPIES[idx])and clear['after_hex']=='00'*8 and clear['source_visit_index']<b['before_source_visit_index']<end['before_source_visit_index'];counts['source_payload_clear_release_header_release_sequences_checked']+=1
  for k,m in enumerate(models):
   expected=[hex(((i+1)*0x123456789abcdef)^(k+1)*0x8b3dc651)for i in range(18)];expected[0]=m['return_value'];assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False
   if m['symbol']=='source_region_remove_request':
    args=[int(x,16)for x in m['arguments8']]
    if stage=='copyin':idx=SOURCES.index(args[1]);assert args[:5]==[MAP,SOURCES[idx],(SOURCES[idx]+lens[idx]+16383)&~16383,2,0];counts['source_map_remove_before_publication_requests_checked']+=1
    else:assert stage=='copyout'and c.get('copy_result')==5 and args[:5]==[KMAP,DEST,DEST+16384,0,0];counts['failed_destination_mapping_cleanup_requests_checked']+=1
  totals.update(Replay(im,row).run());summary.append({'case':j,'configuration':c,'producer_case':row['source_producer_case'],'source_visits':len(row['source_visits']),'API_models':len(models),'raw_return_u32':row['return_u32']});print(json.dumps({**summary[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=18,functions=23,captured_instructions=4492,original_instruction_roles=32)
 deps=[PREFIX+'_source.json',PREFIX+'_profiles.json','rpc502_reply_copyin_profiles.json','replay_'+PREFIX+'.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':summary,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
