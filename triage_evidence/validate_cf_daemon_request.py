#!/usr/bin/env python3
"""Independent produced-buffer, CF ABI, control and complete-record oracles.
O(source/cache bytes+visits+RAM+journals), O(image+RAM+journals). No native
framework reception, registration, thread API or FairPlay round trip.
"""
import json,struct
from collections import Counter
from daemon_receive_tools import ROOT,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from recover_cf_daemon_request import P,FLAGS,sha,build
from recover_cf_receive import DO_SOURCE,SOURCE_CALL,PERFORM
from replay_cf_daemon_request import Replay,B,USER,OOL,REPLY,OBJ,RL,MODE,SRC,OUT,STACK,HALT
from replay_daemon_request_application import Replay as ApplicationReplay
from replay_kernel_request_delivery import Replay as KernelReplay
from replay_rpc502_vm_handoff import decode
from kernel_vm_mig_tools import Image as KernelImage
def get(name):return json.loads((ROOT/name).read_text())
def main():
 src=get(P+'_source.json');prof=get(P+'_profiles.json');kernel=get('kernel_request_delivery_profiles.json');app=get('daemon_request_application_profiles.json');appsrc=get('daemon_request_application_source.json');callback=get('daemon_request_consumption_profiles.json');counts=Counter();totals=Counter();kt=Counter();at=Counter();summaries=[];slots=set();assert src==build();im=KernelImage()
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 counts.update({'CF_functions_recaptured':len(src['CF_functions']),'CF_instructions_recaptured':sum(len(f['instructions'])for f in src['CF_functions']),'CF_original_pages_recaptured':len(src['CF_original_pages']),'CF_helper_boundaries_recaptured':len(src['CF_runtime_boundary_helpers']),'cache_files_hashed':len(src['cache_files']),'original_CF_pointer_chains_checked':sum('original_cache_pointer'in e for e in src['CF_runtime_global_cells'])})
 assert len(prof['cases'])==4 and[r['kernel_case_index']for r in prof['cases']]==[1,3,5,7]
 for r in prof['cases']:
  idx=r['kernel_case_index'];k=kernel['cases'][idx];assert r['configuration']==k['configuration']and k['configuration']['capacity']==148;kt.update(KernelReplay(im,k).run());ram=decode(k['final_private_RAM']);user=bytes.fromhex(k['final_user8192_hex']);ool=bytes.fromhex(k['final_OOL16384_hex']);assert ram[0x1000:0x1000+8192]==user and ram[0x4000:0x4000+16384]==ool and struct.unpack_from('<II',user,80)==(0,68);counts['fresh_kernel_delivery_and_complete_imported_buffer_oracles_checked']+=1
  cf=r['CF_frames'];entry=next(f for f in cf if f['pc']==hex(DO_SOURCE));sc=next(f for f in cf if f['pc']==hex(SOURCE_CALL));perform=next(f for f in cf if f['pc']==hex(PERFORM));call=next(f for f in cf if f['pc']=='0x100425f78');assert entry['registers31'][:6]==[hex(x)for x in(RL,MODE,SRC,USER,80,OUT)]and sc['registers31'][:5]==[hex(x)for x in(PERFORM,USER,80,OUT,OBJ)]and perform['registers31'][:4]==[hex(x)for x in(USER,80,0x65000b0000,OBJ)]and call['registers31'][:4]==[hex(OBJ),hex(USER),'0x50','0x0'];assert call['source_visit_index']==136
  for f in cf:assert f['user148_hex']==user[:148].hex()
  assert r['final_user8192_hex']==user.hex()and r['final_OOL16384_hex']==ool.hex();counts['original_CF_source_perform_daemon_ABI_and_unchanged_trailer_oracles_checked']+=1
  object_bytes=bytearray(160);struct.pack_into('<Q',object_bytes,0x30,0x100425f78);source_bytes=bytearray(256)
  for off,value in((8,8),(0x70,OBJ),(0xa8,PERFORM)):struct.pack_into('<Q',source_bytes,off,value)
  assert r['final_CF_object160_hex']==object_bytes.hex()and r['final_source256_hex']==source_bytes.hex();counts['complete_CF_object_and_source_record_oracles_checked']+=1
  clear=[w for w in r['source_writes']if w['pc']=='0x184758c88'];assert len(clear)==1 and clear[0]['address']==hex(SRC+0x58)and clear[0]['size_bytes']==8 and clear[0]['after_hex']=='00'*8;counts['original_source_pending_field_clear_checked']+=1
  iscf=lambda v:any(int(f['start'],16)<=int(v['pc'],16)<int(f['end'],16)for f in src['CF_functions']);component=[v for v in r['source_visits']if not iscf(v)];kind=r['boundary']['kind'];mid=struct.unpack_from('<I',user,20)[0]
  if mid==502:
   old=next(e for e in app['cases']if e['kernel_case_index']==idx);at.update(ApplicationReplay(old,k,appsrc).run());assert kind=='before_pthread_self'and component==old['source_visits']and r['final_argument_record120_hex']==old['final_argument_record120_hex']and r['reply384_hex']==old['reply384_hex']and r['final_generic_reply8_hex']=='a5'*8
   assert int(r['application_handoff']['SP'],16)==int(old['application_handoff']['SP'],16)-0x1110;control=next(f for f in r['application_frames']if f['pc']=='0x100023a74');sp=int(r['application_handoff']['SP'],16)-0x150;F=sp+0xc0;R=sp+0x28;U=sp+0xa0;p=((F&0xffffffff)^0xeaae0ac9)*0x7398180b&0xffffffff;expected=struct.pack('<QIIQ',U^0x1c0b9f7ce10f2255,p^0x6cf4,p^0xbc84919b,R)+b'\xa5'*8;assert control['control_record_address']==hex(F)and control['control_record32_hex']==expected.hex();counts['continuous_CF_daemon_application_record_and_component_trace_oracles_checked']+=1
  else:
   assert mid==700 and kind=='CF_source_returned'and component==callback['cases'][idx]['source_visits']and r['application_handoff']is None and not r['application_frames']and r['reply384_hex']=='a5'*384 and r['final_generic_reply8_hex']=='00'*8;assert r['boundary']['registers31'][0]=='0x1'and r['boundary']['SP']==hex(STACK+0x78000)and r['boundary']['registers31'][18:30]==['0x0']*12 and r['boundary']['registers31'][30]==hex(HALT)
   stores=[e for e in r['source_writes']if e['address']==hex(OUT)];assert len(stores)==1 and stores[0]['pc']=='0x184758efc'and stores[0]['size_bytes']==8 and stores[0]['before_hex']=='a5'*8 and stores[0]['after_hex']=='00'*8;counts['RPC700_actual_callback_return_CF_null_reply_and_handled_boolean_checked']+=1
  assert len(r['CF_models'])==(10 if mid==502 else 15)and r['CF_models'][0]['before']['registers31'][9]=='0x1040';counts['explicit_CF_runtime_model_sets_checked']+=1
  for e in r['source_reads']:
   a=int(e['address'],16);slots.update(x for x in range(a,a+e['size_bytes'])if x in FIXUPS)
  totals.update(Replay(r,k,src).run());summaries.append({'kernel_case':idx,'message_id':mid,'inline_bytes':80,'trailer_bytes':68,'source_visits':len(r['source_visits']),'boundary':kind,'CF_generic_reply_bytes':r['final_generic_reply8_hex']});print(json.dumps(summaries[-1]),flush=True)
 rebases={a for a in slots if not FIXUPS[a]['kind'].endswith('bind')};fix=verify_original_fixups(rebases);imports=[binding(a)for a in sorted(slots-rebases)];counts['original_used_daemon_fixup_words_checked']=len(fix['records'])+len(imports);counts['cases']=4
 oldchecks=get('daemon_request_application_checks.json');known={int(e['address'],16)for e in oldchecks['original_rebase_checks']['records']}|{int(e['slot'],16)for e in oldchecks['original_import_checks']};assert slots-known=={0x10106fbe8,0x101076268,0x101086268}and known<=slots;counts['additional_RPC700_callback_continuation_fixups_checked']=len(slots-known)
 assert totals['original_instruction_visits_checked']==7038 and totals['cached_CF_instruction_visits_checked']==658 and totals['cached_libbsm_instruction_visits_checked']==38 and totals['whole_private_RAM_bytes_checked']==6291456 and totals['explicit_CF_primitive_and_stack_contracts_checked']==50 and totals['CF_daemon_complete_ABI_object_and_message_frames_checked']==30 and kt['source_visits_checked']==10380 and at['original_instruction_visits_checked']==5934 and counts['original_used_daemon_fixup_words_checked']==160,{'counts':dict(counts),'replay':dict(totals),'kernel_visits':kt['source_visits_checked'],'application_visits':at['original_instruction_visits_checked']}
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','daemon_request_application_profiles.json','daemon_request_application_source.json','daemon_request_application_checks.json','replay_daemon_request_application.py','kernel_request_delivery_profiles.json','replay_kernel_request_delivery.py','daemon_import_bindings.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_kernel_delivery_replay':dict(kt),'fresh_application_component_replay':dict(at),'original_daemon_rebase_checks':fix,'original_daemon_import_checks':imports,'case_summaries':summaries,'all_checks_pass':True,**FLAGS};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(counts),'replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
