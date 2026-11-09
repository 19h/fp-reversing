#!/usr/bin/env python3
"""Verify original CF packet -> original kernel Mach -47/send/set receive -> CF.
Independent complete CPU/RAM and semantic ABI oracles; declared epoch/raw/copy/
hash/runtime/PAC boundaries remain. No native exception crossing or Mach IPC.
"""
import copy,json,struct,subprocess
from collections import Counter
from pathlib import Path
from daemon_receive_tools import ROOT
from recover_kernel_wake_send_ingress import P,FLAGS,sha,build,HANDLER,SEND,ROFLAGS
from replay_kernel_wake_send_ingress import Replay,CFReplay,WKMSG,WPORT,WNODE,RO,B,ARGS
from replay_cf_wake_send_wrapper import Replay as ProducerReplay
from replay_kernel_timer_port_create import StartupReplay,NODE,NODE2,NODE3,PS,TABLE
from replay_kernel_zone_startup import Replay as ZoneReplay
from replay_kernel_request_delivery import Replay as LoanReplay
from replay_rpc502_vm_handoff import decode
from bootpolicy_cache_reader import Cache
from kernel_vm_mig_tools import Image
from recover_cf_source_scheduling import DGET

def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def w(b,o):return struct.unpack_from('<I',b,o)[0]
def h(b,o):return struct.unpack_from('<H',b,o)[0]
def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');prior=get('cf_runloop_wake_port_profiles.json');producers=get('cf_wake_send_wrapper_profiles.json');baseline=get('kernel_timer_port_create_profiles.json');assert s==build();im=Image();cache=Cache();c=Counter();kt=Counter();ct=Counter();pt=Counter();st=Counter();zt=Counter();lt=Counter();summaries=[]
 for o,script in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for n,digest in o['dependencies'].items():assert sha(ROOT/n)==digest
 assert s['kernel_sha256']==im.k.sha256 and len(s['functions'])==183 and sum(len(f['instructions'])for f in s['functions'])==24084 and len(p['cases'])==5 and len(p['CF_cases'])==4
 for f in s['functions']:assert im.k.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 cs={**s['CF_source'],'root_caller_options':s['root_caller_options']}
 for f in cs['CF_functions']+cs['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in cs['cache_files']+s['SDK_wake_headers']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 assert len(cs['CF_functions'])==52 and sum(len(f['instructions'])for f in cs['CF_functions'])+4*len(cs['import_stubs'])==4024
 sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk');command=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-fsyntax-only','-x','c','-'];layout='#include <stddef.h>\n#include <mach/message.h>\n_Static_assert(sizeof(mach_msg_mac_trailer_t)==68,"MAC trailer");\n_Static_assert(offsetof(mach_msg_mac_trailer_t,msgh_sender)==12,"sender");\n_Static_assert(offsetof(mach_msg_mac_trailer_t,msgh_audit)==20,"audit");\n_Static_assert(offsetof(mach_msg_mac_trailer_t,msgh_context)==52,"context");\n';subprocess.run(command,input=layout,text=True,capture_output=True,check=True)
 c.update(complete_kernel_functions_recaptured=183,captured_kernel_instructions=24084,complete_CF_functions_recaptured=52,captured_CF_instructions=4024,cache_files_hashed=9,SDK_headers_hashed=2,SDK_arm64e_trailer_layout_assertions_checked=4)
 for r in p['startup_cases']:st.update(StartupReplay(im,r).run())
 for r in get('kernel_request_delivery_profiles.json')['loans']:lt.update(LoanReplay(im,r).run())
 for r in get('kernel_zone_startup_profiles.json')['cases'][:3]:zt.update(ZoneReplay(im,r).run())
 for j in(1,6):pt.update(ProducerReplay(producers['cases'][j],prior['kernel_cases'][2],cs).run())
 for j,r in enumerate(p['cases']):
  packet=s['CF_original_trap_packets'][r['configuration']['packet']];kt.update(Replay(im,r,packet).run());ports=bytes.fromhex(r['final_wake_port144_hex']);assert r['wake_kmsg_guard_hex']==r['readonly_guard_hex']==r['identity_guard_hex']=='a5'and r['wake_guards_hex']=='a5a5';ret=r['ingress_returns'][0];assert ret['phase']=='wake_send';pcs={e['pc']for e in r['source_visits']};assert hex(HANDLER)in pcs and hex(ROFLAGS)in pcs;c['original_Mach47_and_task_readonly_validation_paths_checked']+=1
  if r['configuration'].get('vector_copyin_error'):
   assert ret['registers31'][0]=='0x10000002'and r['boundary']['kind']=='original_Mach47_vector_copyin_error_returned'and hex(SEND)not in pcs and not r['raw_storage_contracts']and bytes.fromhex(r['final_wake_kmsg256_hex'])==bytes(256);c['original_vector_copyin_failure_before_send_and_allocation_checked']+=1;continue
  assert ret['registers31'][0]=='0x0'and r['boundary']['kind']=='receive_frontend_returned'and r['boundary']['registers31'][0]=='0x0';queued=bytes.fromhex(ret['wake_port144_hex']);msg=bytes.fromhex(ret['wake_kmsg256_hex']);assert h(queued,0x38)==1 and q(queued,0x28)==WKMSG and w(queued,4)==2 and w(queued,0x88)==2 and msg[64:96]==struct.pack('<IIQQII',0x11,32,WPORT,0,0,0);c['original_namespace_copy_send_reference_and_internal_header32_enqueue_checked']+=1
  first=next(e for e in r['pset_stage_returns']if e['phase']=='first_receive');wire=bytes.fromhex(first['user148_hex'])[:92];header=struct.pack('<6I',0x1100,24,0,0x807,0,0);trailer=struct.pack('<13I',0,68,0,0x11,0x33,0x55,0x11,0x33,0x22,0x44,0x77,0x66,0x88)+struct.pack('<QII',B+0xa0000,0,0);assert wire==header+trailer;c['complete_wake_header24_trailer68_identity_and_context_oracles_checked']+=1
  assert w(ports,4)==1 and w(ports,0x88)==1 and h(ports,0x38)==0 and h(ports,0x3a)==1 and w(ports,0x30)==1 and q(ports,0x78)==B+0xa0000 and w(bytes.fromhex(r['final_entry8_24_hex']),8)==0x04030001;c['drained_wake_queue_sequence_context_and_unchanged_user_send_uref_checked']+=1
  ps1=bytes.fromhex(first['pset56_hex']);ps2=bytes.fromhex(r['final_pset56_hex']);wake=bytes.fromhex(r['final_wake_link48_hex']);service=bytes.fromhex(r['final_service_link48_hex']);assert q(ps1,0x28)==NODE3+24 and q(ps2,0x28)==WNODE+24 and q(wake,0)==q(service,0)==(PS+0x10)|1 and q(wake,24)==q(wake,32)==NODE3+24 and q(service,24)==q(service,32)==WNODE+24 and q(ps2,0x20)==NODE+24;c['actual_wake_then_service_ready_head_rotation_and_retained_ready_bits_checked']+=1
  copies=[e for e in r['ingress_models']if e['name']=='declared_exact_original_CF_user_copyin']
  if r['configuration']['packet']==0:assert not copies and msg[216:]==bytes(40);c['scalar_header_reconstructed_from_packed_slots_without_user_copyin_checked']+=1
  else:
   assert[int(e['before']['registers31'][2],16)for e in copies]==[48,32];aux=next(e for e in packet['regions']if e['role']=='original_dispatch_aux40');assert msg[216:].hex()==aux['bytes_hex']and int(copies[1]['before']['registers31'][0],16)==int(aux['address'],16)+8;c['original_vector48_copyin_and_aux_payload32_header8_reconstruction_checked']+=1
  old=prior['kernel_cases'][r['configuration']['producer']];assert r['final_user8192_hex']==old['final_user8192_hex']and r['final_OOL16384_hex']==old['final_OOL16384_hex'];c['unchanged_service_receive_buffers_after_actual_wake_checked']+=1
  assert bytes.fromhex(r['final_wake_kmsg256_hex'])==bytes(256);c['complete_final_retired_raw_wake_storage_checked']+=1
  summaries.append({'case':j,'producer':r['configuration']['producer'],'vector':bool(r['configuration']['packet']),'original_visits':len(r['source_visits']),'wake_wire_bytes':92,'wake_received_name':'0x807','subsequent_service_name':r['receive_name']});print(json.dumps(summaries[-1]),flush=True)
 for j,r in enumerate(p['CF_cases']):
  ct.update(CFReplay(r,p['cases'][j],cs).run());pcs=[e['pc']for e in r['source_visits']];event=next(e for e in r['mode_models']if e['name']=='original_kernel_wake_set_receive_return');first=next(e for e in p['cases'][j]['pset_stage_returns']if e['phase']=='first_receive');assert event['patches'][0]['after_hex']==first['user148_hex'][:184]and event['wake_receive_oracle']=={'case':j,'return_source_visit_index':first['source_visit_index'],'wire_size_bytes':92};assert len(r['wake_receive_transfers'])==1 and len(r['kernel_transfers'])==1 and pcs.count(hex(DGET))==1 and pcs.count('0x100425f78')==1 and '0x184757744'not in pcs;c['actual_kernel_wake_routes_before_one_service_lookup_and_daemon_callback_checked']+=1
  old=baseline['CF_cases'][p['cases'][j]['configuration']['producer']];daemon=lambda x:[e for e in x['source_visits']if 0x100000000<=int(e['pc'],16)<0x102000000];assert daemon(r)==daemon(old)and r['boundary']['kind']==old['boundary']['kind'];assert decode(r['final_private_RAM'])[0x90000:0x900a0]==decode(old['final_private_RAM'])[0x90000:0x900a0]and r['final_OOL16384_hex']==old['final_OOL16384_hex']
  if j%2==0:assert r['final_argument_record120_hex']==old['final_argument_record120_hex']
  else:assert r['boundary']['registers31'][0]=='0x4'
  c['unchanged_complete_daemon_suffix_object_and_argument_record_or_return_checked']+=1
  push=[e for e in r['mode_models']if e['name']=='declared_objc_autorelease_pool_push'];assert len(push)==1 and push[0]['pool_tokens_before']==[]and push[0]['pool_tokens_after']==r['final_pool_tokens']==['0x123400001'];c['original_CF_pool_wrapper_and_declared_outstanding_runtime_token_checked']+=1
 for a,b in((0,2),(1,3)):
  x,y=p['CF_cases'][a],p['CF_cases'][b];assert x['source_visits']==y['source_visits']and x['final_private_RAM']==y['final_private_RAM']and x['final_lower_stack']==y['final_lower_stack']and x['final_model_state']==y['final_model_state'];c['scalar_and_vector_delivery_produce_identical_complete_CF_execution_state_checked']+=1
 assert kt['source_visits_checked']==45316 and kt['whole_final_RAM_bytes_checked']==5242880 and kt['complete_CF_user_epoch_final_bytes_checked']==10485760 and ct['original_instruction_visits_checked']==14848 and ct['whole_final_private_RAM_bytes_checked']==12582912 and pt['original_instruction_visits_checked']==3120 and pt['whole_final_private_RAM_bytes_checked']==6291456 and st['source_visits_checked']==170 and zt['source_visits_checked']==618 and lt['source_visits_checked']==216
 rejected=[]
 for tag in('source_CF_header','kernel_wake_local_name','kernel_sender_trailer','kernel_aux_payload_copy','CF_wake_return_bytes','CF_receive_provenance'):
  if tag.startswith('CF_'):
   bad=copy.deepcopy(p['CF_cases'][0])
   for key in('imports','runloop_models','mode_models'):
    e=next(e for e in bad[key]if e['name']=='original_kernel_wake_set_receive_return')
    if tag=='CF_wake_return_bytes':raw=bytearray.fromhex(e['patches'][0]['after_hex']);raw[12]^=1;e['patches'][0]['after_hex']=raw.hex()
    else:e['wake_receive_oracle']['case']=99
   check=lambda:CFReplay(bad,p['cases'][0],cs).run()
  else:
   ix=2 if tag=='kernel_aux_payload_copy'else 0;bad=copy.deepcopy(p['cases'][ix])
   if tag=='source_CF_header':bad['original_CF_user_epoch']['regions'][0]['bytes_hex']='00'*24
   elif tag=='kernel_aux_payload_copy':
    e=next(e for e in bad['ingress_models']if e['name']=='declared_exact_original_CF_user_copyin'and e['before']['registers31'][2]=='0x20');raw=bytearray.fromhex(e['patches'][0]['after_hex']);raw[0]^=1;e['patches'][0]['after_hex']=raw.hex()
   else:e=next(e for e in bad['pset_stage_returns']if e['phase']=='first_receive');raw=bytearray.fromhex(e['user148_hex']);raw[12 if tag=='kernel_wake_local_name'else 44]^=1;e['user148_hex']=raw.hex()
   check=lambda:Replay(im,bad,s['CF_original_trap_packets'][bad['configuration']['packet']]).run()
  try:check()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('altered record accepted',tag))
 c['altered_evidence_controls_rejected']=len(rejected)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','cf_wake_send_wrapper_profiles.json','replay_cf_wake_send_wrapper.py','cf_runloop_wake_port_profiles.json','kernel_timer_port_create_profiles.json','kernel_zone_startup_profiles.json','kernel_request_delivery_profiles.json','replay_kernel_zone_startup.py','replay_kernel_request_delivery.py']},'source_recapture_match':True,'verified_counts':dict(c),'independent_A64_replay':dict(kt),'independent_CF_replay':dict(ct),'fresh_CF_producer_replay':dict(pt),'fresh_timer_startup_replay':dict(st),'fresh_receiver_loan_replay':dict(lt),'fresh_zone_replay':dict(zt),'SDK_layout_validation':{'command':command,'source':layout,'exit_code':0,'native_executed':False},'altered_evidence_rejected':rejected,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'kernel_visits':kt['source_visits_checked'],'CF_visits':ct['original_instruction_visits_checked'],'aggregate_positive_visits':45316+14848+3120+170+618+216,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
