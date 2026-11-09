#!/usr/bin/env python3
"""Verify original CF wake/libkernel/dispatch aux/retry/SVC composition.
Independent provenance, full CPU/RAM, original stores, all packed/vector bytes,
retry status streams and altered evidence rejection. No kernel send executes.
"""
import copy,json,struct
from collections import Counter
from pathlib import Path
from daemon_receive_tools import ROOT
from recover_cf_wake_send_wrapper import P,FLAGS,sha,build,MACH,OVERWRITE,INTERNAL,TRAP,SVC,AUX
from replay_cf_wake_send_wrapper import Replay
from replay_cf_runloop_wake_port import Replay as KernelReplay,CFReplay as FactoryReplay
from replay_kernel_timer_port_create import StartupReplay
from replay_kernel_request_delivery import Replay as LoanReplay
from replay_kernel_zone_startup import Replay as ZoneReplay
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache

def get(n):return json.loads((ROOT/n).read_text())
def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');prior=get('cf_runloop_wake_port_profiles.json');assert s==build();im=Image();cache=Cache();c=Counter();kt=Counter();ct=Counter();ft=Counter();st=Counter();zt=Counter();lt=Counter();summaries=[]
 for o,script in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 assert s['kernel_sha256']==im.k.sha256 and len(s['functions'])==173 and sum(len(f['instructions'])for f in s['functions'])==22684
 for f in s['functions']:assert im.k.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 cs={**s['CF_source'],'root_caller_options':s['root_caller_options']}
 for f in cs['CF_functions']+cs['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in cs['cache_files']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 assert len(cs['CF_functions'])==50 and sum(len(f['instructions'])for f in cs['CF_functions'])+4*len(cs['import_stubs'])==3992 and s['raw_send_trap']=={'entry':hex(TRAP),'svc':hex(SVC),'selector':-47,'bytes12_hex':cache.read(TRAP,12).hex(),'native_executed':False};binding=s['kernel_trap_binding'];assert binding['handler_pointer']['target']=='0xfffffe000bcdd73c'and binding['argument_count']==8 and binding['u32_words']==16 and binding['handler_executed']is False
 ref=s['pinned_public_header'];assert sha(ROOT/ref['path'])==ref['sha256']and ref['exact_target_revision']is False
 c.update(complete_kernel_functions_recaptured=173,captured_kernel_instructions=22684,complete_CF_functions_recaptured=50,captured_CF_instructions=3992,cache_files_hashed=9,pinned_public_header_rehashed=1,static_trap47_eight_slot_kernel_binding_checked=1)
 for r in prior['startup_cases']:st.update(StartupReplay(im,r).run())
 for r in get('kernel_request_delivery_profiles.json')['loans']:lt.update(LoanReplay(im,r).run())
 for r in get('kernel_zone_startup_profiles.json')['cases'][:3]:zt.update(ZoneReplay(im,r).run())
 for r in prior['kernel_cases']:kt.update(KernelReplay(im,r).run())
 for r in prior['CF_cases']:ft.update(FactoryReplay(r,prior['kernel_cases'][2],cs).run())
 assert len(p['cases'])==8
 for j,r in enumerate(p['cases']):
  ct.update(Replay(r,prior['kernel_cases'][2],cs).run());cfg=r['configuration'];label=cfg['label'];rows=r['SVC_return_contracts'];assert len(rows)==len(cfg['trap_results'])and not r['kernel_transfers']and not r['application_frames']and r['runloop_guard_hex']=='a5';pcs=[e['pc']for e in r['source_visits']]
  assert not any(e['name']=='declared_wake_mach_msg_send_result'for e in r['imports']);c['direct_mach_msg_result_model_removed_checked']+=1
  base=prior['CF_cases'][0 if label=='suppressed'else 2 if cfg['trap_results'][-1]==0x10000004 else 1];assert r['final_runloop2720_hex']==base['final_runloop2720_hex']and r['final_mode512_hex']==base['final_mode512_hex']and r['final_queue128_hex']==base['final_queue128_hex']and r['final_model_state']==base['final_model_state']and r['final_user8192_hex']==base['final_user8192_hex']and r['final_OOL16384_hex']==base['final_OOL16384_hex'];c['unchanged_factory_mode_memberships_and_untouched_receive_buffers_checked']+=1
  if label=='suppressed':assert not rows and not r['wake_send']and not r['wrapper_returns']and hex(MACH)not in pcs and r['boundary']['kind']=='original_CFRunLoopWakeUp_returned';c['original_suppression_still_skips_entire_wrapper_checked']+=1
  else:
   assert len(r['wake_send'])==len(r['wrapper_returns'])==1 and all(hex(a)in pcs for a in(MACH,OVERWRITE,INTERNAL,TRAP,AUX,SVC));header=struct.pack('<6I',0x13,24,0x807,0,0,0);assert r['wake_send'][0]['header24_hex']==header.hex();ret=r['wrapper_returns'][0];assert ret['registers31'][0]==hex(cfg['trap_results'][-1])and ret['original_header24_hex']==header.hex()and ret['hook_root8_hex']==struct.pack('<Q',0x1e24b27d0).hex();c['original_installed_hook_aux_callback_and_wrapper_to_CF_returns_checked']+=1
   for ix,e in enumerate(rows):assert e['before']['original_header24_hex']==e['after']['original_header24_hex']==header.hex()and e['declared_status']==hex(cfg['trap_results'][ix])and e['memory_before']==e['memory_after'];c['original_header_preserved_at_each_status_only_trap_boundary_checked']+=1
   assert all(e['arguments8']==rows[0]['arguments8']and e['vector48_hex']==rows[0]['vector48_hex']and e['aux40_hex']==rows[0]['aux40_hex']for e in rows);c['unchanged_packed_retry_arguments_and_vector_backing_checked']+=1
   assert sum(pc==hex(SVC)for pc in pcs)==len(rows)and sum(pc==hex(AUX)for pc in pcs)==1 and sum(pc==hex(0x18055a918)for pc in pcs)==len(rows)-1;c['retry_loop_call_counts_without_reinvoking_aux_callback_checked']+=1
   if len(rows)>1:assert cfg['trap_results'][:-1]==[0x10000007]*(len(rows)-1)and cfg['trap_results'][-1]in(0,0x10000004);c['interrupted_trap_results_retried_before_CF_checked']+=1
   if cfg.get('aux'):
    c['original_nonempty_TLS_aux40_and_two_record_vector_cases_checked']+=1;stores=[e for e in r['source_writes']if e['pc']in('0x18553c2d0','0x18553c2d8','0x18553c2dc')];assert len(stores)==5 and[e['pc']for e in stores]==['0x18553c2d0']*2+['0x18553c2d8']+['0x18553c2dc']*2 and all(e['size_bytes']==8 for e in stores)and[int(e['address'],16)for e in stores]==[int(stores[0]['address'],16)+8*i for i in range(5)]and''.join(e['after_hex']for e in stores)==rows[0]['aux40_hex'];c['complete_original_aux_producer_store_sets_checked']+=1
   else:assert all(e['vector48_hex']is None for e in rows);c['original_empty_TLS_aux_scalar_transport_cases_checked']+=1
   if label=='invalid_data':assert cfg['trap_results']==[0x10000002]and r['boundary']['kind']=='before_original_wake_send_failure'and r['boundary']['pc']=='0x1848d4168';c['nonretry_trap_status_reaches_original_CF_diagnostic_boundary_checked']+=1
   else:assert r['boundary']['kind']=='original_CFRunLoopWakeUp_returned';c['eventual_success_timeout_return_to_original_CF_checked']+=1
  summaries.append({'case':label,'original_visits_including_intercepted_SVC':len(r['source_visits']),'intercepted_SVC_count':len(rows),'declared_trap_status_stream':[hex(v)for v in cfg['trap_results']],'aux_vector':cfg.get('aux',False),'boundary':r['boundary']['kind']});print(json.dumps(summaries[-1]),flush=True)
 assert ct['original_instruction_visits_checked']==12163 and ct['whole_final_private_RAM_bytes_checked']==25165824 and ct['intercepted_original_SVC_visits_checked']==11 and ct['complete_two_record_vectors_and_original_aux40_bytes_checked']==3 and ct['original_libkernel_wrapper_and_aux_visits_checked']==1135
 assert kt['source_visits_checked']==27756 and ft['original_instruction_visits_checked']==5425 and st['source_visits_checked']==170 and zt['source_visits_checked']==618 and lt['source_visits_checked']==216
 rejected=[]
 for tag,case in(('packed_option',1),('packed_size',1),('vector_aux_size',6),('aux_producer_bytes',6),('interrupted_status',3),('original_wrapper_return',1)):
  bad=copy.deepcopy(p['cases'][case]);e=bad['SVC_return_contracts'][0]
  if tag in('packed_option','packed_size'):ix=1 if tag=='packed_option'else 2;e['arguments8'][ix]=hex(int(e['arguments8'][ix],16)^1)
  elif tag=='vector_aux_size':raw=bytearray.fromhex(e['vector48_hex']);raw[40]^=1;e['vector48_hex']=raw.hex()
  elif tag=='aux_producer_bytes':raw=bytearray.fromhex(e['aux40_hex']);raw[8]^=1;e['aux40_hex']=raw.hex()
  elif tag=='interrupted_status':e['declared_status']='0x0'
  else:bad['wrapper_returns'][0]['registers31'][0]='0x1'
  try:Replay(bad,prior['kernel_cases'][2],cs).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('altered record accepted',tag))
 c['altered_evidence_controls_rejected']=len(rejected)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','cf_runloop_wake_port_profiles.json','replay_cf_runloop_wake_port.py','kernel_zone_startup_profiles.json','kernel_request_delivery_profiles.json','replay_kernel_zone_startup.py','replay_kernel_request_delivery.py']},'source_recapture_match':True,'verified_counts':dict(c),'independent_A64_replay':dict(kt),'independent_CF_replay':dict(ct),'fresh_CF_factory_replay':dict(ft),'fresh_timer_startup_replay':dict(st),'fresh_receiver_loan_replay':dict(lt),'fresh_zone_replay':dict(zt),'altered_evidence_rejected':rejected,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'new_CF_visits':ct['original_instruction_visits_checked'],'aggregate_positive_visits':12163+5425+27756+170+618+216,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
