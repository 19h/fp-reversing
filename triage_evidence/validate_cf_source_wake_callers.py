#!/usr/bin/env python3
"""Verify full CF B/BL census, raw daemon import inventory and source contracts.
Independent original instruction/CPU/RAM replay, source timestamp and callback
oracles; six deliberately altered records must be rejected. Source-pinned
private evidence only: no native IPC, scheduling, caller or PAC proof.
O(captured text + visits + hashed input bytes + RAM + journals) time/space.
"""
import copy,json,struct
from collections import Counter
from pathlib import Path
import capstone
from daemon_receive_tools import ROOT
from recover_cf_source_wake_callers import P,FLAGS,sha,build,SIGNAL,WAKELOOPS,LOOP,COPY,APPLY,INVOKE,WAKE
from replay_cf_source_wake_callers import Replay,SRC,RL,COPYBAG
from replay_kernel_wake_send_ingress import Replay as KernelReplay
from replay_kernel_timer_port_create import StartupReplay
from replay_kernel_zone_startup import Replay as ZoneReplay
from replay_kernel_request_delivery import Replay as LoanReplay
from bootpolicy_cache_reader import Cache
from kernel_vm_mig_tools import Image

def get(n):return json.loads((ROOT/n).read_text())
def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');assert s==build();c=Counter();ct=Counter();kt=Counter();st=Counter();zt=Counter();lt=Counter();cache=Cache();cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};prior=get('cf_runloop_wake_port_profiles.json');im=Image();summaries=[]
 for o,n in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert o['generator_sha256']==sha(ROOT/n)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 for f in cs['CF_functions']+cs['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in cs['cache_files']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 scan=s['caller_census'];start=int(scan['section_address'],16);raw=cache.read(start,scan['section_size_bytes']);assert sha_bytes(raw)==scan['section_sha256'];md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM);md.skipdata=True;refs={WAKE:[],WAKELOOPS:[]}
 for i in md.disasm(raw,start):
  if i.mnemonic in('b','bl'):
   target=int(i.op_str.lstrip('#'),16)
   if target in refs:refs[target].append((hex(i.address),bytes(i.bytes).hex()))
 for target,key in((WAKE,'direct_B_BL_refs'),(WAKELOOPS,'direct_source_wake_helper_B_BL_refs')):assert refs[target]==[(e['pc'],e['bytes_hex'])for e in scan[key]]
 assert len(refs[WAKE])==26 and len(refs[WAKELOOPS])==7 and len({e['caller_start']for e in scan['direct_B_BL_refs']})==25 and len({e['caller_start']for e in scan['direct_source_wake_helper_B_BL_refs']})==5
 assert all('FileDescriptor'in e['caller_exact_nlist'][0]['name']for e in scan['direct_source_wake_helper_B_BL_refs'])and all(v is None for v in s['source_wake_helper_linkage']['queried_exports'].values())
 imports=s['daemon_named_import_inventory'];assert imports['import_count']==243 and len(imports['all_import_records'])==243 and len(imports['queried_names']['_CFRunLoopAddSource'])==len(imports['queried_names']['_CFMachPortInvalidate'])==1
 for n,rows in imports['queried_names'].items():
  if n not in('_CFRunLoopAddSource','_CFMachPortInvalidate'):assert not rows
 assert len(imports['file_descriptor_named_imports'])==len(imports['file_descriptor_bindings'])==5 and {e['name']for e in imports['file_descriptor_named_imports']}=={'_CFFileDescriptorCreate','_CFFileDescriptorCreateRunLoopSource','_CFFileDescriptorEnableCallBacks','_CFFileDescriptorInvalidate','_CFFileDescriptorGetNativeDescriptor'}
 c.update(complete_CF_functions_recaptured=len(cs['CF_functions']),captured_CF_instructions=sum(len(f['instructions'])for f in cs['CF_functions'])+4*len(cs['import_stubs']),cache_files_hashed=len(cs['cache_files']),CF_text_instruction_words_scanned=scan['instruction_words_scanned'],direct_wake_branch_sites=26,direct_wake_caller_functions=25,direct_helper_branch_sites=7,direct_helper_file_descriptor_callers=5,raw_daemon_import_records_checked=243,selected_raw_daemon_bindings_checked=7,daemon_file_descriptor_named_imports=5)
 # Fresh downstream scalar send/set-delivery and its prerequisite epochs.
 prior_kernel=get('kernel_wake_send_ingress_profiles.json');kr=prior_kernel['cases'][1];packet=s['CF_original_trap_packets'][kr['configuration']['packet']];kt.update(KernelReplay(im,kr,packet).run())
 for r in get('kernel_timer_port_create_profiles.json')['startup_cases'][:1]:st.update(StartupReplay(im,r).run())
 for r in get('kernel_zone_startup_profiles.json')['cases'][:3]:zt.update(ZoneReplay(im,r).run())
 for r in get('kernel_request_delivery_profiles.json')['loans']:lt.update(LoanReplay(im,r).run())
 for a,b in zip(prior['kernel_cases'][2]['wake_returns'],kr['wake_returns'],strict=True):assert a['registers31'][0]==b['registers31'][0]=='0x0'and a['wake_name4_hex']==b['wake_name4_hex']=='07080000'
 c['CF_constructor_member_returns_match_fresh_kernel_prefix']=2
 assert len(p['cases'])==10
 for j,r in enumerate(p['cases']):
  ct.update(Replay(r,prior['kernel_cases'][2],cs).run());cfg=r['configuration'];pcs=[e['pc']for e in r['source_visits']];last=r['source_wake_returns'][-1];source=bytes.fromhex(last['source256_hex']);timestamp=struct.unpack_from('<Q',source,0x58)[0];clock=0 if cfg['source_invalid']else cfg['signal_repeats'];assert timestamp==(100 if clock else 0)and r['signal_clock_calls']==clock and pcs.count(hex(SIGNAL))==cfg['signal_repeats'];assert r['copy_guard_hex']=='a5'
  callbacks=0 if not cfg['call_helper']or cfg['source_invalid']or cfg['missing_bag']or cfg['copy_null']else cfg['bag_multiplicity'];assert pcs.count(hex(LOOP))==pcs.count(hex(WAKE))==callbacks
  assert len(r['SVC_return_contracts'])==(0 if cfg['wake_case']=='suppressed'else callbacks)and len(r['wrapper_returns'])==len(r['SVC_return_contracts'])and r['boundary']['kind']=='original_source_wake_contract_returned';c['source_timestamp_callback_and_original_send_oracles_checked']+=1
  if callbacks:
   apply=next(e for e in r['source_wake_frames']if e['pc']==hex(0x1847b7a44));assert[int(v,16)for v in apply['registers31'][:3]]==[COPYBAG,LOOP,0];unlock=next(e for e in r['source_wake_frames']if e['pc']==hex(0x1847b7a24));assert unlock['source_visit_index']<apply['source_visit_index'];c['original_source_unlock_before_original_bag_callbacks_checked']+=1
  if cfg['signal_repeats']==2:
   assert[struct.unpack_from('<Q',bytes.fromhex(e['source256_hex']),0x58)[0]for e in r['source_wake_returns']]==[100,100];c['first_nonzero_timestamp_preserved_across_repeated_signal_checked']+=1
  for e in r['SVC_return_contracts']:
   assert e['arguments8'][1:]==packet['arguments8'][1:]and e['before']['original_header24_hex']==packet['regions'][0]['bytes_hex'];c['source_callback_to_downstream_kernel_scalar_ABI_matches_checked']+=1
  if cfg['label']=='suppressed':assert callbacks==1 and not r['SVC_return_contracts'];c['original_runloop_suppression_after_bag_callback_checked']+=1
  if cfg['label']=='duplicate_bag':assert[e['declared_status']for e in r['SVC_return_contracts']]==['0x0','0x10000004'];c['original_duplicate_bag_callback_multiplicity_checked']+=1
  summaries.append({'label':cfg['label'],'original_visits':len(r['source_visits']),'signal_timestamp_ticks':timestamp,'declared_clock_calls':clock,'original_wake_callbacks':callbacks,'original_SVC_visits':len(r['SVC_return_contracts']),'private_backend_copy_multiplicity':r['declared_copy_multiplicity']});print(json.dumps(summaries[-1]),flush=True)
 assert ct['original_instruction_visits_checked']==15836 and ct['whole_final_private_RAM_bytes_checked']==30*1048576 and kt['source_visits_checked']==10384 and kt['whole_final_RAM_bytes_checked']+kt['complete_CF_user_epoch_final_bytes_checked']==3*1048576 and st['source_visits_checked']==170 and zt['source_visits_checked']==618 and lt['source_visits_checked']==216
 rejected=[]
 for tag in('signal_instruction','source_timestamp','bag_element','source_entry_premise','callback_target_frame','SVC_return_status'):
  bad=copy.deepcopy(p['cases'][2])
  if tag=='signal_instruction':next(e for e in bad['source_visits']if e['pc']==hex(0x184751c90))['bytes_hex']='00000000'
  elif tag=='source_timestamp':e=bad['source_wake_returns'][0];b=bytearray.fromhex(e['source256_hex']);b[0x58]^=1;e['source256_hex']=b.hex()
  elif tag=='source_entry_premise':bad['declared_source_fixture']['patches'][0]['after_hex']='00'*8
  elif tag=='callback_target_frame':next(e for e in bad['source_wake_frames']if e['pc']==hex(0x1847b7a44))['registers31'][1]='0x0'
  elif tag=='SVC_return_status':bad['SVC_return_contracts'][0]['declared_status']='0x10000004'
  else:
   for key in('imports','runloop_models','mode_models'):
    next(e for e in bad[key]if e['name']=='declared_source_bag_elements')['patches'][0]['after_hex']=struct.pack('<Q',RL+8).hex()
  try:Replay(bad,prior['kernel_cases'][2],cs).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('altered record accepted',tag))
 c['altered_evidence_controls_rejected']=len(rejected);positive=15836+10384+170+618+216;ram=30+3+1+3+4
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','replay_cf_wake_send_wrapper.py','cf_runloop_wake_port_profiles.json','kernel_wake_send_ingress_profiles.json','replay_kernel_wake_send_ingress.py','kernel_timer_port_create_profiles.json','replay_kernel_timer_port_create.py','kernel_zone_startup_profiles.json','kernel_request_delivery_profiles.json','replay_kernel_zone_startup.py','replay_kernel_request_delivery.py']},'source_recapture_match':True,'verified_counts':dict(c),'independent_CF_replay':dict(ct),'fresh_downstream_kernel_replay':dict(kt),'fresh_timer_startup_replay':dict(st),'fresh_zone_replay':dict(zt),'fresh_receiver_loan_replay':dict(lt),'case_summaries':summaries,'aggregate_positive_visits':positive,'whole_final_private_RAM_bytes_checked':ram*1048576,'altered_evidence_rejected':rejected,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'aggregate_positive_visits':positive,'whole_final_private_RAM_bytes_checked':ram*1048576,'all_checks_pass':True}),flush=True)
def sha_bytes(b):return __import__('hashlib').sha256(b).hexdigest()
if __name__=='__main__':main()
