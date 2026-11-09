#!/usr/bin/env python3
"""Verify original wake port/CF construction/emission with independent replay.
Full provenance, CPU/RAM/model/state/original-store oracles and six altered
controls. Injected Mach send statuses are not kernel queue delivery evidence.
"""
import copy,json,struct
from collections import Counter
from pathlib import Path
from daemon_receive_tools import ROOT
from recover_cf_runloop_wake_port import P,FLAGS,sha,build,CREATE,WAKE,CHECK,MACH,DEFAULT
from replay_cf_runloop_wake_port import Replay,CFReplay,WPORT,WNODE,COMMON,OWNER,RL,MODE,REGISTRY
from replay_kernel_timer_port_create import StartupReplay,NODE,NODE2,NODE3,PS,TABLE
from replay_kernel_request_delivery import Replay as LoanReplay
from replay_kernel_zone_startup import Replay as ZoneReplay
from replay_rpc502_vm_handoff import P as B
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache

def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def w(b,o):return struct.unpack_from('<I',b,o)[0]
def h(b,o):return struct.unpack_from('<H',b,o)[0]
def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');old=get('kernel_timer_port_create_profiles.json');loans=get('kernel_request_delivery_profiles.json')['loans'];zones=get('kernel_zone_startup_profiles.json')['cases'];assert s==build();im=Image();c=Counter();kt=Counter();ct=Counter();st=Counter();lt=Counter();zt=Counter();summaries=[]
 for o,script in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for n,digest in o['dependencies'].items():assert sha(ROOT/n)==digest
 assert len(s['functions'])==172 and sum(len(f['instructions'])for f in s['functions'])==22410 and len(p['kernel_cases'])==4 and len(p['CF_cases'])==5 and len(p['startup_cases'])==1
 cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};cache=Cache()
 for f in cs['CF_functions']+cs['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in cs['cache_files']+s['SDK_wake_headers']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 assert s['wake_original_options24_hex']==struct.pack('<IIQQ',0x33,1,0,0).hex()and s['wake_original_message_constant8_hex']==struct.pack('<2I',0x13,24).hex();assert s['SDK_wake_constants']=={'MPO_CONTEXT_AS_GUARD':1,'MPO_QLIMIT':2,'MPO_INSERT_SEND_RIGHT':16,'MPO_STRICT':32,'MACH_SEND_TIMED_OUT':0x10000004,'MACH_SEND_INTERRUPTED':0x10000007}
 c.update(complete_kernel_functions_recaptured=172,captured_kernel_instructions=22410,complete_CF_functions_recaptured=len(cs['CF_functions']),captured_CF_instructions=sum(len(f['instructions'])for f in cs['CF_functions'])+4*len(cs['import_stubs']),cache_files_hashed=9,SDK_headers_hashed=2,original_wake_options24_and_header_constant_checked=1)
 for r in p['startup_cases']:st.update(StartupReplay(im,r).run())
 for r in loans:lt.update(LoanReplay(im,r).run())
 for j in(0,1,2):zt.update(ZoneReplay(im,zones[j]).run())
 for j,r in enumerate(p['kernel_cases']):
  kt.update(Replay(im,r).run());port=bytes.fromhex(r['final_wake_port144_hex']);entry=bytes.fromhex(r['final_entry8_24_hex']);wake=bytes.fromhex(r['final_wake_link48_hex']);root=bytes.fromhex(r['final_link48_hex']);timer=bytes.fromhex(r['final_unused_link48_hex']);service=bytes.fromhex(r['final_service_link48_hex']);ps=bytes.fromhex(r['final_pset56_hex']);assert r['boundary']['kind']=='receive_frontend_returned'and r['boundary']['registers31'][0]=='0x0'and r['wake_guards_hex']=='a5a5'
  assert w(port,0)==0x101 and w(port,4)==1 and w(port,0x34)==0x807 and h(port,0x38)==0 and h(port,0x3a)==1 and q(port,0x28)==0 and q(port,0x78)==RL and q(port,0x10)&0xc00==0xc00 and w(port,0x84)==w(port,0x88)==1 and q(entry,0)==WPORT and w(entry,8)==0x04030001;c['source_wake_receive_send_rights_qlimit_context_and_guard_oracles_checked']+=1
  assert[(e['phase'],e['registers31'][0])for e in r['wake_returns']]==[('wake_construct','0x0'),('wake_insert','0x0')]and r['final_wake_name4_hex']=='07080000';assert any(e['pc']=='0xfffffe000bcc8c60'and e['phase']=='wake_construct'for e in r['wake_frames']);c['source_wake_construct_qlimit_and_membership_ABI_checked']+=1
  assert q(root,0)==q(timer,0)==q(wake,0)==PS+0x10 and q(root,24)==NODE2+24 and q(root,32)==WNODE+24 and q(timer,24)==WNODE+24 and q(timer,32)==NODE+24 and q(wake,24)==NODE+24 and q(wake,32)==NODE2+24 and q(wake,40)==WPORT+0x10 and q(port,0x20)==WNODE+8 and q(service,0)==(PS+0x10)|1 and q(ps,32)==NODE+24 and q(ps,40)==NODE3+24;c['three_inactive_control_members_and_ready_service_ring_checked']+=1
  assert r['final_user8192_hex']==old['kernel_cases'][j]['final_user8192_hex']and r['final_OOL16384_hex']==old['kernel_cases'][j]['final_OOL16384_hex'];c['unchanged_original_service_delivery_bytes_checked']+=1
  summaries.append({'kernel_case':j,'visits':len(r['source_visits']),'wake_name':'0x807','wake_context':hex(RL),'rights_word':'0x04030001','queue_limit':1,'boundary':r['boundary']['kind']});print(json.dumps(summaries[-1]),flush=True)
 for j,r in enumerate(p['CF_cases']):
  ct.update(CFReplay(r,p['kernel_cases'][2],cs).run());b=bytes.fromhex(r['final_runloop2720_hex']);cfg=r['configuration'];pcs={e['pc']for e in r['source_visits']};assert r['runloop_guard_hex']=='a5'and not r['kernel_transfers']and not r['application_frames']and '0x100425f78'not in pcs and '0x184757744'not in pcs
  if cfg.get('create_null'):assert r['boundary']['kind']=='original_runloop_Create_null'and b==bytes(0xaa0)and not r['wake_send']and not r['final_model_state']['members'];c['original_runloop_runtime_null_early_return_checked']+=1;continue
  assert w(b,0x50)==0x807 and h(b,0x54)==0 and q(b,0xa48)==OWNER and q(b,0xa50)==COMMON and q(b,0xa68)==REGISTRY and b[0xa99:0xa9b]==b'\1\0';state=r['final_model_state'];assert state['collections'][hex(COMMON)]==[hex(DEFAULT)]and state['collections'][hex(REGISTRY)]==[hex(MODE)]and state['members']==[['0x507',x]for x in('0x403','0x607','0x707','0x807')];c['source_runloop_factory_fields_default_mode_and_all_four_members_checked']+=1
  cm=next(e for e in r['mode_models']if e['name']=='original_kernel_wake_construct_return');assert cm['original_options24_hex']==s['wake_original_options24_hex']and cm['wake_kernel_oracle']['context']==hex(RL);mm=next(e for e in r['mode_models']if e['name']=='original_kernel_wake_member_return');assert mm['wake_kernel_oracle']['arguments24_hex']==p['kernel_cases'][2]['wake_handoffs'][1]['patches'][0]['after_hex'];c['CF_kernel_wake_options_context_name_and_membership_pairings_checked']+=1
  expected={'0x184717f38':(RL+0x50,'07080000'),'0x184717f40':(RL+0x54,'0000'),'0x184717f48':(RL+0x153,'01'),'0x184717f64':(RL+0xa50,struct.pack('<Q',COMMON).hex()),'0x184717f8c':(RL+0xa68,struct.pack('<Q',REGISTRY).hex()),'0x184717f90':(RL+0xa48,struct.pack('<Q',OWNER).hex())}
  for pc,(at,raw)in expected.items():assert any(e['pc']==pc and e['address']==hex(at)and e['after_hex']==raw for e in r['source_writes'])
  c['original_factory_store_sites_checked']+=len(expected)
  gates=[(e['pc'],e['after_hex'])for e in r['source_writes']if e['address']==hex(RL+0x153)]
  if cfg['wake_case']=='suppressed':assert gates==[('0x184717f48','01')]and b[0x153]==1 and not r['wake_send']and hex(MACH)not in pcs and r['boundary']['kind']=='original_CFRunLoopWakeUp_returned';c['source_created_suppression_skips_send_checked']+=1
  else:
   assert gates==[('0x184717f48','01'),('0x184757168','00')]and b[0x153]==0 and len(r['wake_send'])==1;send=r['wake_send'][0];hdr=struct.pack('<6I',0x13,24,0x807,0,0,0);ptr=int(send['arguments7'][0],16);assert send['header24_hex']==hdr.hex()and send['arguments7'][1:]==['0x11','0x18','0x0','0x0','0x0','0x0']and send['declared_send_return']==hex(cfg['send_status'])and hex(CHECK)in pcs
   stores=[e for e in r['source_writes']if e['pc']in('0x18473af08','0x18473af0c','0x18473af10')];want=[('0x18473af08',ptr,hdr[:8]),('0x18473af0c',ptr+8,hdr[8:12]),('0x18473af0c',ptr+12,hdr[12:16]),('0x18473af10',ptr+16,hdr[16:24])];assert[(e['pc'],int(e['address'],16),bytes.fromhex(e['after_hex']))for e in stores]==want;c['complete_original_wake_header_stores_send_tuple_and_check_helper_checked']+=1
   if cfg['send_status']==0x10000007:assert cfg['diagnostic_status_counterfactual']is True and r['boundary']['kind']=='before_original_wake_send_failure'and r['boundary']['pc']=='0x1848d4168';c['counterfactual_interrupted_send_diagnostic_boundary_checked']+=1
   else:assert cfg['send_status']in(0,0x10000004)and r['boundary']['kind']=='original_CFRunLoopWakeUp_returned';c['success_or_timeout_original_wake_return_checked']+=1
   assert not any(e['pc']=='0x188076b70'for e in r['source_visits']);c['no_message_destroy_in_selected_send_cases_checked']+=1
  print(json.dumps({'CF_case':j,'visits':len(r['source_visits']),'send_count':len(r['wake_send']),'boundary':r['boundary']['kind']}),flush=True)
 assert kt['source_visits_checked']==27756 and ct['original_instruction_visits_checked']==5425 and st['source_visits_checked']==170 and lt['source_visits_checked']==216 and zt['source_visits_checked']==618
 assert kt['whole_final_RAM_bytes_checked']==4194304 and ct['whole_final_private_RAM_bytes_checked']==15728640 and st['whole_final_RAM_bytes_checked']==1048576
 rejected=[]
 for tag in('wake_queue_limit','wake_guard_context','wake_namespace_rights','CF_wake_header','CF_constructor_options','CF_suppression_gate'):
  if tag.startswith('CF_'):
   case=0 if tag=='CF_suppression_gate'else 1;bad=copy.deepcopy(p['CF_cases'][case])
   if tag=='CF_wake_header':e=bad['wake_send'][0];raw=bytearray.fromhex(e['header24_hex']);raw[20]=1;e['header24_hex']=raw.hex()
   elif tag=='CF_constructor_options':
    for key in('imports','runloop_models','mode_models'):e=next(e for e in bad[key]if e['name']=='original_kernel_wake_construct_return');e['original_options24_hex']='00'*24
   else:raw=bytearray.fromhex(bad['final_runloop2720_hex']);raw[0x153]=0;bad['final_runloop2720_hex']=raw.hex()
   check=lambda:CFReplay(bad,p['kernel_cases'][2],cs).run()
  else:
   bad=copy.deepcopy(p['kernel_cases'][0]);key,offset={'wake_queue_limit':('final_wake_port144_hex',0x3a),'wake_guard_context':('final_wake_port144_hex',0x78),'wake_namespace_rights':('final_entry8_24_hex',8)}[tag];raw=bytearray.fromhex(bad[key]);raw[offset]^=1;bad[key]=raw.hex();check=lambda:Replay(im,bad).run()
  try:check()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('altered record accepted',tag))
 c['altered_evidence_controls_rejected']=len(rejected)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','kernel_timer_port_create_profiles.json','kernel_zone_startup_profiles.json','kernel_request_delivery_profiles.json','replay_kernel_timer_port_create.py','replay_kernel_zone_startup.py','replay_kernel_request_delivery.py']},'source_recapture_match':True,'verified_counts':dict(c),'independent_A64_replay':dict(kt),'independent_CF_replay':dict(ct),'fresh_timer_startup_replay':dict(st),'fresh_receiver_loan_replay':dict(lt),'fresh_zone_replay':dict(zt),'altered_evidence_rejected':rejected,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'kernel_visits':kt['source_visits_checked'],'CF_visits':ct['original_instruction_visits_checked'],'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
