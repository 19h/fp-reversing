#!/usr/bin/env python3
"""Verify dynamic timer startup, original kernel creation/member and CF pairing.
Original source and full CPU/RAM/semantic oracles; no native timer or IPC claim.
"""
import copy,json,struct
from collections import Counter
from pathlib import Path
from daemon_receive_tools import ROOT
from recover_kernel_timer_port_create import P as PREFIX,FLAGS,sha,build,CREATE,CALLBACK,PUBLICATION
from replay_kernel_timer_port_create import Replay,CFReplay,StartupReplay,TOBJ,TKMSG,TPORT,NODE3,PS,NODE,NODE2,TABLE
from replay_kernel_request_delivery import Replay as LoanReplay
from replay_kernel_zone_startup import Replay as ZoneReplay
from replay_rpc502_vm_handoff import P,SIZE,decode
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache

def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def w(b,o):return struct.unpack_from('<I',b,o)[0]
def h(b,o):return struct.unpack_from('<H',b,o)[0]
def main():
 s=get(PREFIX+'_source.json');p=get(PREFIX+'_profiles.json');prior=get('kernel_root_port_construct_profiles.json');loans=get('kernel_request_delivery_profiles.json')['loans'];zones=get('kernel_zone_startup_profiles.json')['cases'];assert s==build();im=Image();c=Counter();st=Counter();kt=Counter();ct=Counter();zt=Counter();lt=Counter();summaries=[]
 for o,script in((s,'recover_'+PREFIX+'.py'),(p,'probe_'+PREFIX+'.py')):
  assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for n,digest in o['dependencies'].items():assert sha(ROOT/n)==digest
 assert len(s['functions'])==171 and sum(len(f['instructions'])for f in s['functions'])==22373 and len(p['startup_cases'])==2 and len(p['kernel_cases'])==len(p['CF_cases'])==4 and s['timer_trap_binding']['signed_selector']==-91 and s['timer_trap_binding']['handler_pointer']['target']==hex(CREATE)and s['timer_trap_binding']['returns_port']and s['timer_trap_binding']['argument_count']==0
 cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};cache=Cache()
 for f in cs['CF_functions']+cs['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in cs['cache_files']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 c.update(complete_kernel_functions_recaptured=171,captured_kernel_instructions=22373,complete_CF_functions_recaptured=43,captured_CF_instructions=3498,cache_files_hashed=9,original_port_returning_trap91_binding_checked=1)
 for r in p['startup_cases']:
  st.update(StartupReplay(im,r).run());slot=r['configuration']['dynamic_timer_zone_slot'];b=bytes.fromhex(r['final_zone192_hex']);zone=0xfffffe000caeb480+192*slot;assert h(b,0x34)==168 and q(b,0)==zone and r['publication_pointer8_hex']==struct.pack('<Q',zone).hex();stores=[e for e in r['source_writes']if e['address']==hex(PUBLICATION)];assert len(stores)==1 and stores[0]['pc']=='0xfffffe000c63225c'and stores[0]['size_bytes']==8 and stores[0]['after_hex']==r['publication_pointer8_hex'];c['original_dynamic_zone_extent_publication_and_slot_variations_checked']+=1
 for r in loans:lt.update(LoanReplay(im,r).run())
 for j in(0,1,2):zt.update(ZoneReplay(im,zones[j]).run())
 for j,r in enumerate(p['kernel_cases']):
  kt.update(Replay(im,r).run());timer=bytes.fromhex(r['final_timer168_hex']);port=bytes.fromhex(r['final_timer_port144_hex']);kmsg=bytes.fromhex(r['final_timer_kmsg256_hex']);entry=bytes.fromhex(r['final_entry7_24_hex']);ps=bytes.fromhex(r['final_pset56_hex']);root=bytes.fromhex(r['final_link48_hex']);timlink=bytes.fromhex(r['final_unused_link48_hex']);service=bytes.fromhex(r['final_service_link48_hex']);assert r['timer_raw_guards_hex']=='a5'*4 and r['boundary']['kind']=='receive_frontend_returned'and r['boundary']['registers31'][0]=='0x0'
  assert q(timer,8)==0x11 and w(timer,0x50)==0x02000001 and q(timer,0x68)==CALLBACK and q(timer,0x70)==TOBJ and q(timer,0x98)==TPORT and q(timer,0xa0)==TKMSG;c['complete_original_timer_callback_context_port_and_kmsg_associations_checked']+=1
  assert w(port,0)==0x209 and w(port,4)==2 and q(port,8)==TOBJ and w(port,0x34)==0x707 and q(port,0x28)==0 and h(port,0x38)==0 and h(port,0x3a)==5 and w(port,0x84)==w(port,0x88)==1 and q(entry,0)==TPORT and w(entry,8)==0x04020000;c['receive_only_namespace_and_separate_kernel_send_reference_oracles_checked']+=1
  before=next(e for e in r['timer_frames']if e['pc']=='0xfffffe000bccfc94');bp=bytes.fromhex(before['timer_port144_hex']);assert w(bp,4)==1 and w(bp,0x84)==w(bp,0x88)==0;after=next(e for e in r['timer_frames']if e['pc']=='0xfffffe000bd13450');ap=bytes.fromhex(after['timer_port144_hex']);assert w(ap,4)==2 and w(ap,0x84)==w(ap,0x88)==1;c['original_kernel_send_reference_increment_oracles_checked']+=1
  expected=bytearray(256);expected[0x32]=1;assert kmsg==bytes(expected);c['prepared_kmsg_storage_not_completed_message_oracles_checked']+=1
  assert q(root,0)==q(timlink,0)==PS+0x10 and q(root,24)==q(root,32)==NODE2+24 and q(timlink,24)==q(timlink,32)==NODE+24 and q(timlink,40)==TPORT+0x10 and q(port,0x20)==NODE2+8 and q(service,0)==(PS+0x10)|1 and q(service,40)==int(r['destination'],16)+0x10 and q(ps,32)==NODE+24 and q(ps,40)==NODE3+24;c['shared_root_timer_inactive_ring_and_ready_service_topology_checked']+=1
  assert[(e['phase'],e['registers31'][0])for e in r['timer_returns']]==[('timer_create','0x707'),('timer_insert','0x0')];assert r['final_user8192_hex']==prior['kernel_cases'][j]['final_user8192_hex']and r['final_OOL16384_hex']==prior['kernel_cases'][j]['final_OOL16384_hex'];c['timer_name_versus_status_ABI_and_unchanged_service_bytes_checked']+=1
  startup=p['startup_cases'][0];initial={(e['address'],e['bytes_hex'])for e in r['initial_image_fixtures']};assert(startup['zone_address'],startup['final_zone192_hex'])in initial and(hex(PUBLICATION),startup['publication_pointer8_hex'])in initial;c['source_dynamic_zone_record_and_publication_transfer_checked']+=1
  summaries.append({'kernel_case':j,'original_visits':len(r['source_visits']),'timer_name':'0x707','timer_namespace_rights_word':'0x04020000','boundary':r['boundary']['kind']});print(json.dumps(summaries[-1]),flush=True)
 for j,r in enumerate(p['CF_cases']):
  k=p['kernel_cases'][j];ct.update(CFReplay(r,k,cs).run());created=next(e for e in r['mode_models']if e['name']=='original_kernel_timer_create_name_return');member=next(e for e in r['mode_models']if e['name']=='original_kernel_timer_member_return');assert created['result']=='0x707'and created['timer_kernel_oracle']['return_source_visit_index']==k['timer_returns'][0]['source_visit_index']and member['timer_kernel_oracle']['arguments24_hex']==k['timer_handoffs'][1]['patches'][0]['after_hex'];old=prior['CF_cases'][j];assert r['source_visits']==old['source_visits']and r['final_user8192_hex']==old['final_user8192_hex']and r['final_OOL16384_hex']==old['final_OOL16384_hex']and r['final_mode512_hex']==old['final_mode512_hex']and r['final_queue128_hex']==old['final_queue128_hex']and r['final_model_state']==old['final_model_state']and r['boundary']['kind']==old['boundary']['kind']
  if j<2:assert r['final_argument_record120_hex']==old['final_argument_record120_hex']
  else:assert r['boundary']['registers31'][0]=='0x4'
  c['source_timer_create_member_and_CF_daemon_compositions_checked']+=1
 assert st['source_visits_checked']==340 and st['whole_final_RAM_bytes_checked']==2097152 and kt['source_visits_checked']==23380 and kt['whole_final_RAM_bytes_checked']==4194304 and ct['original_instruction_visits_checked']==12356 and ct['whole_final_private_RAM_bytes_checked']==12582912 and zt['source_visits_checked']==618 and lt['source_visits_checked']==216
 rejected=[]
 for tag in('dynamic_zone_publication','timer_callback_context','timer_namespace_rights','ready_service_link','CF_timer_name','CF_timer_membership_tuple'):
  if tag=='dynamic_zone_publication':bad=copy.deepcopy(p['startup_cases'][0]);bad['publication_pointer8_hex']='00'*8;replay=lambda:StartupReplay(im,bad).run()
  elif tag.startswith('CF_'):
   bad=copy.deepcopy(p['CF_cases'][0]);name='original_kernel_timer_create_name_return'if tag=='CF_timer_name'else'original_kernel_timer_member_return'
   for key in('imports','runloop_models','mode_models'):
    e=next(e for e in bad[key]if e['name']==name)
    if tag=='CF_timer_name':e['result']='0x0'
    else:e['timer_kernel_oracle']['arguments24_hex']='00'*24
   replay=lambda:CFReplay(bad,p['kernel_cases'][0],cs).run()
  else:
   bad=copy.deepcopy(p['kernel_cases'][0]);key,offset={'timer_callback_context':('final_timer168_hex',0x70),'timer_namespace_rights':('final_entry7_24_hex',8),'ready_service_link':('final_service_link48_hex',0)}[tag];raw=bytearray.fromhex(bad[key]);raw[offset]^=1;bad[key]=raw.hex();replay=lambda:Replay(im,bad).run()
  try:replay()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('accepted altered record',tag))
 c['altered_evidence_controls_rejected']=len(rejected)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json',PREFIX+'_profiles.json','recover_'+PREFIX+'.py','probe_'+PREFIX+'.py','replay_'+PREFIX+'.py','kernel_root_port_construct_profiles.json','kernel_zone_startup_profiles.json','kernel_request_delivery_profiles.json','replay_kernel_zone_startup.py','replay_kernel_request_delivery.py']},'source_recapture_match':True,'verified_counts':dict(c),'independent_startup_replay':dict(st),'independent_A64_replay':dict(kt),'independent_CF_replay':dict(ct),'fresh_receiver_loan_replay':dict(lt),'fresh_zone_replay':dict(zt),'altered_evidence_rejected':rejected,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'startup':dict(st),'kernel':dict(kt),'CF':dict(ct),'loans':dict(lt),'zones':dict(zt),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
