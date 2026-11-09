#!/usr/bin/env python3
"""Verify original timer arm/header/send, actual set receive and CF routing.
Clock/scheduler/tag/preflight and inherited allocation/VM/PAC contracts remain
explicit. Exact source, CPU/RAM, packet, queue and negative-control oracles.
"""
import copy,json,struct
from collections import Counter
from pathlib import Path
from daemon_receive_tools import ROOT
from recover_kernel_timer_expiration_delivery import P as PREFIX,FLAGS,sha,build,ARM
from replay_kernel_timer_expiration_delivery import Replay,CFReplay,TOBJ,TKMSG,TPORT,USER
from replay_kernel_timer_port_create import StartupReplay,PS,NODE,NODE2,NODE3
from replay_kernel_request_delivery import Replay as LoanReplay
from replay_kernel_zone_startup import Replay as ZoneReplay
from replay_rpc502_vm_handoff import P,SIZE,decode
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache
from recover_cf_receive import DO_SOURCE

def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def w(b,o):return struct.unpack_from('<I',b,o)[0]
def main():
 s=get(PREFIX+'_source.json');p=get(PREFIX+'_profiles.json');old=get('kernel_timer_port_create_profiles.json');zones=get('kernel_zone_startup_profiles.json')['cases'];loans=get('kernel_request_delivery_profiles.json')['loans'];assert s==build();c=Counter();kt=Counter();ct=Counter();st=Counter();zt=Counter();lt=Counter();im=Image();summaries=[]
 for o,script in((s,'recover_'+PREFIX+'.py'),(p,'probe_'+PREFIX+'.py')):
  assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for n,hv in o['dependencies'].items():assert sha(ROOT/n)==hv
 assert len(s['functions'])==175 and sum(len(f['instructions'])for f in s['functions'])==22589 and len(p['kernel_cases'])==5 and len(p['CF_cases'])==4 and s['timer_arm_trap_binding']['handler_pointer']['target']==hex(ARM)and s['timer_arm_trap_binding']['signed_selector']==-93
 assert s['expiration_original_header_constant']['bytes8_hex']=='1300000038000000'and s['original_instrumentation_flag4_hex']=='00000000'
 cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};cache=Cache()
 for f in cs['CF_functions']+cs['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in cs['cache_files']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 c.update(complete_kernel_functions_recaptured=175,captured_kernel_instructions=22589,complete_CF_functions_recaptured=43,captured_CF_instructions=3498,cache_files_hashed=9,original_arm_trap93_binding_checked=1)
 st.update(StartupReplay(im,old['startup_cases'][0]).run())
 for j in(0,1,2):zt.update(ZoneReplay(im,zones[j]).run())
 for r in loans:lt.update(LoanReplay(im,r).run())
 wire=struct.pack('<6I',0x1100,48,0,0x707,0,0)+bytes(24)+struct.pack('<17I',0,68,0,0,1,*([0]*12))
 assert len(wire)==116
 for j,r in enumerate(p['kernel_cases']):
  kt.update(Replay(im,r).run());cfg=r['configuration'];timer=bytes.fromhex(r['final_timer168_hex']);port=bytes.fromhex(r['final_timer_port144_hex']);ram=decode(r['final_private_RAM']);first=next(e for e in r['pset_stage_returns']if e['phase']=='first_receive');assert first['registers31'][0]=='0x0'and first['user148_hex'][:232]==wire.hex();c['complete_actual_timer_user_header_payload_trailer_and_name_oracles_checked']+=1
  e=next(e for e in r['expiration_frames']if e['pc']=='0xfffffe000bd13520');want=struct.pack('<IIQQII',0x13,56,TPORT,0,0,0)+bytes(24);assert bytes.fromhex(e['timer_kmsg256_hex'])[0x40:0x78]==want;rebuilt=bytearray(56);covered=set();pcs={'0xfffffe000bd1350c','0xfffffe000bd13514','0xfffffe000bd13518','0xfffffe000bd1351c'}
  for wr in r['source_writes']:
   if wr['pc']in pcs and wr['source_visit_index']<e['source_visit_index']:
    at=int(wr['address'],16)-(TKMSG+0x40);data=bytes.fromhex(wr['after_hex']);assert 0<=at<at+len(data)<=56;rebuilt[at:at+len(data)]=data;covered.update(range(at,at+len(data)))
  assert covered==set(range(56))and bytes(rebuilt)==want;c['complete_internal_message_constructed_by_original_stores_checked']+=1
  send=next(e for e in r['expiration_frames']if e['pc']=='0xfffffe000bd13528');assert send['registers31'][0]=='0x0'and all(any(e['pc']==pc for e in r['source_visits'])for pc in('0xfffffe000bd13524','0xfffffe000bcf57a0','0xfffffe000bcc7c34'));c['original_callback_wrapper_queue_send_success_path_checked']+=1
  queued=bytes.fromhex(send['timer_port144_hex']);first_ram=decode(first['private_RAM']);assert q(queued,0x28)==TKMSG and struct.unpack_from('<H',queued,0x38)[0]==1 and q(first_ram,TPORT-P+0x28)==0 and struct.unpack_from('<H',first_ram,TPORT-P+0x38)[0]==0 and q(bytes.fromhex(first['node2_48_hex']),0)==(PS+0x10)|1 and q(bytes.fromhex(first['pset56_hex']),40)==NODE3+24;final_node=bytes.fromhex(r['final_unused_link48_hex']);final_ps=bytes.fromhex(r['final_pset56_hex']);service=bytes.fromhex(r['final_service_link48_hex']);assert q(final_node,0)==q(service,0)==(PS+0x10)|1 and q(final_ps,32)==NODE+24 and q(final_ps,40)==NODE2+24 and q(final_node,24)==q(final_node,32)==NODE3+24 and q(service,24)==q(service,32)==NODE2+24;c['actual_timer_enqueue_dequeue_and_ready_head_rotation_checked']+=1
  armed,expired=r['expiration_returns'];ab=bytes.fromhex(armed['timer168_hex']);eb=bytes.fromhex(expired['timer168_hex']);assert armed['phase']=='timer_arm'and armed['registers31'][0]=='0x0'and ab[0x91]==1 and w(ab,0x94)==1 and expired['phase']=='timer_expiration'and eb[0x91]==0 and w(eb,0x94)==0 and q(eb,0)==0 and q(timer,0)==0
  assert len(r['counter_contracts'])==1 and r['counter_contracts'][0]['raw_counter']==100 and cfg['deadline']in(0,100)and [e['name']for e in r['expiration_models']]==['declared_scheduler_newly_queued_timer_callback','declared_message_tag_helper','declared_send_preflight'];c['original_arm_pending_count_and_expiration_clear_under_counter_scheduler_contracts_checked']+=1
  assert bytes.fromhex(armed['timer_kmsg256_hex'])[0x32]==1 and bytes.fromhex(expired['timer_kmsg256_hex'])[0x32]==3 and bytes.fromhex(r['final_timer_kmsg256_hex'])[0x32]==1 and q(timer,0x98)==TPORT and q(timer,0xa0)==TKMSG and w(port,4)==2 and w(port,0x84)==w(port,0x88)==1;c['reusable_message_flag_and_retained_association_return_state_checked']+=1
  counters=[e for e in r['source_writes']if e['address']==hex(P+0x5b000)];assert len(counters)==1 and counters[0]['pc']=='0xfffffe000bcc8228'and counters[0]['after_hex']==struct.pack('<Q',1).hex()and q(ram,0x5b000)==1;c['original_per_CPU_send_counter_increment_under_declared_task_epoch_checked']+=1
  entry=bytes.fromhex(r['final_entry7_24_hex']);assert w(entry,8)==0x04020000 and r['timer_raw_guards_hex']=='a5'*4 and r['boundary']['kind']=='receive_frontend_returned'and r['boundary']['registers31'][0]=='0x0';origin=old['kernel_cases'][cfg['producer']];assert r['final_user8192_hex']==origin['final_user8192_hex']and r['final_OOL16384_hex']==origin['final_OOL16384_hex'];c['timer_first_service_second_and_unchanged_service_buffers_checked']+=1
  summaries.append({'kernel_case':j,'configuration':cfg,'original_visits':len(r['source_visits']),'actual_timer_wire_bytes':116,'timer_message_size':48,'timer_local_name':'0x707','later_service_local_name':r['receive_name'],'boundary':r['boundary']['kind']});print(json.dumps(summaries[-1]),flush=True)
 assert p['kernel_cases'][2]['pset_stage_returns'][2]['user148_hex']==p['kernel_cases'][4]['pset_stage_returns'][2]['user148_hex'];c['deadline_below_and_equal_to_declared_counter_cases_checked']=2
 for j,r in enumerate(p['CF_cases']):
  k=p['kernel_cases'][j];ct.update(CFReplay(r,k,cs).run());actual=next(e for e in r['mode_models']if e['name']=='original_kernel_timer_expiration_receive_return');assert actual['patches'][0]['after_hex']==wire.hex()and len(actual['patches'])==1 and actual['timer_receive_oracle']['wire_size_bytes']==116 and len(r['expiration_transfers'])==len(r['kernel_transfers'])==1
  visits=r['source_visits'];assert sum(e['pc']=='0x184771f9c'for e in visits)==1 and sum(e['pc']=='0x18471cd5c'for e in visits)==1 and sum(e['pc']=='0x1847576f4'for e in visits)==1 and sum(e['pc']=='0x184757718'for e in visits)==1 and not any(e['pc']=='0x184757744'for e in visits);c['actual_timer_message_routes_to_timers_then_one_service_source_checked']+=1
  origin=old['CF_cases'][j];a=next(i for i,e in enumerate(visits)if e['pc']==hex(DO_SOURCE));b=next(i for i,e in enumerate(origin['source_visits'])if e['pc']==hex(DO_SOURCE));assert visits[a:]==origin['source_visits'][b:]and r['final_user8192_hex']==origin['final_user8192_hex']and r['final_OOL16384_hex']==origin['final_OOL16384_hex']and r['reply384_hex']==origin['reply384_hex']and r['final_mode512_hex']==origin['final_mode512_hex']and r['final_queue128_hex']==origin['final_queue128_hex']and r['final_model_state']==origin['final_model_state']and r['boundary']['kind']==origin['boundary']['kind']
  if j<2:assert r['final_argument_record120_hex']==origin['final_argument_record120_hex']
  else:assert r['boundary']['registers31'][0]=='0x4'
  c['unchanged_complete_daemon_suffix_buffers_objects_and_CF_state_checked']+=1
 assert kt['source_visits_checked']==44090 and kt['whole_final_RAM_bytes_checked']==5242880 and ct['original_instruction_visits_checked']==14128 and ct['whole_final_private_RAM_bytes_checked']==12582912 and st['source_visits_checked']==170 and zt['source_visits_checked']==618 and lt['source_visits_checked']==216
 rejected=[]
 for tag in('raw_counter_contract','scheduler_result','callback_header_store','actual_first_receive_wire','CF_actual_timer_packet','CF_timer_wire_extent'):
  if tag.startswith('CF_'):
   bad=copy.deepcopy(p['CF_cases'][0])
   for key in('imports','runloop_models','mode_models'):
    e=next(e for e in bad[key]if e['name']=='original_kernel_timer_expiration_receive_return')
    if tag=='CF_actual_timer_packet':e['patches'][0]['after_hex']='00'*116
    else:e['timer_receive_oracle']['wire_size_bytes']=92
   replay=lambda:CFReplay(bad,p['kernel_cases'][0],cs).run()
  else:
   bad=copy.deepcopy(p['kernel_cases'][0])
   if tag=='raw_counter_contract':bad['counter_contracts'][0]['raw_counter']=101
   elif tag=='scheduler_result':bad['expiration_models'][0]['result']='0x1'
   elif tag=='callback_header_store':next(e for e in bad['source_writes']if e['pc']=='0xfffffe000bd13518')['after_hex']='00'*8
   else:bad['pset_stage_returns'][2]['user148_hex']='00'*148
   replay=lambda:Replay(im,bad).run()
  try:replay()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('accepted altered record',tag))
 c['altered_evidence_controls_rejected']=len(rejected)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json',PREFIX+'_profiles.json','recover_'+PREFIX+'.py','probe_'+PREFIX+'.py','replay_'+PREFIX+'.py','kernel_timer_port_create_profiles.json','kernel_zone_startup_profiles.json','kernel_request_delivery_profiles.json','replay_kernel_timer_port_create.py','replay_kernel_request_delivery.py','replay_kernel_zone_startup.py']},'source_recapture_match':True,'verified_counts':dict(c),'independent_A64_replay':dict(kt),'independent_CF_replay':dict(ct),'fresh_timer_startup_replay':dict(st),'fresh_receiver_loan_replay':dict(lt),'fresh_zone_replay':dict(zt),'actual_timer_wire116_hex':wire.hex(),'altered_evidence_rejected':rejected,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'kernel':dict(kt),'CF':dict(ct),'startup':dict(st),'loans':dict(lt),'zones':dict(zt),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
