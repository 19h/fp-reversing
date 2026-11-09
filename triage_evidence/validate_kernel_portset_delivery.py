#!/usr/bin/env python3
"""Recapture and independently verify source-created port-set delivery and CF.
O(image+cache hashes+visits+RAM+journals) time/space. Native epochs, raw
allocation/task/VM/CF backends and hardware PAC remain explicit boundaries.
"""
import copy,json,struct
from collections import Counter
from daemon_receive_tools import ROOT
from recover_kernel_portset_delivery import P as PREFIX,FLAGS,sha,build,ALLOC,INSERT,LINK,READY,SELECT
from kernel_vm_mig_tools import Image
from replay_rpc502_vm_handoff import decode,P,SIZE
from replay_kernel_portset_delivery import Replay,CFReplay,PS,NODE,NODE2,TABLE,NAME_OUT,INSERT_ARGS,TASK_NAME
from replay_kernel_request_delivery import Replay as PriorReplay
from replay_kernel_zone_startup import Replay as ZoneReplay
def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def w(b,o):return struct.unpack_from('<I',b,o)[0]
def h(b,o):return struct.unpack_from('<H',b,o)[0]
def main():
 s=get(PREFIX+'_source.json');p=get(PREFIX+'_profiles.json');assert s==build();old=get('kernel_request_delivery_profiles.json');prior=get('cf_source_scheduling_profiles.json');prior_by_j={r['kernel_case_index']:r for r in prior['cases']if r['configuration']['mode']=='schedule_then_run'};zone=get('kernel_zone_startup_profiles.json')['cases'][2];c=Counter();kt=Counter();ct=Counter();lt=Counter();zt=Counter();summaries=[];im=Image()
 for obj,script in((s,'recover_'+PREFIX+'.py'),(p,'probe_'+PREFIX+'.py')):
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj['dependencies'].items():assert sha(ROOT/n)==digest
 assert s['kernel_sha256']==im.k.sha256 and len(s['functions'])==163 and sum(len(f['instructions'])for f in s['functions'])==21506 and len(p['kernel_cases'])==8 and len(p['CF_cases'])==4
 c.update({'complete_kernel_functions_recaptured':163,'captured_kernel_instructions':21506,'complete_CF_cache_functions_recaptured':len(s['CF_source']['CF_functions']),'captured_CF_cache_instructions':sum(len(f['instructions'])for f in s['CF_source']['CF_functions'])+4*len(s['CF_source']['import_stubs']),'cache_files_hashed':len(s['CF_source']['cache_files']),'original_Mach_trap_table_bindings_checked':len(s['original_trap_bindings'])});assert c['captured_CF_cache_instructions']==2309 and c['original_Mach_trap_table_bindings_checked']==2
 zt.update(ZoneReplay(im,zone).run());assert zone['identifier']==23 and zone['zone_address']=='0xfffffe000caec5c0';c['fresh_original_pset_zone_startup_replay_checked']=1
 for r in old['loans']:lt.update(PriorReplay(im,r).run())
 for j,r in enumerate(p['kernel_cases']):
  kt.update(Replay(im,r).run());cfg=r['configuration'];origin=old['loans'][cfg['producer']];initial=decode(origin['final_private_RAM']);b=decode(r['final_private_RAM']);port=int(r['receive_name'],16);dest=int(r['destination'],16);d=dest-P;ps=b[PS-P:PS-P+56];node=b[NODE-P:NODE-P+48];assert r['post_setup_original_kmsg256_hex']==initial[0xd0000:0xd0100].hex()
  a=r['pset_stage_returns'][0];ab=decode(a['private_RAM']);aps=bytes.fromhex(a['pset56_hex']);assert a['phase']=='allocate'and a['registers31'][0]=='0x0'and w(ab,NAME_OUT-P)==int(r['receive_facility_name'],16)==0x507 and w(aps,0)==0x200 and w(aps,4)==1 and q(aps,8)==0 and w(aps,16)==(13|(5<<5))and q(aps,24)==q(aps,32)==q(aps,40)==q(aps,48)==0
  entry=bytes.fromhex(a['entry5_24_hex']);assert q(entry,0)==PS and w(entry,8)==0x04080000;c['original_pset_object_name_and_namespace_publication_oracles_checked']+=1
  first_insert=r['pset_stage_returns'][1];assert first_insert['phase']=='insert'and first_insert['registers31'][0]=='0x0';ib=decode(first_insert['private_RAM']);ips=bytes.fromhex(first_insert['pset56_hex']);inode=bytes.fromhex(first_insert['node48_hex']);assert q(inode,0)==(PS+0x10)|1 and q(inode,8)==q(inode,16)==NODE+8 and q(inode,24)==q(inode,32)==NODE+24 and q(inode,40)==dest+0x10 and q(ips,32)==0 and q(ips,40)==NODE+24 and q(ib,d+0x20)==NODE+8 and w(ib,d+0x10)&0x10;c['original_membership_and_ready_ring_complete_link_oracles_checked']+=1
  assert all(r[k]=='a5'for k in('raw_pset_guard_hex','raw_link_guard_hex','raw_unused_link_guard_hex'))and all(e['private_RAM_before']['sha256']==e['private_RAM_after']['sha256']for e in r['pset_stage_handoffs']if not e['patches']);c['whole_RAM_call_handoff_and_raw_guard_oracles_checked']+=1
  if j<4:
   assert r['boundary']['kind']=='receive_frontend_returned'and r['boundary']['registers31'][0]=='0x0'and r['final_user8192_hex']==prior['kernel_cases'][j]['final_user8192_hex']and r['final_OOL16384_hex']==prior['kernel_cases'][j]['final_OOL16384_hex'];raw=bytes.fromhex(r['final_user8192_hex']);assert w(raw,12)==port!=0x507 and w(raw,4)==80 and w(raw,80+4)==68 and q(b,d+0x28)==0 and h(b,d+0x38)==0 and w(ps,4)==1 and not(w(b,d+0x10)&0x10);c['complete_portset_receive_wire_OOL_local_name_and_dequeue_oracles_checked']+=1
   reads=[e for e in r['source_reads']if e['address']==hex(dest+0x34)];assert len(reads)==1 and reads[0]['pc']=='0xfffffe000bcca2ec'and reads[0]['size_bytes']==4 and reads[0]['bytes_hex']==struct.pack('<I',port).hex();c['original_member_receive_name_field_to_wire_oracles_checked']+=1
  elif j in(4,5):
   assert r['boundary']['kind']=='before_original_receive_results_with_queue_preserved'and q(b,d+0x28)==P+0xd0000 and h(b,d+0x38)==1 and r['final_user8192_hex']=='a5'*8192 and w(ps,4)==2;c['short_capacity_preserves_original_queue_before_results_oracles_checked']+=1
  elif j==6:
   assert r['boundary']['kind']=='original_membership_repeat_returned'and r['boundary']['registers31'][0]=='0xb'and len(r['pset_stage_returns'])==3 and r['pset_stage_returns'][2]['node48_hex']==first_insert['node48_hex']and r['final_unused_link48_hex']=='00'*48 and q(b,d+0x28)==P+0xd0000 and h(b,d+0x38)==1;c['duplicate_membership_status11_topology_and_unused_storage_oracles_checked']+=1
  else:
   assert r['boundary']['kind']=='before_original_scheduler_block'and r['boundary']['pc']=='0xfffffe000bd28f6c'and q(ps,32)==NODE+24 and q(ps,40)==0 and q(node,0)==PS+0x10 and q(node,24)==q(node,32)==NODE+24 and q(b,d+0x28)==0 and h(b,d+0x38)==0;assert r['pset_stage_returns'][2]['phase']=='first_receive'and r['pset_stage_returns'][2]['user148_hex']==prior['kernel_cases'][0]['final_user8192_hex'][:296];c['drained_set_demotes_ready_link_and_reaches_wait_frontier_oracles_checked']+=1
  summaries.append({'kernel_case':j,'configuration':cfg,'source_name':hex(port),'produced_set_name':'0x507','original_visits':len(r['source_visits']),'boundary':r['boundary']['kind']});print(json.dumps(summaries[-1]),flush=True)
 for j,r in enumerate(p['CF_cases']):
  k=p['kernel_cases'][j];ct.update(CFReplay(r,k,s['CF_source']).run());assert r['receive_facility_name']==k['receive_facility_name']=='0x507'and r['final_model_state']['dictionary']=={k['receive_name']:hex(P+0xa8000)}and r['final_model_state']['members']==[['0x507',k['receive_name']]]
  member=next(e for e in r['imports']if e['name']=='original_kernel_member_return_contract');kernel_args=k['pset_stage_handoffs'][0]['patches'][0]['after_hex'];assert member['kernel_oracle']['arguments24_hex']==kernel_args==struct.pack('<3Q',TASK_NAME,int(k['receive_name'],16),0x507).hex();receive=next(e for e in r['imports']if e['name']=='original_portset_receive_return_contract');assert receive['before']['registers31'][4]=='0x507'and receive['patches'][0]['after_hex']==k['final_user8192_hex'][:296]and receive['patches'][1]['after_hex']==k['final_OOL16384_hex'][:58]
  original=prior_by_j[j];assert r['source_visits']==original['source_visits']and r['final_user8192_hex'][:296]==original['final_user8192_hex'][:296]and r['final_OOL16384_hex']==original['final_OOL16384_hex']and r['boundary']['kind']==original['boundary']['kind']
  if j<2:assert r['final_argument_record120_hex']==original['final_argument_record120_hex']
  else:assert r['boundary']['registers31'][0]=='0x4'
  c['source_kernel_membership_set_receive_and_CF_daemon_contract_compositions_checked']+=1
 assert kt['source_visits_checked']==24911 and kt['whole_final_RAM_bytes_checked']==8*SIZE and ct['original_instruction_visits_checked']==10108 and ct['whole_final_private_RAM_bytes_checked']==12*SIZE
 rejected=[]
 for tag in('pset_namespace_object','ready_member_link','receive_facility_argument','CF_kernel_packet_patch'):
  if tag=='CF_kernel_packet_patch':
   bad=copy.deepcopy(p['CF_cases'][0])
   for key in('imports','runloop_models'):
    next(e for e in bad[key]if e['name']=='original_portset_receive_return_contract')['patches'][0]['after_hex']='00'*148
   try:CFReplay(bad,p['kernel_cases'][0],s['CF_source']).run()
   except AssertionError:rejected.append(tag)
   else:raise AssertionError(('accepted altered CF evidence',tag))
  else:
   bad=copy.deepcopy(p['kernel_cases'][0])
   if tag=='pset_namespace_object':bad['pset_stage_returns'][0]['entry5_24_hex']='00'*24
   elif tag=='ready_member_link':bad['pset_stage_returns'][1]['node48_hex']='00'*48
   else:next(e for e in bad['pset_stage_handoffs']if e['kind']=='insert_to_set_receive')['after']['registers31'][7]=bad['receive_name']
   try:Replay(im,bad).run()
   except AssertionError:rejected.append(tag)
   else:raise AssertionError(('accepted altered kernel evidence',tag))
 c['altered_evidence_controls_rejected']=len(rejected);out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json',PREFIX+'_profiles.json','recover_'+PREFIX+'.py','probe_'+PREFIX+'.py','replay_'+PREFIX+'.py','kernel_request_delivery_profiles.json','kernel_zone_startup_profiles.json','cf_source_scheduling_profiles.json','replay_kernel_request_delivery.py','replay_cf_source_scheduling.py','replay_kernel_zone_startup.py']},'source_recapture_match':True,'verified_counts':dict(c),'independent_A64_replay':dict(kt),'independent_CF_replay':dict(ct),'fresh_receiver_loan_replay':dict(lt),'fresh_pset_zone_replay':dict(zt),'altered_evidence_rejected':rejected,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'kernel_replay':dict(kt),'CF_replay':dict(ct),'loan_replay':dict(lt),'zone_replay':dict(zt),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
