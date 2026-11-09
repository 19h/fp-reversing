#!/usr/bin/env python3
"""Recapture and independently replay original mode construction and consumers.
O(cache bytes+image+visits+RAM+journals) time/space. Native runtime, auxiliary
kernel ports, scheduling, allocator ownership and hardware PAC remain unknown.
"""
import copy,json,struct
from collections import Counter
from daemon_receive_tools import ROOT
from recover_cf_mode_construction import P,FLAGS,sha,build,CALLBACK
from replay_cf_mode_construction import Replay,B,MODE,REGISTRY,QUEUE,TIMER_SOURCE,BLOCK,BYREF,NAME,SET0,SET1,DICT
from replay_kernel_portset_delivery import Replay as KernelReplay
from kernel_vm_mig_tools import Image
from recover_cf_receive import DO_SOURCE

def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def w(b,o):return struct.unpack_from('<I',b,o)[0]
def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');prior=get('kernel_portset_delivery_profiles.json');assert s==build();ct=Counter();kt=Counter();c=Counter();summaries=[]
 for o,script in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 assert len(s['CF_functions'])==39 and len(s['import_stubs'])==24 and sum(len(f['instructions'])for f in s['CF_functions'])+96==2834 and len(s['cache_files'])==9 and len(p['cases'])==15 and p['kernel_cases']==prior['kernel_cases'][:4]
 layout=s['timer_block_layout'];assert layout['block_size_bytes']==40 and layout['byref_size_bytes']==32 and struct.unpack('<2Q',bytes.fromhex(layout['descriptor16_hex']))==(0,40)and w(bytes.fromhex(layout['byref_template8_hex']),4)==32
 c.update(complete_cache_functions_recaptured=39,captured_cache_instructions=2834,import_stubs_checked=24,cache_files_hashed=9,original_block_descriptor_and_byref_size_oracles_checked=1)
 im=Image()
 for r in p['kernel_cases']:kt.update(KernelReplay(im,r).run())
 for j,r in enumerate(p['cases']):
  k=p['kernel_cases'][r['configuration']['kernel_case']];ct.update(Replay(r,k,s).run());cfg=r['configuration']['mode'];m=bytes.fromhex(r['final_mode512_hex']);qu=bytes.fromhex(r['final_queue128_hex']);events=r['mode_models'];names=[e['name']for e in events];state=r['final_model_state'];published=state['collections'][hex(REGISTRY)];assert m[200]==qu[120]==0xa5
  if cfg in('schedule_then_run','repeat_mode','timer_callback'):
   assert published==[hex(MODE)]and q(m,0x50)==NAME and w(m,0x88)==0x507 and q(m,0x98)==TIMER_SOURCE and q(m,0xa0)==QUEUE and w(m,0xac)==0x707 and q(m,0xb8)==q(m,0xc0)==0xffffffffffffffff
   assert q(qu,0)==0x1ed897df0 and q(qu,0x20)==0x607 and q(qu,0x40)==22 and w(qu,0x50)==0x40001 and w(qu,0x54)==(0x101 if r['configuration'].get('tls_priority_word')else 0)
   assert r['final_fork_flag1_hex']=='01'and int.from_bytes(bytes.fromhex(r['final_queue_serial_counter8_hex']),'little')==23
   members={tuple(v)for v in state['members']};assert {('0x507',hex(v))for v in(0x607,0x707,0x807)}<=members
   assert names.count('original_kernel_pset_allocate_return')==names.count('root_port_construct_contract')==1
   alloc=next(e for e in events if e['name']=='original_kernel_pset_allocate_return');assert alloc['kernel_allocate_oracle']=={'case':r['configuration']['kernel_case'],'return_source_visit_index':k['pset_stage_returns'][0]['source_visit_index'],'name':'0x507'}
   stores=[e for e in r['source_writes']if e['pc']=='0x184831868'];assert len(stores)==1 and stores[0]['address']==hex(MODE+0x88)and stores[0]['size_bytes']==4 and stores[0]['after_hex']=='07050000'
   construct=next(e for e in events if e['name']=='root_port_construct_contract');assert construct['original_options16_hex']=='31'+'00'*15
   e=next(e for e in events if e['name']=='dispatch_timer_event_handler_contract');literal=bytes.fromhex(e['original_block40_hex']);by=bytes.fromhex(e['original_byref32_hex']);assert q(literal,0x10)==CALLBACK and q(literal,0x18)==0x1e2330700 and w(by,0x14)==32 and q(by,0x18)==MODE+0xa8
   assert q(bytes.fromhex(r['final_block40_hex']),0x20)==BYREF and q(bytes.fromhex(r['final_byref32_hex']),8)==BYREF
   c['constructed_mode_queue_control_ports_block_and_publication_oracles_checked']+=1
   if cfg!='timer_callback':
    assert q(m,0x60)==SET0 and q(m,0x68)==SET1 and q(m,0x80)==DICT and state['dictionary']=={k['receive_name']:hex(B+0xa8000)}and('0x507',k['receive_name'])in members
    rec=next(e for e in r['imports']if e['name']=='original_portset_receive_return_contract');assert rec['before']['registers31'][4]=='0x507'and rec['patches'][0]['after_hex']==k['final_user8192_hex'][:296]and rec['patches'][1]['after_hex']==k['final_OOL16384_hex'][:58]
    old=prior['CF_cases'][r['configuration']['kernel_case']];a=next(i for i,e in enumerate(r['source_visits'])if e['pc']==hex(DO_SOURCE));b=next(i for i,e in enumerate(old['source_visits'])if e['pc']==hex(DO_SOURCE));assert r['source_visits'][a:]==old['source_visits'][b:]and r['boundary']['kind']==old['boundary']['kind']and r['final_OOL16384_hex']==old['final_OOL16384_hex']
    if r['configuration']['kernel_case']<2:assert r['final_argument_record120_hex']==old['final_argument_record120_hex']
    else:assert r['boundary']['registers31'][0]=='0x4'and not any(e['pc']=='0x184757744'for e in r['source_visits'])
    c['source_kernel_allocation_receive_and_original_daemon_suffix_compositions_checked']+=1
   if cfg=='repeat_mode':assert names.count('mode_registry_bucket_contract')==2 and names.count('runtime_mode_storage_contract')==1 and len(r['registration_returns'])==2;c['existing_mode_and_duplicate_source_oracles_checked']+=1
   if cfg=='timer_callback':
    writes=[e for e in r['source_writes']if e['pc']=='0x1848329b8'];assert len(writes)==1 and writes[0]['address']==hex(MODE+0xa8)and writes[0]['before_hex']=='00'and writes[0]['after_hex']=='01'and m[0xa8]==1;c['original_six_instruction_byref_timer_callback_oracles_checked']+=1
  else:
   assert not published
   if cfg in('no_create','runtime_null'):assert r['boundary']['registers31'][0]=='0x0'and 'original_kernel_pset_allocate_return'not in names and not state['members'];c['null_mode_return_oracles_checked']+=1
   elif cfg=='pset_error':assert w(m,0x88)==0 and next(e for e in events if e['name']=='original_kernel_pset_allocate_return')['result']=='0x4'and 'root_port_construct_contract'not in names;c['allocation_failure_before_facility_store_oracles_checked']+=1
   elif cfg in('root_member_error','timer_member_error','wake_member_error'):
    members=state['members'];n={'root_member_error':0,'timer_member_error':1,'wake_member_error':2}[cfg];assert members==[['0x507',hex(v)]for v in(0x607,0x707)[:n]]and events[-1]['name']=='declared_mode_control_port_member'and events[-1]['result']=='0x4';c['checked_control_membership_failure_before_publication_oracles_checked']+=1
   elif cfg=='timer_zero':assert w(m,0xac)==0 and state['members']==[['0x507','0x607']];c['zero_kernel_timer_failure_oracles_checked']+=1
   else:assert cfg=='fork_flag2'and r['final_fork_flag1_hex']=='03'and r['boundary']['pc']=='0x185522f38'and 'root_port_construct_contract'not in names;c['original_fork_flag_atomic_transition_failure_oracles_checked']+=1
  if r['configuration'].get('tls_priority_word'):c['private_TSD_word_to_original_queue_field_oracles_checked']+=1
  summaries.append({'case':j,'configuration':r['configuration'],'original_visits':len(r['source_visits']),'boundary':r['boundary']['kind']});print(json.dumps(summaries[-1]),flush=True)
 assert ct['original_instruction_visits_checked']==19208 and ct['whole_final_private_RAM_bytes_checked']==47185920 and kt['source_visits_checked']==15172 and kt['whole_final_RAM_bytes_checked']==4194304
 rejected=[]
 for tag in('allocate_name_patch','control_member_status','byref_forwarding_copy','final_mode_facility','original_callback_write'):
  bad=copy.deepcopy(p['cases'][12 if tag=='original_callback_write'else 0])
  if tag=='final_mode_facility':v=bytearray.fromhex(bad['final_mode512_hex']);struct.pack_into('<I',v,0x88,0x503);bad['final_mode512_hex']=v.hex()
  elif tag=='original_callback_write':next(e for e in bad['source_writes']if e['pc']=='0x1848329b8')['after_hex']='00'
  else:
   name={'allocate_name_patch':'original_kernel_pset_allocate_return','control_member_status':'declared_mode_control_port_member','byref_forwarding_copy':'dispatch_timer_event_handler_contract'}[tag]
   for key in('imports','runloop_models','mode_models'):
    e=next(e for e in bad[key]if e['name']==name)
    if tag=='allocate_name_patch':e['patches'][0]['after_hex']='03050000'
    elif tag=='control_member_status':e['result']='0x4'
    else:v=bytearray.fromhex(e['patches'][1]['after_hex']);struct.pack_into('<Q',v,8,0);e['patches'][1]['after_hex']=v.hex()
  try:Replay(bad,p['kernel_cases'][bad['configuration']['kernel_case']],s).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('accepted altered record',tag))
 c['altered_evidence_controls_rejected']=len(rejected)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','replay_kernel_portset_delivery.py','kernel_portset_delivery_profiles.json']},'source_recapture_match':True,'verified_counts':dict(c),'independent_A64_replay':dict(ct),'fresh_kernel_replay':dict(kt),'altered_evidence_rejected':rejected,'case_summaries':summaries,'all_checks_pass':True,**FLAGS};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'A64':dict(ct),'fresh_kernel':dict(kt),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
