#!/usr/bin/env python3
"""Recapture original control dispatch and independently verify finite paths.
Exact instruction/CPU/RAM and semantic oracles; synthetic control packets and
runtime ownership/cardinality contracts are not native kernel execution proof.
"""
import copy,json,struct
from collections import Counter
from daemon_receive_tools import ROOT
from recover_cf_control_port_dispatch import P,FLAGS,sha,build,ROOTPERFORM,TIMERS,ARM,EMPTY
from replay_cf_control_port_dispatch import Replay,MODE,QUEUE,RL
from replay_cf_mode_construction import Replay as ModeReplay
from replay_kernel_portset_delivery import Replay as KernelReplay
from kernel_vm_mig_tools import Image
from recover_cf_receive import DO_SOURCE

def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');old=get('cf_mode_construction_profiles.json');kernel=get('kernel_portset_delivery_profiles.json');assert s==build();c=Counter();ct=Counter();kt=Counter();mt=Counter();summaries=[]
 for o,script in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 assert len(s['CF_functions'])==43 and len(s['import_stubs'])==25 and sum(len(f['instructions'])for f in s['CF_functions'])+100==3498 and len(s['cache_files'])==9 and len(p['cases'])==9 and p['kernel_cases']==kernel['kernel_cases'][:4]
 c.update(complete_cache_functions_recaptured=43,captured_cache_instructions=3498,import_stubs_checked=25,cache_files_hashed=9)
 im=Image()
 for k in p['kernel_cases']:kt.update(KernelReplay(im,k).run())
 for j in(0,2):mt.update(ModeReplay(old['cases'][j],p['kernel_cases'][j],get('cf_mode_construction_source.json')).run())
 for j,r in enumerate(p['cases']):
  cfg=r['configuration'];origin=old['cases'][cfg['kernel_case']];k=p['kernel_cases'][cfg['kernel_case']];ct.update(Replay(r,k,s).run());seq=cfg['control_sequence'];models=r['control_models'];receives=[e for e in models if e['name']=='declared_control_port_receive'];assert len(receives)==len(seq)==r['final_control_cursor'];assert len(r['kernel_transfers'])==1
  for ordinal,(kind,e)in enumerate(zip(seq,receives,strict=True),1):
   name={'root':0x607,'timer':0x707,'wake':0x807}[kind];raw=bytes.fromhex(e['patches'][0]['after_hex']);assert len(raw)==92 and struct.unpack_from('<6I',raw)==(0,24,0,name,0,cfg.get('control_message_id',0))and raw[24:]==struct.pack('<2I',0,68)+bytes(60)and len(e['patches'])==1 and e['result']=='0x0'and e['control_kind']==kind and e['control_ordinal']==ordinal;c['complete_declared_control_packet_header_trailer_and_ordinal_oracles_checked']+=1
  frames=r['control_frames'];classifications=[(int(f['registers31'][8],16),int(f['registers31'][25],16))for f in frames if f['pc']=='0x1847573f8'];expected=[]
  for kind in seq:
   if kind=='wake':expected.append((0x807,2))
   elif kind=='timer':expected.append((0x707,3))
   elif cfg['timer_callback_before_run']:expected.append((0x607,3))
  expected.append((int(k['receive_name'],16),5));assert classifications==expected;c['original_local_name_classification_sequence_oracles_checked']+=1
  roots=[f for f in frames if f['pc']==hex(ROOTPERFORM)];root_returns=[f for f in frames if f['pc']=='0x1855226e8'];assert len(roots)==len(root_returns)==seq.count('root')and all(f['registers31'][0]==hex(QUEUE)and q(bytes.fromhex(f['queue128_hex']),0x30)==0 for f in roots)and all(f['registers31'][23]=='0x0'for f in root_returns)
  assert sum(e['name']=='declared_dispatch_root_retain'for e in models)==sum(e['name']=='declared_dispatch_root_release'for e in models)==len(roots);c['original_empty_root_drain_and_declared_reference_pair_oracles_checked']+=len(roots)
  ntimers=seq.count('timer')+int(cfg['timer_callback_before_run']);timer_entries=[f for f in frames if f['pc']==hex(TIMERS)];timer_returns=[f for f in frames if f['pc']=='0x18477210c'];arm_entries=[f for f in frames if f['pc']==hex(ARM)];assert len(timer_entries)==len(timer_returns)==len(arm_entries)==ntimers and all(q(bytes.fromhex(f['mode512_hex']),0x78)==0 for f in timer_entries+arm_entries)and all(f['registers31'][23]=='0x0'for f in timer_returns);c['original_null_timer_array_no_fire_and_rearm_oracles_checked']+=ntimers
  empties=[f for f in frames if f['pc']==hex(EMPTY)];empty_returns=[f for f in frames if f['pc']=='0x184756e68'];expected_empty=seq.count('wake')+ntimers;assert len(empties)==len(empty_returns)==expected_empty and all(f['registers31'][0]=='0x0'for f in empty_returns);cards=[int(e['result'],16)for e in models if e['name']=='declared_collection_cardinality'];assert cards==[0,1]*expected_empty;c['original_mode_nonempty_from_registered_source_oracles_checked']+=expected_empty
  resets=[e for e in r['source_writes']if e['pc']=='0x1847575c0'];assert len(resets)==2*seq.count('timer')and[(e['address'],e['size_bytes'],e['after_hex'])for e in resets]==[(hex(at),8,'ff'*8)for _ in range(seq.count('timer'))for at in(MODE+0xb8,MODE+0xc0)];assert all(resets[i]['source_visit_index']==resets[i+1]['source_visit_index']for i in range(0,len(resets),2));c['kernel_timer_only_deadline_reset_oracles_checked']+=len(resets)//2
  if cfg['timer_callback_before_run']:
   flag=[e for e in r['source_writes']if e['address']==hex(MODE+0xa8)and e['pc']in('0x1848329b8','0x1847573e4')];assert[(e['pc'],e['before_hex'],e['after_hex'])for e in flag]==[('0x1848329b8','00','01'),('0x1847573e4','01','00')]and len(r['callback_returns'])==1 and bytes.fromhex(r['callback_returns'][0]['mode512_hex'])[0xa8]==1;c['original_timer_callback_flag_to_root_dispatch_clear_oracles_checked']+=1
  else:assert not r['callback_returns']
  if cfg.get('control_message_id'):assert classifications==[(0x807,2),(0x403,5)];c['wake_route_independent_of_tested_message_id_oracles_checked']+=1
  assert sum(e['pc']=='0x1847576f4'for e in r['source_visits'])==1 and sum(e['pc']=='0x184757718'for e in r['source_visits'])==1 and not any(e['pc']=='0x184757744'for e in r['source_visits']);c['control_ports_bypass_source_dictionary_and_generic_reply_oracles_checked']+=1
  a=next(i for i,e in enumerate(r['source_visits'])if e['pc']==hex(DO_SOURCE));b=next(i for i,e in enumerate(origin['source_visits'])if e['pc']==hex(DO_SOURCE));assert r['source_visits'][a:]==origin['source_visits'][b:]and r['boundary']['kind']==origin['boundary']['kind']and r['final_user8192_hex']==origin['final_user8192_hex']and r['final_OOL16384_hex']==origin['final_OOL16384_hex']and r['reply384_hex']==origin['reply384_hex']and r['final_mode512_hex']==origin['final_mode512_hex']and r['final_queue128_hex']==origin['final_queue128_hex']and r['final_model_state']==origin['final_model_state']
  if cfg['kernel_case']==0:assert r['final_argument_record120_hex']==origin['final_argument_record120_hex']
  else:assert r['boundary']['registers31'][0]=='0x4'
  c['unchanged_original_service_suffix_complete_buffers_objects_and_state_oracles_checked']+=1
  summaries.append({'case':j,'configuration':cfg,'original_visits':len(r['source_visits']),'classification_sequence':[[hex(name),code]for name,code in classifications],'boundary':r['boundary']['kind']});print(json.dumps(summaries[-1]),flush=True)
 assert ct['original_instruction_visits_checked']==21771 and ct['whole_final_private_RAM_bytes_checked']==28311552 and kt['source_visits_checked']==15172 and kt['whole_final_RAM_bytes_checked']==4194304 and mt['original_instruction_visits_checked']==6178 and mt['whole_final_private_RAM_bytes_checked']==6291456
 rejected=[]
 for tag,index in(('control_local_name',2),('control_sequence_ordinal',6),('root_empty_return_frame',4),('timer_flag_clear_write',5),('final_timer_flag',5)):
  bad=copy.deepcopy(p['cases'][index])
  if tag=='control_local_name':
   for key in('imports','runloop_models','mode_models','control_models'):
    e=next(e for e in bad[key]if e['name']=='declared_control_port_receive');raw=bytearray.fromhex(e['patches'][0]['after_hex']);struct.pack_into('<I',raw,12,0x707);e['patches'][0]['after_hex']=raw.hex()
  elif tag=='control_sequence_ordinal':
   for key in('imports','runloop_models','mode_models','control_models'):next(e for e in bad[key]if e['name']=='declared_control_port_receive')['control_ordinal']=2
  elif tag=='root_empty_return_frame':next(e for e in bad['control_frames']if e['pc']=='0x1855226e8')['registers31'][23]='0x1'
  elif tag=='timer_flag_clear_write':next(e for e in bad['source_writes']if e['pc']=='0x1847573e4')['after_hex']='01'
  else:raw=bytearray.fromhex(bad['final_mode512_hex']);raw[0xa8]=1;bad['final_mode512_hex']=raw.hex()
  try:Replay(bad,p['kernel_cases'][bad['configuration']['kernel_case']],s).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('accepted altered evidence',tag))
 c['altered_evidence_controls_rejected']=len(rejected)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','cf_mode_construction_source.json','cf_mode_construction_profiles.json','replay_cf_mode_construction.py','kernel_portset_delivery_profiles.json','replay_kernel_portset_delivery.py']},'source_recapture_match':True,'verified_counts':dict(c),'independent_A64_replay':dict(ct),'fresh_kernel_replay':dict(kt),'fresh_mode_replay':dict(mt),'altered_evidence_rejected':rejected,'case_summaries':summaries,'all_checks_pass':True,**FLAGS};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'A64':dict(ct),'fresh_kernel':dict(kt),'fresh_mode':dict(mt),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
