#!/usr/bin/env python3
"""Recapture and independently replay complete original run-loop composition.
O(source/cache bytes+visits+RAM+journals) time/space. Exact byte/ABI oracles
and bounded rejection controls; native source registration remains unknown.
"""
import copy,json,struct
from collections import Counter
from daemon_receive_tools import ROOT
from recover_cf_runloop_handoff import P,FLAGS,sha,build
from recover_cf_receive import RUN,DO_SOURCE
from replay_cf_runloop_handoff import Replay,B,USER,OOL,RL,MODE,SRC,DICT,RUN_SP,ENTRY_SP
from replay_kernel_request_delivery import Replay as KernelReplay
from kernel_vm_mig_tools import Image
def get(n):return json.loads((ROOT/n).read_text())
def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');old=get('dispatch_voucher_hooks_profiles.json');prior=get('cf_daemon_request_profiles.json');assert s==build();c=Counter();rt=Counter();kt=Counter();rows=[]
 for obj,script in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 fs={int(f['start'],16):f for f in s['CF_functions']};assert len(fs)==18 and len(fs[RUN]['instructions'])==677 and fs[RUN]['end']=='0x184757910'and fs[RUN]['exact_nlist'][0]['name']=='___CFRunLoopRun';assert len(s['import_stubs'])==8 and s['extra_pointer_fixups'][0]['target']=='0x1855148ec'and any(e['name']=='_os_release'for e in s['extra_pointer_fixups'][0]['exact_nlist']);c.update({'complete_cache_functions_recaptured':18,'captured_cache_instructions':sum(len(f['instructions'])for f in fs.values())+4*len(s['import_stubs']),'complete_runloop_body_instructions':677,'original_import_stubs_checked':8,'cache_files_hashed':len(s['cache_files'])})
 assert p['kernel_cases']==old['kernel_cases']and len(p['cases'])==4 and{r['kernel_case_index']for r in p['cases']}==set(range(4));im=Image()
 for r in p['cases']:
  j=r['kernel_case_index'];k=p['kernel_cases'][j];kt.update(KernelReplay(im,k).run());rt.update(Replay(r,k,s).run());frames={int(f['pc'],16):f for f in r['runloop_frames']};cf={int(f['pc'],16):f for f in r['CF_frames']};entry=frames[RUN];assert entry['registers31'][:3]==[hex(RL),hex(MODE),'0x1']and entry['SP']==hex(ENTRY_SP)and entry['Q_registers32'][0]=='0x7ff0000000000000'
  receive=frames[0x18475730c];assert receive['registers31'][:6]==[k['receive_name'],hex(RUN_SP+0x68),hex(RUN_SP+0x64),'0xffffffff',hex(RUN_SP+0x78),hex(RUN_SP+0x70)]and receive['SP']==hex(RUN_SP)and ENTRY_SP-RUN_SP==0xd50 and RUN_SP+0xd0==USER;c['original_prologue_receive_buffer_and_six_argument_geometry_checked']+=1
  after=frames[0x184757310];assert after['registers31'][0]=='0x1'and after['native_buffer_pointer8_hex']==struct.pack('<Q',USER).hex()and after['native_live_name4_hex']==struct.pack('<I',int(k['receive_name'],16)).hex()and after['native_voucher_state8_hex']=='ff'*8 and after['native_voucher_copy8_hex']=='00'*8
  expected=bytearray(bytes.fromhex(k['final_user8192_hex'])[:3072]);assert struct.unpack_from('<I',expected)[0]==0x80111112;struct.pack_into('<I',expected,0,0x80001112);assert after['user148_hex']==expected[:148].hex()and r['final_user8192_hex'][:6144]==expected.hex()and r['final_OOL16384_hex']==k['final_OOL16384_hex'];c['original_receive_normalization_complete_capacity_and_OOL_oracles_checked']+=1
  dictionary=[e for e in r['runloop_models']if e['pc']=='0x1846ddc8c'];assert len(dictionary)==1 and dictionary[0]['before']['registers31'][:2]==[hex(DICT),k['receive_name']]and dictionary[0]['result']==hex(SRC)
  source=frames[0x184757718];args=[hex(RL),hex(MODE),hex(SRC),hex(USER),'0x50',hex(RUN_SP+0x50)];assert source['registers31'][:6]==cf[DO_SOURCE]['registers31'][:6]==args and source['native_reply8_hex']=='00'*8;c['source_dictionary_live_port_key_and_original_source_call_ABIs_checked']+=1
  callback=cf[0x100425f78];assert callback['registers31'][:4]==[hex(B+0x90000),hex(USER),'0x50','0x0']and callback['user148_hex']==expected[:148].hex();a=cf[DO_SOURCE]['source_visit_index'];oldvis=prior['cases'][j]['source_visits'];assert r['source_visits'][a:a+len(oldvis)]==oldvis;c['unchanged_original_CF_daemon_application_instruction_suffixes_checked']+=1
  tsd=[e for e in r['runloop_models']if e['pc']=='0x1846ddde4'];assert len(tsd)==(1 if j<2 else 2)and all(e['before']['registers31'][:3]==['0xd','0x0','0x1855148ec']and e['result']=='0x0'for e in tsd);c['original_TSD_key_copy_and_os_release_callback_argument_oracles_checked']+=len(tsd)
  visited={int(e['pc'],16)for e in r['source_visits']};assert 0x184757744 not in visited
  if j<2:assert r['boundary']['kind']=='before_pthread_self'and '0x18475771c'not in{f['pc']for f in r['runloop_frames']}and r['final_argument_record120_hex'][40*2:72*2]=='00'*32;c['application_pre_pthread_boundaries_checked']+=1
  else:
   assert r['boundary']['kind']=='original_runloop_returned'and r['boundary']['registers31'][0]=='0x4'and r['boundary']['SP']==hex(ENTRY_SP)and frames[0x18475771c]['registers31'][0]=='0x1'and frames[0x184757720]['native_reply8_hex']=='00'*8 and frames[0x1847577b0]['native_buffer_pointer8_hex']==struct.pack('<Q',USER).hex();assert 0x18040bbec in visited and 0x18040bbdc in visited;c['source_handled_null_reply_no_send_and_original_runloop_return_oracles_checked']+=1
  assert len(r['kernel_transfers'])==1 and len([e for e in r['imports']if e['pc']=='0x180547f94'])==1;c['single_receive_and_no_generic_reply_emission_oracles_checked']+=1
  rows.append({'kernel_case':j,'request_id':struct.unpack_from('<I',expected,20)[0],'receive_name':k['receive_name'],'source_visits':len(r['source_visits']),'ordered_reads':len(r['source_reads']),'ordered_writes':len(r['source_writes']),'boundary':r['boundary']['kind'],'runloop_result':4 if j>=2 else None,'native_source_binding_attested':False});print(json.dumps(rows[-1]),flush=True)
 assert c['captured_cache_instructions']==1722 and c['cache_files_hashed']==9 and rt['original_instruction_visits_checked']==8736 and kt['source_visits_checked']==10652 and rt['whole_final_private_RAM_bytes_checked']==12582912
 control=next(r for r in p['cases']if r['kernel_case_index']==2);rejected=[]
 for tag in('instruction_word','receive_patch','dictionary_result','return_status'):
  bad=copy.deepcopy(control)
  if tag=='instruction_word':bad['source_visits'][0]['bytes_hex']='00000000'
  elif tag=='receive_patch':next(e for e in bad['imports']if e['pc']=='0x180547f94')['patches'][0]['after_hex']='00'*148
  elif tag=='dictionary_result':next(e for e in bad['imports']if e['pc']=='0x1846ddc8c')['result']='0x0'
  else:bad['boundary']['registers31'][0]='0x0'
  try:Replay(bad,p['kernel_cases'][2],s).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('accepted invalid journal',tag))
 c['tampered_journal_controls_rejected']=len(rejected);out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','dispatch_voucher_hooks_profiles.json','cf_daemon_request_profiles.json','replay_cf_daemon_request.py','replay_kernel_request_delivery.py']},'source_recapture_match':True,'verified_counts':dict(c),'independent_A64_replay':dict(rt),'fresh_kernel_delivery_replay':dict(kt),'tampered_journals_rejected':rejected,'case_summaries':rows,'all_checks_pass':True,**FLAGS};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'runloop_replay':dict(rt),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
