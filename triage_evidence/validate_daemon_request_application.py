#!/usr/bin/env python3
"""Independent continuous-producer, record, copy, libbsm and source oracles.
O(source/cache bytes+visits+RAM+journals+fixups), O(image+RAM+journals).
This proves finite local composition under explicit binding/stack premises.
"""
import json,struct
from collections import Counter
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_request_application import P,FLAGS,sha,build,BSM,SLOT
from replay_daemon_request_application import Replay
from replay_daemon_request_consumption import Replay as PrefixReplay
def get(path):return json.loads((ROOT/path).read_text())
def main():
 src=get(P+'_source.json');prof=get(P+'_profiles.json');prior=get('daemon_request_consumption_profiles.json');kernel=get('kernel_request_delivery_profiles.json');oldsrc=get('daemon_request_consumption_source.json');counts=Counter();totals=Counter();prefix=Counter();summaries=[];slots=set();assert src==build()
 for o,s in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/s)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 assert len(prof['cases'])==2;counts['daemon_ranges_recaptured']=len(src['ranges']);counts['daemon_instructions_recaptured']=sum(len(r['instructions'])for r in src['ranges']);counts['cache_function_instructions_recaptured']=len(src['cache_function']['instructions']);counts['complete_cache_source_files_hashed']=len(src['cache_files'])
 for r in prof['cases']:
  idx=r['kernel_case_index'];assert idx in(1,3);old=prior['cases'][idx];k=kernel['cases'][idx];prefix.update(PrefixReplay(old,k,oldsrc).run());f=r['application_handoff'];n=len(old['source_visits']);assert f['source_visit_index']==n==331 and r['source_visits'][:n]==old['source_visits']and[e for e in r['source_reads']if e['source_visit_index']<n]==old['source_reads']and[e for e in r['source_writes']if e['source_visit_index']<n]==old['source_writes']and r['imports'][0]==old['imports'][0]
  for name in('registers31','SP','NZCV','Q_registers32'):assert f[name]==old['boundary'][name]
  assert f['private1048576_sha256']==old['final_private1048576_sha256']and f['stack524288_sha256']==old['final_stack524288_sha256'];counts['exact_original_callback_CPU_and_whole_RAM_prefixes_checked']+=1
  stack=int(f['SP'],16)-0x150;record=stack+0x28;u=stack+0xa0;control=stack+0xc0;expected=bytearray(b'\xa5'*120)
  struct.pack_into('<I',expected,0,0x303)
  for off,value in[(8,0x6500004000),(16,0x100000c),(24,0),(32,1),(72,0x6500080044),(80,0x65000800cc)]:struct.pack_into('<Q',expected,off,value)
  expected[40:72]=bytes(32);assert r['argument_record_address']==hex(record)and r['final_argument_record120_hex']==expected.hex();counts['complete_private_argument_record120_oracles_checked']+=1
  frames=r['application_frames'];cf=next(e for e in frames if e['pc']=='0x100023a74');p=((control&0xffffffff)^0xeaae0ac9)*0x7398180b&0xffffffff;want=struct.pack('<QIIQ',u^0x1c0b9f7ce10f2255,p^0x6cf4,p^0xbc84919b,record)+b'\xa5'*8;assert cf['control_record_address']==hex(control)and cf['control_record32_hex']==want.hex();counts['complete_encoded_control_record32_oracles_checked']+=1
  copies=[e for e in frames if e['pc']=='0x10046f89c'];assert len(copies)==3 and all(e['copy_arguments3'][2]=='0x20'and e['copy_source32_hex']=='00'*32 for e in copies);assert copies[0]['copy_arguments3'][:2]==[f['registers31'][6],hex(record+40)]and copies[1]['copy_arguments3'][0]==copies[0]['copy_arguments3'][1]and copies[2]['copy_arguments3'][0]==copies[1]['copy_arguments3'][1]
  for e in copies:
   dest=int(e['copy_arguments3'][1],16);end=next((x['source_visit_index']for x in frames if x['source_visit_index']>e['source_visit_index']),len(r['source_visits']));written=set()
   for w in r['source_writes']:
    a=int(w['address'],16)
    if e['source_visit_index']<=w['source_visit_index']<end and dest<=a<a+w['size_bytes']<=dest+32:assert w['after_hex']=='00'*w['size_bytes'];written.update(range(a,a+w['size_bytes']))
   assert written==set(range(dest,dest+32));counts['complete_original_audit_copy_source_destination_and_stores_checked']+=1
  lib=next(e for e in frames if e['pc']==hex(BSM));out=int(lib['PID_output_address'],16);assert lib['registers31'][:8]==[copies[2]['copy_arguments3'][1],'0x0','0x0','0x0','0x0','0x0',hex(out),'0x0']and lib['stack_argument0_hex']=='00'*8 and lib['audit_input32_hex']=='00'*32;counts['selected_libbsm_register_stack_and_token_ABI_checked']+=1
  lr=[e for e in r['source_reads']if BSM<=int(e['pc'],16)<0x20638d7e4 and int(lib['registers31'][0],16)<=int(e['address'],16)<int(lib['registers31'][0],16)+32];assert len(lr)==1 and lr[0]['pc']=='0x20638d7b0'and lr[0]['address']==hex(int(lib['registers31'][0],16)+20)and lr[0]['size_bytes']==4 and lr[0]['bytes_hex']=='00'*4
  lw=[e for e in r['source_writes']if e['address']==hex(out)and BSM<=int(e['pc'],16)<0x20638d7e4];assert len(lw)==1 and lw[0]['pc']=='0x20638d7b4'and lw[0]['size_bytes']==4 and lw[0]['after_hex']=='00'*4;counts['original_libbsm_word5_load_and_PID_store_checked']+=1
  pcs=[e['pc']for e in r['source_visits']];assert pcs.count(hex(BSM))==1 and pcs.count('0x20638d7cc')==0 and pcs.count('0x1005c18c8')==1 and pcs.count('0x100528dd8')==0;assert r['boundary']['kind']=='before_pthread_self'and r['imports'][-1]['name']=='libSystem/_pthread_self'and len(r['stack_check_contracts'])==1;counts['original_PID_zero_continuation_and_unexecuted_pthread_boundary_checked']+=1
  scans=[e for e in r['source_reads']if e['pc']in('0x100422edc','0x10008a958')];assert[(e['address'],e['size_bytes'],e['bytes_hex'])for e in scans]==[(hex(0x6500004000+j),1,bytes.fromhex(k['final_OOL16384_hex'])[j:j+1].hex())for j in range(29)];counts['exact_NUL_terminated_string_scan29_oracles_checked']+=1
  assert r['final_user8192_hex']==k['final_user8192_hex']and r['final_OOL16384_hex']==k['final_OOL16384_hex']and r['reply384_hex']==old['reply384_hex'];counts['complete_message_OOL_and_reply_preservation_oracles_checked']+=1
  for e in r['source_reads']:
   a=int(e['address'],16);slots.update(x for x in range(a,a+e['size_bytes'])if x in FIXUPS)
  totals.update(Replay(r,k,src).run());summaries.append({'kernel_case':idx,'source_visits':len(pcs),'string_bytes_read':29,'audit_copy_calls':3,'libbsm_visits':sum(BSM<=int(e['pc'],16)<0x20638d7e4 for e in r['source_visits']),'PID_output':0,'boundary':r['boundary']['kind']});print(json.dumps(summaries[-1]),flush=True)
 rebases={a for a in slots if not FIXUPS[a]['kind'].endswith('bind')};fix=verify_original_fixups(rebases);imports=[binding(a)for a in sorted(slots-rebases)];assert next(e for e in imports if e['slot']==hex(SLOT))['symbol']=='_audit_token_to_au32';counts['original_used_fixup_words_checked']=len(fix['records'])+len(imports);counts['cases']=2
 assert counts['original_used_fixup_words_checked']==157 and totals['original_instruction_visits_checked']==5934 and totals['cached_libbsm_instruction_visits_checked']==38 and totals['whole_private_RAM_bytes_checked']==3145728 and totals['complete_application_record_and_ABI_frames_checked']==22 and prefix['original_instruction_visits_checked']==662
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','daemon_request_consumption_profiles.json','daemon_request_consumption_source.json','replay_daemon_request_consumption.py','kernel_request_delivery_profiles.json','daemon_import_bindings.py','bootpolicy_cache_reader.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_callback_producer_replay':dict(prefix),'original_rebase_checks':fix,'original_import_checks':imports,'case_summaries':summaries,'all_checks_pass':True,**FLAGS};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(counts),'replay':dict(totals),'prefix':dict(prefix),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
