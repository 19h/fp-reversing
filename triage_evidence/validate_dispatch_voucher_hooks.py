#!/usr/bin/env python3
"""Independent installer-table, header-normalization, clear and dispatch checks.
O(source/cache bytes+visits+RAM+journals), O(image+RAM+journals). Static startup
route and private call transitions do not attest effective native runtime state.
"""
import json,struct
from collections import Counter
from daemon_receive_tools import ROOT
from recover_dispatch_voucher_hooks import P,FLAGS,sha,build,CacheView,TABLE,DISPATCH_INIT,DISPATCH_ADOPT,DISPATCH_REVERT
from replay_dispatch_voucher_hooks import Replay,ClearReplay
from replay_cf_receive_voucher import USER,OOL,BUF,LIVE,STATE,COPY
from recover_cf_receive_voucher import INIT,ROOTCELL,REVERT,ADOPT
from replay_kernel_request_delivery import Replay as KernelReplay
from replay_cf_daemon_request import Replay as DispatchReplay
from kernel_vm_mig_tools import Image
def get(n):return json.loads((ROOT/n).read_text())
def main():
 src=get(P+'_source.json');prof=get(P+'_profiles.json');old=get('cf_receive_voucher_profiles.json');ds=get('cf_daemon_request_source.json');dp=get('cf_daemon_request_profiles.json');counts=Counter();ct=Counter();kt=Counter();dt=Counter();cl=Counter();summary=[];assert src==build();view=CacheView(src);im=Image()
 for o,s in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/s)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 counts.update({'complete_cache_functions_recaptured':len(src['functions']),'captured_cache_instructions':sum(len(f['instructions'])for f in src['functions'])+4*len(src['import_stubs']),'original_import_stubs_checked':len(src['import_stubs']),'original_cache_pointer_chains_checked':len(src['import_stubs'])+len(src['installed_hook_table']['callbacks'])+1,'table_callback_members_checked':len(src['installed_hook_table']['callbacks']),'original_parent_call_edges_checked':len(src['parent_call_edges']),'cache_files_hashed':len(src['cache_files'])});assert src['installed_hook_table']['leading_scalar_u64']==3 and src['voucher_initializer_binding_outside_local_GOT']and len(src['dispatch_local_GOT_sections'])==2;counts['source_initializer_offset_and_shared_binding_geometry_checked']=1
 assert prof['kernel_cases']==old['kernel_cases']and len(prof['cases'])==len(prof['dispatch_cases'])==len(prof['clear_cases'])==4
 for j,(r,k)in enumerate(zip(prof['cases'],prof['kernel_cases'],strict=True)):
  kt.update(KernelReplay(im,k).run());assert r['configuration']=={'kernel_producer':j,'table_mode':'original_libdispatch_table'}and r['entry_PC']==hex(DISPATCH_INIT)and r['entry_registers31'][0]=='0x0'and r['initial_private_fixtures']==old['cases'][2*j+1]['initial_private_fixtures'];counts['exact_kernel_and_declared_receive_predecessor_oracles_checked']+=1
  raw=bytes.fromhex(k['final_user8192_hex']);after=bytearray(raw);H=struct.unpack_from('<I',raw)[0];assert H==0x80111112 and struct.unpack_from('<I',raw,16)[0]==0;struct.pack_into('<I',after,0,H&0xdfe0ffff);assert struct.unpack_from('<I',after)[0]==0x80001112 and r['final_user8192_hex']==after.hex()and r['final_OOL16384_hex']==k['final_OOL16384_hex'];counts['complete_post_adopt_message_OOL_and_header_mask_oracles_checked']+=1
  frames={int(e['pc'],16):e for e in r['frames']};assert frames[INIT]['registers31'][0]==hex(TABLE)and frames[DISPATCH_ADOPT]['registers31'][0]==hex(USER)and frames[DISPATCH_ADOPT]['user148_hex']==raw[:148].hex()and frames[DISPATCH_REVERT]['registers31'][0]=='0xffffffffffffffff';counts['original_leaf_installer_and_callback_ABIs_checked']+=1
  pub=[e for e in r['source_writes']if e['address']==hex(ROOTCELL)];assert len(pub)==1 and pub[0]['pc']==hex(INIT+4)and pub[0]['before_hex']==struct.pack('<Q',0x18057d1a0).hex()and pub[0]['after_hex']==struct.pack('<Q',TABLE).hex();counts['original_const_table_publication_oracles_checked']+=1
  for pc,off,target in((REVERT+8,0x20,DISPATCH_REVERT),(ADOPT+8,0x18,DISPATCH_ADOPT)):
   reads=[e for e in r['source_reads']if e['pc']==hex(pc)];assert len(reads)==1 and reads[0]['address']==hex(TABLE+off)and reads[0]['bytes_hex']==struct.pack('<Q',target).hex();counts['actual_original_callback_table_loads_checked']+=1
  writes=[e for e in r['source_writes']if USER<=int(e['address'],16)<USER+148 and int(e['pc'],16)>=DISPATCH_ADOPT and int(e['pc'],16)<DISPATCH_REVERT];assert len(writes)==2 and writes[0]['pc']=='0x18553aac0'and writes[0]['address']==hex(USER+16)and writes[0]['before_hex']==writes[0]['after_hex']=='00'*4 and writes[1]['pc']=='0x18553aacc'and writes[1]['address']==hex(USER)and writes[1]['after_hex']=='12110080'and writes[0]['source_visit_index']<writes[1]['source_visit_index'];counts['original_zero_name_and_header_store_order_checked']+=1
  ins=[next(view.cs.disasm(view.read(int(e['pc'],16),4),int(e['pc'],16))).mnemonic for e in r['source_visits']];assert not set(ins)&{'mrs','msr','svc','hvc','smc','brk'};assert r['final_hook_root8_hex']==struct.pack('<Q',TABLE).hex()and r['final_voucher_state8_hex']=='ff'*8 and r['final_voucher_copy8_hex']=='00'*8 and r['final_live_name8_hex']==(struct.pack('<I',int(k['receive_name'],16))+b'\xa5'*4).hex()and r['boundary']['registers31'][0]=='0x1';counts['no_TSD_path_and_complete_CF_output_oracles_checked']+=1
  assert len(r['API_models'])==1 and r['API_models'][0]['return_value']=='0x0'and r['API_models'][0]['symbol']=='exact_original_kernel_delivery_return_contract';model=r['API_models'][0];assert model['after_NZCV']=='0xf0000000'and all(int(model['after_registers31'][q],16)==(((q+1)*0x123456789abcdef)^0x8b3dc651)for q in range(1,18));ct.update(Replay(view,r,k).run())
 for j,(r,k)in enumerate(zip(prof['clear_cases'],prof['kernel_cases'],strict=True)):
  assert r['entry_PC']=='0x18553aa44'and r['initial_private_fixtures']==[{'address':hex(USER),'bytes_hex':k['final_user8192_hex']}]and not r['API_models']and r['final_user8192_hex']==k['final_user8192_hex']and r['boundary']['registers31'][0]=='0x0';assert not any(USER<=int(e['address'],16)<USER+8192 for e in r['source_writes']);counts['original_clear_zero_name_complete_unchanged_packet_oracles_checked']+=1;cl.update(ClearReplay(view,r).run())
 for j,r in enumerate(prof['dispatch_cases']):
  received=prof['cases'][j];k=prof['kernel_cases'][j];prior=dp['cases'][j];supplied={**k,'final_user8192_hex':received['final_user8192_hex'],'final_OOL16384_hex':received['final_OOL16384_hex']};assert r['CF_receive_case_index']==j and r['source_visits']==prior['source_visits']and r['final_user8192_hex']==received['final_user8192_hex']==prior['final_user8192_hex']and r['final_OOL16384_hex']==received['final_OOL16384_hex']and r['reply384_hex']==prior['reply384_hex'];assert r['boundary']['kind']==('before_pthread_self'if j<2 else'CF_source_returned')
  for f in r['CF_frames']:assert f['user148_hex']==received['final_user8192_hex'][:296]
  if j<2:assert r['final_argument_record120_hex']==prior['final_argument_record120_hex']
  else:assert r['final_generic_reply8_hex']=='00'*8 and r['boundary']['registers31'][0]=='0x1'
  counts['normalized_bytes_reach_same_original_dispatch_record_and_reply_oracles_checked']+=1;dt.update(DispatchReplay(r,supplied,ds).run());summary.append({'producer':j,'kernel_header':'0x80111112','post_adopt_header':'0x80001112','post_clear_header':'0x80111112','voucher_name':0,'receive_visits':len(received['source_visits']),'dispatch_boundary':r['boundary']['kind']});print(json.dumps(summary[-1]),flush=True)
 assert counts['complete_cache_functions_recaptured']==12 and counts['captured_cache_instructions']==663 and counts['original_cache_pointer_chains_checked']==11 and ct['source_visits_checked']==500 and ct['whole_final_private_RAM_bytes_checked']==4194304 and cl['source_visits_checked']==60 and dt['original_instruction_visits_checked']==7038 and kt['source_visits_checked']==10652
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','cf_receive_voucher_profiles.json','cf_daemon_request_source.json','cf_daemon_request_profiles.json','replay_cf_daemon_request.py','replay_kernel_request_delivery.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(ct),'fresh_kernel_delivery_replay':dict(kt),'fresh_CF_daemon_dispatch_replay':dict(dt),'independent_clear_replay':dict(cl),'case_summaries':summary,'all_checks_pass':True,**FLAGS};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(counts),'receive_replay':dict(ct),'clear_replay':dict(cl),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
