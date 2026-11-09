#!/usr/bin/env python3
"""Independent exact-CF receive geometry, voucher-table and downstream oracles.
O(source/cache bytes+visits+RAM+journals), O(image+RAM+journals). Mach/task and
separate CF-service/dispatch caller handoffs are explicit composition premises.
"""
import json,struct
from collections import Counter
from daemon_receive_tools import ROOT
from recover_cf_receive_voucher import P,FLAGS,sha,build,CacheView,MACH,REVERT,ADOPT,INIT,ROOTCELL
from replay_cf_receive_voucher import Replay,USER,OOL,BUF,LIVE,STATE,COPY,TABLE
from replay_kernel_request_delivery import Replay as KernelReplay
from replay_cf_daemon_request import Replay as DispatchReplay
from replay_rpc502_vm_handoff import decode
from kernel_vm_mig_tools import Image
def get(n):return json.loads((ROOT/n).read_text())
def main():
 src=get(P+'_source.json');prof=get(P+'_profiles.json');old=get('kernel_request_delivery_profiles.json');ds=get('cf_daemon_request_source.json');dp=get('cf_daemon_request_profiles.json');counts=Counter();ct=Counter();kt=Counter();dt=Counter();summary=[];assert src==build();im=Image();view=CacheView(src)
 for o,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 counts.update({'complete_cache_functions_recaptured':len(src['functions']),'captured_cache_instructions':sum(len(f['instructions'])for f in src['functions'])+12,'original_import_stubs_checked':len(src['import_stubs']),'original_cache_pointer_chains_checked':4,'cache_files_hashed':len(src['cache_files']),'kernel_instruction_roles_recaptured':len(src['kernel_instruction_roles'])});assert src['kernel_sha256']==im.k.sha256 and len(prof['kernel_cases'])==4 and len(prof['cases'])==8 and len(prof['dispatch_cases'])==4
 for j,k in enumerate(prof['kernel_cases']):
  assert k['configuration']=={'producer':j,'capacity':3072,'options':0x07000806}and k['entry_registers31'][:8]==[hex(USER),'0x0','0x7000806','0x0','0x0','0xc00','0x0',k['receive_name']];prior=old['cases'][2*j+1]
  for key in('initial_private_fixtures','initial_image_fixtures','input_overlays','post_setup_original_kmsg256_hex'):assert k[key]==prior[key]
  assert decode(k['initial_state_transfer'])==decode(old['loans'][j]['final_private_RAM']);counts['exact_original_loan_context_and_packet_before_images_checked']+=1
  before=bytes.fromhex(prior['final_user8192_hex']);expected=bytearray(before);expected[2]=0x11;u=bytes.fromhex(k['final_user8192_hex']);assert u==expected and k['final_OOL16384_hex']==prior['final_OOL16384_hex'];assert struct.unpack_from('<6I',u)==(0x80111112,80,0x207,0x303 if j<2 else 0x403,0,502 if j<2 else 700)and struct.unpack_from('<II',u,80)==(0,68);queued=bytes.fromhex(k['post_setup_original_kmsg256_hex']);assert struct.unpack_from('<I',queued,0x40)[0]==0x80111211 and queued[0x42]==u[2]==17;counts['complete_wire_OOL_and_preserved_voucher_disposition_oracles_checked']+=1
  assert k['user_byte_copy_contracts'][-1]['arguments3'][1:]==[hex(USER),'0x94']and k['boundary']['registers31'][0]=='0x0';kt.update(KernelReplay(im,k).run())
 for idx,r in enumerate(prof['cases']):
  j=idx//2;k=prof['kernel_cases'][j];mode='file_default'if idx%2==0 else'published_null_callbacks';assert r['configuration']=={'kernel_producer':j,'table_mode':mode};root=0x18057d1a0 if mode=='file_default'else TABLE
  expected_fixtures=[(USER,b'\xa5'*8192),(OOL,b'\xa5'*16384),(BUF,struct.pack('<Q',USER)),(LIVE,b'\xa5'*8),(STATE,b'\xff'*8),(COPY,b'\xa5'*8),(TABLE,bytes(48))];assert r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in expected_fixtures]and r['initial_image_fixtures']==[];receive_header=bytearray(b'\xa5'*148);struct.pack_into('<4I',receive_header,0,0,3072,0,int(k['receive_name'],16));struct.pack_into('<I',receive_header,20,0);transfer=r['kernel_return_transfers'][0];assert transfer['patches'][0]['before_hex']==receive_header.hex()and transfer['patches'][1]['before_hex']=='a5'*29;counts['independent_CF_initial_buffers_and_Mach_before_images_checked']+=1
  assert r['final_user8192_hex']==k['final_user8192_hex']and r['final_OOL16384_hex']==k['final_OOL16384_hex'];assert r['final_hook_root8_hex']==struct.pack('<Q',root).hex()and r['final_buffer_pointer8_hex']==struct.pack('<Q',USER).hex()and r['final_live_name8_hex']==(struct.pack('<I',int(k['receive_name'],16))+b'\xa5'*4).hex()and r['final_voucher_state8_hex']=='ff'*8 and r['final_voucher_copy8_hex']=='00'*8 and r['boundary']['registers31'][0]=='0x1';counts['complete_CF_receive_voucher_and_output_guard_oracles_checked']+=1
  frame={int(e['pc'],16):e for e in r['frames']};assert frame[MACH]['registers31'][:7]==[hex(USER),'0x7000806','0x0','0xc00',k['receive_name'],'0xffffffff','0x0']and frame[REVERT]['registers31'][0]=='0xffffffffffffffff'and frame[ADOPT]['registers31'][0]==hex(USER);counts['actual_CF_Mach_and_voucher_call_ABIs_checked']+=1
  for pc,off in((REVERT+8,0x20),(ADOPT+8,0x18)):
   reads=[e for e in r['source_reads']if e['pc']==hex(pc)];assert len(reads)==1 and reads[0]['address']==hex(root+off)and reads[0]['size_bytes']==8 and reads[0]['bytes_hex']=='00'*8;counts['original_null_callback_loads_checked']+=1
  pcs=[e['pc']for e in r['source_visits']];assert hex(REVERT+16)not in pcs and hex(ADOPT+16)not in pcs and '0x184758aec'not in pcs;counts['original_null_hook_and_no_voucher_copy_paths_checked']+=1
  stores=[e for e in r['source_writes']if e['address']==hex(ROOTCELL)]
  if mode=='file_default':assert not stores and r['initializer_to_CF_call']is None
  else:assert len(stores)==1 and stores[0]['pc']==hex(INIT+4)and stores[0]['before_hex']==struct.pack('<Q',0x18057d1a0).hex()and stores[0]['after_hex']==struct.pack('<Q',TABLE).hex()and r['initializer_to_CF_call']['before']['registers31'][0]=='0x0';counts['original_initializer_pointer_publication_checked']+=1
  assert len(r['API_models'])==1 and r['API_models'][0]['symbol']=='exact_original_kernel_delivery_return_contract'and r['API_models'][0]['return_value']=='0x0';model=r['API_models'][0];assert model['after_NZCV']=='0xf0000000'and all(int(model['after_registers31'][q],16)==(((q+1)*0x123456789abcdef)^0x8b3dc651)for q in range(1,18));ct.update(Replay(view,r,k).run())
 for j,r in enumerate(prof['dispatch_cases']):
  received=prof['cases'][2*j];k=prof['kernel_cases'][j];prior=dp['cases'][j];assert r['kernel_case_index']==j and r['CF_receive_case_index']==2*j and r['source_visits']==prior['source_visits']and r['final_user8192_hex']==received['final_user8192_hex']and r['final_OOL16384_hex']==received['final_OOL16384_hex']and r['reply384_hex']==prior['reply384_hex']
  for f in r['CF_frames']:assert f['user148_hex']==received['final_user8192_hex'][:296]
  assert r['boundary']['kind']==('before_pthread_self'if j<2 else'CF_source_returned')
  if j<2:assert r['final_argument_record120_hex']==prior['final_argument_record120_hex']
  else:assert r['final_generic_reply8_hex']=='00'*8 and r['boundary']['registers31'][0]=='0x1'
  counts['corrected_CF_wire_reaches_same_original_dispatch_and_reply_oracle_checked']+=1;dt.update(DispatchReplay(r,k,ds).run());summary.append({'producer':j,'kernel_visits':len(k['source_visits']),'CF_options':'0x07000806','capacity_bytes':3072,'copied_inline_and_trailer_bytes':148,'wire_bits':'0x80111112','voucher_name':0,'dispatch_boundary':r['boundary']['kind']});print(json.dumps(summary[-1]),flush=True)
 assert kt['source_visits_checked']==10652 and ct['source_visits_checked']==760 and ct['whole_final_private_RAM_bytes_checked']==8388608 and ct['original_initializer_return_and_public_CF_call_handoffs_checked']==4 and ct['exact_kernel_to_CF_transfer_bytes_checked']==1416 and dt['original_instruction_visits_checked']==7038
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','kernel_request_delivery_profiles.json','kernel_request_delivery_source.json','replay_kernel_request_delivery.py','cf_daemon_request_source.json','cf_daemon_request_profiles.json','replay_cf_daemon_request.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(ct),'fresh_kernel_delivery_replay':dict(kt),'fresh_CF_daemon_dispatch_replay':dict(dt),'case_summaries':summary,'all_checks_pass':True,**FLAGS};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(counts),'receive_replay':dict(ct),'kernel_visits':kt['source_visits_checked'],'dispatch_visits':dt['original_instruction_visits_checked'],'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
