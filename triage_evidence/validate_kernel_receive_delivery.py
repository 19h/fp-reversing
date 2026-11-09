#!/usr/bin/env python3
"""Rebuild original source/proofs and independently replay full private delivery.
An independent wire oracle checks conversion/packing and partial-copy effects.
O(source/artifact bytes + visits/effects + compiler/solver resources) time;
O(collection metadata + one private map + largest profile + DAGs) space.
No native rights, authentication, user copyout or deallocation executes.
"""
import json,struct,subprocess
from collections import Counter
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
from recover_kernel_receive_delivery import recover,RESULTS,HEADER,DESTINATION,PACK
from prove_kernel_receive_delivery import obligations
from replay_kernel_receive_delivery import Replay
P=0x6500000000;M=P+0x12000;D=P+0x18000;Q=D+0x28;RX=P+0x38000;SPACE=P+0x48000;MAP=P+0x4a000;USER=P+0x50000;OUT=P+0x58000
def main():
 c=json.loads((ROOT/'kernel_receive_delivery_source.json').read_text());assert recover()==c;p=json.loads((ROOT/'kernel_receive_delivery_profiles.json').read_text());proof=json.loads((ROOT/'kernel_receive_delivery_proofs.json').read_text());prior=json.loads((ROOT/'kernel_queue_send_profiles.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_kernel_receive_delivery.py')
 for obj in [c,p,proof]:
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 qs,counts=obligations();assert counts==proof['source_lift_counts'];smt=0
 for (name,q),row in zip(qs,proof['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
  for f,h in [('file','sha256'),('original_file','original_sha256')]:assert sha(ROOT/row[f])==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row[f])));assert s.check()==z3.unsat;smt+=1
 sdk=subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],capture_output=True,text=True,check=True).stdout.strip();cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',sdk,'-S','-emit-llvm','-O1','-Werror',str(ROOT/'kernel_receive_delivery_sdk.c'),'-o',str(ROOT/'kernel_receive_delivery_sdk.ll')];cc=subprocess.run(cmd,capture_output=True,text=True);assert cc.returncode==0,(cc.stdout,cc.stderr)
 image=Image();totals=Counter();models=Counter();outcomes=Counter();classes=Counter();rows=[];success=first_failed=second_failed=0
 for j,r in enumerate(p['cases']):
  cfg=r['configuration'];seed=prior['cases'][cfg['upstream_index']];prefix=seed['initial_private_fixtures']+[{'address':e['address'],'bytes_hex':e['after_hex']}for e in seed['source_writes']];assert r['initial_private_fixtures'][:len(prefix)]==prefix;assert seed['configuration']['node_qos']==[]and seed['configuration']['case']=='enqueue'
  cpu=Replay(image,r);result=cpu.run();totals.update(result);rows.append({'index':j,'verified_counts':result});classes[cfg['storage_class']]+=1;failure=cfg['copy_failure_at'];extent=cfg['trailer_extent'];name=cfg['receive_name'];expected_status=0 if failure==0 else 0x10004008;outcomes[hex(expected_status)]+=1;assert cpu.reg(0)==expected_status and r['boundary']['kind']=='returned'
  wire_header=struct.pack('<6I',0x1200,36,0,name,0,4901);body=bytes.fromhex('000000000100000000000000');trailer=bytearray(68);struct.pack_into('<5I',trailer,0,0,extent,0xffffffff,0,1);struct.pack_into('<Q',trailer,52,cfg['port_context']);packet=wire_header+body+trailer[:extent]
  expected=bytearray([0xa5])*4096
  if failure==0:expected[:len(packet)]=packet;success+=1
  elif failure==1:first_failed+=1
  else:assert cfg['storage_class']&1;expected[:24]=wire_header;second_failed+=1
  actual=bytes(cpu.u.mem_read(USER,4096));assert actual==expected and actual.hex()==r['private_user_buffer_hex'],(j,cfg,actual[:120].hex(),expected[:120].hex())
  result_record=struct.pack('<6IQQ',36 if failure==0 else 0,extent if failure==0 else 0,0,0,0xffffffff,0,cfg['port_context'],0);published=result_record if cfg['result_record_requested']else bytes([0xa5])*40;assert bytes(cpu.u.mem_read(OUT,40))==published and r['receive_result_record_hex']==published.hex();assert len(r['completion_snapshots'])==1 and r['completion_snapshots'][0]['bytes_hex']==result_record.hex()
  assert r['destination_object_refs']==1 and r['destination_send_once_refs']==0 and r['received_counter']==0;assert int.from_bytes(bytes(cpu.u.mem_read(D+4,4)),'little')==1 and int.from_bytes(bytes(cpu.u.mem_read(D+0x8c,4)),'little')==0
  assert bytes(cpu.u.mem_read(Q,8))==bytes(8)and int.from_bytes(bytes(cpu.u.mem_read(Q+0x10,2)),'little')==0 and int.from_bytes(bytes(cpu.u.mem_read(RX+0x3a0,4)),'little')==0
  cut=r['delivery_entry_cuts'];assert [e['pc']for e in cut]==[hex(HEADER),hex(DESTINATION),hex(PACK)];h,d,pk=[[int(x,16)for x in e['arguments6']]for e in cut];assert h[:4]==[M,SPACE,MAP,cfg['options']]and d[:3]==[SPACE,D,18]and pk[0]==M and pk[3:]==[cfg['options'],MAP,0]
  assert len(r['caller_handovers'])==1 and r['caller_handovers'][0]['before_X0']=='0xa'and r['caller_handovers'][0]['after_X0']==hex(OUT if cfg['result_record_requested']else 0)and r['caller_handovers'][0]['to_PC']==hex(RESULTS)
  copies=r['declared_copyouts'];assert len(copies)==(1 if not(cfg['storage_class']&1)or failure==1 else 2)
  if cfg['storage_class']&1:
   assert copies[0]['size_bytes']==24 and copies[0]['source_hex']==wire_header.hex()
   if len(copies)==2:assert copies[1]['destination']==hex(USER+24)and copies[1]['source_hex']==packet[24:].hex()
  else:assert copies[0]['source_hex']==packet.hex()and copies[0]['size_bytes']==len(packet)
  for e in r['API_models']:assert not e['native_effects_executed'];models[e['symbol']]+=1
  assert not any(e['symbol']in ['header_copyout_model','destination_name_model','packing_model']for e in r['API_models'])
  assert len(r['opaque_hash_inputs'])==2 and r['opaque_hash_inputs'][0]['size_bytes']==36 and r['opaque_hash_inputs'][1]['size_bytes']==68
  assert not r['native_target_executed']and not r['hardware_PAC_executed']
 assert len(rows)==240 and len(qs)==15 and smt==30 and totals['source_visits_checked']==161608 and success==96 and first_failed==96 and second_failed==48 and totals['declared_copyout_calls_checked']==336 and totals['declared_private_copy_bytes_checked']==8704
 deps=['kernel_receive_delivery_source.json','kernel_receive_delivery_profiles.json','kernel_receive_delivery_proofs.json','recover_kernel_receive_delivery.py','probe_kernel_receive_delivery.py','prove_kernel_receive_delivery.py','replay_kernel_receive_delivery.py','replay_kernel_queue_receive.py','replay_kernel_queue_send.py','kernel_receive_delivery_sdk.c','kernel_receive_delivery_sdk.ll']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'profiles':len(rows),'source_obligations_rebuilt':len(qs),'SMT_files_checked':smt,'unique_captured_source_instructions':len(c['unique_source']),'complete_private_packet_copies':success,'first_copy_failures':first_failed,'second_copy_failures_with_header_prefix':second_failed,'declared_copyout_calls':336,'declared_private_copy_bytes':8704,'destination_reference_decrements':480,'send_once_decrements':240,'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'model_counts':dict(models),'outcome_counts':dict(outcomes),'storage_class_counts':dict(classes),'fresh_replay_cases':rows,'SDK_layout':{'command':cmd,'exit_code':cc.returncode,'LLVM_sha256':sha(ROOT/'kernel_receive_delivery_sdk.ll'),'reconstructed_types_are_not_original_headers':True},'source_receive_name_and_packing_executed_in_private_model':True,'native_target_executed':False,'native_IPC_executed':False,'native_user_delivery_established':False,'native_MAC_or_PAC_executed':False,'continuous_daemon_request_to_user_delivery_established':False,'native_port_right_ownership_established':False,'idb_mutated':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'kernel_receive_delivery_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
