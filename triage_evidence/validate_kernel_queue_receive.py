#!/usr/bin/env python3
"""Rebuild source/proofs; independently verify state transfer and fresh CPU replay.
O(artifact/source bytes + private-map cases + visits + solver/compiler resources)
time, O(collection metadata + two private maps + largest profile + DAGs) space.
No native scheduling, authentication, IPC, right conversion or user copyout.
"""
import json,struct,subprocess
from collections import Counter
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
from recover_kernel_queue_receive import recover
from prove_kernel_queue_receive import obligations
from replay_kernel_queue_receive import Replay
P=0x6500000000;SIZE=0x100000;D=P+0x18000;Q=D+0x28;RX=P+0x38000;STATS=P+0x40000
def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def u64(b,o):return struct.unpack_from('<Q',b,o)[0]
def memory(fixtures):
 ram=bytearray(SIZE)
 for e in fixtures:a=int(e['address'],16)-P;b=bytes.fromhex(e['bytes_hex']);assert 0<=a<=a+len(b)<=SIZE;ram[a:a+len(b)]=b
 return ram
def main():
 c=json.loads((ROOT/'kernel_queue_receive_source.json').read_text());assert recover()==c;p=json.loads((ROOT/'kernel_queue_receive_profiles.json').read_text());proof=json.loads((ROOT/'kernel_queue_receive_proofs.json').read_text());up=json.loads((ROOT/'kernel_queue_send_profiles.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_kernel_queue_receive.py')
 for obj in [c,p,proof]:
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 qs,counts=obligations();assert counts==proof['source_lift_counts'];smt=0
 for (name,q),row in zip(qs,proof['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
  for f,h in [('file','sha256'),('original_file','original_sha256')]:assert sha(ROOT/row[f])==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row[f])));assert s.check()==z3.unsat;smt+=1
 sdk=subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],capture_output=True,text=True,check=True).stdout.strip();cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',sdk,'-S','-emit-llvm','-O1','-Werror',str(ROOT/'kernel_queue_receive_sdk.c'),'-o',str(ROOT/'kernel_queue_receive_sdk.ll')];cc=subprocess.run(cmd,capture_output=True,text=True);assert cc.returncode==0,(cc.stdout,cc.stderr)
 image=Image();totals=Counter();kinds=Counter();models=Counter();states=Counter();rows=[];taken=peeked=consumer=transfers=0
 empty_states={'poll':0x10004003,'set_poll':0x10004003,'invalid':0x10004006,'wait_timeout':0x10004003,'wait_interrupted':0x10004005,'wait_restart':0x10004006,'set_timeout':0x10004003,'set_interrupted':0x10004005,'block_timeout':0x10004003,'block_interrupted':0x10004005,'block_restart':0x10004006}
 for j,r in enumerate(p['cases']):
  cfg=r['configuration'];prior=up['cases'][cfg['upstream_index']];prefix=prior['initial_private_fixtures']+[{'address':e['address'],'bytes_hex':e['after_hex']}for e in prior['source_writes']];assert r['initial_private_fixtures'][:len(prefix)]==prefix;transfers+=1
  initial=memory(r['initial_private_fixtures']);before=initial[Q-P:Q-P+0x20];receiver=int(r['receiver'],16);old_receiver=initial[receiver-P+0x380:receiver-P+0x430];old_counter=u64(initial,STATS-P)
  if r['kind']=='queued':assert before.hex()==prior['queue_storage_hex']
  cpu=Replay(image,r);result=cpu.run();totals.update(result);rows.append({'index':j,'verified_counts':result});kinds[r['kind']]+=1
  for e in r['API_models']:assert not e['native_effects_executed'];models[e['symbol']]+=1
  q=bytes(cpu.u.mem_read(Q,0x20));rr=bytes(cpu.u.mem_read(receiver+0x380,0xb0));assert q.hex()==r['queue_storage_hex']and rr.hex()==r['receiver_storage_hex'];state=u32(rr,0x20);states[hex(state)]+=1;assert not r['native_target_executed']and not r['hardware_PAC_executed']
  if r['kind']=='queued':
   head=u64(before,0);ring=[];node=head
   while node not in ring:
    assert len(ring)<3;ring.append(node);node=u64(initial,node-P)
   assert node==head and head!=0;peek=cfg['case']in ['small_peek','set_peek'];assert cpu.reg(0)==10 and r['boundary']['kind']=='returned';cuts=[e for e in r['source_return_cuts']if e['pc']=='0xfffffe000bcc8408'];assert len(cuts)==1 and int(cuts[0]['X0'],16)==10
   assert len(r['logical_data_signing'])==int(not peek)
   if peek:
    peeked+=1;assert q==before and state==0x10004004 and u64(rr,0x38)==0 and u32(rr,0x24)==0 and u32(rr,0x28)==36 and u32(rr,0x2c)==u16(initial,head-P+0x30)and u32(rr,0x30)==u32(before,0xc);assert r['received_counter']==old_counter
    for node in ring:assert bytes(cpu.u.mem_read(node,16))==initial[node-P:node-P+16]
    hh=r['opaque_hash_inputs'];assert len(hh)==2 and hh[0]['size_bytes']==36 and hh[1]['size_bytes']==68 and hh[0]['mode']==0 and hh[1]['mode']==1 and int(hh[0]['seed'],16)==(head&0x0000ffffffffffff)|0x3409000000000000 and int(hh[1]['seed'],16)==0x123456789abcdef0
    assert sum(e['symbol']=='message_object_validation_model'for e in r['API_models'])==1
   else:
    taken+=1;assert u64(q,0)==(ring[1]if len(ring)>1 else 0)and bytes(cpu.u.mem_read(head,16))==bytes(16);assert u16(q,0x10)==u16(before,0x10)-1 and u32(q,8)==(u32(before,8)+1)&0xffffffff;assert u64(rr,0x38)==head and u32(rr,0x24)==u32(before,8)and state==(0x10004004 if cfg['case']=='small_take'else 0);assert r['received_counter']==(old_counter+1)&((1<<64)-1)
    remain=ring[1:]
    for k,node in enumerate(remain):b=bytes(cpu.u.mem_read(node,16));assert u64(b,0)==remain[(k+1)%len(remain)]and u64(b,8)==remain[(k-1)%len(remain)]
    assert not r['opaque_hash_inputs']
   assert u32(q,0xc)==u32(before,0xc)and u16(q,0x12)==u16(before,0x12)
  elif r['kind']=='empty':
   assert state==empty_states[cfg['case']]and u64(rr,0x38)==0 and u64(q,0)==0 and u16(q,0x10)==0 and r['received_counter']==old_counter
   expected_raw=10 if cfg['case']in ['poll','set_poll']else 3 if cfg['case']=='invalid'else cfg.get('block_result',cfg['wait_result']);assert cpu.reg(0)==expected_raw
  else:
   consumer+=1;assert r['boundary']['kind']=='consumer_cut'and rr==old_receiver and q==before and not r['source_writes']and not r['API_models'];message=u64(old_receiver,0x38);assert message!=0 and len(r['logical_data_authentication'])==1
   if r['kind']=='user_fields':assert cpu.reg(0)==u32(old_receiver,0x20)and cpu.reg(23)==message and cpu.reg(21)==u64(old_receiver,0x10)
   else:assert cpu.reg(27)==u32(old_receiver,0x20)and cpu.reg(22)==message
 assert len(rows)==373 and len(qs)==21 and smt==42 and totals['source_visits_checked']==49588 and taken==196 and peeked==102 and consumer==64 and transfers==373
 deps=['kernel_queue_receive_source.json','kernel_queue_receive_profiles.json','kernel_queue_receive_proofs.json','recover_kernel_queue_receive.py','probe_kernel_queue_receive.py','prove_kernel_queue_receive.py','replay_kernel_queue_receive.py','replay_kernel_queue_send.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','kernel_queue_receive_sdk.c','kernel_queue_receive_sdk.ll']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'profiles':len(rows),'source_obligations_rebuilt':len(qs),'SMT_files_checked':smt,'unique_captured_source_instructions':len(c['unique_source']),'state_transfer_prefixes_checked':transfers,'queued_receive_cases':kinds['queued'],'dequeued_messages':taken,'large_message_preservations':peeked,'source_handoff_consumer_components':consumer,'empty_receive_cases':kinds['empty'],'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'model_counts':dict(models),'kind_counts':dict(kinds),'state_counts':dict(states),'fresh_replay_cases':rows,'SDK_layout':{'command':cmd,'exit_code':cc.returncode,'LLVM_sha256':sha(ROOT/'kernel_queue_receive_sdk.ll'),'reconstructed_types_are_not_original_headers':True},'source_produced_state_transfer_established_in_private_model':True,'native_target_executed':False,'native_IPC_executed':False,'native_receiver_execution_established':False,'native_MAC_or_PAC_executed':False,'continuous_request_to_user_delivery_established':False,'idb_mutated':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'kernel_queue_receive_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
