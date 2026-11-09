#!/usr/bin/env python3
"""Rebuild original captures/proofs and independently check continuous queue cases.
O(source/artifact bytes + visits + compiler/solver resources) time;
O(collection metadata + one private CPU map + largest profile + DAGs) space.
No native queue, scheduler, port-right or authentication operation.
"""
import json,struct,subprocess
from collections import Counter
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
from recover_kernel_queue_send import recover,QUEUE,ENQUEUE
from prove_kernel_queue_send import obligations
from replay_kernel_queue_send import Replay
P=0x6500000000;M=P+0x12000;DEST=P+0x18000;Q=DEST+0x28;R=P+0x28000;N1=P+0x30000;N2=P+0x32000;STATS=P+0x2c000
def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def u64(b,o):return struct.unpack_from('<Q',b,o)[0]
def main():
 c=json.loads((ROOT/'kernel_queue_send_source.json').read_text());assert recover()==c;p=json.loads((ROOT/'kernel_queue_send_profiles.json').read_text());proof=json.loads((ROOT/'kernel_queue_send_proofs.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_kernel_queue_send.py')
 for obj in [c,p,proof]:
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 qs,counts=obligations();assert counts==proof['source_lift_counts'];smt=0
 for (name,q),row in zip(qs,proof['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
  for f,h in [('file','sha256'),('original_file','original_sha256')]:assert sha(ROOT/row[f])==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row[f])));assert s.check()==z3.unsat;smt+=1
 sdk=subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],capture_output=True,text=True,check=True).stdout.strip();cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',sdk,'-S','-emit-llvm','-O1','-Werror',str(ROOT/'kernel_queue_send_sdk.c'),'-o',str(ROOT/'kernel_queue_send_sdk.ll')];cc=subprocess.run(cmd,capture_output=True,text=True);assert cc.returncode==0,(cc.stdout,cc.stderr)
 image=Image();totals=Counter();models=Counter();kinds=Counter();rows=[];outcomes=Counter();enqueued=handed=declined=destroyed=0
 expected_errors={'full_poll':0x10000004,'kernel_full':0x1000000d,'kernel_full_poll':0x10000004,'wait_timeout':0x10000004,'wait_interrupted':0x10000007,'wait_restart':0x10000003}
 direct_cases={'direct','direct_aux','too_small_take','linear_combined'};retry_cases={'too_small_retry','linear_aux_too_large'}
 for j,r in enumerate(p['cases']):
  cpu=Replay(image,r);result=cpu.run();totals.update(result);rows.append({'index':j,'verified_counts':result});cfg=r['configuration'];name=cfg['case'];kinds[name]+=1;error=expected_errors.get(name,0);outcomes[hex(error)]+=1
  cuts=r['source_return_cuts'];qcuts=[e for e in cuts if e['pc']=='0xfffffe000bcc7250'];assert len(qcuts)==1 and int(qcuts[0]['X0'],16)==error,(j,name,qcuts)
  assert not any(e['symbol']=='queue_send_model'for e in r['API_models']);assert any(e['pc']==hex(QUEUE)for e in r['source_visits']);assert r['boundary']['kind']=='returned'and cpu.reg(0)==0
  by={}
  for e in r['API_models']:assert not e['native_effects_executed'];models[e['symbol']]+=1;by.setdefault(e['symbol'],[]).append(e)
  def args(n):return [[int(a,16)for a in e['arguments8']]for e in by.get(n,[])]
  q=bytes(cpu.u.mem_read(Q,0x20));receiver=bytes(cpu.u.mem_read(R+0x380,0xb0));assert q.hex()==r['queue_storage_hex']and receiver.hex()==r['receiver_storage_hex'];is_direct=name in direct_cases;is_retry=name in retry_cases;invalid=name=='invalid_waitq';inserted=not(error or is_direct or invalid)
  assert len(r['logical_data_signing'])==int(is_direct)
  if is_direct:
   handed+=1;assert u64(receiver,0x38)==M and u32(receiver,0x24)==cfg['sequence'];assert u32(q,8)==(cfg['sequence']+1)&0xffffffff and u16(q,0x10)==cfg['msgcount'];assert len(args('receiver_resume_model'))==1
   assert r['logical_data_signing'][0]['pointer']==hex(M)and int(r['logical_data_signing'][0]['modifier'],16)==((R+0x3b8)&0x0000ffffffffffff)|0x33ff000000000000
   assert u32(receiver,0x20)==(0x10004004 if name=='too_small_take'else 0)
  else:assert u32(q,8)==cfg['sequence']
  if is_retry:
   declined+=1;assert u32(receiver,0x20)==0x10004004 and u32(receiver,0x28)==36 and u32(receiver,0x2c)==cfg['aux_size']and u32(receiver,0x30)==0xabcdef12 and u64(receiver,0x38)==0 and u32(receiver,0x24)==0;assert len(args('receiver_resume_model'))==1 and len(args('identify_receiver_model'))==2
  if name=='non_receive_waiter':assert u32(receiver,0x20)==0 and u64(receiver,0x38)==0xa5a5a5a5 and len(args('receiver_resume_model'))==1
  if inserted:
   enqueued+=1;links=bytes(cpu.u.mem_read(M,16));assert links.hex()==r['reply_links_hex'];nodes=[N1,N2][:len(cfg['node_qos'])];ecuts=[e for e in cuts if e['pc']=='0xfffffe000bcc7ed4'];assert len(ecuts)==1;assert any(e['pc']==hex(ENQUEUE)for e in r['source_visits'])
   old=list(cfg['node_qos']);new=old[:];changed_all=True
   for k in reversed(range(len(old))):
    if cfg['message_qos']<=old[k]:changed_all=False;break
    new[k]=cfg['message_qos']
   assert int(ecuts[0]['X0'],16)==int(changed_all)
   assert u64(q,0)==(nodes[0]if nodes else M)and u64(links,0)==(nodes[0]if nodes else M)and u64(links,8)==(nodes[-1]if nodes else M)
   ring=nodes+[M]
   for k,node in enumerate(ring):b=bytes(cpu.u.mem_read(node,16));assert u64(b,0)==ring[(k+1)%len(ring)]and u64(b,8)==ring[(k-1)%len(ring)]
   for k,a in enumerate(nodes):assert bytes(cpu.u.mem_read(a+0x3e,1))[0]==new[k]and bytes(cpu.u.mem_read(a,0x40)).hex()==r['node_storage'][k]['bytes_hex']
   assert u16(q,0x10)==cfg['msgcount']+(0 if name=='wait_awakened'else 1)
  elif not is_direct:assert u16(q,0x10)==cfg['msgcount']+int(invalid)
  assert [a[:2]for a in args('message_destroy_model')]==([[M,1]]if error else[[M,0]]if invalid else[])
  destroyed+=bool(error or invalid);assert r['destination_counter']==cfg['object_refs']-int(bool(error))
  want_sent=cfg['initial_sent_counter']if error else(cfg['initial_sent_counter']+1)&((1<<64)-1);assert r['sent_counter']==want_sent==int.from_bytes(bytes(cpu.u.mem_read(STATS,8)),'little')
  for e in cuts:
   if e['pc']in ['0xfffffe000bcc7e34','0xfffffe000bcc7e48']:assert int(e['X0'],16)==36
   if e['pc']=='0xfffffe000bcc7e60':assert int(e['X0'],16)==8
  if args('identify_receiver_model'):assert all(a[:5]==[DEST+0x10,0,0,0x40,0]for a in args('identify_receiver_model'))
  if args('receiver_resume_model'):assert all(a[0]==R for a in args('receiver_resume_model'))
 assert len(rows)==146 and len(qs)==18 and smt==36 and totals['source_visits_checked']==34441
 deps=['kernel_queue_send_source.json','kernel_queue_send_profiles.json','kernel_queue_send_proofs.json','recover_kernel_queue_send.py','probe_kernel_queue_send.py','prove_kernel_queue_send.py','replay_kernel_queue_send.py','kernel_queue_send_sdk.c','kernel_queue_send_sdk.ll']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'profiles':len(rows),'source_obligations_rebuilt':len(qs),'SMT_files_checked':smt,'unique_captured_source_instructions':len(c['unique_source']),'source_queue_entries':len(rows),'original_enqueue_cases':enqueued,'direct_receiver_handoffs':handed,'too_large_retries':declined,'destruction_requests':destroyed,'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'model_counts':dict(models),'case_counts':dict(kinds),'queue_return_counts':dict(outcomes),'fresh_replay_cases':rows,'SDK_layout':{'command':cmd,'exit_code':cc.returncode,'LLVM_sha256':sha(ROOT/'kernel_queue_send_sdk.ll'),'reconstructed_types_are_not_original_headers':True},'continuous_caller_queue_path_executed_in_private_model':True,'native_target_executed':False,'native_IPC_executed':False,'native_queue_delivery_established':False,'native_MAC_or_PAC_executed':False,'continuous_request_to_send_established':False,'idb_mutated':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'kernel_queue_send_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'outcomes':dict(outcomes),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
