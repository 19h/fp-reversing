#!/usr/bin/env python3
"""Rebuild source/proofs and independently replay source bytes and all effects.
O(source/artifact bytes + visits + solver/compiler resources) time;
O(KC metadata + one private CPU map + largest profile + solver DAGs) space.
All helper effects, hash returns and dispatcher outputs are private models.
"""
import json,struct,subprocess
from collections import Counter
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
from recover_kernel_reply_send import recover
from prove_kernel_reply_send import obligations
from replay_kernel_reply_send import Replay
import z3
P=0x6500000000;REQ=P+0x10000;REPLY=P+0x12000;DEST=P+0x18000;INPORT=P+0x1a000
SPECIAL={0x10000003,0x10000004,0x10000007,0x1000000d}
def main():
 c=json.loads((ROOT/'kernel_reply_send_source.json').read_text());assert recover()==c
 p=json.loads((ROOT/'kernel_reply_send_profiles.json').read_text());proof=json.loads((ROOT/'kernel_reply_send_proofs.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_kernel_reply_send.py')
 for obj in [c,p,proof]:
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 qs,counts=obligations();assert counts==proof['source_lift_counts'];smt=0
 for (name,q),r in zip(qs,proof['proofs'],strict=True):
  assert name==r['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   assert sha(ROOT/r[f])==r[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/r[f])));assert s.check()==z3.unsat;smt+=1
 sdk=subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],capture_output=True,text=True,check=True).stdout.strip();cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',sdk,'-S','-emit-llvm','-O1','-Werror',str(ROOT/'kernel_reply_send_sdk.c'),'-o',str(ROOT/'kernel_reply_send_sdk.ll')];cc=subprocess.run(cmd,capture_output=True,text=True);assert cc.returncode==0,(cc.stdout,cc.stderr)
 image=Image();totals=Counter();models=Counter();kinds=Counter();rows=[];template=bytes.fromhex(c['kernel_template']['bytes_hex']);cleanups=lastrefs=hashes=queuecalls=0
 for j,r in enumerate(p['cases']):
  cpu=Replay(image,r);result=cpu.run();totals.update(result);rows.append({'index':j,'verified_counts':result});cfg=r['configuration'];kind=cfg['kind'];kinds[kind]+=1;events=r['API_models'];by={}
  for e in events:models[e['symbol']]+=1;by.setdefault(e['symbol'],[]).append(e)
  def args(name):return [[int(x,16)for x in e['arguments8']]for e in by.get(name,[])]
  assert r['boundary']['kind']=='returned' and not r['native_target_executed'] and not r['hardware_PAC_executed']
  null=kind=='reply' and cfg['null_reply'];status=0 if null else (cfg['queue_status']if kind=='cleanup' or cfg['dest_low3'] else 0x10000003);mode=cfg.get('reply_mode',1);cleanup=not null and (status==0x10000003 or(status!=0 and mode!=0));assert cpu.reg(0)==(0 if cleanup else status),(j,cfg,cpu.reg(0),status)
  assert r['destination_counter']==cfg['object_refs']-int(cleanup)==int.from_bytes(bytes(cpu.u.mem_read(DEST+4,4)),'little')
  assert args('message_destroy_model')==([[REPLY,1]+args('message_destroy_model')[0][2:]]if cleanup else[])
  assert [a[0]for a in args('last_object_reference_model')]==([DEST]if cleanup and cfg['object_refs']==1 else[])
  assert [a[0]for a in args('send_failure_helper_model')]==([REPLY]if not null and status in SPECIAL else[])
  cleanups+=cleanup;lastrefs+=cleanup and cfg['object_refs']==1
  if kind=='reply':
   assert [a[:2]for a in args('kernel_object_dispatch_model')]==[[INPORT,REQ]]
   dispatch=by['kernel_object_dispatch_model'][0];cut=dispatch['before_source_visit_index']
   assert not any(REQ<=int(e['address'],16)<REQ+0x100 for e in r['source_reads']if e['source_visit_index']>=cut)
   if null:assert len(events)==1 and not r['opaque_hash_inputs']
   else:
    hh=r['opaque_hash_inputs'];assert len(hh)==2;hashes+=2;header=int(r['reply_header'],16);canonical=struct.pack('<IIQQIII',0x12&0x80001f1f,44,DEST,0,0,4901,0)
    assert bytes.fromhex(hh[0]['bytes_hex'])==canonical and hh[0]['size_bytes']==36 and int(hh[0]['seed'],16)==(REPLY&0x0000ffffffffffff)|0x3409000000000000 and hh[0]['mode']==0
    assert hh[1]['bytes_hex']==template.hex()and hh[1]['size_bytes']==68 and int(hh[1]['seed'],16)==0x123456789abcdef0 and hh[1]['mode']==1
    assert r['reply_signature_word']=='98badcfe'and bytes(cpu.u.mem_read(REPLY+0x38,4)).hex()=='98badcfe'and r['reply_trailer']['bytes_hex']==template.hex()
    expected_queue=[[DEST+0x28,REPLY,cfg['effective_options'],cfg['inherited_scalar']]]if cfg['dest_low3']else[]
    assert [a[:4]for a in args('queue_send_model')]==expected_queue;queuecalls+=bool(expected_queue)
    assert len(args('send_preflight_model'))==int(cfg['route']=='A')
  else:assert not r['opaque_hash_inputs']and not args('kernel_object_dispatch_model')and not args('queue_send_model')
 assert len(rows)==138 and len(qs)==14 and smt==28 and totals['source_visits_checked']==16520 and cleanups==108 and lastrefs==54 and hashes==224 and queuecalls==96
 deps=['kernel_reply_send_source.json','kernel_reply_send_profiles.json','kernel_reply_send_proofs.json','recover_kernel_reply_send.py','probe_kernel_reply_send.py','prove_kernel_reply_send.py','replay_kernel_reply_send.py','kernel_reply_send_sdk.c','kernel_reply_send_sdk.ll']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'profiles':len(rows),'source_obligations_rebuilt':len(qs),'SMT_files_checked':smt,'unique_captured_source_instructions':len(c['unique_source']),'queue_request_models':queuecalls,'opaque_hash_return_models':hashes,'caller_destruction_requests':cleanups,'last_reference_requests':lastrefs,'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'model_counts':dict(models),'kind_counts':dict(kinds),'fresh_replay_cases':rows,'SDK_layout':{'command':cmd,'exit_code':cc.returncode,'LLVM_sha256':sha(ROOT/'kernel_reply_send_sdk.ll'),'reconstructed_types_are_not_original_headers':True},'native_target_executed':False,'native_IPC_executed':False,'native_queue_delivery_established':False,'native_MAC_or_PAC_executed':False,'continuous_request_to_send_established':False,'idb_mutated':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'kernel_reply_send_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'models':dict(models),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
