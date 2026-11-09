#!/usr/bin/env python3
"""Rebuild source/proofs; fresh kernel/daemon replay with an independent packet oracle.
O(source/artifact bytes + visits/effects + compiler/solver resources) time;
O(collection metadata + one private CPU map + largest profile + DAGs) space.
Namespace/VM/copyout effects and cross-image transfers are declared models.
"""
import json,struct,subprocess
from collections import Counter
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
from recover_rpc502_receive_bridge import recover
from prove_rpc502_receive_bridge import obligations
from replay_rpc502_receive_bridge import Replay
from replay_rpc502_bridge_daemon import Replay as DaemonReplay,View
P=0x6500000000;USER=P+0x50000;OOL=P+0x70000;D=P+0x18000;MAP=P+0x4a000;COPY=P+0x68000;REPLY=P+0x80000
def main():
 c=json.loads((ROOT/'rpc502_receive_bridge_source.json').read_text());assert recover()==c;k=json.loads((ROOT/'rpc502_receive_bridge_profiles.json').read_text());d=json.loads((ROOT/'rpc502_receive_bridge_daemon_profiles.json').read_text());proof=json.loads((ROOT/'rpc502_receive_bridge_proofs.json').read_text());assert k['generator_sha256']==sha(ROOT/'probe_rpc502_receive_bridge.py')and d['generator_sha256']==sha(ROOT/'probe_rpc502_bridge_daemon.py')
 for obj in [c,k,d,proof]:
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 qs,counts=obligations();assert counts==proof['source_lift_counts'];smt=0
 for(name,q),r in zip(qs,proof['proofs'],strict=True):
  assert name==r['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
  for f,h in [('file','sha256'),('original_file','original_sha256')]:assert sha(ROOT/r[f])==r[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/r[f])));assert s.check()==z3.unsat;smt+=1
 sdk=subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],capture_output=True,text=True,check=True).stdout.strip();cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',sdk,'-S','-emit-llvm','-O1','-Werror',str(ROOT/'rpc502_receive_bridge_sdk.c'),'-o',str(ROOT/'rpc502_receive_bridge_sdk.ll')];cc=subprocess.run(cmd,capture_output=True,text=True);assert cc.returncode==0,(cc.stdout,cc.stderr)
 image=Image();view=View();kt=Counter();dt=Counter();outcomes=Counter();scenarios=Counter();rows=[];accepted=rejected=expanded=bodyerrors=0
 for j,(r,dr)in enumerate(zip(k['cases'],d['cases'],strict=True)):
  cfg=r['configuration'];n=cfg['length'];extent=cfg['copy_extent'];mapped=cfg['map_result']==0 and cfg['allocate_result']==0;address=OOL if mapped else 0;delivered_extent=extent if mapped else 0;status=0 if mapped else 0x1000500c if cfg['map_result']==5 else 0x1000440c;scenarios[cfg['case']]+=1;outcomes[hex(status)]+=1;bodyerrors+=bool(status)
  cpu=Replay(image,r);kc=cpu.run();kt.update(kc);assert cpu.reg(0)==status and r['boundary']['kind']=='returned'
  tail=bytes.fromhex('0000000001000000')+struct.pack('<IQQQ',n,0x100000c,0,1);packet=struct.pack('<6I',0x80001112,80,0x203,0x107,0,502)+struct.pack('<IQII',1,address,0x01000101,delivered_extent)+tail;assert len(packet)==80;trailer=bytearray(68);struct.pack_into('<5I',trailer,0,0,68,0xffffffff,0,1);struct.pack_into('<Q',trailer,52,cfg['port_context']);packet+=trailer;expected=packet+bytes([0xa5])*(4096-len(packet));assert bytes(cpu.u.mem_read(USER,4096))==expected and r['private_user_buffer_hex']==expected.hex(),(j,cfg)
  payload=b'/tmp/fp'+b'A'*(n-8)+b'\0'+bytes(extent-n);expected_ool=payload if mapped else bytes([0xa5])*extent;assert bytes(cpu.u.mem_read(OOL,extent))==expected_ool and r['mapped_payload_hex']==expected_ool.hex()
  assert r['destination_object_refs']==1 and r['destination_send_refs']==0 and r['reply_object_refs']==2
  events={}
  for e in r['API_models']:assert not e['native_effects_executed'];events.setdefault(e['symbol'],[]).append(e)
  alloc=events.get('VM_receiver_allocate_model',[]);over=events.get('VM_overwrite_model',[]);direct=events.get('VM_copyout_model',[]);discard=events.get('VM_copy_discard_model',[]);dealloc=events.get('VM_region_deallocate_model',[])
  if cfg['copy_type']==3:assert len(direct)==1 and not alloc and not over;args=[int(x,16)for x in direct[0]['arguments8']];assert args[0]==MAP and args[2:5]==[COPY,extent,1]
  else:
   assert len(alloc)==1 and not direct;args=[int(x,16)for x in alloc[0]['arguments8']];assert args[0]==MAP and args[2:4]==[16384,0x14000000];assert len(over)==int(cfg['allocate_result']==0)
   if over:assert [int(x,16)for x in over[0]['arguments8']][:5]==[MAP,OOL,COPY,extent,0]
  assert len(discard)==int(not mapped)and len(dealloc)==int(cfg['case']=='entry_overwrite_error')
  if dealloc:assert [int(x,16)for x in dealloc[0]['arguments8']][:3]==[MAP,OOL,16384]
  assert any(e['pc']=='0xfffffe000bdd148c'for e in r['source_visits'])and any(e['pc']=='0xfffffe000bcc5564'for e in r['source_visits']);assert len(r['completion_snapshots'])==1;record=bytes.fromhex(r['completion_snapshots'][0]['bytes_hex']);assert struct.unpack_from('<3I',record)==(80,68,0)
  assert dr['configuration']['kernel_case_index']==j and dr['initial_private_fixtures'][0]['bytes_hex']==r['private_user_buffer_hex']and dr['initial_private_fixtures'][1]['bytes_hex']==r['mapped_payload_hex'];dcpu=DaemonReplay(view,dr);dc=dcpu.run();dt.update(dc);compatible=mapped and extent==n
  if compatible:
   accepted+=1;assert dr['boundary']['kind']=='before_application';args=[int(x,16)for x in dr['application_arguments8']];assert args[:6]==[0x107,OOL,n,0x100000c,0,1]and args[7]==REPLY+0x44 and dr['audit_argument_hex']==bytes(32).hex();assert [int(x,16)for x in dr['application_stack_arguments5']]==[REPLY+0xcc,REPLY+0x1c,REPLY+0x178,REPLY+0x2c,REPLY+0x17c]
  else:
   rejected+=1;expanded+=int(mapped);assert dr['boundary']['kind']=='guard_error'and dr['boundary']['detail']['error_signed']==-300
  assert not any(OOL<=int(e['address'],16)<OOL+0x4000 for e in dr['source_reads']);rows.append({'index':j,'kernel_counts':kc,'daemon_counts':dc,'kernel_result':hex(status),'MIG_application_boundary_reached':compatible})
 assert len(rows)==112 and len(qs)==18 and smt==36 and accepted==32 and rejected==80 and expanded==16 and bodyerrors==64 and kt['source_visits_checked']==108488 and dt['source_visits_checked']==2992 and kt['declared_private_copy_bytes_checked']==16576 and kt['namespace_VM_effect_models_checked']==384 and kt['declared_namespace_VM_patch_bytes_checked']==2952
 deps=['rpc502_receive_bridge_source.json','rpc502_receive_bridge_profiles.json','rpc502_receive_bridge_daemon_profiles.json','rpc502_receive_bridge_proofs.json','recover_rpc502_receive_bridge.py','probe_rpc502_receive_bridge.py','probe_rpc502_bridge_daemon.py','prove_rpc502_receive_bridge.py','replay_rpc502_receive_bridge.py','replay_rpc502_bridge_daemon.py','rpc502_receive_bridge_sdk.c','rpc502_receive_bridge_sdk.ll']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'kernel_cases':len(rows),'daemon_guard_cases':len(rows),'source_obligations_rebuilt':len(qs),'SMT_files_checked':smt,'captured_kernel_instructions':len(c['unique_source']),'captured_daemon_guard_instructions':len(c['daemon_guard']['instructions']),'MIG_application_boundaries':accepted,'MIG_type_errors':rejected,'kernel_success_extent_expansion_rejections':expanded,'kernel_VM_body_errors':bodyerrors,'SDK_compile_exit':0},'independent_kernel_A64_totals':dict(kt),'independent_daemon_A64_totals':dict(dt),'kernel_result_counts':dict(outcomes),'scenario_counts':dict(scenarios),'fresh_replay_cases':rows,'SDK_layout':{'command':cmd,'exit_code':cc.returncode,'LLVM_sha256':sha(ROOT/'rpc502_receive_bridge_sdk.ll'),'reconstructed_private_types':True},'native_target_executed':False,'native_IPC_executed':False,'native_VM_or_namespace_effects_executed':False,'native_framework_forwarding_established':False,'native_application_execution_established':False,'complete_FairPlay_round_trip_established':False,'idb_mutated':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'rpc502_receive_bridge_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'kernel_A64':dict(kt),'daemon_A64':dict(dt),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
