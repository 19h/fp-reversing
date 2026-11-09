#!/usr/bin/env python3
"""Original-source clock gates, tail, callback/value lookup and cache contracts.
O(lifted source+solver resources) time/space;30 s/query. All claims retain their
fixed phase, owner/frame and external ABI premises; no native APIs/PAC execute.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,TABLE
from recover_daemon_object_creation import sha,span
from prove_daemon_object_initialization import InitLift
from lskd_values_symbolic import part,mem,cell,resize

def obligations(c):
 c={'spans':c['spans']+[span('incoming_tag_save',0x100aee610,0x100aee618)]};F=0x6800050000;O=0x6800005000;OUT=F+0x3ca0;CACHE=0x1010c6840;REG=0x6800034000;A,B,R,C,T,K,I=z3.BitVecs('clock_A64 clock_B64 clock_return64 clock_cursor64 clock_tag64 clock_factor64 clock_index64',64);H,STATUS,PHASE=z3.BitVecs('clock_value32 clock_status32 clock_phase32',32);qs=[];counts={}
 def run(n,a,z,seeds=(),memory=()):
  v=InitLift(part(c,n,a,z))
  for reg,x in seeds:v.seed(reg,x)
  for at,nb,x in memory:mem(v,at,nb,x)
  v.run(n);counts[n]=v.count;return v
 def add(n,p):qs.append((n,p))
 incoming=run('incoming_tag',0x100aee610,0x100aee618,[('sp',F)],[(F+0x2a70,8,T)]);add('all_u64_incoming_tag_save',cell(incoming,F+0x2b50,8)!=T)
 first=run('first_gate',0x100bad4cc,0x100bad4fc,[('sp',F),('w22',0xb31e),('w23',0x5357)],[(F+0x29a0,8,TABLE),(F+0x3620,8,C),(F+0x2ab8,4,H)]);add('all_u32_first_record_gate',z3.Or(first.read('w10')!=z3.If(H==0x8b3dc651,z3.BitVecVal(0xc1c8,32),z3.BitVecVal(0xb31e,32)),first.read('x8')!=C-16))
 phase=run('second_phase',0x10087cb7c,0x10087cb8c,[('w23',0x5357)]);add('second_clock_phase7F4',phase.read('w22')!=0x7f4)
 second=run('second_status',0x10087cbe4,0x10087cc00,[('sp',F),('w22',0x7f4),('w23',0x5357),('w0',STATUS)],[(F+0x29a0,8,TABLE)]);add('all_int32_second_status_gate',z3.Or(second.read('w9')!=0,second.read('w8')!=z3.If(STATUS==0,z3.BitVecVal(0x5379,32),z3.BitVecVal(0x5357,32))))
 good=run('successful_seconds',0x100d2fa40,0x100d2fa50,[('w23',0x5357),('x21',OUT),('x30',TABLE)],[(OUT,4,H),(TABLE+0x5357*8,8,0x1009b2a54)]);add('all_u32_seconds_success_load',z3.Or(good.read('w9')!=H,good.read('w22')!=0x7f4))
 tail=run('tail',0x1009b2a54,0x1009b2a88,[('sp',F),('w22',0x7f4),('x19',O),('x20',T),('w9',H)],[(F+0x3620,8,C)]);add('all_u64_tag_cursor_and_tail_fields',z3.Or(tail.read('w8')!=0x471c,cell(tail,O+0x354,4)!=H,cell(tail,O+0x358,8)!=T,cell(tail,O+0x360,8)!=0,cell(tail,F+0x3620,8)!=C-656,cell(tail,F+0x344c,4)!=0))
 gate=run('callback_lookup',0x10064ffbc,0x10064ffd4,[('sp',F),('w8',0x471c),('w22',0x7f4),('x30',TABLE)],[(F+0x26c0,8,0x1010c67c0),(0x1010c67c0,8,R),(TABLE+0x7f4*8,8,0x1009d92d0)]);add('all_u64_postclock_callback_and_lock',z3.Or(gate.read('x19')!=0x1009d92d0,gate.read('x9')!=R,gate.read('w20')!=0x40c7,gate.read('w21')!=0x447c))
 lock=run('lock_gate',0x10064ffd4,0x10064fff8,[('x9',R),('w21',0x447c),('w10',0x443f),('w8',0x471c)]);add('all_u64_lock_presence_dispatch',lock.read('w8')!=z3.If(R==0,z3.BitVecVal(0x443f,32),z3.BitVecVal(0x447c,32)))
 query=run('query_gate',0x1009d92d0,0x1009d930c,[('sp',F),('w15',0x471c)],[(F+0x3588,8,R)]);add('all_u64_query_encoded_zero_partition',z3.Or(query.read('w10')!=0x1d17,query.read('w8')!=z3.If(R==0xe3b88695c0d52dbc,z3.BitVecVal(0x5f16,32),z3.BitVecVal(0x5f52,32))))
 count=run('count_gate',0x100963cc0,0x100963ce4,[('x14',0x1010ca2b0),('w13',0x471c),('w10',0x63fb),('w12',0x7aeb)],[(0x1010ca2b0,4,H)]);add('all_u32_inner_count_gate',count.read('w10')!=z3.If(H==0,z3.BitVecVal(0x7aeb,32),z3.BitVecVal(0x7aec,32)))
 pointer=run('pointer_gate',0x10094cbb8,0x10094cbd8,[('x16',R),('w10',0x7ccd)]);add('all_u64_inner_pointer_gate',pointer.read('w8')!=z3.If(R==0,z3.BitVecVal(0x7ccd,32),z3.BitVecVal(0x7cfd,32)))
 compare=run('key_compare',0x1008bb504,0x1008bb530,[('x13',A),('x9',B),('w12',0xadfe),('w6',0xa8c10),('w7',0x5508)]);u=lambda x:x&0xffffffff;delta=u((0xa8c10^(0xadfe<<4))+0x5508)^(7*(0xadfe^0xb58f));yes=0xadfe^delta;add('all_u64_exact_table_key_equality',compare.read('w12')!=z3.If(A==B,z3.BitVecVal(yes,32),z3.BitVecVal(0xadfe,32)))
 stride=run('table_stride',0x10095e94c,0x10095e950,[('x14',I)]);add('all_u64_table_stride32',stride.read('x13')!=I*32)
 step=run('scan_step',0x100839154,0x10083918c,[('w8',0xab17),('w15',0xffffd1b6),('w19',0xffff99f5),('w20',0x210),('w21',0x4723),('w23',1),('x14',I),('x11',B)]);add('all_u64_scan_increment_and_exhaustion',z3.Or(step.read('x14')!=I+1,step.read('w8')!=z3.If(I+1==B,z3.BitVecVal(0xab3f,32),z3.BitVecVal(0xab17,32))))
 found=run('scan_match_index',0x100b328c8,0x100b328cc,[('x8',F+0x344c),('w14',H)]);add('all_u32_matched_index_frame_store',cell(found,F+0x344c,4)!=H)
 for index in [0,1]:
  value=run('value_index'+str(index),0x1008f243c,0x1008f2448,[('sp',F),('x9',REG)],[(F+0x344c,4,index),(REG+index*32+8,8,R)]);add('all_u64_matched_value_plus8_index'+str(index),value.read('x9')!=R)
 saved=run('save_value',0x100c11a28,0x100c11a34,[('sp',F),('x9',R),('w8',PHASE)]);add('all_u64_lookup_value_frame_store',cell(saved,F+0x2ae8,8)!=R)
 status=run('save_status',0x1009512ac,0x1009512b8,[('sp',F),('x13',0x1010c9288),('w20',PHASE),('w10',H)]);add('all_u32_lookup_status_frame_store',z3.Or(cell(status,F+0x26b0,8)!=0x1010c9288,cell(status,F+0x3508,4)!=H))
 cache=run('cache_gate',0x100a42d88,0x100a42da4,[('sp',F),('w8',0x9e58),('w9',0x1c10)],[(F+0x21d0,8,CACHE),(CACHE,8,R)]);add('all_u64_cold_cache_presence_gate',z3.Or(cache.read('x0')!=R,cache.read('w9')!=z3.If(R==0,z3.BitVecVal(0x9e58,32),z3.BitVecVal(0x9e5c,32))))
 size=run('malloc36',0x1009c0140,0x1009c0148);add('cold_cache_source_malloc36',z3.Or(size.read('x0')!=36,size.read('x17')!=0x6aa4))
 publication=run('cache_publication',0x1009c014c,0x1009c0158,[('sp',F),('x20',CACHE),('x0',R)],[(F+0x29a0,8,TABLE)]);add('all_u64_source_cache_return_publication',z3.Or(cell(publication,CACHE,8)!=R,cell(publication,F+0x21d0,8)!=CACHE))
 S=F-0x70;CONSTANT=0x73d046208eaed1a6
 creator=run('creator_state',0x10043a334,0x10043a364,[('sp',S),('x16',T),('x8',K),('x23',0x1010c5040),('x26',0x1010c4670)],[(0x1010c4670,8,B)]);value=((T+S+8+B)^CONSTANT)*K;add('all_u64_creator_state_updates',z3.Or(cell(creator,0x1010c5040,8)!=value,cell(creator,0x1010c4670,8)!=value))
 acquire=run('acquire_state',0x10043e374,0x10043e3ac,[('sp',S),('x10',T),('x21',K),('x22',0x1010b66a8),('x24',0x1010c4670)],[(0x1010c4670,8,B)]);t=T+S+8+B;add('all_u64_acquire_state_updates',z3.Or(cell(acquire,0x1010b66a8,8)!=(t*K)^CONSTANT,cell(acquire,0x1010c4670,8)!=(t^CONSTANT)*K))
 cleanup=run('cleanup_state',0x1004424ec,0x10044251c,[('sp',S),('x10',T),('x20',K),('x22',0x1010b6738),('x24',0x1010c4670)],[(0x1010c4670,8,B)]);value=((T-S-8+B)^CONSTANT)*K;add('all_u64_cleanup_state_updates',z3.Or(cell(cleanup,0x1010b6738,8)!=value,cell(cleanup,0x1010c4670,8)!=value))
 return qs,counts,{'key_equality_true_index':hex(yes),'key_equality_false_index':'0xadfe','callback_query_zero64':'0xe3b88695c0d52dbc','state_xor_constant64':hex(CONSTANT)}
def main():
 c=json.loads((ROOT/'daemon_object_clock_contracts.json').read_text());qs,counts,derived=obligations(c);rows=[]
 for n,p in qs:
  a=ROOT/f'daemon_object_clock_{n}_original.smt2';b=ROOT/f'daemon_object_clock_{n}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());print(json.dumps({'proof':n,'result':answer}),flush=True);assert answer=='unsat',(n,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':n,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer})
 deps=['daemon_object_clock_contracts.json','prove_daemon_object_initialization.py','prove_daemon_registry_lookup.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'derived':derived,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_object_clock_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
