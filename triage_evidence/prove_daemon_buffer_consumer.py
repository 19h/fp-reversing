#!/usr/bin/env python3
"""Source-local buffer transform, publication and private-record obligations.
O(source instructions+256 source-lift cases) DAG time/space;30 s/query.
No target API or native PAC executes. Source array model is u32 little-endian.
"""
import json,hashlib
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,IMAGE,qword,POOL
from prove_daemon_prng_output import OutLift
from prove_daemon_context_transfer import CompareLift,MIX,COEFF
from lskd_values_symbolic import part,mem,cell,resize

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
class Words(OutLift):
 def __init__(self,c,D,A):super().__init__(c);self.D=D;self.array=A;self.read_addresses=[]
 def load(self,a,n):
  assert n==4;self.read_addresses.append(a);return z3.Select(self.array,z3.LShR(a-self.D,2))
 def store(self,a,n,v,pc):
  assert n==4;v=resize(v,32);self.stores.append({'pc':pc,'address':a,'size_bytes':n,'value':v});self.array=z3.Store(self.array,z3.LShR(a-self.D,2),v)
class ReadOnly(OutLift):
 def load(self,a,n):
  a=z3.simplify(a);assert z3.is_bv_value(a),('nonconcrete readonly address',a.sexpr());at=a.as_long();v=qword(at)if n==8 else int.from_bytes(IMAGE.read(at,n),'little');assert isinstance(v,int);return z3.BitVecVal(v,n*8)

def obligations(c,old):
 F,D,R=z3.BitVecs('consumer_frame64 consumer_buffer64 consumer_record64',64);C=z3.BitVec('consumer_counter32',32);CACHE=z3.BitVec('consumer_cached64',64);K=(R^MIX)*COEFF;k=z3.Extract(31,0,K);domain=z3.And(F&15==0,z3.UGE(F,0x6400000000),z3.ULE(F,0x640000f420),R==F+0xaf8);bufdomain=z3.And(D&3==0,z3.UGE(D,0x6500000000),z3.ULE(D,(1<<64)-513));qs=[];counts={};merged={'spans':c['spans']+old['spans']}
 def add(n,p,d=z3.BoolVal(True)):qs.append((n,z3.And(d,p)))
 def run(n,a,z,seeds=(),memory=(),cls=OutLift):
  v=cls(part(merged,n,a,z))
  for reg,value in seeds:v.seed(reg,value)
  for at,width,value in memory:mem(v,at,width,value)
  v.run(n);counts[n]=v.count;return v
 N=z3.BitVec('consumer_next_offset32',32);loop=run('loop_phase',0x1004093fc,0x100409440,[('sp',F),('w10',N),('w9',0x3170)])
 add('loop_to_consumer_phase',loop.read('w10')!=0xb61631af,domain)
 guard=run('publication_guard',0x100315438,0x10031546c,[('sp',F),('w10',loop.read('w10')),('x15',0x1010c8278)],[(0x1010c8278,8,D),(F+0x1f0,8,0x1010c8268)])
 add('all_u64_buffer_alignment_gate',guard.equal!=((D&3)==0),domain);add('publication_phase_and_cache_address',z3.Or(guard.read('w8')!=0x8a9b8560,guard.read('x12')!=0x1010c8268),domain)
 publish=run('publication',0x100315478,0x100315488,[('sp',F),('x9',D),('x12',0x1010c8268)],[(F+0x1e8,8,0x1010c67d4)])
 add('pointer_and_255_stores',z3.Or(cell(publish,0x1010c8268,8)!=D,cell(publish,0x1010c67d4,4)!=255),domain)
 A=z3.Array('consumer_initial_words',z3.BitVecSort(64),z3.BitVecSort(32));v=Words(part(c,'normalization',0x100315488,0x100315648),D,A);v.seed('x9',D);v.run('normalization');counts['normalization']=v.count;assert len(v.stores)==16
 formulas=[]
 for j,row in enumerate(v.stores):
  original=z3.Select(A,z3.BitVecVal(4*j,64));index=z3.ZeroExt(32,(z3.LShR(original,1)&31)*2);reference=original|(~z3.Select(A,index)<<16);formulas.extend([row['address']!=D+j*16,row['value']!=reference])
 add('all_arrays_16_source_write_formula',z3.Or(*formulas),bufdomain)
 ranges=[z3.Or((a-D)&3!=0,z3.UGT(a-D,248))for a in v.read_addresses];add('all_arrays_read_bounds',z3.Or(*ranges),bufdomain)
 add('all_arrays_low16_preserved',z3.Or(*[z3.Extract(15,0,row['value'])!=z3.Extract(15,0,z3.Select(A,z3.BitVecVal(4*j,64)))for j,row in enumerate(v.stores)]),bufdomain)
 add('all_arrays_only_sets_bits',z3.Or(*[(row['value']&z3.Select(A,z3.BitVecVal(4*j,64)))!=z3.Select(A,z3.BitVecVal(4*j,64))for j,row in enumerate(v.stores)]),bufdomain)
 X,T=z3.BitVecs('consumer_update_x32 consumer_lookup_t32',32);g=lambda x,t:x|(~t<<16)
 add('scalar_update_idempotence',g(g(X,T),T)!=g(X,T))
 add('scalar_selector_invariant',((z3.LShR(g(X,T),1)&31)!=(z3.LShR(X,1)&31)))
 pack=run('counter_pack',0x100315694,0x1003156e8,[('sp',F),('x29',R+0xd8),('w19',C),('w8',0x8a9b8560)],[(F+0x120,8,K)])
 add('counter_record_zero_equality',z3.Or(cell(pack,R,4)-k!=0,cell(pack,R+8,8)-K!=z3.ZeroExt(32,C),(cell(pack,R+0x20,8)^K)!=0),domain)
 body=CompareLift(part(merged,'composed_comparison',0x10041a5e0,0x10041a66c));body.memory=pack.memory.copy();body.seed('x0',R);body.overrides={(0x10041a60c,'x8'):R^MIX};body.run('composed_comparison');counts['composed_comparison']=body.count
 add('all_u32_counter_routes',cell(body,R+0x10,4)!=z3.If(C==0,z3.BitVecVal(0x16e5,32),z3.BitVecVal(0x16f4,32)),domain)
 OUT=z3.BitVec('consumer_failure_output64',64);bad=run('publication_failure',0x100315764,0x10031578c,[('sp',F),('w10',0xb61631af)],[(F+0x28,8,OUT)])
 add('failure_raw_status_and_route',z3.Or(cell(bad,OUT,4)!=0x74c29dee,bad.read('w9')!=0x1bcb),domain)
 base=run('reader_pool_base',0x10008cf88,0x10008cf90);add('reader_pool_base_identity',base.read('x2')!=POOL)
 upper=z3.BitVec('consumer_reader_upper24',24);cases=[]
 for low in range(256):
  reader=ReadOnly(part(c,'reader_materializer',0x10008cfac,0x10008d008));reader.seed('sp',F);reader.seed('x2',POOL);reader.seed('w11',z3.Concat(upper,z3.BitVecVal(low,8)));reader.run('reader_materializer');cases.append(reader.read('x6')!=0x1010c8268)
 counts['reader_materializer_per_case']=reader.count;counts['reader_materializer_cases']=256
 add('reader_all_u32_materializes_cache_cell',z3.Or(*cases),domain)
 return qs,counts

def main():
 c=json.loads((ROOT/'daemon_buffer_consumer_contracts.json').read_text());old=json.loads((ROOT/'daemon_context_transfer_contracts.json').read_text());qs,counts=obligations(c,old);rows=[]
 for name,predicate in qs:
  original=ROOT/f'daemon_buffer_consumer_{name}_original.smt2';normalized=ROOT/f'daemon_buffer_consumer_{name}.smt2';s=z3.Solver();s.add(predicate);original.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(predicate));result=str(s.check());assert result=='unsat',(name,result);normalized.write_text(s.to_smt2());rows.append({'name':name,'original_file':original.name,'original_sha256':sha(original),'file':normalized.name,'sha256':sha(normalized),'result':result});print(json.dumps({'proof':name,'result':result}),flush=True)
 witnesses=[]
 for name,predicate in qs:
  if name in ['all_arrays_16_source_write_formula','all_u32_counter_routes','all_u64_buffer_alignment_gate']:
   s=z3.Solver();s.add(predicate.arg(0));assert str(s.check())=='sat';witnesses.append({'proof':name,'premise_result':'sat'})
 deps=['daemon_buffer_consumer_contracts.json','daemon_context_transfer_contracts.json','daemon_context_transfer_proofs.json','prove_daemon_context_transfer.py','prove_daemon_prng_output.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'premise_witnesses':witnesses,'comparison_key_premise':'F+0x120 equals the record48 key under the earlier source constructor; use frozen helper prekey identity at41A60C.','reader_domain':'All 256 low bytes with a symbolic upper24; source pool base and original encoded qwords/banks.','normalization_array_domain':'u32 words; all source read offsets 0..248, aligned4; writes at0..240 stride16.','idempotence_composition':'The all-array source formula and low16 invariance keep every lookup low16 and selector unchanged. scalar_update_idempotence then applies to each of the sixteen distinct destinations; no full two-sweep SMT conclusion is claimed.','solver_diagnostics':[{'query':'full two-sweep source idempotence','result':'unknown','timeout_seconds':30,'retained_query_file':'daemon_buffer_consumer_two_sweep_timeout.smt2','retained_query_sha256':sha(ROOT/'daemon_buffer_consumer_two_sweep_timeout.smt2'),'resolved_by':'source-formula equivalence plus low16/selector invariance and scalar update idempotence'}],'z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_buffer_consumer_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'premise_witnesses':len(witnesses),'counts':counts}),flush=True)
if __name__=='__main__':main()
