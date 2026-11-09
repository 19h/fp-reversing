#!/usr/bin/env python3
"""Source-local self-text range, floor-log2 and encoded window obligations.
O(source instructions+64-bit log expression) DAG time/space;30 s/query.
Preferred-image addresses and abstract fixups; no native target/PAC executes.
"""
import json,hashlib
from pathlib import Path
import z3
from daemon_receive_tools import ROOT
from daemon_global_state_lift import GlobalLift
from lskd_values_symbolic import part,mem,cell
MASK64=(1<<64)-1

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def floorlog(v):
 n=z3.BitVecVal(MASK64,64)
 for j in range(64):n=z3.If(z3.Extract(j,j,v)==1,z3.BitVecVal(j,64),n)
 return n

def obligations(c):
 S,P,Q,V,N,D=z3.BitVecs('window_section_size64 window_section_start64 window_selection64 window_v64 window_log64 window_delta64',64);F=z3.BitVec('window_frame64',64);qs=[];counts={};KO=0xaca72517860a6000;KOFF=0x34936dc72afd2f98;KADDR=0x12af5504870a589f;KMASK=0xfff0c012a7a730ec;KD=0xe2c06c277e3e38;KPRE=0x840204b3d6b78667
 def run(name,a,z,seeds=(),memory=()):
  v=GlobalLift(part(c,name,a,z))
  for reg,value in seeds:v.seed(reg,value)
  for at,n,value in memory:mem(v,at,n,value)
  v.run(name);counts[name]=v.count;return v
 def add(name,predicate,domain=z3.BoolVal(True)):qs.append((name,z3.And(domain,predicate)))
 B,SEG,HEAD,OFF,SEGVA,ADDR=z3.BitVecs('window_runtime_base64 window_segment_command64 window_header_base64 window_section_offset64 window_segment_vmaddr64 window_section_addr64',64)
 pub=run('section_publication',0x10031ed34,0x10031ed64,[('x16',HEAD),('x3',OFF),('x12',B),('x15',SEG),('w11',0x8a9b8560)],[(SEG+24,8,SEGVA),(HEAD+OFF+32,8,ADDR),(HEAD+OFF+40,8,S)])
 add('section_start_slide_and_size',z3.Or(cell(pub,0x1010ca2a8,8)!=ADDR+B-SEGVA,pub.read('x13')!=S))
 sizepub=run('section_size_publication',0x1003875a0,0x1003875bc,[('x13',S),('w12',0x8a9b8560)]);add('section_size_cell',cell(sizepub,0x1010c6800,8)!=S)
 pre=run('range_prekey',0x1003f1390,0x1003f15e0,[('w9',0x8a9b8560)],[(0x1010c6800,8,S)]);add('all_u64_range_prekey',pre.read('x13')!=((S-16)^KPRE))
 log=run('floor_log2',0x1003f15e0,0x1003f176c,[('x13',V^KPRE)]);n=floorlog(V);add('all_u64_floor_log2',log.read('x14')!=n);add('log_comparison_phase',log.read('x15')!=n+0x93cab4961044d4e8)
 validN=z3.Or(N==MASK64,z3.ULE(N,63));small=z3.Or(N==MASK64,z3.ULT(N,15));split=run('range_split',0x1003f176c,0x1003f17b0,[('x14',N),('x15',N+0x93cab4961044d4e8)])
 delta=z3.If(small,z3.BitVecVal(0,64),(z3.BitVecVal(1,64)<<(N&63))-32768)
 add('floor_log_split_and_delta',z3.Or(split.read('x16')!=z3.If(small,N,z3.BitVecVal(0,64)),split.read('x15')!=z3.If(small,z3.BitVecVal(0,64),z3.BitVecVal(15,64)),split.read('x14')!=delta),validN)
 dp1=run('span_codec_part1',0x1003f17f8,0x1003f1820,[('x14',D)]);dp2=run('span_codec_part2',0x1003f182c,0x1003f1844,[('x0',dp1.read('x0')),('x14',dp1.read('x14'))]);add('all_u64_span_codec',dp2.read('x14')!=D+KD)
 k=z3.If(small,N,z3.BitVecVal(15,64));L=z3.BitVecVal(1,64)<<(k&63);R=Q&(V-L)&~0xfff
 offset=run('selection_offset',0x1003f1854,0x1003f1898,[('sp',F),('x2',1),('x15',z3.If(small,z3.BitVecVal(0,64),z3.BitVecVal(15,64))),('x16',z3.If(small,N,z3.BitVecVal(0,64))),('x13',V)],[(F+0x358,8,Q)])
 add('all_u64_selection_offset',z3.Or(offset.read('x8')!=(R^KO),offset.read('x14')!=L),validN)
 of=run('offset_codec',0x1003f18cc,0x1003f18e0,[('x8',Q^KO)]);add('all_u64_offset_codec',of.read('x15')!=(Q^KOFF))
 ptr=run('window_address_codec',0x1003f18fc,0x1003f19e0,[('x8',Q^KO)],[(0x1010ca2a8,8,P)]);add('all_u64_window_address_codec',cell(ptr,0x1010ca2a8,8)!=((P+Q)^KADDR))
 mask=run('window_mask_codec',0x1003f19e0,0x1003f19fc,[('x14',Q),('x3',0x1010c6800)]);add('all_u64_window_mask_codec',cell(mask,0x1010c6800,8)!=((Q-1)^KMASK))
 # Independent mathematical range obligations compose with source identities.
 nv=floorlog(V);lv=z3.BitVecVal(1,64)<<(z3.If(z3.ULT(nv,15),nv,z3.BitVecVal(15,64))&63);rv=Q&(V-lv)&~0xfff
 add('nonzero_v_block_fits',z3.UGT(lv,V),V!=0)
 add('selected_offset_and_window_fit',z3.Or(z3.UGT(rv,V-lv),z3.UGT(rv+lv,V),rv&0xfff!=0),V!=0)
 sr=S-16;ns=floorlog(sr);ls=z3.BitVecVal(1,64)<<(z3.If(z3.ULT(ns,15),ns,z3.BitVecVal(15,64))&63);rs=Q&(sr-ls)&~0xfff
 add('section_window_16byte_end_margin',z3.UGT(P+rs+ls,P+S-16),z3.And(z3.UGT(S,16),z3.ULE(P,MASK64-S)))
 add('current_image_offset_mask',(Q&((0xe297a8-16)-32768)&~0xfff)!=(Q&0xe21000))
 HI=z3.BitVec('window_selection_high32',32);add('current_image_high_word_irrelevant',((Q^(z3.ZeroExt(32,HI)<<32))&0xe21000)!=(Q&0xe21000))
 return qs,counts

def main():
 c=json.loads((ROOT/'daemon_global_state_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for name,predicate in qs:
  op=ROOT/f'daemon_global_state_{name}_original.smt2';np=ROOT/f'daemon_global_state_{name}.smt2';s=z3.Solver();s.add(predicate);op.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(predicate));result=str(s.check());assert result=='unsat',(name,result);np.write_text(s.to_smt2());rows.append({'name':name,'original_file':op.name,'original_sha256':sha(op),'file':np.name,'sha256':sha(np),'result':result});print(json.dumps({'proof':name,'result':result}),flush=True)
 witnesses=[]
 for name,bindings in [('floor_log_split_and_delta',{'window_log64':23}),('selected_offset_and_window_fit',{'window_v64':0xe29798}),('section_window_16byte_end_margin',{'window_section_size64':0xe297a8,'window_section_start64':0x100001058})]:
  predicate=next(v for n,v in qs if n==name);solver=z3.Solver();solver.add(predicate.arg(0))
  for variable,value in bindings.items():solver.add(z3.BitVec(variable,64)==value)
  assert str(solver.check())=='sat';witnesses.append({'proof':name,'bindings':{k:hex(v)for k,v in bindings.items()},'premise_result':'sat'})
 deps=['daemon_global_state_contracts.json','daemon_global_state_lift.py','prove_daemon_prng_output.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'nonempty_premise_witnesses':witnesses,'normalization_dependencies':'The source range prekey identity supplies (S-16)^KPRE to the floor-log block; the floor-log and comparison-phase identities supply N and N+93CAB4961044D4E8 to the split. Selection offset and publication codecs compose through the explicit intermediate XOR. Range containment requires S>16 and no P+S wrap.','z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_global_state_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
