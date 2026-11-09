#!/usr/bin/env python3
"""Source-local consumer codec, prefix-copy and context-field equations.
O(source DAG+solver resources) time/space; 30 s/query. Calibrated constants,
separated valid cells and word-table mask255 are explicit premises.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,TABLE
from recover_daemon_object_creation import sha
from prove_daemon_digest_completion import CompletionLift
from lskd_values_symbolic import part,mem,cell,resize
from daemon_cache_publication_model import DECODER_CONSTANTS,COPY_CONSTANTS,KEYS,word,word_index,byte_value
class PublicationLift(CompletionLift):
 def load(self,a,n):
  if self.pc==0x100be09c0:
   assert n==8;self.data_reads.append((a,n));return self.cached_word
  return super().load(a,n)
def obligations(c):
 F=0x6f00050000;I=0x6f00010000;O=0x6f00020000;C=0x6f00030000;B=F+0x3ab0;M=0x1010c67f8;WP=0x6f00060000
 N,J,Q,Y,R=z3.BitVecs('publication_N64 publication_i64 publication_cursor64 publication_cached_word64 publication_return64',64);BYTE,FLAG=z3.BitVecs('publication_byte8 publication_flag8',8);A=z3.BitVec('publication_address64',64);qs=[];counts={}
 def add(n,p,pre=z3.BoolVal(True)):qs.append((n,z3.And(pre,p)))
 def run(n,a,z,seeds=(),memory=(),data=(),cached=Y):
  v=PublicationLift(part(c,n,a,z),data=data);v.cached_word=cached
  for r,x in seeds:v.seed(r,x)
  for at,nb,x in memory:mem(v,at,nb,x)
  v.run(n);counts[n]=v.count;return v
 v=run('format_result_capture',0x100ad6fd0,0x100ad6fd8,[('sp',F),('x0',R)])
 add('all_u64_formatted_object_saved_at_3650',z3.Or(cell(v,F+0x3650,8)!=R,v.read('x0')!=R))
 # This helper's first input address is I+N-1. Its word table and input byte
 # are distinct data reads; the final table read is a control-cell read.
 seeds=[*DECODER_CONSTANTS.items(),('x13',N),('x11',I),('x8',O)]
 v=run('consumer_byte_codec',0x100be097c,0x100be0a84,seeds,[(0x1010c67d4,4,255),(0x1010c8268,8,WP)],[(1,BYTE)])
 address=z3.BitVecVal(I,64)+N-1;pre=z3.And(z3.UGE(N,1),z3.ULE(N,20));assert len(v.data_reads)==2 and len(v.stores)==1 and len(v.control_reads)==1
 add('all_word_byte_reverse_codec_addresses_and_value',z3.Or(v.data_reads[0][0]!=WP+word_index(address),v.data_reads[1][0]!=address,v.stores[0]['address']!=O+N-1,v.stores[0]['value']!=resize(byte_value(address,Y,z3.ZeroExt(56,BYTE)),8),v.read('x13')!=N-1),pre)
 want=z3.If(N==1,z3.BitVecVal(TABLE+8*(0x655f^0x3d),64),z3.BitVecVal(TABLE+8*0x655f,64))
 add('codec_original_control_and_loop_live_handover',z3.Or(v.control_reads[0]!=want,v.read('x11')!=I,v.read('x8')!=O,*[v.read(r)!=resize(x,v.width(r))for r,x in DECODER_CONSTANTS.items()]),pre)
 idx=word_index(A);add('all_u64_addresses_word_table_bounds_mask255',z3.Or(z3.UGT(idx,248),idx&7!=0))
 # The eight-round word model is separately checked with an arbitrary aligned
 # address and arbitrary word. No source-register rewrites are used.
 v=run('codec_word',0x100be09c4,0x100be0a58,[('x16',A&~7),('x27',Y),*KEYS.items()])
 add('all_u64_eight_round_word_model',v.read('x16')!=word(A,Y))
 X=z3.BitVec('publication_mba64',64);a=KEYS['x5'];d=KEYS['x20'];assert not(a&1 or d&1)
 add('all_u64_OR_mixer_reduction',(((X<<1)|a)-X+KEYS['x10'])!=((X^(a//2))+(a//2)+KEYS['x10']))
 add('all_u64_AND_mixer_reduction',(X-((X<<1)&d)+KEYS['x21'])!=((X^(d//2))-(d//2)+KEYS['x21']))
 v=run('prefix_copy',0x100d59b88,0x100d59bcc,[*COPY_CONSTANTS.items(),('x0',J),('x16',N),('w10',resize(J-0xe98c785d,32)),('x12',I),('x4',C)],data=[(1,BYTE)])
 pre=z3.And(z3.UGE(N,1),z3.ULE(N,20),z3.ULT(J,N));assert len(v.data_reads)==len(v.stores)==1
 add('all_bytes_prefix_copy_addresses_and_counters',z3.Or(v.data_reads[0][0]!=I+J,v.stores[0]['address']!=C+J,v.stores[0]['value']!=BYTE,v.read('x0')!=J+1,v.read('w10')!=resize(J+1-0xe98c785d,32)),pre)
 want=z3.If(z3.ULT(J+1,N),z3.BitVecVal(TABLE+8*(0x7e65^0xc3),64),z3.BitVecVal(TABLE+8*0x7e65,64))
 add('prefix_copy_original_control_and_live_handover',z3.Or(v.control_reads[0]!=want,v.read('x12')!=I,v.read('x4')!=C,v.read('x16')!=N,*[v.read(r)!=resize(x,v.width(r))for r,x in COPY_CONSTANTS.items()]),pre)
 v=run('context_initialization',0x100aee670,0x100aee70c,[('sp',F),('w12',0x51e5),('x1',Q)],[(F+0x26e0,8,M),(M,1,FLAG),(F+0x3178,8,B)])
 count=z3.If(FLAG==0,z3.BitVecVal(0,32),z3.BitVecVal(20,32))
 add('all_u8_marker_to_prefix_length_and_cursor_sub64',z3.Or(cell(v,F+0x3504,4)!=count,cell(v,F+0x3620,8)!=Q-64,v.read('x17')!=z3.ZeroExt(32,count)))
 expected={0x70:0x93bc0ef6,0x74:0x1b34867e,0x78:0x6c43f109,0x7c:0xe4cb7981,0x80:0x372bcc07,0x84:20,0x88:2}
 # STP Wn,Wm produces two independent u32 cells in the word-cell lift.
 add('new_context_encoded_IV_size_selector_and_aliases',z3.Or(cell(v,F+0x30b8,8)!=B+0x28,cell(v,F+0x2a70,8)!=B+0x28,cell(v,F+0x2a60,8)!=B,cell(v,B+0x68,8)!=0,v.read('x8')!=B+0x150,*[cell(v,B+off,4)!=x for off,x in expected.items()]))
 return qs,counts
def main():
 c=json.loads((ROOT/'daemon_cache_publication_contracts.json').read_text());qs,lifts=obligations(c);rows=[]
 for name,p in qs:
  a=ROOT/f'daemon_cache_publication_{name}_original.smt2';b=ROOT/f'daemon_cache_publication_{name}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p,bv_sort_ac=True));answer=str(s.check());print(json.dumps({'proof':name,'result':answer}),flush=True);assert answer=='unsat',(name,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer})
 deps=['daemon_cache_publication_contracts.json','daemon_cache_publication_model.py','prove_daemon_digest_completion.py','prove_daemon_digest_output.py','prove_daemon_sha1_core.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':lifts,'source_register_rewrites':0,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_cache_publication_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(lifts.values())}),flush=True)
if __name__=='__main__':main()
