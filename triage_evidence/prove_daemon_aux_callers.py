#!/usr/bin/env python3
"""Universal source key/record equations, saved-phase predicates and exhaustive
byte-bank-to-slot identities for nine conditional caller components. Valid
fixed cells for record proofs; arbitrary u64 frame arithmetic for key proofs.
O(lift + BV DAGs + byte arrays + solver resources) time/space. No native epoch.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE,TABLE
from capture_daemon_record720 import sha
from probe_daemon_aux_callers import SPECS,record_address
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell

def obligations():
 qs=[];counts={};S=0x6800060000;FP=S+0x4000;B=z3.BitVec('aux_emit_frame_base64',64);payload=z3.BitVec('aux_emit_input_pointer64',64);phase=z3.BitVec('aux_emit_saved_phase64',64);pad,result=z3.BitVecs('aux_emit_old_pad32 aux_emit_old_result32',32)
 def run(n,a,z,seeds=(),memory=()):
  v=LifetimeFlags({'spans':[{'label':n,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
  for r,x in seeds:v.seed(r,x)
  for a,nm,x in memory:mem(v,a,nm,x)
  v.run(n);counts[n]=v.count;return v
 for s in SPECS:
  reg='sp'if s['layout']=='SP10CB8'else'x29';P=B+0x10cb8 if reg=='sp'else B-(0x100 if s['layout']=='FP100'else 0xa8);v=run(s['label']+'_key',s['key_start'],s['key_end'],[(reg,B)]);K=(z3.Extract(31,0,P)^0xdc40790b)*0x5973a279;qs.append((s['label']+'_aligned_u64_key',z3.And((B&15)==0,v.read(s['key_reg'])!=K)))
  if s['label']=='2BE':qs.append(('2BE_key_equality_iff_even_address',z3.Xor(v.read(s['key_reg'])==K,(B&1)==0)))
  R=record_address(s,S,FP);K=z3.BitVecVal((((R&0xffffffff)^0xdc40790b)*0x5973a279)&0xffffffff,32);memory=[(S+s['input_offset'],8,payload),(R+4,4,pad),(R+16,4,result)]
  if s['layout']=='SP10CB8':memory.append((S+0x9d0,8,phase));mode=z3.Extract(31,0,phase)-0x25d8
  elif s['layout']=='FPA8':memory.append((S+0x6c,4,z3.Extract(31,0,phase)));mode=z3.Extract(31,0,phase)-0x4395
  else:mode=z3.BitVecVal(0x471c,32)
  v=run(s['label']+'_record',s['start'],s['record_end'],[('sp',S),('x29',FP)],memory)
  qs.append((s['label']+'_all_fields_and_preserved_words',z3.Or((cell(v,R,4)^K)!=mode,cell(v,R+20,4)-K!=s['aux'],cell(v,R+8,8)!=payload,cell(v,R+4,4)!=pad,cell(v,R+16,4)!=result)))
 low=z3.Extract(31,0,phase);qs.append(('large_saved_phase_471C_iff_6CF4',z3.Xor(low-0x25d8==0x471c,low==0x6cf4)));qs.append(('small_saved_phase_471C_iff_8AB1',z3.Xor(low-0x4395==0x471c,low==0x8ab1)))
 used=set();q=z3.BitVec('aux_emit_bank_input8',8)
 def table(bs,index):
  def node(offset,bit):
   if bit<0:return z3.BitVecVal(bs[offset],8)
   return z3.If(z3.Extract(bit,bit,index)==0,node(offset,bit-1),node(offset+(1<<bit),bit-1))
  return node(0,7)
 for s in SPECS:
  k=(s['left'],s['right'],s['key'],s['add'])
  if k in used:continue
  used.add(k);a,b=IMAGE.read(k[0],256),IMAGE.read(k[1],256);values={j^b[a[j]^k[2]]for j in range(256)};assert len(values)==1;c=values.pop();assert s['add']+c==0xcd2e and TABLE+(s['add']+c)*8==0x1010a0860
  byte=q^table(b,table(a,q)^k[2]);qs.append((s['label']+'_all_u8_bank_and_slot',z3.Or(byte!=c,z3.BitVecVal(TABLE,64)+(z3.ZeroExt(56,byte)+s['add'])*8!=0x1010a0860)))
 return qs,counts,{'bank_rules':len(used),'sites':len(SPECS),'source_key_formula':'u32((low32(P) XOR0xDC40790B)*0x5973A279)','frame_phase_producers':'unknown','native_target_executed':False}
if __name__=='__main__':
 qs,counts,meta=obligations();rows=[]
 for name,q in qs:
  a=ROOT/f'daemon_aux_callers_{name}_original.smt2';b=ROOT/f'daemon_aux_callers_{name}.smt2';sol=z3.Solver();sol.add(q);a.write_text(sol.to_smt2());sol=z3.Solver();sol.set(timeout=30000);sol.add(z3.simplify(q));answer=str(sol.check());assert answer=='unsat',(name,answer);b.write_text(sol.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_aux_callers.py','daemon_aux_callers_profiles.json','daemon_arena_lifetime_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'metadata':meta,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_aux_callers_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
