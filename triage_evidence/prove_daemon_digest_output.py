#!/usr/bin/env python3
"""Original-source serializer and frame-root contracts, 30 s/query.
O(source DAG+solver resources) time/space. Valid separated cells, mode0x471C,
recorded helper constants and original table roots are explicit premises.
"""
import json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_EXT_SXTB
from daemon_receive_tools import ROOT,TABLE
from recover_daemon_object_creation import sha
from prove_daemon_sha1_core import CoreLift
from lskd_values_symbolic import part,mem,cell,resize
class OutputLift(CoreLift):
 def operand(self,i,o,n):
  if o.ext==ARM64_EXT_SXTB:return z3.SignExt(n-8,z3.Extract(7,0,self.read(i.reg_name(o.reg))))
  return super().operand(i,o,n)
 def run(self,label):
  old=self.c;row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='sxtb':self.write(i.reg_name(i.operands[0].reg),z3.SignExt(24,z3.Extract(7,0,self.read(i.reg_name(i.operands[1].reg)))));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};CoreLift.run(self,'one')
  self.c=old;return self
def obligations(c):
 F=0x6d00040000;C=0x6d00010000;O=0x6d00020000;J,S,N,P=z3.BitVecs('output_index32 output_word32 output_length32 output_selector32',32);U,A,B,D,E,G,Q=z3.BitVecs('output_root64 output_A64 output_B64 output_D64 output_E64 output_G64 output_Q64',64);qs=[];counts={}
 def add(name,pred,pre=z3.BoolVal(True)):qs.append((name,z3.And(pre,pred)))
 def run(label,a,z,seeds=(),memory=(),data=()):
  v=OutputLift(part(c,label,a,z),data=data)
  for r,x in seeds:v.seed(r,x)
  for at,n,x in memory:mem(v,at,n,x)
  v.run(label);counts[label]=v.count;return v
 def route_slot(pc,target):return int(c['route_slots'][hex(pc)][hex(target)],16)
 def seed_value(spec,index=J):
  kind=spec['kind'];return F if kind=='frame_pointer'else C if kind=='context_pointer'else O if kind=='output_pointer'else TABLE if kind=='table_pointer'else index*4 if kind=='byte_counter'else spec['value']
 for name,abi in c['helper_ABIs'].items():
  a,z=int(abi['start'],16),int(abi['end'],16)-4;v=run(name,a,z,[(r,seed_value(s))for r,s in abi['seeds'].items()],[(F+0x2a70,8,C),(F+0x2fe0,8,O),(C+0x5c,4,abi['output_size'])],[(4,S^0xf4f92df7)])
  lo,hi=abi['counter_domain'];idx=J if name.endswith('loop')else z3.BitVecVal(0,32);pre=z3.And(z3.UGE(J,lo),z3.ULE(J,hi));assert len(v.data_reads)==1 and len(v.stores)==4 and len(v.control_reads)==1
  bad=[v.data_reads[0][0]!=C+0x48+(z3.ZeroExt(32,idx)<<2)]
  for store,j in zip(v.stores,abi['byte_store_order']):
   bit=8*j if abi['selector']==1 else 24-8*j;want=z3.Extract(bit+7,bit,S)^0x98;bad.extend([store['address']!=O+z3.ZeroExt(32,idx*4+j),store['value']!=want])
  add(name+'_all_u32_encoded_bytes_and_addresses',z3.Or(*bad),pre)
  target=z3.If(z3.ULT(J,hi),z3.BitVecVal(int(abi['loop_slot'],16),64),z3.BitVecVal(int(abi['exit_slot'],16),64))if name.endswith('loop')else z3.BitVecVal(int(abi['loop_slot'],16),64)
  add(name+'_original_control_address',v.control_reads[0]!=target,pre)
  nxt=c['helper_ABIs'][name.replace('first','loop')];bad=[]
  for r,spec in nxt['seeds'].items():bad.append(v.read(r)!=resize(seed_value(spec,idx+1),64))
  add(name+'_loop_ABI_handover_and_counter',z3.Or(*bad),pre)
 # Mode-derived selector routing. Each target read is checked as a table cell;
 # the fresh logical target value itself does not enter the proven data results.
 v=run('route_entry',0x1009de090,0x1009de0c4,[('sp',F),('x30',TABLE)],[(F+0x273c,4,0x471c),(F+0x2f40,8,C),(C+0x60,4,P)]);phase=v.read('w10');add('all_u32_selector_entry_context_and_slot',z3.Or(v.read('x11')!=C,v.read('w9')!=P,v.control_reads[0]!=route_slot(0x1009de0c4,0x100b30120)))
 g=run('selector_gate',0x100b30120,0x100b30154,[('sp',F),('x30',TABLE),('x11',C),('w9',P),('w10',phase)]);signed=z3.SignExt(24,z3.Extract(7,0,P));want=z3.If(signed<2,z3.BitVecVal(route_slot(0x100b30154,0x10095b7dc),64),z3.BitVecVal(route_slot(0x100b30154,0x100a4739c),64));add('all_u32_signed_low_byte_selector_partition',z3.Or(g.control_reads[0]!=want,cell(g,F+0x2a70,8)!=C));route_phase=g.read('w8')
 for name,a,z,end,target,byte in [('be_route',0x100a4739c,0x100a473f4,0x100a473f4,0x100ae05dc,2),('le_route',0x10095b7dc,0x10095b830,0x10095b830,0x100c0a3c4,1)]:
  v=run(name,a,z,[('x30',TABLE),('w8',route_phase),('w9',P)]);want=z3.If((P&255)==byte,z3.BitVecVal(route_slot(end,target),64),z3.BitVecVal(route_slot(end,0x100bb1574),64));add(name+'_all_u32_exact_low_byte_match',v.control_reads[0]!=want)
  guard='be_size_gate'if byte==2 else'le_size_gate';ga=0x100ae05dc if byte==2 else 0x100c0a3c4;gz=0x100ae0644 if byte==2 else 0x100c0a414;first=0x100be71bc if byte==2 else 0x100b57120
  h=run(guard,ga,gz,[('sp',F),('x30',TABLE),('w10',v.read('w10'))],[(F+0x2a70,8,C),(C+0x5c,4,N)]);want=z3.If(N==0,z3.BitVecVal(route_slot(gz,0x100bb1574),64),z3.BitVecVal(route_slot(gz,first),64));add(guard+'_all_u32_zero_length_gate',h.control_reads[0]!=want)
 v=run('stack_root',0x1007cfa64,0x1007cfab4,[('sp',F)],[(F+0x16d0,8,U)]);root=z3.BitVecVal(F+0xc070,64)+U;add('all_u64_stack_root_and_produced_aliases',z3.Or(cell(v,F+0x3050,8)!=root,cell(v,F+0x3300,8)!=root+0x480,cell(v,F+0xb10,8)!=root+0x490,cell(v,F+0x1f20,8)!=root+0x560,cell(v,F+0x1428,8)!=root+0x610,v.read('x22')!=root+0x6b0))
 v=run('conditional_root',0x100ace964,0x100ace984,[('sp',F),('w23',S),('x13',U)]);add('all_u64_conditional_root_capture_and_word_flag',z3.Or(cell(v,F+0x3050,8)!=U,cell(v,F+0x3160,4)!=S,cell(v,F+0x2aa7,1)!=z3.If(S==0x8b3dc651,z3.BitVecVal(1,8),z3.BitVecVal(0,8))))
 v=run('direct_root',0x100bdb258,0x100bdb26c,[('sp',F),('w9',P),('w10',S),('x20',U)]);add('all_u64_direct_root_capture_and_zero_flag',z3.Or(cell(v,F+0x3050,8)!=U,cell(v,F+0x3160,4)!=S,cell(v,F+0x2aa7,1)!=0))
 fields=[(0x3050,U),(0x33c8,A),(0x3108,B),(0x2da8,D),(0x34b8,E),(0x2c28,G)];v=run('join_resume',0x100bb15d0,0x100bb1620,[('sp',F)],[(F+off,8,x)for off,x in fields]);expected={0x2a68:U+0x32c,0x2a60:A,0x2a28:B,0x2a58:D,0x2a20:E,0x2a50:G,0x2a48:U+0x11c,0x2a40:U+0x20f,0x2a30:U,0x2a38:U+0xe4};add('all_u64_unresolved_root_copy_and_alias_contract',z3.Or(*[cell(v,F+off,8)!=x for off,x in expected.items()]))
 return qs,counts
def main():
 c=json.loads((ROOT/'daemon_digest_output_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for name,p in qs:
  a=ROOT/f'daemon_digest_output_{name}_original.smt2';b=ROOT/f'daemon_digest_output_{name}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p,bv_sort_ac=True));answer=str(s.check());print(json.dumps({'proof':name,'result':answer}),flush=True);assert answer=='unsat',(name,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer})
 deps=['daemon_digest_output_contracts.json','prove_daemon_sha1_core.py','daemon_digest_output_access.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_digest_output_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
