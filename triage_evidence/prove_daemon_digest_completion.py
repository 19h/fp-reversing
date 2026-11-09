#!/usr/bin/env python3
"""Source-local completion contracts; 30 s/query.
O(source DAG+solver resources) time/space. Valid separated owners, fixed phase
constants and original table cells are premises; native joins are unproved.
"""
import json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,TABLE
from recover_daemon_object_creation import sha
from prove_daemon_digest_output import OutputLift
from daemon_digest_completion_model import seed,overwrite_byte,CONSTANTS
from lskd_values_symbolic import part,mem,cell,resize
class CompletionLift(OutputLift):
 def run(self,label):
  old=self.c;row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address;o=i.operands
   if i.mnemonic=='subs':
    name=i.reg_name(o[0].reg);n=self.width(name);a=self.operand(i,o[1],n);b=self.operand(i,o[2],n);self.sleft=a;self.sright=b;self.equal=a-b==0;self.write(name,a-b);self.count+=1
   elif i.mnemonic=='cset'and i.op_str.endswith(', hi'):
    self.write(i.reg_name(o[0].reg),z3.If(z3.UGT(self.sleft,self.sright),z3.BitVecVal(1,32),z3.BitVecVal(0,32)));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};OutputLift.run(self,'one')
  self.c=old;return self
def obligations(c):
 F=0x6d00040000;C=0x6d00010000;O=0x6d00020000;D=0x6d00030000
 Q,N=z3.BitVecs('completion_seed64 completion_remaining64',64);S=z3.BitVec('completion_size32',32);B=z3.BitVec('completion_encoded_byte8',8)
 A=z3.BitVec('completion_frame64',64);opaque=z3.BitVecs('completion_R64 completion_A64 completion_B64 completion_C64 completion_D64 completion_E64',64)
 qs=[];counts={}
 def add(name,bad,pre=z3.BoolVal(True)):qs.append((name,z3.And(pre,bad)))
 def run(name,a,z,seeds=(),memory=(),data=(),previous=None):
  v=CompletionLift(part(c,name,a,z),data=data)if previous is None else previous
  if previous is not None:v.c=part(c,name,a,z);v.control_reads=[]
  for r,x in seeds:v.seed(r,x)
  for at,n,x in memory:mem(v,at,n,x)
  before=v.count;v.run(name);counts[name]=v.count-before;return v
 def slot(pc,target):return int(c['route_slots'][hex(pc)][hex(target)],16)
 def control(v,pc,target):return v.control_reads[0]!=slot(pc,target)
 v=run('seed',0x100bb1574,0x100bb15d0,[('sp',A),('w27',0x471c)])
 add('all_u64_frame_seed_and_fixed_control_inputs',z3.Or(v.read('x13')!=seed(A),v.read('w2')!=0x7e8c,v.read('w11')!=0x8204ce66))
 protected=['sp','x2','x8','x9','x11','x13','x27','x30'];live={r:z3.BitVec('completion_live_'+r,64)for r in protected if r!='sp'}
 fields=[0x3050,0x33c8,0x3108,0x2da8,0x34b8,0x2c28];saved=[0x2a70,0x3610,0x31a8,0x32e8,0x3620,0x26e0];guards={off:z3.BitVec('completion_saved_'+hex(off),64)for off in saved}
 v=run('opaque_aliases',0x100bb15d0,0x100bb1620,[('sp',F),*live.items()],[(F+off,8,x)for off,x in zip(fields,opaque)]+[(F+off,8,guards[off])for off in saved])
 add('all_opaque_roots_preserve_completion_live_inputs',z3.Or(v.read('sp')!=F,*[v.read(r)!=x for r,x in live.items()],*[cell(v,F+off,8)!=guards[off]for off in saved]))
 v=run('entry',0x100bb1620,0x100bb16c0,[('sp',F),('x30',TABLE),('w27',0x471c),('w11',0x8204ce66),('x13',Q),('x8',0x3705faa50a75fa00),('w2',0x7e8c),('w9',0xbb74a819)],[(F+0x2a70,8,C)])
 expected={**{r:x for r,x in CONSTANTS.items()if r!='w4'},'x6':C,'x19':TABLE,'x13':Q,'x8':0x3705faa50a75fa00,'w9':0xbb74a819,'w7':0x4214,'w15':0x52004d6c,'w0':0xe4054,'w14':0x54eea70c,'w16':0x3d}
 add('entry_original_route_and_overwrite_constants',z3.Or(control(v,0x100bb16c0,0x100a048d4),*[v.read(r)!=resize(x,v.width(r))for r,x in expected.items()]))
 v=run('overwrite_start',0x100a048d4,0x100a04900,previous=v)
 add('overwrite_exact_92_byte_count_and_seed',z3.Or(v.read('x1')!=92,v.read('x11')!=Q,v.read('w4')!=0x471c,v.read('sp')!=F,v.read('x6')!=C,*[v.read(r)!=resize(x,v.width(r))for r,x in CONSTANTS.items()],control(v,0x100a04900,0x100a1bf1c)))
 v=run('overwrite_loop',0x100a1bf1c,0x100a1bfa0,[('sp',F),('x6',C),('x11',Q),('x1',N),*CONSTANTS.items()])
 pre=z3.And(z3.UGE(N,1),z3.ULE(N,92));assert len(v.stores)==2 and not v.data_reads
 add('all_seed_bits_reverse_overwrite_byte_address_counter',z3.Or(v.stores[1]['address']!=C+N-1,v.stores[1]['value']!=resize(overwrite_byte(Q),8),cell(v,F+0x2ba0,8)!=N-1,v.read('x1')!=N-1,v.read('x11')!=Q+1),pre)
 want=z3.If(N==1,z3.BitVecVal(slot(0x100a1bfa0,0x100abd000),64),z3.BitVecVal(slot(0x100a1bfa0,0x100a1bf1c),64))
 add('overwrite_loop_original_branch_and_live_handover',z3.Or(v.control_reads[0]!=want,v.read('sp')!=F,v.read('x6')!=C,*[v.read(r)!=resize(x,v.width(r))for r,x in CONSTANTS.items()]),pre)
 add('all_seed_bits_byte_period_256',resize(overwrite_byte(Q),8)!=resize(overwrite_byte(resize(resize(Q,8),64)),8))
 seeds={**CONSTANTS,'w9':0xbb74a819,'w15':0x52004d6c,'w0':0xe4054,'w14':0x54eea70c,'w16':0x3d}
 chain=[('overwrite_exit',0x100abd000,0x100abd00c,0x100a21560),('gate1',0x100a21560,0x100a2158c,0x100bdb0f0),('gate2',0x100bdb0f0,0x100bdb12c,0x100b3ffb0),('gate3',0x100b3ffb0,0x100b3fff4,0x100babce8),('gate4',0x100babce8,0x100babd28,0x100bf7b18),('gate5',0x100bf7b18,0x100bf7b5c,0x100b132f8)]
 v=None
 for name,a,z,target in chain:
  v=run(name,a,z,list(seeds.items())if v is None else(),previous=v);add(name+'_fixed_phase_original_target',control(v,z,target))
 add('post_overwrite_size_gate_entry_constants',z3.Or(v.read('w11')!=0xc607,v.read('x19')!=TABLE,v.read('w4')!=0x471c))
 v=run('size_gate',0x100b132f8,0x100b13354,[('sp',F),('w11',0xc607),('x19',TABLE)],[(F+0x3610,8,C),(C+0x5c,4,S)])
 want=z3.If(S==0,z3.BitVecVal(slot(0x100b13354,0x100b56660),64),z3.BitVecVal(slot(0x100b13354,0x1009a33bc),64))
 add('all_u32_size_decode_zero_partition_and_count',z3.Or(v.read('w13')!=(S^0x6a2c85c3),v.read('w12')!=0x6a2c85c3,v.read('w20')!=0x471c,v.control_reads[0]!=want,v.read('x30')!=TABLE))
 v=run('copy_start',0x1009a33bc,0x1009a33e0,[('sp',F),('w20',0x471c),('w13',S^0x6a2c85c3),('w12',0x6a2c85c3),('x30',TABLE)],[(F+0x32e8,8,D),(F+0x31a8,8,O)])
 add('all_u32_copy_input_count_and_XOR_key',z3.Or(v.read('x8')!=D,v.read('x9')!=O,v.read('x11')!=z3.ZeroExt(32,S),v.read('w12')!=0x98,v.read('w13')!=0xfbf5,control(v,0x1009a33e0,0x1009a2e90)))
 v=run('copy_loop',0x1009a2e90,0x1009a2eb4,[('x8',D),('x9',O),('x11',N),('w12',0x98),('w13',0xfbf5),('w10',0x6597),('x30',TABLE)],data=[(1,B)])
 pre=z3.And(z3.UGE(N,1),z3.ULE(N,0xffffffff));assert len(v.data_reads)==len(v.stores)==1
 want=z3.If(N==1,z3.BitVecVal(slot(0x1009a2eb4,0x100b56660),64),z3.BitVecVal(slot(0x1009a2eb4,0x1009a2e90),64))
 add('all_byte_reverse_XOR_copy_and_original_control',z3.Or(v.data_reads[0][0]!=O+N-1,v.stores[0]['address']!=D+N-1,v.stores[0]['value']!=(B^0x98),v.read('x11')!=N-1,v.control_reads[0]!=want),pre)
 add('copy_loop_live_handover',z3.Or(*[v.read(r)!=x for r,x in [('x8',D),('x9',O),('w12',0x98),('w13',0xfbf5),('w10',0x6597),('x30',TABLE)]]),pre)
 v=run('restore',0x100b56660,0x100b56688,[('sp',F),('w20',0x471c),('x30',TABLE)],[(F+0x3620,8,Q)]+[(F+off,8,x)for off,x in zip([0x2a88,0x2a90,0x2978,0x2988],opaque)])
 add('all_u64_cursor_sub32_and_four_restores',z3.Or(v.read('x9')!=Q-32,*[v.read(r)!=x for r,x in zip(['x28','x23','x24','x26'],opaque)],control(v,0x100b56688,0x100a53630)))
 v=run('complete',0x100a53630,0x100a53680,[('sp',F),('w20',0x471c),('x30',TABLE),('x9',Q-32)],[(F+0x26e0,8,D),(F+0x2edc,4,S)])
 add('all_u64_saved_cursor_completion_byte_and_status_reload',z3.Or(cell(v,F+0x3620,8)!=Q-32,cell(v,D,1)!=1,v.read('w22')!=S,control(v,0x100a53680,0x100b687e0)))
 v=run('identity_save',0x100baff8c,0x100baffb8,[('sp',F)],[(F+0x3238,8,C),(F+0x3620,8,Q),(F+0x2f00,8,D)]);base=z3.BitVecVal(F+0x39f0,64)+Q
 add('all_u64_identity_context_output_destination_capture',z3.Or(cell(v,F+0x3610,8)!=C,cell(v,F+0x31a8,8)!=base,cell(v,F+0x3620,8)!=Q+32,cell(v,F+0x32e8,8)!=D))
 v=run('scratch_aliases',0x100bd8f80,0x100bd9000,[('sp',F)],[(F+0x3620,8,Q)])
 offsets={0x2b18:0,0x3258:0x10,0x2d70:0x20,0x3640:0x37,0x2ce8:0x4e,0x33c8:0x60,0x2da8:0xe80,0x3108:0x1ca0,0x34b8:0x2ac0,0x2c28:0x38e0,0x2df8:0x4700}
 add('all_u64_scratch_aliases_and_cursor_add_4730',z3.Or(*[cell(v,F+off,8)!=base+delta for off,delta in offsets.items()],cell(v,F+0x3620,8)!=Q+0x4730))
 v=run('destination_save',0x100abdf8c,0x100abdf94,[('sp',F)],[(F+0x3278,8,D)]);add('all_u64_saved_destination_forwarding',cell(v,F+0x2f00,8)!=D)
 v=run('stack_destination',0x10082f448,0x10082f464,[('sp',F)],[(F+0x3620,8,Q)]);add('all_u64_stack_destination_and_cursor_add64',z3.Or(cell(v,F+0x3278,8)!=base,cell(v,F+0x3620,8)!=Q+64))
 return qs,counts
def main():
 c=json.loads((ROOT/'daemon_digest_completion_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for name,p in qs:
  a=ROOT/f'daemon_digest_completion_{name}_original.smt2';b=ROOT/f'daemon_digest_completion_{name}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p,bv_sort_ac=True));answer=str(s.check());print(json.dumps({'proof':name,'result':answer}),flush=True);assert answer=='unsat',(name,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer})
 deps=['daemon_digest_completion_contracts.json','daemon_digest_completion_model.py','prove_daemon_digest_output.py','prove_daemon_sha1_core.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False}
 (ROOT/'daemon_digest_completion_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'lifted_source_instructions':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
