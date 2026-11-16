#!/usr/bin/env python3
"""Source-bitvector auxiliary gate and reverse byte-step certificates.
O(I+query DAG) construction/space; SMT search separately bounded at30 s/query.
"""
import copy
import json
import z3
from capstone.arm64 import ARM64_OP_REG
from kext_port_tools import ROOT,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from audit_userclient_record_metadata import Model as MetadataModel
from audit_userclient_input_reader import DEC,TOKEN,SUCCESS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_auxiliary_copy as R

SK0=0x02e859d27e491464
SK1=0x4dae26df20976138
AK0=0xc318995a4ba7c5cd
AK1=0x72cef43cdf673afd

def mask(a,k0,k1):
 return z3.Extract(7,0,z3.LShR((z3.RotateRight(a&resize(0xfffffffffffffff8,64),8)+k0)^k1,(a&7)*8))

class Model(MetadataModel):
 def __init__(self,e):
  super().__init__(e);self.aux,self.stage,self.arg,self.counter=z3.BitVecs('AC_aux64 AC_stage64 AC_arg64 AC_counter64',64)
  self.extent,self.flag,self.mode=z3.BitVecs('AC_extent32 AC_flag32 AC_mode32',32)
  self.byte=z3.BitVec('AC_stored_source8',8);self.with_buffers=False
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,4096),(self.src,16384)]
  if self.with_buffers:spans.extend([(self.aux,self.counter),(self.stage,self.counter)])
  out=[(self.sp&15)==0]
  for j,(a,n) in enumerate(spans):
   out.extend([a!=0,z3.ULE(a,resize(2**64-1,64)-n)])
   for b,m in spans[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out
 def load(self,a,n):
  if self.pc in R.BRANCHES:
   assert n==8;js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  if self.pc==0xfffffe000a65ffc0:
   assert n==1;self.address_checks.append(a==self.aux+self.counter-1);return self.byte
  return Base.load(self,a,n)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if end is not None and i.address>=end:break
   if i.address==skip:continue
   self.pc=i.address;m=i.mnemonic;o=i.operands
   if m in ['ror','cmp','csel'] or m.startswith('b.') or m in ['lsr','lsl'] and o[2].type==ARM64_OP_REG:
    self.visited.add(i.address);self.count+=1
    if m.startswith('b.'):
     assert i.address in R.RETAGS and m=='b.eq' and o[0].imm&(2**64-1)==i.address+8
     self.branch_guards.append(self.equal);skip=R.RETAGS[i.address]
    elif m=='cmp':
     n=self.width(i.reg_name(o[0].reg));self.cmp_left=self.operand(i,o[0],n);self.cmp_right=self.operand(i,o[1],n);self.equal=self.cmp_left==self.cmp_right
    elif m=='csel':
     assert i.op_str.endswith(', ne');self.write(i.reg_name(o[0].reg),z3.If(z3.Not(self.equal),self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[2].reg))))
    elif m=='ror':self.write(i.reg_name(o[0].reg),z3.RotateRight(self.read(i.reg_name(o[1].reg)),o[2].imm))
    else:
     n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);s=self.operand(i,o[2],n)&(n-1)
     self.write(i.reg_name(o[0].reg),z3.LShR(a,s) if m=='lsr' else a<<s)
   else:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    Base.run(self,'one');self.e,self.c=old_e,old_c
  return self

def setup(e):
 v=Model(e)
 for r,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('w3',TOKEN),('w8',v.flag),('x27',0xfffffe0007949dd0)]:v.seed(r,x)
 for off,x in [(0x888,v.src+0xbe4),(0x878,v.arg),(0xa00,0xfffffe000792fcc0),(0x5b8,v.counter)]:mem(v,v.sp+off,8,x)
 mem(v,v.sp+0x5c0,4,v.mode);mem(v,v.src+0xbe4,4,v.extent^SUCCESS)
 mem(v,v.ctx+0x358,8,v.stage);mem(v,v.ctx+0x3c0,8,v.aux)
 return v

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),'pointer_branch_guards':len(v.branch_guards)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited);print(label,flush=True)
 v=setup(e).run('argument_basis').run('mode_basis').run('saved_counter');n=resize(v.arg,32)
 prove('original_argument_derives_exact_saved_mode_and_zero_extended_counter',v,z3.Or(
  cell(v,v.sp+0x5c0,4)!=(n^0x7c233caf),cell(v,v.sp+0x5b8,8)!=z3.ZeroExt(32,n)))
 v.seed('w8',v.flag);v.run('callback').run('copy_gate')
 prove('matched_success_dispatches_zero_length_to_cleanup_and_positive_length_to_N_step',v,z3.Or(
  v.read('x12')!=z3.ZeroExt(32,n),v.read('x13')!=z3.If(n==0,resize(0xfffffe000a656f00,64),resize(0xfffffe000a65ff84,64))),
  [v.flag==1,v.extent==n])
 v=setup(e);mem(v,v.ctx+0x548,8,v.ctx+0x3c0);mem(v,v.ctx+0x468,8,0xfffffe000a65fea8)
 v.seed('x10',v.aux);v.seed('x21',v.src+0xbe4);v.seed('w28',v.extent^SUCCESS);v.seed('w11',0x217);v.run('publish').run('return')
 prove('conditional_publication_installs_auxiliary_extent_success_flag_and_callback',v,z3.Or(
  cell(v,v.ctx+0x3c0,8)!=v.aux,cell(v,v.src+0xbe4,4)!=(v.extent^SUCCESS),v.read('w8')!=1,
  v.read('w23')!=SUCCESS,v.read('x9')!=0xfffffe000a65fe98,v.read('x24')!=0xfffffe000a65fea8,v.read('x28')!=v.read('x27')))
 v=setup(e).run('callback');same=v.extent==resize(v.arg,32)
 for flag in [0,1]:
  prove('callback_flag'+str(flag)+'_exact_extent_gate_and_frontiers',v,z3.Or(v.cmp_right!=SUCCESS,
   v.read('x8')!=z3.If(z3.And(same,flag==1),resize(0xfffffe000a65ff38,64),resize(0xfffffe000a656f00,64)),
   v.read('x26')!=SK0,v.read('x0')!=SK1,v.read('w9')!=0xb6b,v.read('x1')!=0xffffffff7795e35c),[v.flag==flag])
 prove('callback_ignores_upper_original_argument_bits',v,(v.cmp_left==v.cmp_right)!=same,[z3.Or(v.flag==0,v.flag==1)])
 v.run('copy_gate')
 selected=((z3.If(v.mode==0x7c233caf,resize(1,32),resize(0,32))^resize(TOKEN,32))&1)!=0
 prove('saved_mode_gate_loads_distinct_auxiliary_staging_and_counter_channels',v,z3.Or(v.read('x8')!=v.stage,v.read('x11')!=v.aux,
  v.read('x12')!=v.counter,v.read('x13')!=z3.If(selected,resize(0xfffffe000a65ff84,64),resize(0xfffffe000a656f00,64))),[v.flag==1,same])
 # TOKEN is odd: matching the marker bypasses the byte step.
 prove('matching_saved_mode_bypasses_copy_step',v,v.read('x13')!=0xfffffe000a656f00,[v.flag==1,same,v.mode==0x7c233caf])
 v.with_buffers=True;v.run('step');j=v.counter-1
 prove('arbitrary_positive_counter_step_reverse_addresses_and_exit',v,z3.Or(v.read('x12')!=j,
  v.read('x15')!=v.stage+j,v.read('x13')!=z3.If(j==0,resize(0xfffffe000a656f00,64),resize(0xfffffe000a65ff84,64))),
  [v.flag==1,same,v.mode!=0x7c233caf,v.counter!=0])
 value=cell(v,v.stage+j,1)
 prove('arbitrary_byte_transcode_preserves_auxiliary_decoded_value',v,
  (value^mask(v.stage+j,SK0,SK1))!=(v.byte^mask(v.aux+j,AK0,AK1)),
  [v.flag==1,same,v.mode!=0x7c233caf,v.counter!=0])
 prove('positive_step_read_write_addresses_remain_inside_admitted_extents',v,z3.Or(
  z3.UGE(j,v.counter),z3.ULT(v.aux+j,v.aux),z3.UGE(v.aux+j,v.aux+v.counter),
  z3.ULT(v.stage+j,v.stage),z3.UGE(v.stage+j,v.stage+v.counter)),
  [v.flag==1,same,v.mode!=0x7c233caf,v.counter!=0])
 prove('byte_step_preserves_phase_roots_keys_and_cleanup_inputs',v,z3.Or(v.read('x2')!=v.ctx,v.read('x4')!=v.src,
  v.read('x7')!=TABLE,v.read('w3')!=TOKEN,v.read('x8')!=v.stage,v.read('x11')!=v.aux,
  v.read('x26')!=SK0,v.read('x0')!=SK1,v.read('x1')!=0xffffffff7795e35c,v.read('w9')!=0xb6b),
  [v.flag==1,same,v.mode!=0x7c233caf,v.counter!=0])
 old=json.loads(read(ROOT/'userclient_query_records_audit.json'));prior=[]
 for q in old['source_proofs']:
  if q['label']!='third_success_passes_container_and_auxiliary_output_aliases_to_next_facility':continue
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat;prior.append({'label':q['label'],'result':'unsat'})
 assert len(prior)==1
 altered=copy.deepcopy(e);row=next(r for r in altered['spans'] if r['label']=='callback');b=bytearray.fromhex(row['bytes_hex'])
 off=0xfffffe000a65fed4-int(row['start'],16);word=int.from_bytes(b[off:off+4],'little');b[off:off+4]=(word^(1<<5)).to_bytes(4,'little');row['bytes_hex']=b.hex()
 d=setup(altered).run('callback');s=z3.Solver();s.add(*d.owned(),d.flag==1,d.extent==resize(d.arg,32),d.read('x8')!=0xfffffe000a65ff38);assert s.check()==z3.sat
 selected_pcs={int(i['ea'],16) for row in e['spans'] for i in row['instructions']}
 assert visited==selected_pcs-set(R.RETAGS.values()),selected_pcs-visited
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,
  'source_sha256':e['source_sha256'],'source_proofs':qs,'proof_coverage':coverage,'rechecked_prior_source_proofs':prior,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(prior),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(q['source_instruction_instances'] for q in coverage),
   'excluded_retag_instructions':len(R.RETAGS),'altered_extent_literal_counterexample':True},
  'initial_counter_mode_derivation_established':True,'conditional_N_step_loop_established':True,
  'conditional_auxiliary_copy_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
