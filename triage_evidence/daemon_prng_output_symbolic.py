#!/usr/bin/env python3
"""Extend sealed state with a proved two-address private-table read.
O(snapshot+visits+effects+bounded SSA expansions) time/space plus 2 s
solver queries. Source expressions remain exact; no import/PAC executes.
"""
import z3
from daemon_seed_material_symbolic import Material,decode
from daemon_context_transfer_symbolic import FIXUPS
from lskd_values_symbolic import resize
from replay_daemon_context_transfer import unpack
START=0x10035c6f8
class Output(Material):
 @classmethod
 def from_material(cls,base,prefix,entropy,material):
  v=Material.from_sealed(base,prefix,entropy);v.__class__=cls;t=unpack(material);assert t['boundary']['pc']==hex(START);v.definitions=t['definitions'].copy()
  for event in t['changed_bytes']:v.bytes[int(event['address'],16)]=decode(event['value'],v.F)
  for j,shape in enumerate(t['boundary']['registers31']):v.regs['x'+str(j)]=decode(shape,v.F)
  v.seed('sp',int(t['boundary']['SP'],16))
  for model in t['api_models']:
   for reg,shape in model['register_effects'].items():
    if reg.startswith('q'):v.regs[reg]=decode(shape,v.F)
  for row in t['steps']:
   for reg,shape in row['registers_after'].items():
    if reg.startswith('q'):v.regs[reg]=decode(shape,v.F)
  last=next(row['NZCV_after']for row in reversed(t['steps'])if'NZCV_after'in row);v.n,v.z,v.carry,v.overflow=[z3.BoolVal(bool(last&(1<<(31-j))))for j in range(4)]
  v.steps=[];v.pool={};v.fixups=set();v.zero_reads=[];v.changed=set();v.phases=[];v.lookups=[];v.definitions_map={d['name']:d for d in v.definitions};v.proof_rejections=[];v.export_count=0;return v
 def one(self,i):
  if i.mnemonic=='mvn':
   self.pc=i.address;o=i.operands;dest=i.reg_name(o[0].reg);self.write(dest,~self.operand(i,o[1],self.width(dest)));return
  return super().one(i)
 def run_from(self,start,limit=200000):
  # Use the same original-source interpreter with the newly inspected
  # complete leaf as an additional internal call target.
  from daemon_prng_output_runner import run_path
  return run_path(self,start,limit)
 def expand_once(self,value):
  todo=[value];seen=set();pairs=[];names=[]
  while todo:
   x=todo.pop()
   if x.get_id()in seen:continue
   seen.add(x.get_id())
   if z3.is_const(x)and x.decl().kind()==z3.Z3_OP_UNINTERPRETED and x.decl().name().startswith('value_'):
    name=x.decl().name();index=int(name[6:]);d=self.definitions[index];assert d['name']==name;pairs.append((x,decode(d['expression'],self.F)));names.append(name)
   else:todo.extend(x.children())
  return z3.simplify(z3.substitute(value,*pairs))if pairs else value,names
 def load(self,address,n):
  address=z3.simplify(resize(address,64))
  if z3.is_bv_value(address):
   a=address.as_long()
   if n==8 and a in FIXUPS:self.fixups.add(a)
   if all(a+j in self.bytes for j in range(n)):
    xs=[self.bytes[a+j]for j in range(n-1,-1,-1)];v=xs[0]if n==1 else z3.simplify(z3.Concat(*xs));self.events.append({'kind':'read','address':hex(a),'size_bytes':n,'value':self.shape(v,n)});return v
   return super().load(address,n)
  lo=self.F+0x6d8;hi=lo+4;expanded=address;history=[]
  if n==4:
   for depth in range(9):
    solver=z3.Solver();solver.set(timeout=2000);solver.add(z3.And(expanded!=lo,expanded!=hi));result=str(solver.check())
    if result=='unsat':
     assert all(lo+j in self.bytes for j in range(8));a=z3.simplify(z3.Concat(*[self.bytes[lo+j]for j in range(3,-1,-1)]));b=z3.simplify(z3.Concat(*[self.bytes[hi+j]for j in range(3,-1,-1)]));assert z3.is_bv_value(a)and z3.is_bv_value(b)
     value=z3.simplify(z3.If(expanded==lo,a,b));event={'kind':'read','address_expression':self.shape(address,8),'candidate_addresses':[hex(lo),hex(hi)],'size_bytes':n,'value':self.shape(value,n)};self.events.append(event);self.lookups.append({'pc':hex(self.pc),'source_visit_index':len(self.steps),'original_address':self.shape(address,8),'expanded_address':self.shape(expanded,8),'candidate_addresses':event['candidate_addresses'],'candidate_values_u32':[hex(a.as_long()),hex(b.as_long())],'expansions':history,'range_counterexample_result':'unsat'});return value
    if result=='unknown':break
    expanded,names=self.expand_once(expanded);history.append(names)
    if not names:break
  self.proof_rejections.append({'pc':hex(self.pc),'size_bytes':n,'address':self.shape(address,8),'expansions':history});raise AssertionError(('unproved finite read',hex(self.pc),self.shape(address,8)))
