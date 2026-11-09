#!/usr/bin/env python3
"""Preserve undefined private bytes across source copies after a continuous prefix.
Original source VM preserves arithmetic expressions over undefined bytes and
stops before unknown-dependent addresses/control or uninspected calls.
O(prefix+snapshot+continuation+expression DAG+effects) time/space.
"""
import json,hashlib,base64,zlib
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from lskd_values_symbolic import Lift,resize
from daemon_callback_revisit_symbolic import Revisit,ALLOWED_CALLS
from probe_daemon_descriptor_producers import Run,cases,P,SIZE
ALLOWED_CALLS.add(0x10043a240) # Previously inspected rwlock creator; stop at its imported allocator.
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
class Copies(Revisit):
 def write(self,name,value):
  if name in ['xzr','wzr']:return
  bits=self.width(name);key=self.key(name);self.regs[key]=z3.simplify(resize(resize(value,bits),128 if key.startswith('q')else 64));self.written[key]=self.regs[key]
 @classmethod
 def from_run(cls,run):
  v=cls.__new__(cls);Lift.__init__(v,{'spans':[]});v.F=int(run.boundary['SP'],16);v.H=run.TOKEN;v.bytes={};v.origins={};v.steps=[];v.pool={};v.fixups=set();v.zero_reads=[];v.changed=set();v.dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);v.dec.detail=True;v.cache={};v.definitions=[];v.definition_stage='source';v.api_models=[];v.phases=[];v.events=[];v.written={};v.flag_change=False;v.unknown_inputs_used={};v.undo_bytes={};v.transaction=False;v.physical=run
  raw=bytes(run.u.mem_read(P,SIZE))
  for j,k in enumerate(run.known):
   if k:v.bytes[P+j]=z3.BitVecVal(raw[j],8)
  for j in range(31):v.seed('x'+str(j),run.reg(j))
  from unicorn import arm64_const as ar
  for j in range(32):v.seed('q'+str(j),run.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))
  v.seed('sp',int(run.boundary['SP'],16));f=run.u.reg_read(ar.UC_ARM64_REG_NZCV);v.n,v.z,v.carry,v.overflow=[z3.BoolVal(bool(f&(1<<(31-j))))for j in range(4)];return v
 def load(self,address,n):
  a=self.concrete(resize(address,64),'unknown-dependent read address');private=P<=a<a+n<=P+SIZE
  if private:
   for j in range(a,a+n):
    if j not in self.bytes:self.bytes[j]=z3.BitVec('unknown_'+hex(j),8);self.origins[j]={'first_read_pc':hex(self.pc),'offset':j-self.F}
  else:
   assert 0x100000000<=a<a+n<0x102000000,(hex(a),n);self.physical.ensure(a,n);raw=bytes(self.physical.u.mem_read(a,n))
   for j,b in enumerate(raw,a):
    if j not in self.bytes:self.bytes[j]=z3.BitVecVal(b,8)
   if a in FIXUPS:self.fixups.add(a)
  xs=[self.bytes[j]for j in range(a+n-1,a-1,-1)];value=xs[0]if n==1 else z3.simplify(z3.Concat(*xs));shape=self.shape(value,n);self.events.append({'kind':'read','address':hex(a),'size_bytes':n,'value':shape})
  for term in shape.get('terms',[]):
   if isinstance(term,dict):self.unknown_inputs_used.setdefault(term['origin'],{'first_read_pc':hex(self.pc),'source_visit_index':len(self.steps)})
  return value
 def store(self,address,n,value,pc):
  a=self.concrete(address,'unknown-dependent write address');shape=self.shape(resize(value,n*8),n);assert P<=a<a+n<=P+SIZE or 0x101000000<=a<a+n<0x102000000
  if 'terms'in shape:assert P<=a<a+n<=P+SIZE
  if 'expr'in shape and any(name.startswith('unknown_')for name,bits in shape['symbols']):assert P<=a<a+n<=P+SIZE
  if self.transaction:
   for j in range(a,a+n):self.undo_bytes.setdefault(j,(j in self.bytes,self.bytes.get(j),j in self.changed))
  self.events.append({'kind':'write','address':hex(a),'size_bytes':n,'value':shape})
  for j in range(n):self.bytes[a+j]=z3.simplify(z3.Extract(8*j+7,8*j,resize(value,n*8)));self.changed.add(a+j)
def main():
 rows=[]
 for c in cases():
  if not c['nonnull']or c['probe']!='fast'or c['counter64']!=0:continue
  r=Run(c);prefix=r.run();assert prefix['boundary']['kind']=='before_unknown_private_read';v=Copies.from_run(r);boundary=v.run_revisit(int(prefix['boundary']['pc'],16),limit=30000);trace={'steps':v.steps,'boundary':boundary,'origins':[{'offset':off,**x}for off,x in sorted(v.unknown_inputs_used.items())],'definitions':v.definitions,'source_pool':v.pool,'used_fixups':[hex(a)for a in sorted(v.fixups)],'changed_bytes':[{'address':hex(a),'value':v.shape(v.bytes[a],1)}for a in sorted(v.changed)],'initial_registers':prefix['boundary']['registers31'],'initial_SP':prefix['boundary']['SP']};raw=json.dumps(trace,separators=(',',':')).encode();rows.append({'configuration':c,'prefix':prefix,'source_visits':len(v.steps),'source_pool_instructions':len(v.pool),'unknown_input_bytes_used':len(v.unknown_inputs_used),'boundary':boundary,'payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode(),'payload_sha256':hashlib.sha256(raw).hexdigest(),'native_target_executed':False});print(json.dumps({'configuration':c,'continuation_visits':len(v.steps),'unknown_bytes':len(v.unknown_inputs_used),'boundary':boundary}),flush=True)
 deps=['probe_daemon_descriptor_producers.py','daemon_descriptor_producers_source.json','daemon_callback_revisit_symbolic.py','daemon_seed_material_symbolic.py','daemon_entropy_return_symbolic.py','daemon_context_transfer_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_producers_copies.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'continuation_visits':sum(r['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
