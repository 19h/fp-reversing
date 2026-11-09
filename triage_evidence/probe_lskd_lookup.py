#!/usr/bin/env python3
"""Source-produced table pointers and guarded initialized-cache lookup paths.

Original file-backed table bytes only. One declared cache-presence fixture,
inherited register-only allocation/free models and no model memory writes.
Unknown loaded X13 is tracked until overwrite or a stop before consumption.
O(C*(B+V+E)) time and retained space; no native API, synchronization or IPC.
"""
import gc,hashlib,json
from pathlib import Path
from unicorn import arm64_const as ar
from probe_lskd_state import State,cases as state_cases
from probe_lskd_request import kernel
from probe_legacy_stack import P
from kext_port_tools import ROOT,SOURCE
from lskd_state_spec import ORIGINS
TABLE=0xfffffe000ccc7b08
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Lookup(State):
 def __init__(self,c):
  super().__init__(c);self.lookup_windows=[];self.lookup_active=None;self.lookup_pending=None;self.lookup_prior=None;self.lookup_entries=[];self.lookup_kill_results=[];self.lookup_unexecuted_branch=None
  self.ranges.extend([(0xfffffe000a56df9c,0xfffffe000a56dffc),(0xfffffe000a52dbd8,0xfffffe000a52dc3c)])
 def read(self,u,access,a,n,v,d):
  pc=u.reg_read(ar.UC_ARM64_REG_PC)
  if self.lookup_active is not None and pc==int(self.lookup_active['origin']['pc'],16)and a==int(self.lookup_active['unknown_address'],16):
   assert n==8 and not any(self.known[a-P:a-P+8]);self.reads.append({'pc':hex(pc),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':8,'bytes_hex':bytes(u.mem_read(a,8)).hex(),'probe_only':False,'discarded_dead_load':True});return
  return super().read(u,access,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if self.lookup_pending is not None:
   self.lookup_pending['register13_after']=hex(self.reg(13));self.lookup_pending=None
  if self.deeper and any(x<=a<z for x,z in self.ranges):
   ins=next(self.cs.disasm(kernel().read(a,4),a))
   if ins.mnemonic=='braa':
    target=self.reg(int(ins.op_str.split(',',1)[0][1:]))
    if not any(x<=target<z for x,z in self.ranges):
     self.lookup_unexecuted_branch={'pc':hex(a),'source_visit_index':self.seq,'target':hex(target),'registers31':[hex(self.reg(j))for j in range(31)],'target_executed':False};return self.stop(a,'before_undeclared_lookup_branch')
  if a in ORIGINS:
   assert self.original_case['context_cache_fixture']=='opaque_nonnull';value=int.from_bytes(u.mem_read(0xfffffe000ccc78d0,8),'little');assert value==P+0xe800
   off,width=ORIGINS[a];sp=u.reg_read(ar.UC_ARM64_REG_SP);snap=self.snapshot(sp+off,width);assert snap['known_mask_hex'][:16]=='00'*8
   self.lookup_prior=self.boundary_snapshot(a,'before_uninitialized_private_read');self.state_predicates.append({'pc':hex(a),'source_visit_index':self.seq,'address':'0xfffffe000ccc78d0','value64':hex(value)})
   row={'origin':{'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'snapshot':snap},'unknown_address':hex(sp+off),'register':'x13','cache_predicate':{'address':'0xfffffe000ccc78d0','value64':hex(value)},'intervening':[],'kill':None}
   self.lookup_windows.append(row);self.lookup_active=row;self.unknown_read=None;self.visit(a);return
  if a in[0xfffffe000a59399c,0xfffffe000a531144]:
   sp=u.reg_read(ar.UC_ARM64_REG_SP);off=0x30 if a==0xfffffe000a59399c else 0x60
   self.lookup_entries.append({'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'registers31':[hex(self.reg(j))for j in range(31)],'saved_table_pointer':self.snapshot(sp+off,8)})
  if self.lookup_active is not None:
   ins=next(self.cs.disasm(kernel().read(a,4),a));rd,wr=ins.regs_access();reads=[ins.reg_name(x)for x in rd];writes=[ins.reg_name(x)for x in wr]
   if any(x in['x13','w13']for x in reads):return self.stop(a,'before_lookup_unknown_register_consumption')
   row={'pc':hex(a),'bytes_hex':kernel().read(a,4).hex(),'source_visit_index':self.seq,'reads':reads,'writes':writes};self.lookup_active['intervening'].append(row)
   if any(x in['x13','w13']for x in writes):
    assert(a==0xfffffe000a551f64 and ins.mnemonic=='adrp')or(a==0xfffffe000a531164 and ins.mnemonic=='and')
    self.lookup_active['kill']=row;self.lookup_pending=self.lookup_active;self.lookup_active=None
  if self.deeper and a not in[self.execute_return_pc,P+0x1f000]and not any(x<=a<z for x,z in self.ranges):return self.stop(a,'before_undeclared_lookup_continuation')
  return super().code(u,a,n,d)
 def run(self):
  r=super().run()
  for w in self.lookup_windows:
   if w['kill']is None:
    for row in self.reads:
     if row['source_visit_index']==w['origin']['source_visit_index']and row.get('discarded_dead_load'):row.pop('discarded_dead_load');row['tracked_unknown_load']=True
  r.update(lookup_prior_boundary=self.lookup_prior,lookup_entries=self.lookup_entries,state_dead_load_windows=self.lookup_windows,dead_register_value_live_at_boundary=self.lookup_active is not None,lookup_table_address=hex(TABLE),lookup_table_initial4096_hex=kernel().read(TABLE,4096).hex(),lookup_unexecuted_branch=self.lookup_unexecuted_branch,uninitialized_private_loads=[x for x in self.reads if x.get('discarded_dead_load')or x.get('tracked_unknown_load')])
  assert not self.lookup_pending
  return r
def cases():
 parents=[c for c in state_cases()if c.get('context_cache_fixture')=='opaque_nonnull']
 yield from parents
 for provider in['vault','allowed']:
  parent=next(c for c in parents if c['provider']==provider and c['global_fixture']=='original'and c['placement']==0 and c['auxiliary_location']=='adjacent')
  for ctx in[0,1,0x3ff,0x400,0xffffffff,0x100000000,0x1234567800000000,0xffffffffffffffff]:
   c=json.loads(json.dumps(parent));c['context64']=ctx
   if provider=='vault':c['inputs8'][1]=ctx
   yield c
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Lookup(c);r=f.run();del f;rows.append(r);gc.collect()
  print(json.dumps({'case':j,'provider':c['provider'],'context64':hex(c['context64']),'boundary':r['boundary']['kind'],'pc':r['boundary']['pc'],'windows':[(w['kill']['pc']if w['kill']else None,len(w['intervening']))for w in r['state_dead_load_windows']]}),flush=True)
 deps=['probe_lskd_state.py','lskd_state_spec.py','lskd_state_contracts.json','probe_lskd_continuations.py','lskd_continuations_contracts.json','probe_lskd_request.py','kernel_native_reader.py','kext_port_tools.py']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'model_memory_writes':0,'native_target_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False}
 (ROOT/'lskd_lookup_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
