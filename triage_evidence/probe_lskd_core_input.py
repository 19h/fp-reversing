#!/usr/bin/env python3
"""Numeric input guard successors in the original selector18 core.

All private reads require source-defined bytes. Allocator returns inherited
from Workspace affect registers only. Two additional register-only free-return models complete the rejection epilogue.
The selected input path stops before IOMallocData. O(C*(B+V+E))
time/space,30000 source visits/case; abstract PAC, no native API/IPC.
"""
import hashlib,json
from pathlib import Path
from unicorn import arm64_const as ar
from probe_lskd_core_workspace import Workspace,cases as prior_cases,WORK,AUX
from probe_legacy_stack import P,HALT,kernel
from kext_port_tools import ROOT,SOURCE
class Input(Workspace):
 def __init__(self,c):
  super().__init__(c);self.ranges.extend([(0xfffffe000a56d1b4,0xfffffe000a56d268),(0xfffffe000a58c0bc,0xfffffe000a58c1f4)]);self.shape_boundary=None;self.preceding_shape_dispatch=None;self.cleanup_models=[]
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000a594d14:
   self.shape_boundary={'kind':'before_core_input_guard_selected_fragment','pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]};target=self.reg(8);assert target in[0xfffffe000a56d1b4,0xfffffe000a58c0bc];self.preceding_shape_dispatch={'pc':hex(a),'source_visit_index':self.seq,'target':hex(target),'registers31':self.shape_boundary['registers31'],'target_executed':False};self.visit(a);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if a in[0xfffffe000a58c14c,0xfffffe000a58c194]:
   target=0xfffffe000c4ba368 if a==0xfffffe000a58c14c else 0xfffffe000c4b9a24;assert self.reg(10 if a==0xfffffe000a58c14c else 8)==target
   assert (self.reg(0),self.reg(1))==((0xfffffe000847aee0,AUX)if a==0xfffffe000a58c14c else(WORK,16384))
   self.cleanup_models.append({'pc':hex(a),'target':hex(target),'registers8':[hex(self.reg(j))for j in range(8)],'modifier16':hex(self.reg(17)),'source_visit_index':self.seq,'target_executed':False,'memory_effects_modeled':False});return self.register_return(a,target,'typed_free_register_return'if a==0xfffffe000a58c14c else'aligned_free_register_return',0xdead0000feed0000)
  if a==HALT:return self.stop(a,'returned_original_core')
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(shape_boundary=self.shape_boundary,preceding_shape_dispatch=self.preceding_shape_dispatch,shape_edge_executed=self.shape_boundary is not None,cleanup_models=self.cleanup_models,complete_original_rejection_return=self.reason=='returned_original_core',complete_core_operation_executed=False);return r
def cases():
 cc=list(prior_cases());yield from cc;seen={json.dumps(c,sort_keys=True)for c in cc};base=cc[0]
 for entry in['core','provider']:
  for g in['original','zero','declared_noise']:
   for place in[0,0x100]:
    for pointer,length in[(P+0x2000,16),(P+0x2000,65536),(P+0x2000,15),(P+0x2000,65537),(0,16)]:
     c=json.loads(json.dumps(base));c.update(entry_kind=entry,global_fixture=g,placement=place);c['inputs8'][:2]=[pointer,length];key=json.dumps(c,sort_keys=True)
     if key not in seen:seen.add(key);yield c
if __name__=='__main__':
 rows=[]
 for j,c in enumerate(cases()):
  f=Input(c);r=f.run();del f;rows.append(r);print(json.dumps({'case':j+1,'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'pc':r['boundary']['pc'],'additional_calls':r['additional_calls'][-1:]}),flush=True)
 out={'scope':__doc__,'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'dependencies':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest()for n in['probe_lskd_core_workspace.py','probe_lskd_writers.py','probe_legacy_stack.py','legacy_stack_contracts.json','kernel_native_reader.py','kext_port_tools.py']},'kernel_collection_sha256':kernel().sha256,'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'cases':rows,'model_memory_writes':0,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_core_input_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
