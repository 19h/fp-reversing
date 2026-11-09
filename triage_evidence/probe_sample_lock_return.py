#!/usr/bin/env python3
"""Source-written preparer error records in reconstructed caller continuations.

Copies exact retained preparer output bytes; caller callee-saved state and
frame are declared contexts, not full call-stack/native reachability proof.
Stops before the caller's indirect branch. O(C*(B+V+E)) time/space.
"""
import hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,TABLE
from probe_kext_close import STACK
from probe_sample_lock import Lock
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Return(Lock):
 def __init__(self,gate,caller):
  shift=int(gate['record'],16)-STACK-0x1000
  super().__init__({'caller':None,'phase':'acquire','explicit':False,'cached':False,'record_shift':shift,'status32':0})
  self.case={'caller':caller,'gate_input':gate['gate_input'],'source_record64_hex':gate['final_preparer_record64_hex']};self.seed(self.p,bytes.fromhex(gate['final_preparer_record64_hex']));self.initial_record=bytes(self.u.mem_read(self.p,128))
  if caller=='first':
   self.start=0xfffffe000a64b220;self.finish=0xfffffe000a64b280;self.setreg(20,self.p);self.setreg(24,0x510);self.setreg(19,0xbac)
   for off,value in{0xa28:STACK+0x5000,0xa08:STACK+0x6000,0xa60:TABLE,0xa30:0xfffffe000ccc3630}.items():self.seed(self.sp+off,struct.pack('<Q',value))
  else:
   assert caller=='second';self.start=0xfffffe000a68f41c;self.finish=0xfffffe000a68f444;self.setreg(19,self.p);self.setreg(20,0x598);self.setreg(21,0x753);self.setreg(26,TABLE)
  self.allowed=[(self.start,self.finish)]
 def hook(self,u,a,n,d):
  if a==self.finish:
   self.flush();self.boundary={'kind':'before_caller_dispatch','pc':hex(a),'target':hex(self.reg(8)),'modifier':hex(self.reg(17)),'registers31':[hex(self.reg(j))for j in range(31)]};return self.stop('declared_boundary')
  return super().hook(u,a,n,d)
def main():
 p=json.loads((ROOT/'sample_lock_profiles.json').read_text());rows=[]
 for i,g in enumerate(p['gate_cases']):
  if g['gate_outcome']!='return':continue
  for caller in['first','second']:
   r=Return(g,caller).run();r['source_gate_case_index']=i;rows.append(r)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_sample_lock.py','sample_lock_profiles.json']},'cases':rows,'native_target_executed':False,'native_lock_executed':False,'full_goal_complete':False};(ROOT/'sample_lock_return_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'caller_return_cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
