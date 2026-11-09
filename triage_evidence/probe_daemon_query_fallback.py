#!/usr/bin/env python3
"""Follow original zero-capability/version fallback into its caller continuation.

Preserve prior entry/API/PAC/guard fixtures; no new external model. The leaf
callee reads the prepared record and source-writes its output at+0x10. Stop
before the same unknown iterator load. O(B+C*(V+E+J*F)) time,
O(B+C*(V+E)+F+4096J) space; native target and imports never execute.
"""
import hashlib,json,itertools
from pathlib import Path
from unicorn import arm64_const as ar
from probe_daemon_query_state import FullState as QueryState,full_cases as prior_cases,STATE,EXTENDED
from probe_daemon_iokit_census import P,LIMIT
from daemon_receive_tools import ROOT,SOURCE,IMAGE
RANGES=[(0x10043bd18,0x10043be8c),(0x10025784c,0x1002578b0),(0x10036c670,0x10036c6c4),(0x10034f538,0x10034f59c),(0x100275b80,0x100275bc4),(0x1001a88f8,0x1001a8904),(0x100011678,0x1000116a4),(0x100015278,0x100015290)]
class Fallback(QueryState):
 def __init__(self,c):
  super().__init__(c);self.fallback_calls=[];self.fallback_input_record=None;self.fallback_access_record=None;self.cache_before_fallback=None;self.fallback_returned=False;self.state_before_final_marker=None
 def code(self,u,a,n,d):
  if a==0x100011674:
   self.flush();assert self.reg(8)==0x10043bd18 and self.reg(17)==0xb61a;self.fallback_record=self.snapshot(self.reg(0),16);self.fallback_input_record=self.snapshot(self.reg(0),20);self.cache_before_fallback={'address':hex(STATE),'bytes_hex':bytes(u.mem_read(STATE,24)).hex()};self.fallback_calls.append({'pc':hex(a),'source_visit_index':self.seq,'target':hex(self.reg(8)),'modifier16':hex(self.reg(17)),'registers8':[hex(self.reg(j))for j in range(8)],'target_executed_in_private_guest':True,'native_target_executed':False});self.visit(a);self.set(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(8))
  if a==0x100011678:
   self.flush();self.fallback_returned=True;self.fallback_access_record=self.snapshot(self.reg(0),20)
  if a==0x1003c3aec:self.state_before_final_marker={'address':hex(STATE),'bytes_hex':bytes(u.mem_read(STATE,24)).hex()}
  if not any(x<=a<a+4<=z for x,z in RANGES):return super().code(u,a,n,d)
  self.flush();ins=next(self.dec.disasm(IMAGE.read(a,4),a));m=ins.mnemonic;assert m not in['bl','blr','blraa','br','svc','hvc','smc','retab','retaa'];self.visit(a)
  if m=='braa':
   target=self.reg(int(ins.op_str.split(',',1)[0][1:]));assert any(x<=target<z for x,z in RANGES+EXTENDED),('fallback source escape',hex(a),hex(target));self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'modifier16':hex(self.reg(17))});return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m=='ret':assert self.reg(30)==0x100011678;return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
 def write(self,u,access,a,n,v,d):
  if a==0x1010b6918 and n==8:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,access,a,n,v,d)
 def run(self):
  r=super().run();assert self.helper_returned and self.reason=='before_uninitialized_saved_iterator_read'and not self.extra_calls
  r.update(fallback_calls=self.fallback_calls,fallback_input_record=self.fallback_input_record,fallback_access_record=self.fallback_access_record,cache_before_fallback=self.cache_before_fallback,fallback_returned=self.fallback_returned,state_before_final_marker=self.state_before_final_marker)
  return r

def cases():
 yield from prior_cases()
 base=next(prior_cases())
 for b3,b2,b1,b0,placement in itertools.product([0,45,46,47,255],[0,29,30,31,255],[0,1,255],[0,255],[0,0x100]):
  c=json.loads(json.dumps(base));c.update(placement=placement,words=[(b3<<24)|(b2<<16)|(b1<<8)|b0,0],state_case='accepted_zero_capability_version_boundary');yield c

def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Fallback(c);rows.append(f.run());del f
  if j%32==0:print(json.dumps({'cases_completed':j+1}),flush=True)
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_daemon_query_state.py','probe_daemon_iokit_census.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_query_fallback_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
