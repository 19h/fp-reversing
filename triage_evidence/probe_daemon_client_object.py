#!/usr/bin/env python3
"""Continue the source chain through one declared malloc(32) outcome.
Allocation bytes remain undefined until original source writes them. No native
allocator/framework/IPC executes. O(cases*visits) time, O(private map+journals)
space. The original entry and all predecessor API models remain explicit.
"""
import json
from daemon_receive_tools import ROOT,SOURCE
from capture_daemon_record720 import sha
from probe_daemon_boolean_chain import Run as Chain
from probe_daemon_descriptor_producers import P
class Run(Chain):
 def __init__(self,index,stage,first,plan,allocation):
  self.plan=plan;self.allocation=allocation;self.allocations=[]
  super().__init__(index,stage,first,'boolean_true'if plan=='both'else'boolean_false')
  self.c.update({'client_bit_plan':plan,'client_object_allocation':allocation})
 def code(self,u,a,n,d):
  if self.active and 'key'in self.active and self.plan in ['coreml_only','classic_only']:
   key=self.active['key']['ASCII'];take=key==('FairPlay-CoreML-Client'if self.plan=='coreml_only'else'FairPlay-Classic-Client');self.chain_mode='boolean_true'if take else'boolean_false'
  if a==0x100570148 and not self.allocations:
   assert self.reg(0)==32
   result=0 if self.allocation=='null'else P+0x30000
   self.allocations.append({'pc':hex(a),'source_visit_index':self.seq,'size_bytes':32,'returned_address':hex(result),'state_before':self.state(),'native_allocator_executed':False,'contents_initially_defined':False})
   return self.model(u,a,'libSystem/_malloc',result)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['client_object_allocations']=self.allocations
  if self.allocations and self.allocation!='null':r['client_object_final']=self.snapshot(P+0x30000,32)
  return r
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for first in ['boolean_false','boolean_true']:
  for plan in ['neither','coreml_only','classic_only','both']:
   for allocation in ['null','nonnull']:
    for j in [0,3]:
     r=Run(j,stage,first,plan,allocation).run();rows.append(r);print(json.dumps({'first':first,'plan':plan,'allocation':allocation,'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_boolean_chain.py','daemon_mig_handover_symbolic.json']},'cases':rows,'native_target_executed':False,'native_allocator_executed':False,'full_goal_complete':False};(ROOT/'daemon_client_object_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
