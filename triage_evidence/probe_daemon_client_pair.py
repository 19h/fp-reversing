#!/usr/bin/env python3
"""Continue the distinct 16-byte allocation after a declared 32-byte object.
No native allocator, framework or IPC. Stop at the next unmodeled API or
unavailable owner; new allocation contents are not declared initialized.
O(cases*visits) time, O(one private CPU map + journals) space.
"""
import json
from daemon_receive_tools import ROOT,SOURCE
from capture_daemon_record720 import sha
from probe_daemon_client_object import Run as Object
from probe_daemon_descriptor_producers import P
class Run(Object):
 def __init__(self,index,stage,first,plan,pair):
  self.pair=pair;super().__init__(index,stage,first,plan,'nonnull');self.c['client_pair_allocation']=pair
 def code(self,u,a,n,d):
  if a==0x100699858 and len(self.allocations)==1:
   assert self.reg(0)==16
   result=0 if self.pair=='null'else P+0x31000
   self.allocations.append({'pc':hex(a),'source_visit_index':self.seq,'size_bytes':16,'returned_address':hex(result),'state_before':self.state(),'native_allocator_executed':False,'contents_initially_defined':False})
   return self.model(u,a,'libSystem/_malloc',result)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run()
  if self.pair!='null':r['client_pair_final']=self.snapshot(P+0x31000,16)
  return r
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for first in ['boolean_false','boolean_true']:
  for plan in ['neither','coreml_only','classic_only','both']:
   for pair in ['null','nonnull']:
    for j in [0,3]:
     r=Run(j,stage,first,plan,pair).run();rows.append(r);print(json.dumps({'first':first,'plan':plan,'pair':pair,'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_client_object.py','daemon_mig_handover_symbolic.json']},'cases':rows,'native_target_executed':False,'native_allocator_executed':False,'full_goal_complete':False};(ROOT/'daemon_client_object_pair_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
