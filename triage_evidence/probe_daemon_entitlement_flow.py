#!/usr/bin/env python3
"""Continue the source-established entitlement consumer into its original
caller. Preserve pre-query declared API models; after the original return,
stop before every unmodeled API/owner/undefined read. No new API models,
fixture PC transitions, native target, framework or IPC execution.
O(cases*source visits) time, O(one private CPU map and journals) space.
"""
import json
from daemon_receive_tools import ROOT,SOURCE
from capture_daemon_record720 import sha
from probe_daemon_entitlement_result import Run as BeforeReturn,SCENARIOS
from probe_daemon_record40_consumer import RETURN
from probe_daemon_descriptor_producers import Run as Source
class Run(BeforeReturn):
 def __init__(self,index,stage,scenario):
  self.after_query_return=False;self.continuation_entry=None;super().__init__(index,stage,scenario)
 def code(self,u,a,n,d):
  if a==RETURN and not self.after_query_return:
   self.flush();self.after_query_return=True;self.continuation_entry={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(self.register('sp')),'registers31':[hex(self.reg(j))for j in range(31)],'marker':self.snapshot(self.R+8,1),'flag':self.snapshot(0x6800051f2f,1)}
  if self.after_query_return:return Source.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['continuation_entry']=self.continuation_entry;return r
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for mode in SCENARIOS:
  for j in range(4):
   r=Run(j,stage,mode).run();rows.append(r);print(json.dumps({'scenario':mode,'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_entitlement_result.py','probe_daemon_record40_consumer.py','probe_daemon_descriptor_producers.py','daemon_mig_handover_symbolic.json']},'cases':rows,'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False};(ROOT/'daemon_entitlement_flow_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
