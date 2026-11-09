#!/usr/bin/env python3
"""Continue original VM cleanup under explicit u32 return models and stop
before the next unmodeled API or unavailable owner. No native VM/free/IPC.
O(cases*source visits) time, O(one private CPU map+journals) space.
"""
import json
from daemon_receive_tools import ROOT,SOURCE
from capture_daemon_record720 import sha
from probe_daemon_client_cleanup import Run as BeforeVM
class Run(BeforeVM):
 def __init__(self,index,stage,first,plan,status):
  self.vm_status=status;self.vm_returns=[];super().__init__(index,stage,first,plan);self.c['VM_cleanup_return_model']=hex(status)
 def code(self,u,a,n,d):
  if a==0x1004776c0 and not self.vm_returns:
   assert self.reg(1)==self.reg(2)==0
   self.vm_returns.append({'pc':hex(a),'source_visit_index':self.seq,'arguments8':[hex(self.reg(j))for j in range(8)],'return_value':hex(self.vm_status),'native_VM_executed':False})
   return self.model(u,a,'libSystem/_vm_deallocate',self.vm_status)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['VM_cleanup_returns']=self.vm_returns;return r
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for first in ['boolean_false','boolean_true']:
  for plan in ['neither','coreml_only','classic_only','both']:
   for status in [0,5,0xffffffff]:
    for j in [0,3]:
     r=Run(j,stage,first,plan,status).run();rows.append(r);print(json.dumps({'first':first,'plan':plan,'status':hex(status),'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_client_cleanup.py','daemon_mig_handover_symbolic.json']},'cases':rows,'native_target_executed':False,'native_VM_executed':False,'full_goal_complete':False};(ROOT/'daemon_vm_cleanup_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
