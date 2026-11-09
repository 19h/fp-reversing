#!/usr/bin/env python3
"""Continue the source-issued free request for the modeled 32-byte object.
The void callback is explicit and no native allocator/VM/IPC executes.
Retired physical private bytes are retained solely as a storage snapshot;
validation rejects any later source access to that allocation in these paths.
O(cases*source visits) time, O(one private CPU map+journals) space.
"""
import json
from daemon_receive_tools import ROOT,SOURCE
from capture_daemon_record720 import sha
from probe_daemon_vm_cleanup import Run as BeforeFree
from probe_daemon_descriptor_producers import P
class Run(BeforeFree):
 def __init__(self,index,stage,first,plan,status):
  self.retirements=[];super().__init__(index,stage,first,plan,status)
 def code(self,u,a,n,d):
  if a==0x100541bec and not self.retirements:
   assert self.reg(0)==P+0x30000
   self.flush();self.retirements.append({'pc':hex(a),'source_visit_index':self.seq,'address':hex(self.reg(0)),'size_bytes':32,'before_free_request':self.snapshot(self.reg(0),32),'native_free_executed':False})
   return self.model(u,a,'libSystem/_free',0 if self.source_index==0 else (1<<64)-1)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['source_retirements']=self.retirements
  if self.retirements:r['retired_object_storage_snapshot']=r.pop('client_object_final')
  return r
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for first in ['boolean_false','boolean_true']:
  for plan in ['neither','coreml_only','classic_only','both']:
   for status in [0,5,0xffffffff]:
    for j in [0,3]:
     r=Run(j,stage,first,plan,status).run();rows.append(r);print(json.dumps({'first':first,'plan':plan,'status':hex(status),'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_vm_cleanup.py','daemon_mig_handover_symbolic.json']},'cases':rows,'native_target_executed':False,'native_free_executed':False,'full_goal_complete':False};(ROOT/'daemon_vm_cleanup_retire_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
