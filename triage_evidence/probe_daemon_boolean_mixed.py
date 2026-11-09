#!/usr/bin/env python3
"""Mixed CoreML-named/Classic-named Boolean models to distinguish each key's
state contribution. All outcomes are declared, not native entitlement values.
O(cases*source visits) time, O(one private map/journals) space; no native calls.
"""
import json
from daemon_receive_tools import ROOT,SOURCE
from capture_daemon_record720 import sha
from probe_daemon_boolean_chain import Run as Chain
class Run(Chain):
 def __init__(self,index,stage,first,plan):
  self.plan=plan;super().__init__(index,stage,first,'boolean_false');self.c['Boolean_chain_model']=plan
 def code(self,u,a,n,d):
  if self.active and 'key'in self.active:
   key=self.active['key']['ASCII'];assert key in ['FairPlay-CoreML-Client','FairPlay-Classic-Client'];take=(key=='FairPlay-CoreML-Client')if self.plan=='coreml_only'else(key=='FairPlay-Classic-Client');self.chain_mode='boolean_true'if take else'boolean_false'
  return super().code(u,a,n,d)
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for first in ['boolean_false','boolean_true']:
  for plan in ['coreml_only','classic_only']:
   for j in [0,3]:
    r=Run(j,stage,first,plan).run();rows.append(r);print(json.dumps({'first':first,'plan':plan,'environment':j,'visits':len(r['source_visits']),'keys':[e.get('key',{}).get('ASCII')for e in r['Boolean_adapters']],'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_boolean_chain.py','daemon_mig_handover_symbolic.json']},'cases':rows,'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False};(ROOT/'daemon_boolean_chain_mixed_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
