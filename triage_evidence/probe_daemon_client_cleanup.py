#!/usr/bin/env python3
"""Supply an explicit task-self word after second-allocation failure and stop
before its next imported call. The task name is a private u32 token, not a
native right. No native task query, VM call, allocator or IPC executes.
O(cases*source visits) time, O(one private CPU map+journals) space.
"""
import json
from daemon_receive_tools import ROOT,SOURCE
from capture_daemon_record720 import sha
from probe_daemon_client_pair import Run as Pair
from probe_daemon_descriptor_producers import IMPORTS
SYMBOL='libSystem/_mach_task_self_'
class Run(Pair):
 def __init__(self,index,stage,first,plan):
  super().__init__(index,stage,first,plan,'null');value={0:0x123403,3:0xffffffff}[index];at=IMPORTS[SYMBOL];self.import_word_models[at]=(SYMBOL,value);self.image_fixtures.append({'address':hex(at),'bytes_hex':value.to_bytes(8,'little').hex(),'symbol':SYMBOL,'provenance':'declared imported-data word; only low u32 is consumed; not a native task right'});self.c['cleanup_task_word_model']=hex(value)
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for first in ['boolean_false','boolean_true']:
  for plan in ['neither','coreml_only','classic_only','both']:
   for j in [0,3]:
    r=Run(j,stage,first,plan).run();rows.append(r);print(json.dumps({'first':first,'plan':plan,'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_client_pair.py','daemon_mig_handover_symbolic.json']},'cases':rows,'native_target_executed':False,'native_task_right_observed':False,'full_goal_complete':False};(ROOT/'daemon_client_object_cleanup_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
