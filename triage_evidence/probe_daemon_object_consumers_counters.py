#!/usr/bin/env python3
"""Supplemental occupied-key counter inputs for the same continuous cleanup.
Three defined key records and active_keys=3; native publishers remain unknown.
O(source visits+effects+expression DAG), no source PC or native API mutation.
"""
import json,struct
from pathlib import Path
import probe_daemon_object_consumers as initial
import probe_daemon_registry_lookup as producer
from daemon_object_consumers_symbolic import Consumers
class CounterRun(initial.InitialOwnerRun):
 def __init__(self,entry):
  super().__init__(entry);a=0x1010c5754;b=struct.pack('<I',self.configuration['active_keys']);self.ensure(a,4);self.u.mem_write(a,b);self.image_fixtures.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'declared active-key counter input; three occupied key records'})
def main():
 rows=[];producer.Run=CounterRun;producer.Lifecycle=Consumers
 for chain in['head','interior','exhausted']:
  cfg=next(c for c in initial.cases()if c['chain']==chain and c['fields']=='none'and c['placement']==0);cfg['active_keys']=len(cfg['records']);CounterRun.configuration=cfg;Consumers.input_configuration=cfg;r=producer.execute(cfg);rows.append(r);print(json.dumps({'case':len(rows)-1,'chain':chain,'source_visits':r['source_visits'],'boundary_PC':r['boundary']['pc'],'reason':r['boundary'].get('reason','')[:120]}),flush=True)
 deps=['probe_daemon_object_consumers.py','probe_daemon_registry_lookup.py','daemon_object_consumers_symbolic.py'];out={'scope':__doc__,'generator_sha256':producer.sha(Path(__file__)),'dependencies':{n:producer.sha(producer.ROOT/n)for n in deps},'source_sha256':producer.sha(producer.SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(producer.ROOT/'daemon_object_consumers_counters.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
