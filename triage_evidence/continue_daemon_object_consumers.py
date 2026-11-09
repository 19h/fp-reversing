#!/usr/bin/env python3
"""Repeat original caller compositions with only source-verified free ABI models
added. Initial fixtures are identical to the raw call-boundary stage. No native
APIs/PAC/IPC or source PC transitions. O(source visits+effects+expression DAG).
"""
import json
from pathlib import Path
import probe_daemon_object_consumers as initial
import probe_daemon_registry_lookup as producer
from daemon_object_consumers_symbolic import Consumers

def main():
 rows=[];producer.Run=initial.InitialOwnerRun;producer.Lifecycle=Consumers
 cases=list(initial.cases())
 for chain,fields in[('head','none'),('head','310'),('head','d8'),('head','both'),('interior','none'),('exhausted','none')]:
  cfg=next(c.copy()for c in initial.cases()if c['chain']==chain and c['fields']==fields and c['placement']==0);cfg.update(placement=0x10,controllers=[0x13579bdf,0x2468ace],primitive_status=0,callback_gap=256);cases.append(cfg)
 for j,cfg in enumerate(cases):
  initial.InitialOwnerRun.configuration=cfg;Consumers.input_configuration=cfg;r=producer.execute(cfg);rows.append(r);print(json.dumps({'case':j,'chain':cfg['chain'],'fields':cfg['fields'],'source_visits':r['source_visits'],'boundary_PC':r['boundary']['pc'],'kind':r['boundary']['kind'],'target':r['boundary'].get('target'),'reason':r['boundary'].get('reason','')[:160]}),flush=True)
 deps=['probe_daemon_object_consumers.py','probe_daemon_registry_lookup.py','daemon_object_consumers_symbolic.py','daemon_mode471c_lifecycle_symbolic.py'];out={'scope':__doc__,'generator_sha256':producer.sha(Path(__file__)),'dependencies':{n:producer.sha(producer.ROOT/n)for n in deps},'source_sha256':producer.sha(producer.SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(producer.ROOT/'daemon_object_consumers_continuations.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
