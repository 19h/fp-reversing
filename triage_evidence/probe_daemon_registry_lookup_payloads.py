#!/usr/bin/env python3
"""Initial owner/header fixtures extend successful registry lookup. The source
prefix executes continuously; the fixture factory changes initial RAM only.
Native object type, publishers and lifetime remain unknown. O(visits+effects)
time/space; no native imports, IPC, PAC or IDB mutations.
"""
import json,struct
from pathlib import Path
import probe_daemon_registry_lookup as producer
from probe_daemon_descriptor_producers import Run as BaseRun,P
OBJECT=P+0x20000
class InitialOwnerRun(BaseRun):
 configuration=None
 def __init__(self,entry):
  super().__init__(entry);cfg=self.configuration;self.fixture(producer.PAYLOAD+16,struct.pack('<Q',OBJECT if cfg['object_header32']is not None else 0))
  if cfg['object_header32']is not None:self.fixture(OBJECT,struct.pack('<I',cfg['object_header32']))
  if cfg.get('nested_null',False):
   for off in[0x310,0x360]:self.fixture(OBJECT+off,bytes(8))
def main():
 rows=[];producer.Run=InitialOwnerRun
 for header in[None,0x8b3dc651,0x8b3dc651^22]:
  for placement in[0,0x100]:
   for nested_null in[False]if header is None else[False,True]:
    cfg=next(c for c in producer.cases()if c['category']=='inner_first'and len(c['payload_keys'])==1 and c['placement']==placement);cfg['category']='object_NULL'if header is None else'object_header_equal'if header==0x8b3dc651 else'object_header_unequal';cfg['object_header32']=header;cfg['nested_null']=nested_null;InitialOwnerRun.configuration=cfg;r=producer.execute(cfg);rows.append(r);print(json.dumps({'case':len(rows)-1,'category':cfg['category'],'nested_null':nested_null,'source_visits':r['source_visits'],'boundary_PC':r['boundary']['pc'],'boundary_kind':r['boundary']['kind'],'target':r['boundary'].get('target'),'reason':r['boundary'].get('reason','')[:160]}),flush=True)
 deps=['probe_daemon_registry_lookup.py','probe_daemon_descriptor_producers.py','daemon_mode471c_lifecycle_symbolic.py'];out={'scope':__doc__,'generator_sha256':producer.sha(Path(__file__)),'dependencies':{n:producer.sha(producer.ROOT/n)for n in deps},'source_sha256':producer.sha(producer.SOURCE),'cases':rows,'explicit_additional_input_owner':{'address':hex(OBJECT),'size_bytes':872,'known_initial_bytes':4,'remaining_private_bytes':'arbitrary; native extent unknown'},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(producer.ROOT/'daemon_registry_lookup_payloads.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
