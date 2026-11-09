#!/usr/bin/env python3
"""Continuous mode471C compositions for head/interior/exhausted chains and
NULL/non-NULL object fields. Only initial fixtures change; native object types,
producers,imports and PAC remain unexecuted. O(visits+effects+expression DAG).
"""
import json,struct,itertools
from pathlib import Path
import probe_daemon_registry_lookup as producer
from probe_daemon_descriptor_producers import Run as BaseRun,P
OBJECT=P+0x20000;SECOND=P+0x24000;FIELD310=P+0x30000;FIELDD8=P+0x34000
class InitialOwnerRun(BaseRun):
 configuration=None
 def __init__(self,entry):
  super().__init__(entry);cfg=self.configuration;self.fixture(producer.PAYLOAD+16,struct.pack('<Q',OBJECT));nodes=[(OBJECT,0x8b3dc651,0)]if cfg['chain']=='head'else[(OBJECT,0x8b3dc651^22,SECOND),(SECOND,0x8b3dc651 if cfg['chain']=='interior'else 0x8b3dc651^23,0)]
  for at,header,link in nodes:
   self.fixture(at,struct.pack('<I',header));self.fixture(at+0x360,struct.pack('<Q',link));self.fixture(at+0x310,struct.pack('<Q',FIELD310 if cfg['fields']in['310','both']else 0));self.fixture(at+0xd8,struct.pack('<Q',FIELDD8 if cfg['fields']in['d8','both']else 0))
def cases():
 for chain,fields,placement in itertools.product(['head','interior','exhausted'],['none','310','d8','both'],[0,0x100]):
  if chain=='exhausted'and fields!='none':continue
  cfg=next(c for c in producer.cases()if c['category']=='inner_first'and len(c['payload_keys'])==1 and c['placement']==placement);cfg.update(chain=chain,fields=fields,category=chain+'_'+fields);yield cfg
def main():
 rows=[];producer.Run=InitialOwnerRun
 for j,cfg in enumerate(cases()):
  InitialOwnerRun.configuration=cfg;r=producer.execute(cfg);rows.append(r);print(json.dumps({'case':j,'chain':cfg['chain'],'fields':cfg['fields'],'source_visits':r['source_visits'],'boundary_PC':r['boundary']['pc'],'kind':r['boundary']['kind'],'target':r['boundary'].get('target'),'modifier16':r['boundary'].get('modifier16'),'reason':r['boundary'].get('reason','')[:160]}),flush=True)
 deps=['probe_daemon_registry_lookup.py','probe_daemon_descriptor_producers.py','daemon_mode471c_lifecycle_symbolic.py'];out={'scope':__doc__,'generator_sha256':producer.sha(Path(__file__)),'dependencies':{n:producer.sha(producer.ROOT/n)for n in deps},'source_sha256':producer.sha(producer.SOURCE),'cases':rows,'input_owners':{'object1':{'address':hex(OBJECT),'size_bytes':4096},'object2_if_linked':{'address':hex(SECOND),'size_bytes':4096},'opaque_field310_if_nonNULL':{'address':hex(FIELD310),'size_bytes':8},'opaque_fieldD8_if_nonNULL':{'address':hex(FIELDD8),'size_bytes':8}},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(producer.ROOT/'daemon_object_consumers_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
