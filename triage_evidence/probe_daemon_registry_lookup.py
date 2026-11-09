#!/usr/bin/env python3
"""Characterize explicit registry-state inputs through the original mode471C
caller. Fixtures establish private owners, not native population or reachability.
No fixture PC transition, native PAC/API, IPC or IDB mutation is performed.
O(cases*(source visits+effects+expression DAG)) time/space.
"""
import json,struct,hashlib,base64,zlib,itertools
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE
from probe_daemon_descriptor_producers import Run,cases as preceding_cases,P
from probe_daemon_mode471c_lifecycle import source_input
from daemon_mode471c_lifecycle_symbolic import Lifecycle
KEYS=P+0x10000;PAYLOAD=P+0x18000;LOCK=0x690000f000
MASK64=(1<<64)-1;MASK32=(1<<32)-1;ENC32=0x8b3dc651;ENC64=0xe3b88695c0d52dbc

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def execute(cfg):
 entry=next(preceding_cases());entry.update(nonnull=True,placement=cfg['placement'],controllers=cfg['controllers']);r=Run(entry)
 for off,root in[(0xa28,0x100fc4230),(0xa30,0x101031fa0)]:r.fixture(r.C+off,struct.pack('<Q',root))
 r.fixture(r.TOKEN,source_input(cfg['input_word']^ENC64))
 for address,value,extent in[(0x1010c67c0,LOCK,8),(0x1010c67d0,len(cfg['records']),4),(0x1010c67a8,KEYS,8),(0x1010c9288,PAYLOAD if cfg['payload_nonnull']else 0,8),(0x1010ca2b0,len(cfg.get('payload_keys',[])),4)]:
  b=value.to_bytes(extent,'little');r.ensure(address,extent);r.u.mem_write(address,b);r.image_fixtures.append({'address':hex(address),'bytes_hex':b.hex(),'provenance':'declared_registry_state_input; native publishers unknown'})
 for j,rec in enumerate(cfg['records']):r.fixture(KEYS+16*j,struct.pack('<QII',rec['key64']^ENC64,rec['tag32']^ENC32,rec['state32']^ENC32))
 for j,key in enumerate(cfg.get('payload_keys',[])):r.fixture(PAYLOAD+32*j,struct.pack('<Q',key^ENC64))
 prefix=r.run();v=Lifecycle.from_run(r);v.configure({'old_cell':LOCK,'outcomes':[],'once_completed':cfg['once_completed'],'primitive_status':cfg['primitive_status'],'callback_gap':cfg['callback_gap']});start=int(prefix['boundary']['pc'],16);boundary=v.run_lifecycle(start,limit=50000)
 trace={'steps':v.steps,'boundary':boundary,'source_pool':v.pool,'used_fixups':[hex(a)for a in sorted(v.fixups)],'origins':[{'offset':off,**data}for off,data in sorted(v.unknown_inputs_used.items())],'API_origins':v.api_origins,'api_models':v.api_models,'allocated_owners':[{'address':hex(h),'size_bytes':n}for h,n in sorted(v.heaps.items())],'borrowed_owners':[{'address':hex(h),'size_bytes':n}for h,n in sorted(v.borrowed_owners.items())],'registry_input_owners':[{'address':hex(KEYS),'size_bytes':16*len(cfg['records']),'initial_bytes':'specified encoded key/tag/state fields'},{'address':hex(PAYLOAD),'size_bytes':32*max(len(cfg['records']),len(cfg.get('payload_keys',[]))),'initial_bytes':'first8 bytes specified for each payload key; remaining private bytes arbitrary'}]if cfg['records']else[],'retired_owners':[{'address':hex(h),'size_bytes':n}for h,n in v.retired_owners],'callback_pending':v.callback_pending is not None,'definitions':v.definitions,'initial_registers':prefix['boundary']['registers31'],'initial_SP':prefix['boundary']['SP'],'changed_bytes':[{'address':hex(a),'value':v.shape(v.bytes[a],1)}for a in sorted(v.changed)]};raw=json.dumps(trace,separators=(',',':')).encode();return{'configuration':cfg,'prefix':prefix,'source_visits':len(v.steps),'arbitrary_API_bytes':len(v.api_origins),'api_calls':len(v.api_models),'boundary':boundary,'payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode(),'payload_sha256':hashlib.sha256(raw).hexdigest(),'native_target_executed':False}
def outer_cases():
 D=0x123456789abcdef0
 for N,which,placement in itertools.product([1,2,3,10],['miss','first','last','low_tag_only'],[0,0x100]):
  recs=[{'key64':0x1111111100000000+j,'tag32':0x22220000+j,'state32':0}for j in range(N)]
  if which!='miss':
   j=0 if which in['first','low_tag_only']else N-1;recs[j]={'key64':D if which!='low_tag_only'else D^(1<<63),'tag32':D&MASK32,'state32':0}
  yield{'input_word':D,'records':recs,'category':which,'payload_nonnull':True,'old_cell':LOCK,'outcomes':[],'placement':placement,'controllers':[0,0]if not placement else[0xffffffff,0x87654321],'once_completed':True,'primitive_status':0 if not placement else 22,'callback_gap':256 if not placement else 512}
def cases():
 for cfg in outer_cases():
  cfg['payload_keys']=[];yield cfg
 D=0x123456789abcdef0
 for M,which,placement in itertools.product([1,2,3,10],['first','last','miss'],[0,0x100]):
  if M==1 and which=='last':continue
  cfg=next(c for c in outer_cases()if len(c['records'])==3 and c['category']=='last'and c['placement']==placement);cfg['category']='inner_'+which;keys=[0x7777777700000000+j for j in range(M)]
  if which!='miss':keys[0 if which=='first'else M-1]=D
  cfg['payload_keys']=keys;yield cfg
def main():
 rows=[]
 for j,cfg in enumerate(cases()):
  r=execute(cfg);rows.append(r);print(json.dumps({'case':j,'N':len(cfg['records']),'category':cfg['category'],'source_visits':r['source_visits'],'boundary_PC':r['boundary']['pc'],'boundary_kind':r['boundary']['kind'],'reason':r['boundary'].get('reason','')[:160],'target':r['boundary'].get('target')}),flush=True)
 deps=['probe_daemon_descriptor_producers.py','probe_daemon_mode471c_lifecycle.py','daemon_mode471c_lifecycle_symbolic.py','continue_daemon_descriptor_producers.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_registry_lookup_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
