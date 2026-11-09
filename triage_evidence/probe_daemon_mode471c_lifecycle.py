#!/usr/bin/env python3
"""Continuous mode471C prefix plus declared allocator/initializer outcomes.
Opaque input and source-mode-derived word fixtures remain separate. Original
source continues until a genuine unresolved effect/new call/allocation boundary.
O(cases*(prefix+continuation+byte effects+expression DAG)) time/space.
"""
import json,hashlib,struct,base64,zlib,itertools
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE
from probe_daemon_descriptor_producers import Run,cases as preceding_cases
from daemon_mode471c_lifecycle_symbolic import Lifecycle,CELL,HEAP
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def source_input(word):return(word^0x9898989898989898^0xe3b88695c0d52dbc).to_bytes(8,'big')
def execute(cfg):
 entry=next(preceding_cases());entry.update(nonnull=True,placement=cfg.get('placement',0),controllers=cfg.get('controllers',[0,0]));r=Run(entry)
 for off,root in [(0xa28,0x100fc4230),(0xa30,0x101031fa0)]:r.fixture(r.C+off,struct.pack('<Q',root))
 if cfg['input_word']is not None:r.fixture(r.TOKEN,source_input(cfg['input_word']))
 old=cfg.get('old_cell',0);r.ensure(CELL,8);r.u.mem_write(CELL,struct.pack('<Q',old));r.image_fixtures.append({'address':hex(CELL),'bytes_hex':struct.pack('<Q',old).hex(),'provenance':'declared_prior_lock_cell'});prefix=r.run();v=Lifecycle.from_run(r);v.configure(cfg);start=int(prefix['boundary']['pc'],16);boundary=v.run_lifecycle(start,limit=50000);trace={'steps':v.steps,'boundary':boundary,'source_pool':v.pool,'used_fixups':[hex(a)for a in sorted(v.fixups)],'origins':[{'offset':off,**data}for off,data in sorted(v.unknown_inputs_used.items())],'API_origins':v.api_origins,'api_models':v.api_models,'allocated_owners':[{'address':hex(h),'size_bytes':n}for h,n in sorted(v.heaps.items())],'borrowed_owners':[{'address':hex(h),'size_bytes':n}for h,n in sorted(v.borrowed_owners.items())],'retired_owners':[{'address':hex(h),'size_bytes':n}for h,n in v.retired_owners],'callback_pending':v.callback_pending is not None,'definitions':v.definitions,'initial_registers':prefix['boundary']['registers31'],'initial_SP':prefix['boundary']['SP'],'changed_bytes':[{'address':hex(a),'value':v.shape(v.bytes[a],1)}for a in sorted(v.changed)]};raw=json.dumps(trace,separators=(',',':')).encode();return{'configuration':cfg,'prefix':prefix,'source_visits':len(v.steps),'source_pool_instructions':len(v.pool),'unknown_input_bytes_used':len(v.unknown_inputs_used),'arbitrary_API_bytes':len(v.api_origins),'api_calls':len(v.api_models),'boundary':boundary,'payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode(),'payload_sha256':hashlib.sha256(raw).hexdigest(),'native_target_executed':False}
def cases():
 options=[{'malloc_nonnull':False,'init_status':0}]+[{'malloc_nonnull':True,'init_status':s}for s in[0,12,16,22,0xffffffff]]
 for old,placement,once in itertools.product([0,0x690000f000],[0,0x100],[False,True]):
  for o in options if old==0 else[None]:yield{'input_word':None,'old_cell':old,'outcomes':[o]if o is not None else[],'placement':placement,'controllers':[0,0]if not placement else[0xffffffff,0x87654321],'once_completed':once,'primitive_status':0 if not placement else 22,'callback_gap':256 if not placement else 512}
def main():
 rows=[]
 for j,cfg in enumerate(cases()):
  r=execute(cfg);rows.append(r);print(json.dumps({'case':j,'configuration':cfg,'source_visits':r['source_visits'],'api_calls':r['api_calls'],'boundary_kind':r['boundary']['kind'],'boundary_PC':r['boundary']['pc'],'boundary_target':r['boundary'].get('target'),'reason':r['boundary'].get('reason','')[:250]}),flush=True)
 deps=['daemon_mode471c_lifecycle_symbolic.py','probe_daemon_descriptor_producers.py','continue_daemon_descriptor_producers.py','daemon_descriptor_producers_source.json','daemon_context_lock_symbolic.py','daemon_import_bindings.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_mode471c_lifecycle_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
