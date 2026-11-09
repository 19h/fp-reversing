#!/usr/bin/env python3
"""Continue the sealed arena lock creator under declared API outcomes.
O(cases*(snapshot+source visits+effects)) time/space. Unknown caller-clobbered
registers and post-initializer object bytes remain arbitrary. No native APIs.
"""
import json,hashlib,zlib,base64
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE
from daemon_context_lock_symbolic import ContextLock,HEAP,EXTENT

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def cases():
 opts=[{'malloc_nonnull':False,'init_status':0}]+[{'malloc_nonnull':True,'init_status':s}for s in [0,12,16,22,0xffffffff]]
 for j,o in enumerate(opts):
  if j==1:
   for k,other in enumerate(opts):
    if k==1:
     for nonnull in [False,True]:yield {'name':'both_locks_success_buffer_'+str(int(nonnull)),'outcomes':[o,other,{'malloc_nonnull':nonnull,'init_status':0}]}
    else:yield {'name':'first_success_second_'+str(k),'outcomes':[o,other]}
  else:yield {'name':'first_'+str(j),'outcomes':[o]}
def main():
 snap=json.loads((ROOT/'daemon_context_lock_snapshot.json').read_text());rows=[]
 for cfg in cases():
  v=ContextLock.from_snapshot(snap);v.configure(cfg);b=v.run_context_lock(int(snap['boundary']['pc'],16),limit=200000);t={'steps':v.steps,'boundary':b,'source_pool':v.pool,'used_fixups':[hex(a)for a in sorted(v.fixups)],'origins':[{'offset':off,**row}for off,row in sorted(v.unknown_inputs_used.items())],'API_origins':v.api_origins,'api_models':v.api_models,'definitions':v.definitions,'changed_bytes':[{'address':hex(a),'value':v.shape(x,1)}for a,x in sorted(v.bytes.items())if a in v.changed],'initial_registers':snap['logical_registers'],'initial_NZCV':snap['NZCV'],'allocated_owners':[{'address':hex(h),'size_bytes':v.heaps[h]}for h in sorted(v.heaps)]};raw=json.dumps(t,separators=(',',':')).encode();rows.append({'configuration':cfg,'source_visits':len(v.steps),'source_pool_opcodes':len(v.pool),'api_calls':len(v.api_models),'unknown_input_bytes_used':len(v.unknown_inputs_used),'arbitrary_API_bytes':len(v.api_origins),'boundary':b,'payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode(),'payload_sha256':hashlib.sha256(raw).hexdigest()});print(json.dumps({k:rows[-1][k]for k in ['configuration','source_visits','api_calls','unknown_input_bytes_used','arbitrary_API_bytes','boundary']}),flush=True)
 deps=['daemon_context_lock_snapshot.json','daemon_context_lock_symbolic.py','daemon_callback_revisit_symbolic.py','daemon_callback_simd.py','daemon_import_bindings.py','daemon_receive_tools.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_lock_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
