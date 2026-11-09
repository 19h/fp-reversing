#!/usr/bin/env python3
"""Extend the successful descriptor construction with disjoint allocation tokens.
The preceding three-allocation source prefix must remain byte/effect identical.
O(snapshot+source visits+effects) time/space; no native API/PAC execution.
"""
import json,hashlib,base64,zlib
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE
from daemon_context_lock_symbolic import ContextLock

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def unpack(r):return json.loads(zlib.decompress(base64.b64decode(r['payload_zlib_base64'])))
def main():
 snap=json.loads((ROOT/'daemon_context_lock_snapshot.json').read_text());prior=json.loads((ROOT/'daemon_context_lock_profiles.json').read_text());old=unpack(next(r for r in prior['cases']if r['configuration']['name']=='both_locks_success_buffer_1'));cfg={'name':'all_success_extended','outcomes':[{'malloc_nonnull':True,'init_status':0}for _ in range(16)]};v=ContextLock.from_snapshot(snap);v.configure(cfg);boundary=v.run_context_lock(int(snap['boundary']['pc'],16),limit=200000);assert v.steps[:len(old['steps'])]==old['steps'];t={'steps':v.steps,'boundary':boundary,'source_pool':v.pool,'used_fixups':[hex(a)for a in sorted(v.fixups)],'origins':[{'offset':off,**row}for off,row in sorted(v.unknown_inputs_used.items())],'API_origins':v.api_origins,'api_models':v.api_models,'definitions':v.definitions,'changed_bytes':[{'address':hex(a),'value':v.shape(x,1)}for a,x in sorted(v.bytes.items())if a in v.changed],'initial_registers':snap['logical_registers'],'initial_NZCV':snap['NZCV'],'allocated_owners':[{'address':hex(h),'size_bytes':v.heaps[h]}for h in sorted(v.heaps)]};raw=json.dumps(t,separators=(',',':')).encode();row={'configuration':cfg,'source_visits':len(v.steps),'source_pool_opcodes':len(v.pool),'api_calls':len(v.api_models),'unknown_input_bytes_used':len(v.unknown_inputs_used),'arbitrary_API_bytes':len(v.api_origins),'boundary':boundary,'payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode(),'payload_sha256':hashlib.sha256(raw).hexdigest()};deps=['daemon_context_lock_snapshot.json','daemon_context_lock_profiles.json','daemon_context_lock_symbolic.py','daemon_callback_revisit_symbolic.py','daemon_callback_simd.py','daemon_import_bindings.py','daemon_receive_tools.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'case':row,'preceding_prefix_source_visits':len(old['steps']),'preceding_prefix_identical':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_lock_success.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_visits':len(v.steps),'api_calls':len(v.api_models),'allocations':len(v.heaps),'boundary':boundary,'preceding_prefix_identical':True}),flush=True)
if __name__=='__main__':main()
