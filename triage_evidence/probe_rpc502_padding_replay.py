#!/usr/bin/env python3
"""Fresh complete original executions for the preserved padding-read corpus.

Writes a distinct replay artifact;never rewrites retained profiles. Two
isolated analysis processes,not agents. O(C*(B+V+E+S)) bounded work/space.
No internal interventions,native target/API or IDB action.
"""
import base64,hashlib,json,multiprocessing,zlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from probe_rpc502_padding_cases import cases,run_case,ROOT,SOURCE

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 original=json.loads((ROOT/'rpc502_padding_profiles.json').read_text());rows=[];pool={}
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  for case,(r,bank)in zip(cases(),ex.map(run_case,cases(),buffersize=2)):
   for a,e in bank.items():assert a not in pool or pool[a]==e;pool[a]=e
   rows.append({'case':case,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode())).decode()});print('FRESH',case['label'],r['steps'],r['stop_reason'],len(r['padding_reads']),flush=True)
 deps=sorted(set(original['dependencies'])|{'probe_rpc502_padding_cases.py','rpc502_padding_profiles.json'});out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'original_instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_padding_replays.json').write_text(json.dumps(out,indent=2)+'\n');print('COUNTS',len(rows),len(pool),flush=True)
if __name__=='__main__':main()
