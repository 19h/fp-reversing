#!/usr/bin/env python3
"""Eight finite original-callback/worker cases; declared APIs and private CPUs.

Two isolated analysis processes;no target concurrency or native APIs. All
input and environment choices are retained. O(C*(B+V+E+S)) bounded time/space.
"""
import base64,hashlib,json,multiprocessing,zlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from probe_rpc502_startup import StartupProbe,ROOT,SOURCE
from probe_rpc502_body import file_for_body
from rpc502_body_fixtures import certificate

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cases():
 body=certificate(name=None);raw=file_for_body(body,n=4096).hex();out=[]
 for label,extra in [('cold_worker',{'execute_startup':False}),('arena_malloc_NULL',{'arena_malloc_NULL':True}),('time_failure',{'gettimeofday_result':-1}),('lock_init_failure',{'startup_rwlock_init_result':17}),('startup_budget',{'startup_instruction_budget':10000}),('initialized_worker',{}),('quantum250k_prefix',{'quantum_instructions':250000,'worker_instruction_budget':500000}),('entropy_time_prefix',{'arc4random_u32':[0,0xffffffff,0x11223344],'tv_sec':0,'tv_usec':999999,'worker_instruction_budget':500000})]:
  out.append({'label':label,'file_hex':raw,'fixture':{'body_cpu_model':'MAX',**extra}})
 return out

def run_case(case):
 q=StartupProbe(bytes.fromhex(case['file_hex']),case['fixture']);r=q.run();return r,q.instruction_bank

def main():
 pool={};rows=[]
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  for case,(r,bank)in zip(cases(),ex.map(run_case,cases(),buffersize=2)):
   for a,e in bank.items():assert a not in pool or pool[a]==e;pool[a]=e
   rows.append({'case':case,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode())).decode()});print('CASE',case['label'],r['steps'],r['stop_reason'],r['startup_returned'],r['final_readiness_hex'],r['final_startup_status_hex'],r['records'][-1:]if r['records']else[],flush=True)
 deps=['probe_rpc502_startup.py','probe_rpc502_body.py','rpc502_body_fixtures.py','probe_rpc502_supp.py','probe_rpc502_supp_cases.py','probe_rpc502_parser.py','probe_rpc502_sidecar_contents.py','probe_rpc502_sidecar_copy.py','probe_rpc502_sidecar_mapping.py','probe_rpc502_sidecar_data.py','probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py','daemon_rpc502_context_probe.py','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'original_instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_startup_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print('COUNTS',len(rows),len(pool),flush=True)

if __name__=='__main__':main()
