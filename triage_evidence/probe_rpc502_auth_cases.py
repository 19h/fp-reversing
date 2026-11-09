#!/usr/bin/env python3
"""Six original initialized-worker issuer/verification cases;no gate overrides.

Two private analysis processes;no target concurrency. Fixture bytes are
explicit;source DER inputs are pinned. O(C*(B+V+E+S)) bounded time/space.
"""
import base64,hashlib,json,multiprocessing,zlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from probe_rpc502_auth import AuthProbe,ROOT,SOURCE
from probe_rpc502_body import file_for_body
from rpc502_auth_fixtures import samples

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cases():
 out=[]
 for label,body in samples().items():out.append({'label':label,'body_hex':body.hex(),'file_hex':file_for_body(body,C=256 if label in ['root','key_services']else 128,n=4096).hex(),'fixture':{'body_cpu_model':'MAX','worker_instruction_budget':32000000}})
 return out

def run_case(c):
 q=AuthProbe(bytes.fromhex(c['file_hex']),c['fixture']);r=q.run();return r,q.instruction_bank

def main():
 pool={};rows=[]
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  for case,(r,bank)in zip(cases(),ex.map(run_case,cases(),buffersize=2)):
   for a,e in bank.items():assert a not in pool or pool[a]==e;pool[a]=e
   rows.append({'case':case,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode())).decode()});print('CASE',case['label'],r['steps'],r['stop_reason'],r['records'][-1:],len(r['auth_points']),len(r['auth_reads']),r['multiply_visits'],flush=True)
 deps=['probe_rpc502_auth.py','rpc502_auth_fixtures.py','probe_rpc502_startup.py','probe_rpc502_startup_cases.py','rpc502_startup_tools.py','rpc502_startup_root.der','rpc502_startup_key_services.der','probe_rpc502_body.py','rpc502_body_fixtures.py','probe_rpc502_supp.py','probe_rpc502_supp_cases.py','probe_rpc502_parser.py','probe_rpc502_sidecar_contents.py','probe_rpc502_sidecar_copy.py','probe_rpc502_sidecar_mapping.py','probe_rpc502_sidecar_data.py','probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py','daemon_rpc502_context_probe.py','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'original_instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_auth_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print('COUNTS',len(rows),len(pool),flush=True)

if __name__=='__main__':main()
