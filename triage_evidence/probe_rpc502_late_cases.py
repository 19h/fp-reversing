#!/usr/bin/env python3
"""Matched original-worker inputs varying C or first-file selector only.

Four complete original callback/worker sequences;two isolated analysis
processes,not agents. O(C*(B+V+E+S)) work/space;no native target/API/IDB.
"""
import base64,hashlib,json,multiprocessing,struct,zlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from probe_rpc502_late import LateProbe,ROOT,SOURCE
from probe_rpc502_body import file_for_body

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cases():
 raw=SOURCE.read_bytes();body=bytes(x^0x98 for x in raw[0xee87f4:0xee87f4+719]);out=[]
 for C,selector in[(128,1),(129,1),(0,1),(128,2)]:
  first=struct.pack('>6I',1,0,selector,0,0,0)+bytes(40);out.append({'label':'C'+str(C)+'_selector'+str(selector),'version':5,'C':C,'selector':selector,'first_hex':first.hex(),'body_hex':body.hex(),'second_hex':file_for_body(body,v=5,C=C,n=4096).hex(),'fixture':{'body_cpu_model':'MAX','worker_instruction_budget':32000000}})
 return out

def run_case(c):
 q=LateProbe(bytes.fromhex(c['second_hex']),c['fixture'],bytes.fromhex(c['first_hex']));r=q.run();return r,q.instruction_bank

def main():
 rows=[];pool={}
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  for c,(r,bank)in zip(cases(),ex.map(run_case,cases(),buffersize=2)):
   for a,e in bank.items():assert a not in pool or pool[a]==e;pool[a]=e
   rows.append({'case':c,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode())).decode()});print('CASE',c['label'],r['steps'],r['stop_reason'],r['records'][-1:],len(r['late_calls']),flush=True)
 deps=['probe_rpc502_late.py','probe_rpc502_policy_cases.py','probe_rpc502_policy_transition.py','probe_rpc502_auth.py','probe_rpc502_auth_cases.py','rpc502_auth_models.py','probe_rpc502_startup.py','rpc502_startup_tools.py','rpc502_startup_root.der','rpc502_startup_key_services.der','probe_rpc502_body.py','rpc502_body_fixtures.py','probe_rpc502_supp.py','probe_rpc502_supp_cases.py','probe_rpc502_parser.py','probe_rpc502_sidecar_contents.py','probe_rpc502_sidecar_copy.py','probe_rpc502_sidecar_mapping.py','probe_rpc502_sidecar_data.py','probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py','daemon_rpc502_context_probe.py','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'original_instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_late_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print('COUNTS',len(rows),len(pool),flush=True)
if __name__=='__main__':main()
