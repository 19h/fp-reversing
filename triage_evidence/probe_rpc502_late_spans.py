#!/usr/bin/env python3
"""Matched original inputs varying only version5's skipped byte span.

The valid embedded leaf/C128 and first file stay fixed. A=1/4 with explicit
nonzero bytes tests prefix/extent/hash flow without internal interventions.
O(C*(B+V+E+S)) work/space;two isolated analysis processes,not agents.
No native target/API/IDB action. All inputs precede every guest instruction.
"""
import base64,hashlib,json,multiprocessing,struct,zlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from probe_rpc502_late import LateProbe,ROOT,SOURCE
from probe_rpc502_body import file_for_body

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cases():
 raw=SOURCE.read_bytes();body=bytes(x^0x98 for x in raw[0xee87f4:0xee87f4+719]);first=struct.pack('>6I',1,0,1,0,0,0)+bytes(40);out=[]
 for payload in[bytes.fromhex('a5'),bytes.fromhex('01234567')]:
  A=len(payload);second=bytearray(file_for_body(body,v=5,A=A,C=128,n=4096));second[8:8+A]=payload;out.append({'label':'C128_A'+str(A),'version':5,'A':A,'skip_payload_hex':payload.hex(),'C':128,'selector':1,'first_hex':first.hex(),'body_hex':body.hex(),'second_hex':second.hex(),'fixture':{'body_cpu_model':'MAX','worker_instruction_budget':32000000}})
 return out

def run_case(c):
 q=LateProbe(bytes.fromhex(c['second_hex']),c['fixture'],bytes.fromhex(c['first_hex']));r=q.run();return r,q.instruction_bank

def main():
 rows=[];pool={}
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  for c,(r,bank)in zip(cases(),ex.map(run_case,cases(),buffersize=2)):
   for a,e in bank.items():assert a not in pool or pool[a]==e;pool[a]=e
   rows.append({'case':c,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode())).decode()});print('CASE',c['label'],r['steps'],r['stop_reason'],r['records'][-1:],len(r['late_calls']),flush=True)
 prior=json.loads((ROOT/'rpc502_policy_profiles.json').read_text());deps=list(prior['dependencies'])+['probe_rpc502_late.py','probe_rpc502_policy_cases.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in sorted(set(deps))},'original_instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_late_span_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print('COUNTS',len(rows),len(pool),flush=True)
if __name__=='__main__':main()
