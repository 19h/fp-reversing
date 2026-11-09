#!/usr/bin/env python3
"""Original late public operation with a nonzero external signature input.

A fixed public certificate signature modulo the leaf modulus supplies a
within-range representative. It is not a newly authenticated signature.
Inputs precede every guest instruction;no internal intervention or native API.
O(B+V+E+S) bounded original callback/worker work and observation space.
"""
import base64,hashlib,json,struct,zlib
from pathlib import Path
from probe_rpc502_late import LateProbe,ROOT,SOURCE
from probe_rpc502_body import file_for_body
from rpc502_startup_tools import certificate_view

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cases():
 raw=SOURCE.read_bytes();body=bytes(x^0x98 for x in raw[0xee87f4:0xee87f4+719]);v=certificate_view(body);N=int(v['modulus_hex'],16);S=int(v['signature_hex'],16)%N;assert 1<S<N;second=bytearray(file_for_body(body,v=5,C=128,n=4096));off=12+len(body)+4;second[off:off+128]=S.to_bytes(128,'big');first=struct.pack('>6I',1,0,1,0,0,0)+bytes(40)
 return[{'label':'C128_signature_nonzero','version':5,'A':0,'C':128,'selector':1,'first_hex':first.hex(),'body_hex':body.hex(),'second_hex':second.hex(),'signature_hex':S.to_bytes(128,'big').hex(),'fixture':{'body_cpu_model':'MAX','worker_instruction_budget':32000000}}]
def run_case(c):
 q=LateProbe(bytes.fromhex(c['second_hex']),c['fixture'],bytes.fromhex(c['first_hex']));r=q.run();return r,q.instruction_bank

def main():
 c=cases()[0];r,pool=run_case(c);prior=json.loads((ROOT/'rpc502_late_profiles.json').read_text());deps=sorted(set(prior['dependencies'])|{'rpc502_startup_tools.py'});out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'original_instruction_pool':list(pool.values()),'cases':[{'case':c,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode())).decode()}],'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_late_signature_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print('CASE',c['label'],r['steps'],r['stop_reason'],r['records'][-1:],len(r['late_calls']),len(pool),flush=True)
if __name__=='__main__':main()
