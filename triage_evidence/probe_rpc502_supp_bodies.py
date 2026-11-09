#!/usr/bin/env python3
"""Five source-driven candidate bodies;no encoding or acceptance claim.

Original entry and declared APIs inherited unchanged. O(C*(B+V+E+S)) bounded
time/space. No native target/API operations and no parser/state overrides.
"""
import base64,hashlib,json,struct,zlib
from pathlib import Path
from probe_rpc502_supp_cases import make,run_case,ROOT,SOURCE

def cases():
 out=[]
 for h in ['3000','3100','0400','0200','3003020100']:
  body=bytes.fromhex(h);raw=bytearray(make(2,n=512,B=len(body),C=128));raw[12:12+len(body)]=body;out.append({'label':'body_'+h,'file_hex':raw.hex(),'fixture':{}})
 return out

def main():
 rows=[];pool={};sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
 for case in cases():
  r,bank=run_case(case);pool.update(bank);payload=json.dumps(r,separators=(',',':')).encode();rows.append({'case':case,'payload_zlib_base64':base64.b64encode(zlib.compress(payload)).decode()});print(case['label'],r['steps'],r['records'][-1],flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['probe_rpc502_supp.py','probe_rpc502_supp_cases.py','rpc502_supp_profiles.json']},'source_sha256':sha(SOURCE),'original_instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_supp_bodies_profiles.json').write_text(json.dumps(out,indent=2)+'\n')

if __name__=='__main__':main()
