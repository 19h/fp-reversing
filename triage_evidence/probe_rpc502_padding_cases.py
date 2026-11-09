#!/usr/bin/env python3
"""Full original zero/nonzero file-signature cases;positive certificate stages.

Two isolated analysis processes,not agents. Unmodified explicit input files
from frozen late cases;new observers only. O(C*(B+V+E+S)) bounded work/space.
No native target/API/IDB action.
"""
import base64,hashlib,json,multiprocessing,zlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from probe_rpc502_padding import PaddingProbe,ROOT,SOURCE
from probe_rpc502_late_cases import cases as controls
from probe_rpc502_late_signature import cases as signatures

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cases():return[controls()[0],signatures()[0]]
def run_case(c):
 q=PaddingProbe(bytes.fromhex(c['second_hex']),c['fixture'],bytes.fromhex(c['first_hex']));r=q.run();return r,q.instruction_bank

def main():
 rows=[];pool={}
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  for c,(r,bank)in zip(cases(),ex.map(run_case,cases(),buffersize=2)):
   for a,e in bank.items():assert a not in pool or pool[a]==e;pool[a]=e
   rows.append({'case':c,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode())).decode()});print('CASE',c['label'],r['steps'],r['stop_reason'],r['records'][-1:],[(s['encoded_extent'],s['digest_extent'],s.get('first_reduction_result'),s['complete_end'])for s in r['padding_stages']],len(r['padding_reads']),flush=True)
 old=json.loads((ROOT/'rpc502_late_signature_profiles.json').read_text());deps=sorted(set(old['dependencies'])|{'probe_rpc502_padding.py','probe_rpc502_late_cases.py','probe_rpc502_late_signature.py'});out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'original_instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_padding_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print('COUNTS',len(rows),len(pool),flush=True)
if __name__=='__main__':main()
