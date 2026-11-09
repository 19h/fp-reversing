#!/usr/bin/env python3
"""Check post-call independence from prior lower-stack bytes in retained paths.
At each imported call, taint every private byte below that call's SP; source
writes clear taint. Only the explicitly stable canary fixture may be reread.
O(cases*(private extent+source events)) time, O(private extent+largest trace)
space. No native API, target execution, authentication or IDB mutation.
"""
import json,zlib,base64,collections,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
SOURCE=Path('/Users/___/Downloads/zut/fairplayd.arm64e')
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=json.loads((ROOT/'daemon_context_lock_profiles.json').read_text());s=json.loads((ROOT/'daemon_context_lock_success.json').read_text());k=json.loads((ROOT/'daemon_context_lock_checks.json').read_text());assert k['all_checks_pass'];rows=[];calls=0;guard_reads=0
 for r in p['cases']+[s['case']]:
  raw=zlib.decompress(base64.b64decode(r['payload_zlib_base64']));assert hashlib.sha256(raw).hexdigest()==r['payload_sha256'];t=json.loads(raw);regs=t['initial_registers'].copy();taint=set();hits=collections.Counter()
  for step in t['steps']:
   if 'api_model'in step:
    sp=int.from_bytes(bytes.fromhex(regs['sp']['hex']),'little');assert 0x6400000000<=sp<0x6400010000;taint.update(range(0x6400000000,sp));calls+=1
   for e in step['events']:
    a=int(e['address'],16);n=e['size_bytes'];which=set(range(a,a+n))&taint
    if e['kind']=='read'and which:hits[(step['pc'],hex(a),n)]+=1
    if e['kind']=='write':taint.difference_update(range(a,a+n))
   regs.update(step['registers_after'])
  assert all(int(a,16)==0x6400001000 and n==8 for pc,a,n in hits),(r['configuration']['name'],hits);guard_reads+=sum(hits.values());rows.append({'name':r['configuration']['name'],'reads_of_prior_lower_stack_after_API':[{'pc':pc,'address':a,'size_bytes':n,'count':count}for(pc,a,n),count in hits.items()]})
 assert len(rows)==13 and calls==47;deps=['daemon_context_lock_profiles.json','daemon_context_lock_success.json','daemon_context_lock_checks.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'verified_counts':{'conditional_paths':len(rows),'modeled_API_calls':calls,'explicit_stable_guard_reads':guard_reads,'other_post_API_reads_of_prior_lower_stack':0},'only_explicit_stable_guard_fixture_read':True,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_stack_scratch_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)
if __name__=='__main__':main()
