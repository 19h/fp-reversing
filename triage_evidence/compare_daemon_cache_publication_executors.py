#!/usr/bin/env python3
"""Compare independent cached execution with the legacy source harness.
O(selected complete visits/effects) time, O(two case journals+decoded cache)
space. The subset spans three SP placements, two cache placements, three
modeled messages and both void-ABI outcomes; full production remains separate.
"""
import json,hashlib,time
from pathlib import Path
from collections import defaultdict
from daemon_receive_tools import ROOT,SOURCE
from recover_daemon_object_creation import sha
from probe_daemon_cache_publication import Run,outcomes
from daemon_cache_publication_replay import execute,equivalent
def selected():
 cs=json.loads((ROOT/'daemon_cache_publication_context.json').read_text())['contexts'];by=defaultdict(list)
 for c in cs:by[(c['SP'],c['cache_owner_address'])].append(c)
 assert len(by)==6
 rows=[]
 for j,(k,group)in enumerate(sorted(by.items())):
  message=['','41','c3a9'][j%3];matches=[c for c in group if c['message_hex']==message];assert matches;rows.append(matches[-1]if j&1 else matches[0])
 assert len({c['SP']for c in rows})==3 and len({c['cache_owner_address']for c in rows})==2 and len({c['message_hex']for c in rows})==3;return rows
def semantic_hash(t):
 t=dict(t)
 for name,mask in [('cache_hex36','cache_defined_mask36'),('destination_hex64','destination_defined_mask64')]:t[name]=[v if m else None for v,m in zip(bytes.fromhex(t[name]),t[mask],strict=True)]
 return hashlib.sha256(json.dumps(t,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def build():
 rows=[]
 for c in selected():
  for cfg in outcomes():
   start=time.monotonic();old=Run(c,cfg).run();oldtime=time.monotonic()-start;start=time.monotonic();new=execute(c,cfg);newtime=time.monotonic()-start;assert equivalent(old,new);a,b=semantic_hash(old),semantic_hash(new);assert a==b
   rows.append({'identity_case_index':c['identity_case_index'],'configuration':cfg,'source_visits':len(old['steps']),'read_effects':sum(e['kind']=='read'for e in old['events']),'write_effects':sum(e['kind']=='write'for e in old['events']),'API_models':len(old['API_models']),'legacy_semantic_sha256':a,'cached_semantic_sha256':b,'streams_equal':True,'legacy_elapsed_seconds':oldtime,'cached_elapsed_seconds':newtime})
   print(json.dumps({'compared_cases':len(rows),'identity_case_index':c['identity_case_index'],'streams_equal':True}),flush=True)
 assert len(rows)==12;return rows
def main():
 rows=build();deps=['daemon_cache_publication_context.json','probe_daemon_cache_publication.py','daemon_cache_publication_replay.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache_publication_executor_comparison.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'compared_cases':len(rows),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
