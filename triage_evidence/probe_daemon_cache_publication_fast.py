#!/usr/bin/env python3
"""Run the full declared cohort with cached source decoding.
O(unique source+all visits/effects) time; O(compressed cohort+one case+decoder
cache) space. Same 288 contexts/two ABI outcomes as the legacy generator.
"""
import json
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE
from recover_daemon_object_creation import sha
from probe_daemon_cache_publication import packed,outcomes
from daemon_cache_publication_replay import execute
def main():
 contexts=json.loads((ROOT/'daemon_cache_publication_context.json').read_text())['contexts'];rows=[]
 for j,c in enumerate(contexts):
  for cfg in outcomes():rows.append(packed(execute(c,cfg)))
  if j%24==23:print(json.dumps({'contexts_finished':j+1,'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
 assert len(rows)==576
 deps=['daemon_cache_publication_context.json','daemon_cache_publication_replay.py','probe_daemon_cache_publication.py','daemon_cache_publication_executor_comparison.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'new_port_emission_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache_publication_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
