#!/usr/bin/env python3
"""Rebuild relocation patches, audit nine streams and freshly rerun each case.
O(nine visits/effects+defined input bytes) time; O(compressed profiles+two
journals+decoder cache) space. Relocation causality remains finite/model-only.
"""
import json
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE
from recover_daemon_object_creation import sha
from replay_daemon_descriptor_producers import unpack
from validate_daemon_object_clock import checked
from probe_daemon_cache_relocation import configurations
from daemon_cache_publication_replay import execute,equivalent
from recover_daemon_cache_publication import summary
from validate_daemon_cache_publication import trace
def main():
 r=checked('daemon_cache_relocation_profiles.json','probe_daemon_cache_relocation.py');counts=Counter();bases={};totals=Counter()
 for (c,spec),row in zip(configurations(),r['cases'],strict=True):
  assert row['specification']==spec;t=unpack(row['profile']);assert summary(t,c)==row['summary'];assert not trace(t,c,counts);assert equivalent(t,execute(c,t['configuration']));s=row['summary'];totals.update({'source_visits':len(t['steps']),'modeled_internal_edges':len(t['edges']),'modeled_import_calls':len(t['API_models']),'read_effects':sum(e['kind']=='read'for e in t['events']),'write_effects':sum(e['kind']=='write'for e in t['events'])});counts['fresh_complete_cases_recomputed']+=1
  if spec['kind']=='baseline':bases[c['identity_case_index']]=s;counts['baseline_cases']+=1
  else:
   b=bases[c['identity_case_index']];assert all(s[k]==b[k]for k in ['padded_input32_hex','consumer_intermediate32_hex','recovered_encoded20_hex','next_input_address']);assert s['cache32_hex']!=b['cache32_hex'];assert row['profile']['source_visits']==73044;counts['controlled_cache_only_relocations']+=1
 assert counts['controlled_cache_only_relocations']==6 and counts['baseline_cases']==3;totals['A64_executed_instructions']=totals['source_visits']-totals['modeled_internal_edges']-totals['modeled_import_calls']
 deps=['daemon_cache_relocation_profiles.json','probe_daemon_cache_relocation.py','daemon_cache_publication_replay.py','validate_daemon_cache_publication.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'all_checks_pass':True,'native_relocation_tested':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache_relocation_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'counts':dict(counts),'totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
