#!/usr/bin/env python3
"""Fresh A64 replay of populated-state caller compositions; source executes via
Unicorn while imported effects remain explicit ABI models. Four private backings
per case. O(visits+events+expression evaluation) time, O(trace+RAM) space.
"""
import json
from pathlib import Path
from collections import Counter
from replay_daemon_mode471c_lifecycle import LifecycleReplay
from replay_daemon_descriptor_producers import Replay,ROOT,SOURCE,sha
class RegistryReplay(LifecycleReplay):
 def run(self):
  out=Replay.run(self);assert self.invocation is None;assert self.retired==[(int(x['address'],16),x['size_bytes'])for x in self.raw['retired_owners']];out['configuration']=self.cfg;return out

def main():
 data=json.loads((ROOT/'daemon_registry_lookup_profiles.json').read_text());rows=[];totals=Counter()
 for j,r in enumerate(data['cases']):
  for pattern in range(4):
   row=RegistryReplay(r,pattern).run();rows.append(row);totals.update(row['verified_counts'])
  print(json.dumps({'case':j,'four_backings_pass':True}),flush=True)
 deps=['daemon_registry_lookup_profiles.json','replay_daemon_mode471c_lifecycle.py','replay_daemon_descriptor_producers.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'verified_totals':dict(totals),'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_registry_lookup_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'verified_totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
