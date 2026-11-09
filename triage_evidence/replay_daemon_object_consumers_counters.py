#!/usr/bin/env python3
"""Independent A64 replay with explicit void-free ABI for registered owners.
Original instructions execute via Unicorn; API transitions carry no native call.
O(source visits+events+expression evaluation) time, O(largest trace+RAM) space.
"""
import json
from pathlib import Path
from collections import Counter
from unicorn import arm64_const as ar
import replay_daemon_mode471c_lifecycle as legacy
from replay_daemon_registry_lookup import RegistryReplay
from replay_daemon_descriptor_producers import ROOT,SOURCE,sha
NEW={0x100bdf330:('free',0x10109ff30,0x46a2),0x100be0e80:('free',0x10109ff30,0x46a2),0x100bd9d88:('free',0x10109ff30,0x46a2)}
legacy.SPECS.update(NEW)
from replay_daemon_object_consumers import ConsumersReplay

def main():
 d=json.loads((ROOT/'daemon_object_consumers_counters.json').read_text());rows=[];totals=Counter()
 for j,r in enumerate(d['cases']):
  for pattern in range(4):
   row=ConsumersReplay(r,pattern).run();rows.append(row);totals.update(row['verified_counts'])
  print(json.dumps({'case':j,'four_backings_pass':True}),flush=True)
 deps=['daemon_object_consumers_counters.json','replay_daemon_object_consumers.py','replay_daemon_registry_lookup.py','replay_daemon_mode471c_lifecycle.py','replay_daemon_descriptor_producers.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'verified_totals':dict(totals),'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_consumers_counter_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'verified_totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
