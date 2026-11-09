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
class ConsumersReplay(RegistryReplay):
 def complete_api(self,model,row,callback=False):
  if model['name']!='free':return super().complete_api(model,row,callback)
  pc=int(model['pc'],16);assert pc in set(NEW)|{0x10039c988}and model['binding']['slot']=='0x10109ff30'and not callback;args=self.args(model['arguments8']);assert args==[self.reg('x'+str(j))for j in range(8)];c=self.cfg;owners={0x6800001000:8,0x6800020000:4096}
  if c['chain']!='head':owners[0x6800024000]=4096
  if c['fields']in['310','both']:owners[0x6800030000]=8
  if c['fields']in['d8','both']:owners[0x6800034000]=8
  ptr=args[0];assert ptr in owners and not any(a==ptr for a,n in self.retired);assert model['owner_effects']==[{'kind':'retire','address':hex(ptr),'size_bytes':owners[ptr]}]and model['memory_effects']==[];before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]+['q'+str(j)for j in range(8,16)]}
  for name,s in model['preserved'].items():assert self.reg(name)==int.from_bytes(self.value(s),'little')
  assert set(row['registers_after'])<=set(['x'+str(j)for j in range(18)]+['x30']+['q'+str(j)for j in range(32)])
  for name,s in row['registers_after'].items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+name.upper()),int.from_bytes(self.value(s),'little'))
  for name,value in before.items():assert(self.reg(name)&((1<<64)-1)==value&((1<<64)-1))if name.startswith('q')else self.reg(name)==value
  assert self.reg('x30')==pc+4;self.retired.append((ptr,owners[ptr]));nzcv=sum((self.backing(self.F+off)&1)<<(31-j)for j,off in enumerate(model['NZCV_origin_bytes']));self.u.reg_write(ar.UC_ARM64_REG_NZCV,nzcv);self.u.reg_write(ar.UC_ARM64_REG_PC,pc+4);self.counts['modeled_API_returns']+=1;self.counts['typed_void_free_returns_checked']+=1

def main():
 d=json.loads((ROOT/'daemon_object_consumers_continuations.json').read_text());rows=[];totals=Counter()
 for j,r in enumerate(d['cases']):
  for pattern in range(4):
   row=ConsumersReplay(r,pattern).run();rows.append(row);totals.update(row['verified_counts'])
  print(json.dumps({'case':j,'four_backings_pass':True}),flush=True)
 deps=['daemon_object_consumers_continuations.json','replay_daemon_registry_lookup.py','replay_daemon_mode471c_lifecycle.py','replay_daemon_descriptor_producers.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'verified_totals':dict(totals),'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_consumers_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'verified_totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
