#!/usr/bin/env python3
"""Fresh A64 comparison of arena creator and caller, including opaque API effects.
O(cases*patterns*(snapshot+visits+effects)) time, O(largest trace+RAM) space.
Calls/PAC use explicit logical models; original conditional branches execute.
"""
import json,hashlib,base64,zlib
from pathlib import Path
from collections import Counter
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS
from replay_daemon_callback_revisit import Replay
from replay_daemon_context_transfer import evaluate
from daemon_import_bindings import binding
APIS={0x10019385c:('malloc',0x10109ff58,0x6aa4),0x100130fcc:('pthread_rwlock_init',0x1010a0dd0,0xa027),0x10038eb5c:('malloc',0x10109ff58,0x6aa4)}
HEAP=0x6600001000

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def unpack(r):
 b=zlib.decompress(base64.b64decode(r['payload_zlib_base64']));assert hashlib.sha256(b).hexdigest()==r['payload_sha256'];return json.loads(b)
class ContextReplay(Replay):
 def __init__(self,snapshot,trace,pattern):
  super().__init__(snapshot,trace,pattern);
  for owner in trace['allocated_owners']:
   page=int(owner['address'],16)&~4095;self.u.mem_map(page,4096);self.pages.add(page)
  for row in trace['API_origins']:
   off=row['offset'];self.backing[off]=0 if pattern==1 else 255 if pattern==2 else(off*41+7)&255 if pattern==0 else(off*73+19)&255
 def code(self,u,a,n,d):
  if self.index<len(self.trace['steps'])and 'api_model'in self.trace['steps'][self.index]:
   self.finish();row=self.trace['steps'][self.index];assert a==int(row['pc'],16)and bytes(u.mem_read(a,4)).hex()==row['bytes_hex'];model=row['api_model'];name,slot,div=APIS[a];assert model['name']==name and binding(slot)==model['binding']and self.register('X8')==0x7c100000 and self.register('X17')==div
   assert [self.register('X'+str(j))for j in range(8)]==[int.from_bytes(evaluate(s,self.backing),'little')for s in model['arguments8']]
   current_heap=HEAP+model['allocation_index']*4096;assert current_heap==int(model['allocation_address'],16)
   if name=='malloc':assert self.register('X0')==(960 if a==0x10038eb5c else 200)
   else:assert[self.register('X0'),self.register('X1')]==[current_heap,0]and bytes(u.mem_read(current_heap,8))==bytes(8)
   self.index+=1;self.counts['source_visits']+=1;self.counts['modeled_API_calls_checked']+=1;self.previous=row;self.reads=[];self.writes=[];self.rcursor=self.wcursor=0;assert not row['events']
   for e in model['memory_effects']:
    a2=int(e['address'],16);b=evaluate(e['value'],self.backing);assert len(b)==e['size_bytes']and len(b)in [200,960]and a2==current_heap;u.mem_write(a2,b);assert bytes(u.mem_read(a2,len(b)))==b;self.counts['opaque_API_memory_bytes_checked']+=len(b)
   for name,shape in row['registers_after'].items():u.reg_write(getattr(ar,'UC_ARM64_REG_'+name.upper()),int.from_bytes(evaluate(shape,self.backing),'little'))
   u.reg_write(ar.UC_ARM64_REG_NZCV,sum((self.backing[off]&1)<<(31-j)for j,off in enumerate(model['NZCV_origin_bytes'])));u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   for name,s in model['preserved'].items():assert self.register(name)==int.from_bytes(evaluate(s,self.backing),'little')
   return
  return super().code(u,a,n,d)

def main():
 snap=json.loads((ROOT/'daemon_context_lock_snapshot.json').read_text());p=json.loads((ROOT/'daemon_context_lock_profiles.json').read_text());extended=json.loads((ROOT/'daemon_context_lock_success.json').read_text());cases=p['cases']+[extended['case']];rows=[]
 for case in cases:
  t=unpack(case);assert not t['definitions']
  for pattern in range(4):
   row=ContextReplay(snap,t,pattern).run();row['configuration']=case['configuration'];rows.append(row);print(json.dumps({'case':case['configuration']['name'],'pattern':pattern,'source_visits':row['verified_counts']['source_visits'],'all_checks_pass':True}),flush=True)
 deps=['daemon_context_lock_snapshot.json','daemon_context_lock_profiles.json','daemon_context_lock_success.json','replay_daemon_callback_revisit.py','replay_daemon_context_transfer.py','daemon_import_bindings.py','daemon_receive_tools.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_lock_replays.json').write_text(json.dumps(out,indent=2)+'\n');tot=Counter()
 for r in rows:tot.update(r['verified_counts'])
 print(json.dumps({'cases':len(rows),'verified_totals':dict(tot)}),flush=True)
if __name__=='__main__':main()
