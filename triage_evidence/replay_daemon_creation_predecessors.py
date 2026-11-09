#!/usr/bin/env python3
"""Private A64 compositions from AEE5C8, plus marker/reset fragment checks.
No internal phase is changed between source fragments. Frame fields are declared
inputs; native production/caller reachability is unknown. malloc is an explicit
ABI outcome; original instructions execute via Unicorn, logical PAC only.
O(cases*(source visits+mapped bytes)) time, O(one map+outputs) space.
"""
import json,hashlib,itertools
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,TABLE
from recover_daemon_object_creation import sha
from replay_daemon_object_creation import Run as BaseRun,P,MARK,CELL,OBJ
class Run(BaseRun):
 def __init__(self,c):
  self.case=c;self.passed=False;kind='allocation'if c.get('marker',1)==1 else'zero';base={**c,'kind':kind};super().__init__(base);F=self.F
  if c['kind']=='composition':
   for o,n,v in [(0x26c8,8,MARK),(0x2a58,8,0x1122334455667788),(0x2a48,8,c.get('presence',1)),(0x2a60,8,0x9988776655443322),(0x2a50,4,c['decoded']^0x8b3dc651),(0x2a70,8,0x123456789abcdef0),(0x273c,4,0x471c)]:self.fixture(F+o,n,v)
  elif c['kind']=='marker_resolver':
   data=json.loads((ROOT/'daemon_creation_predecessors_contracts.json').read_text())['isolated_marker_initial_registers']
   for n,v in data.items():
    if isinstance(v,dict)and 'hex'in v:self.set(n,int.from_bytes(bytes.fromhex(v['hex']),'little'))
   t=0x12340000|c['low'];self.set('w9',t);self.set('x12',t&255);self.set('sp',F)
  elif c['kind']=='callback':
   self.set('w15',0x471c)
   for off,ptr in [(0x2698,P+0x8000),(0x26e8,P+0x9000),(0x26b0,P+0xa000)]:self.fixture(F+off,8,ptr);self.fixture(ptr,8,0xabcdef0112345678)
 def code(self,u,a,n,d):
  kind=self.case['kind']
  if(kind=='composition'and a==0x100add9a8)or(kind=='marker_resolver'and a==0x1009d0458)or(kind=='callback'and a==0x100b280e8):return self.stop(a)
  if kind=='composition'and a==0x100a035f0:self.passed=True;assert self.reg('w8')==0x621b and self.reg('w16')==(self.case['decoded']^0x8b3dc651)
  return super().code(u,a,n,d)
 def run(self):
  c=self.case;kind=c['kind'];start={'composition':0x100aee5c8,'marker_resolver':0x1009d03e4,'callback':0x100b280c8}[kind];self.ensure(start);self.u.emu_start(start,0,count=300);assert self.done;critical={}
  if kind=='composition':
   accepted=bool(c.get('presence',1))and 2<=c['decoded']<=200;assert self.passed==accepted;assert self.value(self.F+0x2fac,4)==c['decoded']^0x8b3dc651;assert self.reg('sp')==self.F
   if not accepted:assert self.boundary==0x100add9a8 and not self.api
   elif c.get('marker',1):
    ret=OBJ if c['nonnull']else 0;assert len(self.api)==1 and self.value(self.F+0x2c08,8)==ret and self.boundary==(0x1006534e8 if ret else 0x100987c84)
   else:assert not self.api and self.boundary==(0x100933c2c if c.get('lock',0)else 0x10097290c)
   assert self.value(MARK,1)==c.get('marker',1);critical={'accepted_classifier':accepted,'decoded':c['decoded'],'presence_value':hex(c.get('presence',1)),'marker_value':self.value(MARK,1),'phase_changed_by_fixture_between_fragments':False}
  elif kind=='marker_resolver':assert self.value(self.F+0x26c8,8)==0x1010c8254;critical={'source_saved_marker_address':'0x1010c8254','bank_input_byte':c['low']}
  else:
   assert self.value(P+0x8000,8)==self.value(P+0x9000,8)==0xabcdef0100000000 and self.value(P+0xa000,8)==0;assert [(int(x[1],16),x[2])for x in self.writes]==[(P+0x8000,4),(P+0x9000,4),(P+0xa000,8)];critical={'private_reset_widths_bytes':[4,4,8],'upper32_canaries_preserved':True,'native_callback_invoked':False}
  h=lambda x:hashlib.sha256(json.dumps(x,separators=(',',':')).encode()).hexdigest()
  return {'configuration':c,'entry_PC':hex(start),'entry_SP':hex(self.F),'boundary_PC':hex(self.boundary),'source_visits':len(self.steps),'source_visits_sha256':h(self.steps),'read_effects':len(self.reads),'read_effects_sha256':h(self.reads),'private_writes':self.writes,'logical_edges':self.edges,'used_fixups':[hex(x)for x in sorted(self.fix)],'modeled_allocator_calls':self.api,'critical':critical,'all_checks_pass':True}
def cases():
 for d,nonnull in itertools.product(range(256),[False,True]):yield {'kind':'composition','decoded':d,'presence':1,'marker':1,'nonnull':nonnull,'pattern':255 if nonnull else 0,'placement':0x100 if nonnull else 0}
 for d in [0x100,0x7fffffff,0x80000000,0xfffffffe,0xffffffff]:yield {'kind':'composition','decoded':d,'presence':1,'marker':1,'nonnull':True}
 for d,lock,pattern in itertools.product([0,1,2,200,201,0xffffffff],[0,0x690000f000],[0,255]):yield {'kind':'composition','decoded':d,'presence':1,'marker':0,'nonnull':False,'lock':lock,'pattern':pattern}
 for d,marker in itertools.product([0,2,200,201,0xffffffff],[0,1]):yield {'kind':'composition','decoded':d,'presence':0,'marker':marker,'nonnull':True}
 for d,marker,nonnull in itertools.product([2,200],[0,1],[False,True]):yield {'kind':'composition','decoded':d,'presence':0xffffffffffffffff,'marker':marker,'nonnull':nonnull,'pattern':17,'placement':16}
 for low in range(256):yield {'kind':'marker_resolver','low':low,'pattern':low}
 for pattern in [0,17,93,255]:yield {'kind':'callback','pattern':pattern}
def main():
 rows=[];counts=Counter()
 for cfg in cases():
  r=Run(cfg).run();rows.append(r);counts.update({'cases':1,'source_visits':r['source_visits'],'read_effects':r['read_effects'],'write_effects':len(r['private_writes']),'logical_edges':len(r['logical_edges']),'modeled_allocator_calls':len(r['modeled_allocator_calls'])})
 deps=['daemon_creation_predecessors_contracts.json','replay_daemon_object_creation.py','daemon_receive_tools.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'case_counts':dict(Counter(r['configuration']['kind']for r in rows)),'cases':rows,'verified_totals':dict(counts),'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_creation_predecessors_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'case_counts':out['case_counts'],'verified_totals':dict(counts)}),flush=True)
if __name__=='__main__':main()
