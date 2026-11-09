#!/usr/bin/env python3
"""Independent A64 execution of each continuous lifecycle, four arbitrary-byte
backings. Imported operations are explicit ABI/environment models. Source code
uses Unicorn, not the symbolic executor; native PAC/API behavior remains unknown.
O(cases*(visits+events+expression evaluation)) time, O(largest trace+RAM) space.
"""
import json,struct
from collections import Counter
import z3
from unicorn import arm64_const as ar
from replay_daemon_descriptor_producers import Replay,unpack,sha,P,SIZE,ROOT,SOURCE,IMAGE,CS,IMPORTS,FIXUPS
from daemon_seed_material_symbolic import decode
HEAP_MIN=0x6900000000;HEAP_MAX=0x6900100000;ORIGIN=0x6b00000000
SPECS={0x10019385c:('malloc',0x10109ff58,0x6aa4),0x100130fcc:('pthread_rwlock_init',0x1010a0dd0,0xa027),0x10043e508:('pthread_once',0x10109fe80,0x8489),0x100442650:('pthread_once',0x10109fe80,0x8489),0x100361df4:('pthread_rwlock_wrlock',0x1010a0a00,0x4c4d),0x100208efc:('pthread_rwlock_unlock',0x1010a0d78,0x5431),0x10039c988:('free',0x10109ff30,0x46a2)}
class LifecycleReplay(Replay):
 def __init__(self,row,pattern=0):
  self.cfg=row['configuration'];self.raw=unpack(row);self.extra={};self.invocation=None;self.retired=[]
  super().__init__(row['prefix'],self.raw,pattern)
  off=len(row['prefix']['source_visits'])
  for k,s in enumerate(self.raw['steps']):
   if any(n in s for n in ['api_model','callback_invocation_model','after_callback_api_model']):self.extra[off+k]=s
 def backing(self,a):
  if P<=a<P+SIZE:return self.ram[a-P]
  assert HEAP_MIN<=a<HEAP_MAX or ORIGIN<=a<ORIGIN+0x100000,hex(a)
  return [0x35,0,255,((a*73)^(a>>8)^19)&255][self.pattern]
 def ensure(self,a,n=1):
  if HEAP_MIN<=a<a+n<=HEAP_MAX:
   for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
    if pg not in self.pages:self.u.mem_map(pg,4096);self.pages.add(pg);self.u.mem_write(pg,bytes(self.backing(pg+j)for j in range(4096)))
   return
  return super().ensure(a,n)
 def value(self,s):
  if 'hex'in s:return bytes.fromhex(s['hex'])
  key=json.dumps(s,sort_keys=True)
  if key in self.evalcache:return self.evalcache[key]
  if'terms'in s:out=bytes(x if isinstance(x,int)else self.backing(self.F+x['origin'])for x in s['terms'])
  else:
   v=decode(s,self.F);pairs=[]
   for name,bits in s['symbols']:
    assert name.startswith('unknown_')and bits==8;pairs.append((z3.BitVec(name,8),z3.BitVecVal(self.backing(int(name[8:],16)),8)))
   val=z3.simplify(z3.substitute(v,*pairs));assert z3.is_bv_value(val);out=val.as_long().to_bytes(s['bits']//8,'little')
  self.evalcache[key]=out;return out
 def read(self,u,t,a,n,v,d):
  assert not any(h<a+n and a<h+z for h,z in self.retired),('retired owner read',hex(a))
  super().read(u,t,a,n,v,d)
 def args(self,shapes):return[int.from_bytes(self.value(s),'little')for s in shapes]
 def complete_api(self,model,row,callback=False):
  pc=int(model['pc'],16);name,slot,div=SPECS[pc];assert model['name']==name and model['binding']['slot']==hex(slot)
  if not callback:assert self.args(model['arguments8'])==[self.reg('x'+str(j))for j in range(8)]
  before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]+['q'+str(j)for j in range(8,16)]}
  for n,s in model['preserved'].items():assert self.reg(n)==int.from_bytes(self.value(s),'little'),(hex(pc),n)
  args=self.args(model['arguments8']);effects=model['memory_effects']
  if name=='malloc':assert args[0]==200 and len(effects)==int(bool(model['configuration']['malloc_nonnull']))
  elif name=='pthread_rwlock_init':assert args[0]==int(model['allocation_address'],16)and args[1]==0 and len(effects)==1
  elif name=='pthread_once':assert args[:2]==[0x1010b8cd0,0x10040ebd4]and len(effects)==1
  elif name in ['pthread_rwlock_wrlock','pthread_rwlock_unlock']:assert args[0]!=0 and len(effects)==1
  elif name=='free':assert args[0]==P+0x1000 and effects==[];self.retired.append((args[0],8))
  for e in effects:
   a=int(e['address'],16);n=e['size_bytes'];assert n==(16 if name=='pthread_once'else 200);self.ensure(a,n);b=self.value(e['value']);assert len(b)==n;self.u.mem_write(a,b);self.counts['modeled_API_effect_bytes']+=n
  regs=row['registers_after']
  assert set(regs)<=set(['sp','x0','x30']+['x'+str(j)for j in range(1,18)]+['q'+str(j)for j in range(32)])
  for n,s in regs.items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+n.upper()),int.from_bytes(self.value(s),'little'))
  for n,v in before.items():
   if n.startswith('q'):assert self.reg(n)&((1<<64)-1)==v&((1<<64)-1)
   else:assert self.reg(n)==v
  assert self.reg('x30')==pc+4
  if name=='malloc':assert self.reg('x0')==(int(model['allocation_address'],16)if model['configuration']['malloc_nonnull']else 0)
  elif name=='pthread_rwlock_init':assert self.reg('x0')&0xffffffff==model['configuration']['init_status']
  elif name!='free':assert self.reg('x0')&0xffffffff==model['returned_status32']
  nzcv=sum((self.backing(self.F+off)&1)<<(31-j)for j,off in enumerate(model['NZCV_origin_bytes']));self.u.reg_write(ar.UC_ARM64_REG_NZCV,nzcv);self.u.reg_write(ar.UC_ARM64_REG_PC,pc+4);self.counts['modeled_API_returns']+=1
 def code(self,u,a,n,d):
  if self.seq not in self.extra:return super().code(u,a,n,d)
  self.finish();row=self.extra[self.seq];assert row['pc']==hex(a);raw=bytes(u.mem_read(a,4));assert raw.hex()==row['bytes_hex']and raw==IMAGE.read(a,4);ins=next(CS.disasm(raw,a));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits']+=1
  if 'after_callback_api_model'in row:
   assert ins.mnemonic in ['ret','retab','retaa']and self.invocation is not None;pending=self.invocation;assert self.reg('x30')==int(pending['return_token'],16)and self.reg('sp')==int(pending['entry_SP'],16);assert self.reg('sp')+self.cfg['callback_gap']==pending['original_SP'];u.reg_write(ar.UC_ARM64_REG_SP,pending['original_SP']);self.complete_api(row['after_callback_api_model'],row,True);self.invocation=None;self.counts['callback_returns']+=1;return
  assert ins.mnemonic=='blraa';name,slot,div=SPECS[a];operands=[x.strip()for x in ins.op_str.split(',')];assert self.reg(operands[0])==IMPORTS[FIXUPS[slot]['target']]and self.reg(operands[1])==div;self.counts['import_target_modifier_checks']+=1
  if 'callback_invocation_model'in row:
   m=row['callback_invocation_model'];assert self.invocation is None and self.args(m['arguments8'])==[self.reg('x'+str(j))for j in range(8)];assert self.reg('x0')==0x1010b8cd0 and self.reg('x1')==0x10040ebd4;self.invocation={**m,'original_SP':self.reg('sp')};assert int(m['entry_SP'],16)==self.reg('sp')-self.cfg['callback_gap'];u.reg_write(ar.UC_ARM64_REG_SP,int(m['entry_SP'],16));u.reg_write(ar.UC_ARM64_REG_X30,int(m['return_token'],16));self.ensure(0x10040ebd4);u.reg_write(ar.UC_ARM64_REG_PC,0x10040ebd4);self.counts['callback_invocations']+=1
  else:self.complete_api(row['api_model'],row)
 def run(self):
  out=super().run();assert self.invocation is None and self.retired==[(P+0x1000,8)];out['configuration']=self.cfg;return out

def main():
 data=json.loads((ROOT/'daemon_mode471c_lifecycle_profiles.json').read_text());rows=[];totals=Counter()
 for i,r in enumerate(data['cases']):
  for pattern in range(4):
   out=LifecycleReplay(r,pattern).run();rows.append(out);totals.update(out['verified_counts'])
  print(json.dumps({'case':i,'four_patterns_pass':True}),flush=True)
 deps=['daemon_mode471c_lifecycle_profiles.json','replay_daemon_descriptor_producers.py','daemon_descriptor_producers_source.json','daemon_seed_material_symbolic.py','daemon_receive_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__import__('pathlib').Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'verified_totals':dict(totals),'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_mode471c_lifecycle_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'verified_totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
