#!/usr/bin/env python3
"""Original drain/lock/prefill components and independent partition oracle.
O(visits + private bytes + journals) time/space. PAC is a logical identity;
leaf preparation/zeroing/retirement remain explicit inherited call models.
"""
import struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_rpc502_vm_handoff import compressed,decode
from probe_kernel_zone_prefill_callers import Probe as Parent,ZONE,OTHER,STATS,PAIR,GROUPS
import recover_kernel_magazine_depot_drain as R
BASE=P+0x40000;DESC=P+0x18000;THREAD=P+0x19000;CTX=P+0x1a000
SEED_A=[P+0x80000,P+0x80020];SEED_B=[P+0x80100,P+0x80120]
def nodes(cpu,empty,count):return [P+0x60000+cpu*0x2000+int(empty)*0x1000+32*j for j in range(count)]

def configurations():
 rows=[]
 for control in [0,1,2,3,4,0xfffffffe,0xffffffff]:
  for count in [0,1,3]:rows.append({'mode':'drain','control':control,'cpus':count,'pattern':'mixed','seed':True})
 for mode in ['drain','prefill','arm']:
  for pattern in ['empty','full','empties','mixed']:
   rows.append({'mode':mode,'control':0,'cpus':3,'pattern':pattern,'seed':False})
 for mode in ['prefill','arm']:
  rows.append({'mode':mode,'control':0,'cpus':1,'pattern':'mixed','seed':False,'old':3})
 rows.extend([{'mode':'drain','control':0,'cpus':0,'pattern':'empty','cache_pointer':0},
  {'mode':'drain','control':0,'cpus':1,'pattern':'empty','cache_pointer':0},
  {'mode':'drain','control':0,'cpus':1,'pattern':'empty','cache_pointer':0xffffffffffffc000}])
 return rows

def counts(c,j):
 return (0,0) if c['pattern']=='empty' else (3,0) if c['pattern']=='full' else (0,3) if c['pattern']=='empties' else [(3,1),(1,3),(2,2)][j]

class Probe(Parent):
 def __init__(self,image,c,mutate=None):
  setup={'mode':'arm' if c['mode']=='arm' else 'prefill','quota':4,'a':0,'b':0,'old':c.get('old',0),'reserve':2}
  super().__init__(image,setup);self.c=c;self.base=c.get('cache_pointer',BASE);self.drain_locks=[]
  self.put(ZONE+0x40,8,self.base);self.global_put(R.COUNT,4,c['cpus']);self.global_put(0xfffffe000cb115b0,4,0)
  self.put(THREAD+0x1c8,4,1);self.put(THREAD+0x1c0,8,CTX);self.put(CTX+0x4c,1,0)
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  if self.base==BASE:
   for j in range(c['cpus']):
    a,b=counts(c,j);cache=BASE+j*16384;aa=nodes(j,False,a);bb=nodes(j,True,b)
    self.fixture(cache,bytes(64));self.chain(aa+bb);self.put(cache+0x18,4,a);self.put(cache+0x1c,4,b)
    self.put(cache+0x20,8,(aa+bb)[0] if aa+bb else 0);self.put(cache+0x28,8,aa[-1] if aa else cache+0x20)
  if c['mode']=='drain':
   aa=SEED_A if c.get('seed') else [];bb=SEED_B if c.get('seed') else [];self.chain(aa+bb)
   self.fixture(DESC,struct.pack('<IIQQ',len(aa),len(bb),(aa+bb)[0] if aa+bb else 0,aa[-1] if aa else DESC+8))
   self.entry=R.DRAIN;self.set(0,ZONE);self.set(1,c['control']);self.set(2,DESC)
  self.allowed.extend([(R.DRAIN,R.END),(R.ACQUIRE,0xfffffe000bd0ab80)])
  self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.before=bytes(self.u.mem_read(P,SIZE));self.mutate=mutate
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def code(self,u,a,n,d):
  self.flush()
  if a in [R.ACQUIRE,R.UNLOCK]:
   cache=self.reg(0);self.drain_locks.append({'pc':hex(a),'cache':hex(cache),'before_source_visit_index':len(self.visits),
    'nesting_before':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little')})
   if cache==0:return self.stop('before_null_cache_lock')
   assert BASE<=cache<BASE+self.c['cpus']*16384 and (cache-BASE)%16384==0
  if R.DRAIN<=a<R.END or R.ACQUIRE<=a<0xfffffe000bd0ab80:
   raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4))
   i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic in ['autda','pacda']:
    self.auth.append({'pc':hex(a),'instruction':i.mnemonic,'operands':i.op_str,'logical_identity_model':True})
    self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
   if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
   return CPU.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush()
  assert self.reason in ['returned','before_assert_wait','before_null_cache_lock'],self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_registers31':self.entry_regs,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,
   'API_models':self.models,'declared_model_RAM_writes':self.effects,'logical_authentication':self.auth,
   'drain_lock_boundaries':self.drain_locks,'boundary':self.boundary,
   'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate is not None else None,**{n:False for n in R.FALSE}}

def oracle(row):
 c=row['configuration'];before=decode(row['initial_private_RAM']);after=decode(row['final_private_RAM']);expected=bytearray(before);checks=[]
 def put(a,n,v):expected[a-P:a-P+n]=(v&((1<<(8*n))-1)).to_bytes(n,'little')
 def check(name,p):assert p,(name,c);checks.append(name)
 def chain(xs):
  for j,a in enumerate(xs):put(a,8,xs[j+1] if j+1<len(xs) else 0)
 direct=c['mode']=='drain';base=c.get('cache_pointer',BASE);walked=c['cpus'] if base==BASE else 0
 aa=list(SEED_A) if direct and c.get('seed') else [];bb=list(SEED_B) if direct and c.get('seed') else []
 control=c['control'] if direct else 0;keep_a=((control+1)&0xffffffff)>>1;keep_b=control>>1
 for j in range(walked):
  a,b=counts(c,j);cache=BASE+j*16384;full=nodes(j,False,a);empty=nodes(j,True,b)
  take_a=max(a-keep_a,0);take_b=max(b-keep_b,0);aa+=full[:take_a];bb=empty[:take_b]+bb
  left_a=full[take_a:];left_b=empty[take_b:];left=left_a+left_b
  put(cache,4,0x01010000);put(cache+0x18,4,len(left_a));put(cache+0x1c,4,len(left_b))
  boundary=left_a[-1] if left_a else cache+0x20
  # The source resets the boundary using control==0, rather than the
  # derived keep_A==0. All-ones control wraps keep_A to zero but leaves
  # the old boundary when a nonempty full partition is removed.
  if control==0xffffffff and take_a:boundary=full[-1]
  put(cache+0x20,8,left[0] if left else 0);put(cache+0x28,8,boundary);chain(left)
 chain(aa+bb)
 null_lock=base==0 and c['cpus']>0
 check('raw_null_cache_positive_count_stops_before_lock',row['boundary']['kind']=='before_null_cache_lock' if null_lock else row['boundary']['kind'] in ['returned','before_assert_wait'])
 if direct:
  put(DESC,4,len(aa));put(DESC+4,4,len(bb));put(DESC+8,8,(aa+bb)[0] if aa+bb else 0);put(DESC+16,8,aa[-1] if aa else DESC+8)
  check('provider_has_no_external_allocator_or_result_models',not row['API_models'] and not row['declared_model_RAM_writes'])
 else:
  old=GROUPS[0][:c.get('old',0)];reserved=GROUPS[1][:2];available=old+aa;reserved=bb+reserved
  pop=available[0] if available else None;left=available[1:] if pop else [];combined=left+reserved;chain(combined)
  put(ZONE+0x48,4,len(left));put(ZONE+0x4c,4,len(reserved));put(ZONE+0x50,8,combined[0] if combined else 0)
  put(ZONE+0x58,8,left[-1] if left else ZONE+0x50);put(ZONE+0x7c,2,0)
  flags=0xa5a50004|(16 if c['mode']=='arm' and pop is None else 0);put(ZONE+0x3c,4,flags)
  put(ZONE+0x62,1,9+int(c['mode']=='arm' and pop is None))
  if pop:
   expected[pop-P:pop-P+32]=bytes(32);put(ZONE+0x64,4,min(2,len(left)))
   prep=next(m for m in row['API_models'] if m['symbol']=='declared_node_preparation_no_RAM_effect')
   ret=next(m for m in row['API_models'] if m['symbol']=='declared_retirement_no_RAM_effect')
   check('source_drained_node_reaches_original_prefill_consumers',int(prep['arguments8'][2],16)==pop+16 and [int(v,16) for v in ret['arguments8'][:4]]==[OTHER,STATS,pop,32])
  check('drain_is_original_source_not_list_provider_model',all(m['symbol']!='declared_list_provider' for m in row['API_models']))
  result=int(pop is not None)
  if c['mode']=='prefill' or result:check('source_Boolean_and_arm_early_return',row['boundary']['kind']=='returned' and int(row['boundary']['registers31'][0],16)==result)
  else:check('source_arm_wait_boundary',row['boundary']['kind']=='before_assert_wait' and [int(v,16) for v in row['boundary']['registers31'][:2]]==[ZONE+32,8])
 check('original_cache_lock_pairs',[(x['pc'],int(x['cache'],16)) for x in row['drain_lock_boundaries']]==[(hex(pc),BASE+j*16384) for j in range(walked) for pc in [R.ACQUIRE,R.UNLOCK]]+([(hex(R.ACQUIRE),0)] if null_lock else []))
 check('source_nesting_balanced',int.from_bytes(after[THREAD-P+0x1c8:THREAD-P+0x1cc],'little')==1)
 lo,hi=SP-P-0x200,SP-P+0x100
 check('all_nonstack_private_RAM_exact',after[:lo]==expected[:lo] and after[hi:]==expected[hi:])
 if row['boundary']['kind']=='returned':check('SP_and_saved_GPs_restored',int(row['boundary']['SP'],16)==SP and all(row['boundary']['registers31'][j]==row['entry_registers31'][j] for j in [*range(19,30),30]))
 return checks
