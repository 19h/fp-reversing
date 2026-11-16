#!/usr/bin/env python3
"""Original prefill CPU components with a separate partition-list oracle.
O(visits + private bytes + journals) time/space. Calls, authentication and
list-provider writes are declared models; no native thread is executed.
"""
import struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_rpc502_vm_handoff import compressed,decode
import recover_kernel_zone_prefill_callers as R
ZONE=P+0x10000;OTHER=P+0x11000;STATS=P+0x12000;PAIR=P+0x13000
GROUPS=[[P+0x20000+0x100*g+0x20*j for j in range(3)] for g in range(4)]

def configurations():
 rows=[]
 for mode in ['prefill','arm']:
  for a in [0,1,3]:
   for b in [0,1,3]:
    for old in [0,1,3]:rows.append({'mode':mode,'quota':4,'a':a,'b':b,'old':old,'reserve':2})
  for old in [0,1,3]:rows.append({'mode':mode,'quota':0,'a':0,'b':0,'old':old,'reserve':2})
 for monitor in [1,0xffffffff]:
  for old,a,b in [(0,0,0),(0,3,3),(3,1,1)]:rows.append({'mode':'prefill','quota':0xffff,'a':a,'b':b,'old':old,'reserve':0,'monitor':monitor,'owner':255})
 return rows

class Probe(CPU):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,'selector',{'id':0});self.c=c;self.effects=[];self.auth=[];self.mutate=mutate
  self.entry=R.PREFILL if c['mode']=='prefill' else R.ARM
  self.allowed=[(R.PREFILL,R.ARM),(R.ARM,0xfffffe000bd73458)]
  self.fixture(ZONE,bytes(192));self.put(ZONE+0x3c,4,0xa5a50000);self.put(ZONE+0x40,8,PAIR)
  self.put(ZONE+0x7c,2,c['quota']);self.put(ZONE+0x48,4,c['old']);self.put(ZONE+0x4c,4,c['reserve'])
  self.put(ZONE+0x64,4,c.get('minimum',2));self.put(ZONE+0x62,1,c.get('owner',7))
  aa=GROUPS[0][:c['old']];bb=GROUPS[1][:c['reserve']]
  self.chain(aa+bb);self.put(ZONE+0x50,8,(aa+bb)[0] if aa+bb else 0)
  self.put(ZONE+0x58,8,aa[-1] if aa else ZONE+0x50)
  self.chain(GROUPS[2][:c['a']]+GROUPS[3][:c['b']])
  self.put(PAIR,8,OTHER);self.put(PAIR+8,8,STATS);self.put(OTHER+0x34,2,32)
  self.global_put(0xfffffe000cb0bc50,4,c.get('monitor',0));self.global_put(0xfffffe0007e6a248,2,0xbeef)
  self.global_put(0xfffffe0007e66f58,8,PAIR);self.global_put(0xfffffe0007f213e0,8,0)
  for j in range(31):self.set(j,0x1010101000000000+j)
  self.set(0,ZONE);self.set(30,HALT);self.entry_regs=[hex(self.reg(j)) for j in range(31)]
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,0);self.entry_NZCV='0x0'
  self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def put(self,a,n,v):self.fixture(a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
 def global_put(self,a,n,v):
  self.ensure(a,n);raw=v.to_bytes(n,'little');self.u.mem_write(a,raw)
  self.image_initial.append({'address':hex(a),'bytes_hex':raw.hex(),'provenance':'Declared global snapshot, no native epoch assertion'})
 def chain(self,nodes):
  for j,a in enumerate(nodes):self.fixture(a,struct.pack('<Q',nodes[j+1] if j+1<len(nodes) else 0)+bytes([0x5a])*24)
 def effect(self,a,raw,reason):
  old=bytes(self.u.mem_read(a,len(raw)));self.u.mem_write(a,raw)
  self.effects.append({'before_source_visit_index':len(self.visits),'address':hex(a),'before_hex':old.hex(),
   'after_hex':raw.hex(),'reason':reason,'native_effect_executed':False})
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('returned')
  if a==0xfffffe000bd28394:return self.stop('before_assert_wait')
  if a==0xfffffe000bd7497c:
   desc=self.reg(2);assert [self.reg(j) for j in range(2)]==[ZONE,0]
   assert bytes(u.mem_read(desc,24))==struct.pack('<IIQQ',0,0,0,desc+8)
   na=GROUPS[2][:self.c['a']];nb=GROUPS[3][:self.c['b']];head=(na+nb)[0] if na+nb else 0
   self.effect(desc,struct.pack('<IIQQ',len(na),len(nb),head,na[-1] if na else desc+8),'Declared list-provider descriptor output')
   return self.model(a,'declared_list_provider',0xdeadbeef)
  if a==0xfffffe000bd0ae78:
   assert self.reg(0)==ZONE+0x60;return self.model(a,'declared_lock_no_RAM_effect',0)
  if a==0xfffffe000bd0ab80:
   assert self.reg(0)==ZONE+0x60;return self.model(a,'declared_monitor_no_RAM_effect',0)
  if a==0xfffffe000bd74bec:
   assert [self.reg(j) for j in range(2)]==[ZONE,0xbeef];return self.model(a,'declared_node_preparation_no_RAM_effect',0)
  if a==0xfffffe000c6480c0:
   assert self.reg(1)==32;self.effect(self.reg(0),bytes(32),'Declared bzero semantic model')
   return self.model(a,'declared_bzero',0xdeadbeef)
  if a==0xfffffe000bd74fcc:
   assert [self.reg(j) for j in [0,1,3]]==[OTHER,STATS,32]
   return self.model(a,'declared_retirement_no_RAM_effect',0xffffffff)
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_unmodeled_code')
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4))
  i=next(self.image.k.cs.disasm(raw,a))
  if i.mnemonic=='autda':
   self.auth.append({'pc':hex(a),'raw_pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'logical_identity_model':True})
   self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=10000);self.flush()
  assert self.reason in ['returned','before_assert_wait'],self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_registers31':self.entry_regs,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,
   'API_models':self.models,'declared_model_RAM_writes':self.effects,'logical_authentication':self.auth,'boundary':self.boundary,
   'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate is not None else None,**{n:False for n in R.FALSE}}

def oracle(row):
 c=row['configuration'];initial=decode(row['initial_private_RAM']);ram=decode(row['final_private_RAM']);expected=bytearray(initial);checks=[]
 def put(a,n,v):expected[a-P:a-P+n]=(v&((1<<(8*n))-1)).to_bytes(n,'little')
 def check(name,p):assert p,(name,c);checks.append(name)
 aa=GROUPS[0][:c['old']];bb=GROUPS[1][:c['reserve']];na=GROUPS[2][:c['a']] if c['quota'] else [];nb=GROUPS[3][:c['b']] if c['quota'] else []
 prefill=c['mode']=='prefill' or c['quota']!=0
 available=aa+na;reserved=nb+bb;pop=available[0] if available and prefill else None;left=available[1:] if pop else available
 result=int(pop is not None);owner=c.get('owner',7)+int(c['quota']!=0)+int(prefill)
 put(ZONE+0x62,1,owner);put(ZONE+0x48,4,len(left));put(ZONE+0x4c,4,len(reserved))
 chain=left+reserved
 put(ZONE+0x50,8,chain[0] if chain else 0);put(ZONE+0x58,8,left[-1] if left else ZONE+0x50)
 # Only the inserted partitions and old boundary can change. Reconstruct
 # the abstract resulting sequence, including the vacated node, directly.
 for j,a in enumerate(chain):put(a,8,chain[j+1] if j+1<len(chain) else 0)
 if pop:expected[pop-P:pop-P+32]=bytes(32);put(ZONE+0x64,4,min(c.get('minimum',2),len(left)))
 flags=0xa5a50000|(4 if c['quota'] else 0)
 if c['quota']:put(ZONE+0x7c,2,0)
 if c['mode']=='arm' and not result:flags|=16;put(ZONE+0x62,1,owner+1)
 put(ZONE+0x3c,4,flags)
 check('Boolean_result_or_wait_boundary',row['boundary']['kind']==('before_assert_wait' if c['mode']=='arm' and not result else 'returned'))
 if row['boundary']['kind']=='returned':check('return_boolean_ignores_modeled_leaf_results',int(row['boundary']['registers31'][0],16)==result)
 else:check('source_arm_wait_arguments',list(map(lambda v:int(v,16),row['boundary']['registers31'][:2]))==[ZONE+32,8])
 calls=row['API_models'];check('provider_called_exactly_for_nonzero_quota',sum(x['symbol']=='declared_list_provider' for x in calls)==int(c['quota']!=0))
 check('preparation_and_retirement_only_for_consumed_node',sum(x['symbol']=='declared_retirement_no_RAM_effect' for x in calls)==result and sum(x['symbol']=='declared_node_preparation_no_RAM_effect' for x in calls)==result)
 if pop:
  prep=next(x for x in calls if x['symbol']=='declared_node_preparation_no_RAM_effect');ret=next(x for x in calls if x['symbol']=='declared_retirement_no_RAM_effect')
  check('preparation_payload_and_retirement_node',int(prep['arguments8'][2],16)==pop+16 and list(map(lambda v:int(v,16),ret['arguments8'][:4]))==[OTHER,STATS,pop,32])
 check('lock_request_count',sum(x['symbol']=='declared_lock_no_RAM_effect' for x in calls)==int(prefill)+int(c['quota']!=0)+int(c['mode']=='arm' and not result))
 check('monitor_request_count',sum(x['symbol']=='declared_monitor_no_RAM_effect' for x in calls)==(int(prefill)+int(c['quota']!=0)+int(c['mode']=='arm' and not result) if c.get('monitor') else 0))
 # Stack frames and descriptor output are separately journaled; the byte
 # oracle covers every other private byte without replaying source stores.
 lo,hi=SP-P-0x200,SP-P+0x100
 check('all_nonstack_private_RAM_exact',ram[:lo]==expected[:lo] and ram[hi:]==expected[hi:])
 check('entire_zone192_exact',ram[ZONE-P:ZONE-P+192]==expected[ZONE-P:ZONE-P+192])
 if row['boundary']['kind']=='returned':check('restored_SP_and_saved_GPs',int(row['boundary']['SP'],16)==SP and all(row['boundary']['registers31'][j]==row['entry_registers31'][j] for j in [*range(19,30),30]))
 check('declared_effects_remain_models',all(not x['native_effect_executed'] for x in row['declared_model_RAM_writes']))
 return checks
