#!/usr/bin/env python3
"""Private original-byte observer/event components and independent ABI oracle.
O(source visits + private RAM/journals) time/space. Native calls, PAC, DAIF
and callback effects are unexecuted; each declared effect is separately logged.
"""
import struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_zone_bitmap_release import Probe as Setup,ZONE,CACHE,THREAD,STATS,META
from probe_rpc502_vm_handoff import compressed,decode
import recover_kernel_zone_observer_event as R
MASK=(1<<64)-1;TABLE=P+0x90000;NODES=[P+0xa0000+0x100*j for j in range(3)]
CALLBACKS=[P+0xb0000+0x100*j for j in range(3)]

def hashed(event,count,base):
 a=((event^(event>>31))*0x7fb5d329728ea185)&MASK
 b=((a^(a>>27))*0x81dadef4bc2dd44d)&MASK
 index=((b^(b>>33))&0xffffffff)&((count-1)&0xffffffff);offset=index*24
 ordinary=offset<0x80000000
 address=(base+offset)&MASK if ordinary else ((base+offset)&0xffffffffffff)|0x2bad000000000000
 return index,address

def configurations():
 rows=[]
 for mode in ['arm','follow','release']:
  for nodes in [0,1,3]:
   for count in [1,8,64]:rows.append({'mode':mode,'nodes':nodes,'count':count})
 for mode in ['arm','follow','release']:
  for action in ['flag','skip','stop']:rows.append({'mode':mode,'nodes':3,'action':action})
 for flags in [0,16,0xdeadbeef,0xffffffff]:
  rows.extend([{'mode':'arm','nodes':3,'flags':flags},{'mode':'follow','nodes':3,'flags':flags}])
 for status in [0,2,0xffffffff]:rows.append({'mode':'arm','nodes':1,'registration_result':status})
 for result in [0,3,0xffffffff]:rows.append({'mode':'follow','nodes':1,'builder_result':result})
 for result in [0,1,2,0xffffffff]:rows.append({'mode':'arm','cache':True,'quota':4,'refill_result':result,'nodes':1})
 rows.extend([{'mode':'arm','cache':True,'quota':0,'nodes':1},
  {'mode':'arm','nodes':1,'monitor':7},{'mode':'follow','nodes':1,'daif':0x200},
  {'mode':'follow','nodes':1,'daif':0},{'mode':'follow','qtype':3,'daif':0},
  {'mode':'follow','valid':False},{'mode':'arm','invalid_zone':True,'nodes':1},
  {'mode':'follow','invalid_zone':True,'nodes':1},{'mode':'follow','invalid_zone':True,'nodes':0},
  {'mode':'follow','count':0,'hash_only':True},{'mode':'follow','count':0xffffffff,'hash_only':True}])
 return rows

class Probe(Setup):
 def __init__(self,image,parent,c,mutate=None):
  base={'followup':True} if c['mode']=='release' else {}
  Setup.__init__(self,image,parent,base);self.c=c;self.mode=c['mode'];self.callbacks=[];self.model_RAM_writes=[];self.hash_boundaries=[];self.daif=c.get('daif',0x3c0)
  self.entry={'arm':R.ARM,'follow':R.FOLLOW,'release':0xfffffe000bd74fcc}[self.mode]
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in self.capture_functions()]
  if self.mode=='release':self.allowed.append((0xfffffe000bd74fcc,R.FOLLOW))
  self.zone=P+0xac000 if c.get('invalid_zone') else ZONE
  if self.zone!=ZONE:self.patch(self.zone,bytes(self.u.mem_read(ZONE,192)),'Declared mapped non-zone geometry control')
  flags=c.get('flags',16 if self.mode=='release' else 0)
  self.val(self.zone+0x3c,4,flags,'Declared initial observer/event flag word')
  self.val(self.zone+0x40,8,CACHE if c.get('cache') else 0,'Declared cache slot for optional prefill gate')
  self.val(self.zone+0x7c,2,c.get('quota',0),'Declared prefill quota')
  self.val(0xfffffe000cb0bc50,4,c.get('monitor',0),'Declared monitor handle')
  self.val(0xfffffe000cb5c400,1,0,'Declared trace hook disabled for assert-wait hash path')
  self.val(R.OBSERVER,8,NODES[0] if c.get('nodes',0) else 0,'Declared observer chain root, not a native registration')
  for j,a in enumerate(NODES):
   nxt=NODES[j+1] if j+1<c.get('nodes',0) else 0
   self.patch(a,struct.pack('<QQ',nxt,CALLBACKS[j]),'Declared distinct observer node and opaque callback pointer')
  self.val(0xfffffe0007e66df8,8,TABLE,'Declared shared wait-table root epoch')
  self.val(0xfffffe0007e66e00,4,c.get('count',8),'Declared shared wait-table count epoch')
  self.event=(self.zone+0x20)&MASK;self.bucket,self.queue=hashed(self.event,c.get('count',8),TABLE)
  if not c.get('hash_only'):
   assert P<=self.queue<self.queue+24<P+SIZE
   self.patch(self.queue,struct.pack('<IIQQ',c.get('qtype',1),0x144 if c.get('valid',True) else 0,0,0),'Declared selected queue record; no actual waiter membership')
  self.val(THREAD+0x1c8,4,0 if self.mode=='release' else 1,'Declared nesting epoch for selected entry')
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  for j in range(31):self.set(j,0x1010101000000000+j)
  args=[self.zone,STATS,self.element,self.extent] if self.mode=='release' else [self.zone]
  for j,v in enumerate(args):self.set(j,v)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j)) for j in range(31)]
  self.initial_zone=bytes(self.u.mem_read(self.zone,192)).hex();self.mutate=mutate
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def capture_functions(self):
  return [self.image.k.function(a) for a in R.FUNCTIONS]
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or self.zone<=a<a+n<=self.zone+192 or ZONE<=a<a+n<=ZONE+192,(hex(a),n)
  row={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n}
  self.writes.append(row);self.pending.append(row)
 def effect(self,a,n,v,why):
  before=bytes(self.u.mem_read(a,n));b=(v&((1<<(8*n))-1)).to_bytes(n,'little');self.u.mem_write(a,b)
  self.model_RAM_writes.append({'before_source_visit_index':len(self.visits),'address':hex(a),'before_hex':before.hex(),'after_hex':b.hex(),'reason':why,'native_effect_executed':False})
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('original_zone_event_returned')
  if a==0xfffffe000bd0aab4:return self.stop('before_original_reacquire')
  if a==0xfffffe000bd6e22c:
   self.hash_boundaries.append({'kind':'wake','arguments5':[hex(self.reg(j)) for j in range(5)],'source_visit_index':len(self.visits)})
   if self.c.get('hash_only'):return self.stop('before_hashed_wrapper_dereference')
  if a in [0xfffffe000c6336f8,0xfffffe000c62a2b0,0xfffffe000c631d74,0xfffffe000c63aec8,0xfffffe000c633aa0]:return self.stop('before_original_diagnostic')
  if a==0xfffffe000bd730f8:
   assert self.reg(0)==self.zone;return self.model(a,'declared_prefill_return_no_RAM_effect',self.c.get('refill_result',0))
  if a==0xfffffe000bd0ae78:
   assert self.reg(0)==self.zone+0x60;return self.model(a,'declared_zone_lock_acquire_no_RAM_effect',0)
  if a==0xfffffe000bd0ab80:
   assert self.reg(0) in [self.zone+0x60,self.zone+0x80];return self.model(a,'declared_unlock_monitor_no_RAM_effect',0)
  if a==0xfffffe000bd0aecc:
   assert self.reg(0)==self.queue+4 and self.reg(1)==0xfffffe0007e66e08;return self.model(a,'declared_queue_lock_no_RAM_effect',0)
  if a==0xfffffe000bd6dfdc:
   self.hash_boundaries.append({'kind':'wait','arguments5':[hex(self.reg(j)) for j in range(5)],'source_visit_index':len(self.visits)})
   return self.model(a,'declared_registration_result_no_RAM_effect',self.c.get('registration_result',0xffffffff))
  if a==0xfffffe000bd28f6c:
   assert [self.reg(j) for j in range(3)]==[0,0,0];return self.model(a,'declared_block_return_no_RAM_effect',0)
  if a==0xfffffe000bd6c59c:
   assert [self.reg(j) for j in [0,1,2,4]]==[self.queue,self.event,0,0xffffffff]
   return self.model(a,'declared_builder_result_no_RAM_effect',self.c.get('builder_result',0))
  if not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_uncaptured_code')
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4))
  i=next(self.image.k.cs.disasm(raw,a))
  if i.mnemonic=='blraa':
   node=self.reg(20);rawtarget=self.reg(8);modifier=self.reg(17)
   event={'call_site':hex(a),'node':hex(node),'raw_callback':hex(rawtarget),'modifier':hex(modifier),
    'arguments3':[hex(self.reg(j)) for j in range(3)],'source_visit_index':len(self.visits)}
   assert node in NODES and rawtarget==CALLBACKS[NODES.index(node)] and modifier==0xeed9
   self.callbacks.append(event);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(30,a+4)
   if len(self.callbacks)==1:
    action=self.c.get('action')
    if action=='flag':
     flag=int.from_bytes(bytes(u.mem_read(self.zone+0x3c,4)),'little');value=flag&~16 if self.mode=='arm' else flag|16
     self.effect(self.zone+0x3c,4,value,'Declared observer changes the zone flag after source publication')
    elif action in ['skip','stop']:self.effect(node,8,NODES[2] if action=='skip' else 0,'Declared observer changes the next link before source reload')
   return self.model(rawtarget,'declared_observer_authenticated_call_boundary',0xdeadbeef)
  if i.mnemonic=='mrs' and i.op_str.endswith(', daif'):
   assert i.op_str=='x8, daif';self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(8,self.daif);u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if i.mnemonic=='msr':
   assert i.op_str=='daifset, #7';self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.daif|=0x1c0;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if i.mnemonic=='autda':
   self.auth.append({'pc':hex(a),'raw_pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'assumed_identity':True});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return CPU.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=30000);self.flush()
  assert self.reason in ['original_zone_event_returned','before_original_reacquire','before_original_diagnostic','before_hashed_wrapper_dereference'],self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,
   'initial_state_transfer':self.transfer,'initial_image_globals':self.image_initial,'overlays':self.overlays,
   'initial_zone192_hex':self.initial_zone,'zone':hex(self.zone),'event':hex(self.event),'expected_bucket_index':self.bucket,
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,
   'observer_requests':self.callbacks,'declared_callback_RAM_writes':self.model_RAM_writes,'hash_boundaries':self.hash_boundaries,
   'logical_data_authentication':self.auth,'final_DAIF_snapshot':hex(self.daif),'boundary':self.boundary,
   'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'final_zone192_hex':bytes(self.u.mem_read(self.zone,192)).hex(),
   'release_fixture':{'bitmap_word':hex(self.bit_address),'bitmap_width_bits':self.bit_width,
    'bitmap_mask':hex(self.mask),'metadata':hex(META),'extent_bytes':self.extent},
   'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate is not None else None,**{n:False for n in R.FALSE}}

def oracle(row):
 c=row['configuration'];mode=c['mode'];z=int(row['zone'],16);event=(z+32)&MASK
 index,queue=hashed(event,c.get('count',8),TABLE);before=bytes.fromhex(row['initial_zone192_hex']);after=bytes.fromhex(row['final_zone192_hex']);ram=decode(row['final_private_RAM'])
 def u(a,n=4):return int.from_bytes(after[a-z:a-z+n] if z<=a<a+n<=z+192 else ram[a-P:a-P+n],'little')
 checks=[]
 def check(name,p):assert p,(name,c);checks.append(name)
 old_flags=int.from_bytes(before[0x3c:0x40],'little');early=mode=='arm' and c.get('cache') and c.get('quota',0)>0 and c.get('refill_result',0)&1
 active=not early and (mode!='arm' or not old_flags&16);geometry_error=active and c.get('nodes',0)>0 and c.get('invalid_zone')
 sequence=list(range(c.get('nodes',0))) if active and not geometry_error else []
 if sequence and c.get('action')=='skip':sequence=[0,2]
 if sequence and c.get('action')=='stop':sequence=[0]
 check('observer_postcallback_link_sequence',[int(x['node'],16) for x in row['observer_requests']]==[NODES[j] for j in sequence])
 zone_id=((((z-R.BASE)&MASK)*0x1555556)&MASK)>>32
 check('observer_request_ABI',all([int(v,16) for v in x['arguments3']]==[zone_id&0xffff,z,int(mode=='arm')] and int(x['modifier'],16)==0xeed9 and int(x['raw_callback'],16)==CALLBACKS[NODES.index(int(x['node'],16))] for x in row['observer_requests']))
 flags=old_flags if early or mode=='arm' and not active else old_flags|16 if mode=='arm' else old_flags&~16
 if sequence and c.get('action')=='flag':flags=flags&~16 if mode=='arm' else flags|16
 check('source_flag_update_and_declared_interference',u(z+0x3c)==flags)
 if geometry_error:check('geometry_diagnostic',int(row['boundary']['pc'],16)==0xfffffe000c6336f8 and int(row['boundary']['registers31'][0],16)==z)
 elif early:check('prefill_odd_early_return',row['boundary']['kind']=='original_zone_event_returned' and not row['hash_boundaries'])
 else:
  check('same_event_hash_boundary',len(row['hash_boundaries'])==1 and row['hash_boundaries'][0]['kind']==('wait' if mode=='arm' else 'wake'))
  args=[int(v,16) for v in row['hash_boundaries'][0]['arguments5']]
  check('queue_and_full_event',args[:2]==[queue,event] and row['expected_bucket_index']==index)
  if mode=='arm':
   check('wait_raw_control8_deadline0',args[2:4]==[8,0])
   check('registration_result_does_not_gate_block',sum(m['symbol']=='declared_block_return_no_RAM_effect' for m in row['API_models'])==1)
   check('reacquire_boundary',row['boundary']['kind']=='before_original_reacquire' and int(row['boundary']['registers31'][0],16)==z+0x80)
   check('actual_unlock_nesting',u(THREAD+0x1c8)==0)
  else:
   check('wake_zero_result_flags_and_maximum',args[2:5]==[0,0,0xffffffff])
   if c.get('hash_only'):check('no_hash_only_dereference',row['boundary']['kind']=='before_hashed_wrapper_dereference')
   elif not c.get('valid',True):check('invalid_queue_diagnostic',int(row['boundary']['pc'],16)==0xfffffe000c631d74)
   elif c.get('daif',0x3c0)&0x200==0 and c.get('qtype',1) in [1,2]:check('DAIF_diagnostic',int(row['boundary']['pc'],16)==0xfffffe000c62a2b0)
   else:
    check('conditional_builder_return',row['boundary']['kind']=='original_zone_event_returned')
    builder=next(m for m in row['API_models'] if m['symbol']=='declared_builder_result_no_RAM_effect')
    builder_args=[int(x,16) for x in builder['arguments8']]
    check('builder_ABI',builder_args[:5]==[queue,event,0,4|(16 if c.get('qtype',1) in [1,2] and c.get('daif',0x3c0)&0x1c0!=0x1c0 else 0),0xffffffff])
    if mode=='follow':check('direct_follow_returns_raw_builder_word',int(row['boundary']['registers31'][0],16)==c.get('builder_result',0))
 normal=row['boundary']['kind'] in ['original_zone_event_returned','before_original_reacquire']
 if normal:
  check('SP_and_callee_saved_GPs',int(row['boundary']['SP'],16)==SP and all(row['boundary']['registers31'][j]==row['entry_registers31'][j] for j in [*range(19,30),30]))
  if mode=='release':check('release_accounting_and_nesting_join',u(THREAD+0x1c8)==0 and u(STATS+8,8)==256 and u(META+2,2)==1 and u(z+0xa8)==0)
 check('declared_callback_effects_only',all(not w['native_effect_executed'] for w in row['declared_callback_RAM_writes']))
 # Independent byte-exact non-stack oracle, not a replay of source stores.
 # The source semantic changes are the flag protocol, owner bytes, and
 # the separately recovered release accounting/bitmap/count transition.
 expected=bytearray(decode(row['initial_state_transfer']));ez=bytearray(before)
 for p in row['overlays']:
  a=int(p['address'],16);b=bytes.fromhex(p['after_hex'])
  if P<=a<a+len(b)<=P+SIZE:expected[a-P:a-P+len(b)]=b
 def put(a,n,v):
  b=(v&((1<<(8*n))-1)).to_bytes(n,'little')
  if z<=a<a+n<=z+192:ez[a-z:a-z+n]=b
  if P<=a<a+n<=P+SIZE:expected[a-P:a-P+n]=b
 def get(a,n):
  b=ez[a-z:a-z+n] if z<=a<a+n<=z+192 else expected[a-P:a-P+n]
  return int.from_bytes(b,'little')
 put(z+0x3c,4,flags)
 if mode=='arm' and active:put(z+0x62,1,get(z+0x62,1)+1)
 if sequence and c.get('action') in ['skip','stop']:put(NODES[0],8,NODES[2] if c['action']=='skip' else 0)
 if mode=='release':
  f=row['release_fixture'];a=int(f['bitmap_word'],16);n=f['bitmap_width_bits']//8
  put(THREAD+0x1c8,4,1);put(STATS+8,8,f['extent_bytes']);put(a,n,get(a,n)^int(f['bitmap_mask'],16))
  put(int(f['metadata'],16)+2,2,1);put(z+0x80,4,get(z+0x80,4)+0x1000000)
 if normal and not early:
  if mode in ['arm','release']:
   put(z+0x82,1,get(z+0x82,1)+1);put(THREAD+0x1c8,4,0)
  if mode=='release':put(z+0xa8,4,0)
 stack_lo,stack_hi=SP-P-0x100,SP-P+0x100
 check('all_nonstack_private_RAM_exact',ram[:stack_lo]==expected[:stack_lo] and ram[stack_hi:]==expected[stack_hi:])
 check('entire_zone192_exact',after==ez)
 return checks
