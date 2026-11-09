#!/usr/bin/env python3
"""Independent source-signal/bag-callback/wake replay; no new probe import.
All source bytes, private entry patches, clock, hash lower contracts, original
callback multiplicity, complete CPU/RAM and SVC returns are recomputed.
No native callers, IPC, collection backend, concurrency or hardware PAC proof.
O(V*F + I + R + J) time, O(I + R + J) space: visits V, captured
function count F, captured image I, private RAM R and retained journals J.
"""
import hashlib,struct
from unicorn import arm64_const as A
from daemon_receive_tools import CS
from replay_cf_wake_send_wrapper import Replay as Parent,RETURN,MACH
from replay_cf_runloop_wake_port import CFReplay as WakeBase,WAKER_SP
from replay_cf_source_scheduling import B,RL,SRC,BAG,HALT,USER
from replay_cf_runloop_handoff import LOW,LOW_SIZE
from recover_cf_source_wake_callers import SIGNAL,WAKELOOPS,LOOP,COPY,APPLY,HASHAPPLY,INVOKE,WAKE
COPYBAG=B+0xbf000;ALLOC=B+0xb0000;SELECTED={SIGNAL,WAKELOOPS,LOOP,COPY,APPLY,HASHAPPLY,INVOKE}
class Replay(Parent):
 def __init__(self,p,k,s):
  super().__init__(p,k,s);self.source_fi=self.source_ri=0;self.fixture_checked=False;self.signal_calls=self.clock_calls=self.copy_count=0;self.u.mem_write(COPYBAG,bytes(64)+b'\xa5')
 def source_frame(self,e,a):
  assert e['pc']==hex(a)and e['phase']==self.wphase;self.check_frame(e);assert e['source256_hex']==bytes(self.u.mem_read(SRC,256)).hex()and e['copy64_hex']==bytes(self.u.mem_read(COPYBAG,64)).hex()and e['model_state']==self.state();self.counts['source_bag_complete_CPU_and_object_frames_checked']+=1
 def prepare(self,a):
  assert not self.fixture_checked and self.collections[BAG]=={RL}and self.bag_counts[RL]==1;e=self.p['declared_source_fixture'];self.source_frame(e['before'],a);cfg=self.config
  patches=[(SRC+8,struct.pack('<Q',0 if cfg['source_invalid']else 8)),(SRC+0x60,struct.pack('<Q',0 if cfg['missing_bag']else BAG))];assert len(e['patches'])==2
  for(at,b),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
  self.collections[BAG]={RL}if cfg['bag_multiplicity']else set();self.bag_counts[RL]=cfg['bag_multiplicity'];self.source_frame(e['after'],a);self.fixture_checked=True;self.counts['explicit_source_entry_premises_recomputed']+=1
 def public_entry(self,e,target,args):
  self.check_frame(e['before']);assert e['model_state']==self.state()
  for at,n,k in((B,0x100000,'private_RAM_sha256'),(LOW,LOW_SIZE,'lower_stack_sha256')):assert e[k]==hashlib.sha256(bytes(self.u.mem_read(at,n))).hexdigest()
  for j,v in enumerate(args):self.setreg(j,v)
  self.setreg(30,HALT)
  if 'declared_waker_SP'in e:assert e['declared_waker_SP']==hex(WAKER_SP);self.u.reg_write(A.UC_ARM64_REG_SP,WAKER_SP)
  self.u.reg_write(A.UC_ARM64_REG_PC,target);self.check_frame(e['after']);self.pi+=1;self.counts['declared_source_function_entry_CPU_RAM_handoffs_checked']+=1
 def new_model(self,a):
  x=[self.reg(j)for j in range(9)];before=self.state();value=0;patches=[];name=None
  if a==0x184833380 and x[0]==SRC:name='declared_source_runtime_validate'
  elif a==0x184833694 and x[0]==SRC:name='declared_source_runtime_type46';value=46
  elif a==0x184833260 and x[0]==4 and x[1]==BAG:name='declared_source_bag_nonObjC';value=1
  elif a==0x1847290e4 and x[0]==BAG:name='declared_source_bag_total_count';value=self.config['bag_multiplicity']
  elif a==0x184749a88 and x[0]==BAG:
   assert x[1:3]==[self.config['bag_multiplicity'],0];name='declared_source_bag_elements';patches=[(x[3],b''.join(struct.pack('<Q',RL)for _ in range(x[1])))]if x[1]else[]
  elif a==0x18471aab0:
   assert x[:2]==[ALLOC,0x1e232d698];name='declared_source_copy_hash_storage';value=0 if self.config['copy_null']else COPYBAG
   if value:self.collections[COPYBAG]=set();self.copy_count=0;raw=bytearray(64);raw[0x1a]=1;patches=[(COPYBAG,bytes(raw))]
  elif a==0x1846f3564 and x[0]==COPYBAG:assert x[1]==self.config['bag_multiplicity'];name='declared_source_copy_capacity'
  elif a==0x1846fb960 and x[0]==COPYBAG:
   assert x[1:3]==[RL,RL];name='declared_source_copy_add';self.collections[COPYBAG].add(RL);self.copy_count+=1;patches=[(COPYBAG+0x14,struct.pack('<I',1))]
  elif a==0x1846dc364 and x[:2]==[COPYBAG,4]:name='declared_source_copy_type4'
  elif a==0x18471c584 and x[0]==COPYBAG:
   assert x[1]==0 and self.copy_count in(1,2);name='declared_source_copy_bucket';patches=[(x[8],struct.pack('<4Q',0,RL,RL,self.copy_count))]
  elif a==0x18054808c and self.wphase=='signal':self.clock_calls+=1;name='declared_source_signal_clock';value=100*self.clock_calls
  if name:self.mode_call(a,name,value,patches,{'declared_copy_multiplicity':self.copy_count},before=before);self.counts['source_lower_runtime_contracts_recomputed']+=1;return True
  return False
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==WAKE and self.wphase=='wake_loops':self.wphase='wakeup'
  if a==0x184794f14:self.wphase='wake_loops'
  if self.source_fi<len(self.p['source_wake_frames']):
   e=self.p['source_wake_frames'][self.source_fi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.source_frame(e,a);self.source_fi+=1
  if self.pi<len(self.p['public_handoffs']):
   e=self.p['public_handoffs'][self.pi]
   if e['kind'].startswith('declared_source_entry_from_')and e['before']['source_visit_index']==self.seq:
    assert a in(HALT,MACH)
    if a==HALT:
     assert self.wphase=='registration'and self.config['wake_case']=='suppressed'and bytes(u.mem_read(RL+0x153,1))==b'\1';ret=self.p['registration_returns'][self.rri];self.check_schedule_frame(ret);self.rri+=1;assert e['kind']=='declared_source_entry_from_AddSource_to_WakeUp_suppressed'
    else:assert self.wphase=='runloop'and e['kind']=='declared_source_entry_from_waiting_receive_to_external_waker_entry'and[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,self.facility,0xffffffff,0]and bytes(u.mem_read(RL+0x153,1))==b'\0'
    self.wphase='wakeup';self.prepare(a);self.wphase='signal'if self.config['signal_repeats']else'wake_loops';return self.public_entry(e,SIGNAL if self.wphase=='signal'else WAKELOOPS,(SRC,))
  if a==HALT and self.wphase in('signal','wake_loops'):
   e=self.p['source_wake_returns'][self.source_ri];self.source_frame(e,a);self.source_ri+=1
   if self.wphase=='signal':
    self.signal_calls+=1
    if self.signal_calls<self.config['signal_repeats']:e=self.p['public_handoffs'][self.pi];assert e['kind']=='repeat_source_signal';return self.public_entry(e,SIGNAL,(SRC,))
    if self.config['call_helper']:e=self.p['public_handoffs'][self.pi];assert e['kind']=='signal_to_source_wake_helper';self.wphase='wake_loops';return self.public_entry(e,WAKELOOPS,(SRC,))
   assert self.pi==len(self.p['public_handoffs'])and self.seq==len(self.p['source_visits'])and self.p['boundary']['kind']=='original_source_wake_contract_returned';self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if self.new_model(a):return
  if a==RETURN:
   e=self.p['wrapper_returns'][self.xri];self.wrapper_frame(e,a);assert self.si and self.reg(0)==self.config['trap_results'][self.si-1];self.xri+=1;self.counts['original_per_callback_wrapper_status_returns_checked']+=1;return WakeBase.hook(self,u,a,n,d)
  if a==MACH and self.wphase=='wakeup':
   saved=self.config['trap_results'];self.config['trap_results']=[*saved[:-1],saved[self.si]]
   try:return super().hook(u,a,n,d)
   finally:self.config['trap_results']=saved
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in SELECTED and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};i=next(CS.disasm(raw,a));self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['original_source_bag_callback_visits_checked']+=1;op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac'))
   return
  return super().hook(u,a,n,d)
 def run(self):
  super().run();assert self.fixture_checked and self.source_fi==len(self.p['source_wake_frames'])and self.source_ri==len(self.p['source_wake_returns'])and self.p['final_copy64_hex']==bytes(self.u.mem_read(COPYBAG,64)).hex()and self.p['copy_guard_hex']==bytes(self.u.mem_read(COPYBAG+64,1)).hex()=='a5'and self.p['declared_copy_multiplicity']==self.copy_count and self.p['signal_clock_calls']==self.clock_calls;return dict(self.counts)
