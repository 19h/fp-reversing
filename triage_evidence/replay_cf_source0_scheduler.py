#!/usr/bin/env python3
"""Independent full-state source0 scheduler replay; no new probe import.
Original collection/callout/pool wrappers and RUN control flow; lower effects
and callback returns recomputed. No native IPC/PAC/runtime/daemon callback body.
O(V*F+J+H*R) time,O(I+J+R) space.
"""
import struct,hashlib
from unicorn import arm64_const as A
from daemon_receive_tools import CS
from replay_cf_descriptor_source_factory import Replay as Parent,FDO
from replay_cf_source_scheduling import B,RL,MODE,SRC,SET0,HALT
from replay_cf_runloop_handoff import LOW,LOW_SIZE,USER
from recover_cf_source0_scheduler import FUNCS
from recover_cf_descriptor_source_factory import DAEMON
from recover_cf_receive import RUN
from recover_cf_receive_voucher import MACH
POOL=B+0xca000
class Replay(Parent):
 def __init__(self,p,k,s):
  super().__init__(p,k,s);self.sci=self.cbi=self.pooli=self.latei=0;self.pool_stack=[];self.prepared=False;self.u.mem_write(POOL,bytes(64)+b'\xa5')
 def sf(self,e,a):
  assert e['pc']==hex(a)and e['stage']==self.stage;self.check_frame(e);assert e['source184_hex']==bytes(self.u.mem_read(SRC,184)).hex()and e['descriptor112_hex']==bytes(self.u.mem_read(FDO,112)).hex()and e['source_set64_hex']==bytes(self.u.mem_read(SET0,64)).hex()and e['model_state']==self.state()and e['pool_stack']==[hex(v)for v in self.pool_stack];self.counts['source0_full_CPU_object_collection_pool_frames_checked']+=1
 def prepare(self):
  e=self.p['declared_scheduler_field_variants'];self.sf(e['before'],HALT);changes=[];cfg=self.config
  if cfg.get('source_valid')is False:changes.append((SRC+8,struct.pack('<Q',int.from_bytes(bytes(self.u.mem_read(SRC+8,8)),'little')&~8)))
  if cfg.get('source_version'):changes.append((SRC+0x68,struct.pack('<Q',cfg['source_version'])))
  if cfg.get('clear_signal'):changes.append((SRC+0x58,bytes(8)))
  if cfg.get('null_perform'):changes.append((SRC+0xb0,bytes(8)))
  if cfg.get('pool_disabled'):changes.append((RL+0xa99,b'\0'))
  assert len(e['patches'])==len(changes)
  for(at,b),v in zip(changes,e['patches'],strict=True):assert v=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
  self.sf(e['after'],HALT);self.prepared=True
 def scheduler_lower(self,a):
  x=[self.reg(j)for j in range(9)];before=self.state();name=None;value=0;patches=[];extra={}
  if a==0x1846da4dc and x[1]==46:
   assert x[2:4]==[168,0];name='declared_source0_runtime_header_type46';value=SRC;raw=bytearray(184);raw[8:16]=(46<<8).to_bytes(8,'little');patches=[(SRC,bytes(raw))]
  elif a==0x1846fb960 and x[0]==SET0:
   assert x[1:3]==[SRC,SRC];name='declared_source0_hash_add_and_count';self.collections[SET0].add(SRC);patches=[(SET0+0x14,struct.pack('<I',len(self.collections[SET0]))),(SET0+0x1a,b'\x01')]
  elif a==0x18471c584 and x[0]==SET0:assert x[1]==0 and self.collections[SET0]=={SRC};name='declared_source0_hash_bucket';patches=[(x[8],struct.pack('<4Q',0,SRC,SRC,1))]
  elif a==0x184833260 and x[:2]==[46,SRC]:name='declared_source0_nonObjC_type46';value=0
  elif a==0x188076e60:
   assert not self.pool_stack;name='declared_objc_autorelease_pool_push';value=POOL;self.pool_stack.append(value);event={'operation':'push','token':hex(value),'source_visit_index':self.seq};assert self.p['declared_pool_events'][self.pooli]==event;self.pooli+=1;extra={'pool_stack_after':[hex(v)for v in self.pool_stack]}
  elif a==0x188076e50:
   assert self.pool_stack==[x[0]];name='declared_objc_autorelease_pool_pop';event={'operation':'pop','token':hex(x[0]),'source_visit_index':self.seq};assert self.p['declared_pool_events'][self.pooli]==event;self.pooli+=1;self.pool_stack.pop();extra={'pool_stack_after':[]}
  elif a==DAEMON:
   assert self.stage=='runloop'and x[:3]==[FDO,self.config.get('enable_mask',1),0];e=self.p['daemon_callback_return_calls'][self.cbi];self.sf(e,a);assert e['arguments3']==[hex(v)for v in x[:3]];self.cbi+=1;name='declared_daemon_descriptor_void_callback_return';extra={'callback_arguments3':e['arguments3']}
  if name:self.mode_call(a,name,value,patches,extra,before);self.counts['source0_lower_contracts_recomputed']+=1;return True
  return False
 def lower(self,a):
  if a==0x188086d70 and self.stage=='runloop':
   self.stage='perform'
   try:return super().lower(a)
   finally:self.stage='runloop'
  return super().lower(a)
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==0x1847587d4 and self.config.get('late_change'):
   e=self.p['declared_late_source_variants'][self.latei];self.sf(e['before'],a);kind=self.config['late_change'];at=SRC+(8 if kind=='invalidate'else 0x58);b=struct.pack('<Q',int.from_bytes(bytes(u.mem_read(at,8)),'little')&~8)if kind=='invalidate'else bytes(8);assert e['patches']==[{'address':hex(at),'before_hex':bytes(u.mem_read(at,8)).hex(),'after_hex':b.hex()}];u.mem_write(at,b);self.sf(e['after'],a);self.latei+=1
  if self.sci<len(self.p['scheduler_frames']):
   e=self.p['scheduler_frames'][self.sci]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.sf(e,a);self.sci+=1
  if a==HALT and self.stage=='fd_register':
   e=self.p['factory_returns'][self.fri];self.ff(e,a);self.fri+=1;self.check_schedule_frame(self.p['registration_returns'][self.rri]);self.rri+=1;self.prepare();e=self.p['public_handoffs'][self.pi];assert e['kind']=='AddSource0_to_original_RUN';self.check_frame(e['before']);assert e['model_state']==self.state()
   for at,n,key in((B,0x100000,'private_RAM_sha256'),(LOW,LOW_SIZE,'lower_stack_sha256')):assert e[key]==hashlib.sha256(bytes(self.u.mem_read(at,n))).hexdigest()
   self.stage=self.wphase='runloop';self.transition=True
   for j,v in enumerate((RL,MODE,1)):self.setreg(j,v)
   self.setreg(30,HALT);u.reg_write(A.UC_ARM64_REG_Q0,0x7ff0000000000000);u.reg_write(A.UC_ARM64_REG_PC,RUN);self.check_frame(e['after']);self.pi+=1;self.counts['registered_source_to_original_RUN_CPU_RAM_handoff_checked']+=1;return
  if a==HALT and self.stage=='runloop':
   assert self.p['boundary']['kind']=='original_source0_RUN_returned'and self.seq==len(self.p['source_visits']);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if a==MACH and self.stage=='runloop':
   args=[self.reg(j)for j in range(7)]
   if args==[USER,0x07000906,0,3072,self.facility,0,0]:self.mode_call(a,'declared_source0_nonblocking_receive_timeout',0x10004003,extra={'arguments7':[hex(v)for v in args]});self.counts['source0_nonblocking_receive_timeout_contracts_checked']+=1;return
   assert args==[USER,0x07000806,0,3072,self.facility,0xffffffff,0]and self.p['boundary']['kind']=='before_original_source0_idle_receive'and self.seq==len(self.p['source_visits']);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if self.scheduler_lower(a):return
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in FUNCS and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};i=next(CS.disasm(raw,a));self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['original_source0_scheduler_pool_collection_visits_checked']+=1;op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autiza','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac'))
   return
  return super().hook(u,a,n,d)
 def run(self):
  super().run();assert self.latei==len(self.p['declared_late_source_variants'])and self.prepared and self.sci==len(self.p['scheduler_frames'])and self.cbi==len(self.p['daemon_callback_return_calls'])and self.pooli==len(self.p['declared_pool_events'])and not self.pool_stack and self.p['final_pool_stack']==[]and self.p['final_source_set64_hex']==bytes(self.u.mem_read(SET0,64)).hex()and self.p['final_pool65_hex']==bytes(self.u.mem_read(POOL,65)).hex();return dict(self.counts)
