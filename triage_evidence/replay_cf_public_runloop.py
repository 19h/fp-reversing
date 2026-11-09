#!/usr/bin/env python3
"""Independent public CF/TSD/context/Stop-wake/cleanup replay.
No new probe import; recompute entry arguments, original stack-derived receive
address, diagnostic fields and callback-operation return contract. No native
CF/IPC/thread/PAC or daemon callback body. O(V*F+J+H*R),O(I+J+R).
"""
import struct,hashlib
from unicorn import arm64_const as A
from daemon_receive_tools import CS
from replay_cf_source0_scheduler import Replay as Parent
from replay_cf_source_scheduling import B,RL,MODE,SRC,SET0,HALT,NAME
from replay_cf_mode_construction import TLS
from replay_cf_wake_send_wrapper import Replay as Wrapper,MACH
from replay_cf_runloop_handoff import LOW,LOW_SIZE
from recover_cf_public_runloop import FUNCS,FATALS,SPEC,INMODE,PUBLICRUN,STOP
from recover_cf_receive import RUN
from recover_cf_descriptor_source_factory import DAEMON
from recover_cf_source_wake_callers import WAKE
from recover_cf_runloop_wake_port import DEFAULT
COMMON=DEFAULT+0x20;TSD=B+0xcb000;PREVIOUS=B+0xcc000;STOP_RETURN=HALT+0x200
class Replay(Parent):
 def __init__(self,p,k,s):
  super().__init__(p,k,s);self.pfi=self.efi=0;self.effect_stack=[];self.effect_done=False;self.public_prepared=False;self.active_run_sp=self.active_user=None;raw=bytearray(1128);struct.pack_into('<Q',raw,88,RL);wanted=[(TSD,bytes(raw)+b'\xa5'),(TLS+0x1b8,struct.pack('<Q',TSD)),(PREVIOUS,bytes(64)+b'\xa5'),(0x1eb15a448,b'\xff'*8)];assert len(p['public_initial'])==len(wanted)
  for(at,b),e in zip(wanted,p['public_initial'],strict=True):assert e=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
 def pf(self,e,a):
  assert e['pc']==hex(a)and e['stage']==self.stage;self.check_frame(e);assert e['runloop2720_hex']==bytes(self.u.mem_read(RL,2720)).hex()and e['mode512_hex']==bytes(self.u.mem_read(MODE,512)).hex()and e['TSD1128_hex']==bytes(self.u.mem_read(TSD,1128)).hex()and e['model_state']==self.state()and e['pool_stack']==[hex(v)for v in self.pool_stack];self.counts['public_RUN_full_tracked_CPU_context_TSD_frames_checked']+=1
 def public_prepare(self):
  e=self.p['declared_public_field_variants'];self.pf(e['before'],HALT);cfg=self.config;changes=[]
  if cfg.get('depth'):changes.append((RL+0x54,bytes([cfg['depth']])))
  if cfg.get('previous_mode'):changes.append((RL+0xa60,struct.pack('<Q',PREVIOUS)))
  if cfg.get('deallocating'):changes.append((RL+8,struct.pack('<Q',int.from_bytes(bytes(self.u.mem_read(RL+8,8)),'little')|4)))
  if cfg.get('forked'):changes.append((0x1ed891720,b'\x01'))
  if cfg.get('empty_mode'):changes.append((SET0+0x14,bytes(4)));self.collections[SET0].clear()
  assert len(e['patches'])==len(changes)
  for(at,b),v in zip(changes,e['patches'],strict=True):assert v=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
  self.pf(e['after'],HALT);self.public_prepared=True
 def public_lower(self,a):
  x=[self.reg(j)for j in range(9)]
  if a==0x1846df588:assert x[0]in(DEFAULT,COMMON,NAME)and x[1]in(DEFAULT,COMMON,NAME);self.mode_call(a,'declared_runloop_mode_name_equality',int(x[0]==x[1]));self.counts['declared_public_name_contracts_recomputed']+=1;return True
  if a==0x184833694 and x[0]==RL and self.stage=='runloop'and self.config.get('bad_type'):self.mode_call(a,'declared_public_runloop_type44',44);return True
  return False
 def begin_effect(self):
  e=self.p['declared_callback_effects'][self.efi];self.efi+=1;assert e['kind']=='declared_daemon_callback_requests_original_CFRunLoopStop';self.pf(e['before'],DAEMON);self.effect_stack.append(e);self.effect_done=True;self.setreg(0,RL);self.setreg(30,STOP_RETURN);self.u.reg_write(A.UC_ARM64_REG_PC,STOP);self.pf(e['entry'],STOP);self.counts['declared_callback_to_original_Stop_handoffs_checked']+=1
 def finish_effect(self):
  e=self.effect_stack.pop();self.pf(e['original_Stop_return'],STOP_RETURN);f=e['before']
  for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
  for j,v in enumerate(f['Q_registers32']):self.u.reg_write(getattr(A,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  self.u.reg_write(A.UC_ARM64_REG_SP,int(f['SP'],16));self.u.reg_write(A.UC_ARM64_REG_NZCV,int(f['NZCV'],16));self.u.reg_write(A.UC_ARM64_REG_PC,DAEMON);self.wphase='runloop';self.pf(e['declared_callback_resume'],DAEMON);self.counts['original_Stop_return_to_declared_callback_contracts_checked']+=1
 def check_run_frame(self,e):
  sp=self.active_run_sp;assert sp is not None and e['runloop_frame_base']==hex(sp)and e['receive_buffer_address']==hex(self.active_user);self.check_frame(e)
  for a,n,key in((sp+0x68,8,'native_buffer_pointer8_hex'),(sp+0x64,4,'native_live_name4_hex'),(sp+0x50,8,'native_reply8_hex'),(sp+0x78,8,'native_voucher_state8_hex'),(sp+0x70,8,'native_voucher_copy8_hex'),(self.active_user,148,'user148_hex')):assert e[key]==bytes(self.u.mem_read(a,n)).hex()
  self.counts['original_public_stack_relative_runloop_frames_checked']+=1
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==RUN:self.active_run_sp=u.reg_read(A.UC_ARM64_REG_SP)-0xd50;self.active_user=self.active_run_sp+0xd0
  if a==STOP_RETURN:return self.finish_effect()
  if a==DAEMON and self.config.get('callback_stop')and not self.effect_done:return self.begin_effect()
  if a==WAKE and self.effect_stack:self.wphase='wakeup'
  if self.pfi<len(self.p['public_RUN_frames']):
   e=self.p['public_RUN_frames'][self.pfi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.pf(e,a);self.pfi+=1
  if a in FATALS:
   assert self.p['boundary']['kind']=='before_original_public_runloop_'+FATALS[a]and self.seq==len(self.p['source_visits']);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if a==HALT and self.stage=='fd_register':
   self.ff(self.p['factory_returns'][self.fri],a);self.fri+=1;self.check_schedule_frame(self.p['registration_returns'][self.rri]);self.rri+=1;self.prepare();self.public_prepare();e=self.p['public_handoffs'][self.pi];kind=self.config['entry'];assert e['kind']=='registered_source_to_public_'+kind;self.check_frame(e['before']);assert e['model_state']==self.state()
   for at,n,key in((B,0x100000,'private_RAM_sha256'),(LOW,LOW_SIZE,'lower_stack_sha256')):assert e[key]==hashlib.sha256(bytes(u.mem_read(at,n))).hexdigest()
   name={'default':DEFAULT,'common':COMMON,'null':0,'missing':NAME}[self.config.get('mode_name','default')];args=(RL,name,self.config.get('boolean',1))if kind=='specific'else(name,self.config.get('boolean',1))if kind=='inmode'else();target=SPEC if kind=='specific'else INMODE if kind=='inmode'else PUBLICRUN;self.stage=self.wphase='runloop';self.transition=True
   for j,v in enumerate(args):self.setreg(j,v)
   self.setreg(30,HALT);u.reg_write(A.UC_ARM64_REG_PC,target);u.reg_write(A.UC_ARM64_REG_Q0,0x7ff0000000000000);self.check_frame(e['after']);self.pi+=1;self.counts['registered_source_to_original_public_entry_CPU_RAM_handoffs_checked']+=1;return
  if a==HALT and self.stage=='runloop':
   assert self.p['boundary']['kind']=='original_public_runloop_returned'and self.seq==len(self.p['source_visits']);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if a==MACH and self.effect_stack and self.reg(1)==0x11:return Wrapper.hook(self,u,a,n,d)
  if a==MACH and self.stage=='runloop':
   args=[self.reg(j)for j in range(7)]
   if args==[self.active_user,0x07000906,0,3072,self.facility,0,0]:self.mode_call(a,'declared_public_runloop_nonblocking_receive_timeout',0x10004003,extra={'arguments7':[hex(v)for v in args]});self.counts['public_RUN_nonblocking_receive_timeout_contracts_checked']+=1;return
   assert args==[self.active_user,0x07000806,0,3072,self.facility,0xffffffff,0]and self.p['boundary']['kind']=='before_original_public_runloop_idle_receive'and self.seq==len(self.p['source_visits']);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if self.public_lower(a):return
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in FUNCS and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};i=next(CS.disasm(raw,a));self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['original_public_wrapper_TSD_cleanup_Stop_visits_checked']+=1;op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autiza','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   elif op=='mrs':assert i.op_str=='x20, tpidrro_el0'and u.reg_read(A.UC_ARM64_REG_TPIDRRO_EL0)==TLS
   else:assert op not in('svc','hvc','smc','brk','msr')and not op.startswith(('pac','aut','xpac'))
   return
  return super().hook(u,a,n,d)
 def run(self):
  super().run();assert self.public_prepared and self.pfi==len(self.p['public_RUN_frames'])and self.efi==len(self.p['declared_callback_effects'])and not self.effect_stack and self.p['final_TSD1129_hex']==bytes(self.u.mem_read(TSD,1129)).hex()and self.p['final_warning_once8_hex']==bytes(self.u.mem_read(0x1eb15a448,8)).hex();assert self.p['active_RUN_frame_base']==(None if self.active_run_sp is None else hex(self.active_run_sp))and self.p['active_receive_buffer']==(None if self.active_user is None else hex(self.active_user));return dict(self.counts)
