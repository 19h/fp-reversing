#!/usr/bin/env python3
"""Independent control dispatch replay; no new probe import or trace playback.
Recompute synthetic receive and lower contracts; execute original branch bodies
in a fresh CPU and compare complete inherited journals and final private RAM.
"""
import hashlib,struct
from unicorn import arm64_const as A
from daemon_receive_tools import CS
from replay_cf_mode_construction import Replay as Parent,B,MODE,RL,QUEUE,BLOCK,CALLBACK,HALT
from replay_cf_runloop_handoff import USER,LOW,LOW_SIZE
from recover_cf_receive import RUN
from recover_cf_receive_voucher import MACH
from recover_cf_control_port_dispatch import ROOTPERFORM,TIMERS,ARM,EMPTY,BOUNDARIES
NEWFUNCS={ROOTPERFORM,TIMERS,ARM,EMPTY}
PORTS={'root':0x607,'timer':0x707,'wake':0x807}
class Replay(Parent):
 def __init__(self,p,k,s):
  super().__init__(p,k,s);self.control_cursor=self.ccfi=self.ccmi=self.cbri=0;self.control_code={int(i['ea'],16):bytes.fromhex(f['bytes'])[4*j:4*j+4]for f in s['CF_functions']if int(f['start'],16)in NEWFUNCS for j,i in enumerate(f['instructions'])}
 def control_frame(self,f):
  self.check_frame(f);assert f['model_state']==self.state()and f['control_cursor']==self.control_cursor
  for a,n,key in((MODE,512,'mode512_hex'),(QUEUE,128,'queue128_hex')):assert f[key]==bytes(self.u.mem_read(a,n)).hex()
  self.counts['control_CPU_object_state_and_sequence_frames_checked']+=1
 def control_call(self,a,name,value,patches=(),extra=None):
  self.mode_call(a,name,value,patches,extra);assert self.p['control_models'][self.ccmi]==self.p['mode_models'][self.mmi-1];self.ccmi+=1;self.counts['declared_control_receive_and_lower_contracts_recomputed']+=1
 def hook(self,u,a,n,d):
  self.finish_writes()
  if self.ccfi<len(self.p['control_frames']):
   f=self.p['control_frames'][self.ccfi]
   if f['pc']==hex(a)and f['source_visit_index']==self.seq:self.control_frame(f);self.ccfi+=1
  if a==HALT and self.pi<len(self.p['public_handoffs']):
   e=self.p['public_handoffs'][self.pi];kind=e['kind']
   if kind in('AddSource_to_control_timer_callback','control_timer_callback_to_runloop'):
    assert self.config['timer_callback_before_run']
    if kind=='AddSource_to_control_timer_callback':self.check_schedule_frame(self.p['registration_returns'][self.rri]);self.rri+=1;target=CALLBACK;args=(BLOCK,)
    else:self.control_frame(self.p['callback_returns'][self.cbri]);self.cbri+=1;target=RUN;args=(RL,MODE,1);self.transition=True
    self.check_frame(e['before']);assert e['model_state']==self.state()
    for at,size,key in((B,0x100000,'private_RAM_sha256'),(LOW,LOW_SIZE,'lower_stack_sha256')):assert e[key]==hashlib.sha256(bytes(u.mem_read(at,size))).hexdigest()
    for j,v in enumerate(args):self.setreg(j,v)
    self.setreg(30,HALT)
    if target==RUN:u.reg_write(A.UC_ARM64_REG_Q0,0x7ff0000000000000)
    u.reg_write(A.UC_ARM64_REG_PC,target);self.check_frame(e['after']);self.pi+=1;self.counts['original_timer_callback_and_runloop_entry_handoffs_checked']+=1;return
  if a==MACH and self.control_cursor<len(self.config['control_sequence']):
   assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,self.facility,0xffffffff,0];kind=self.config['control_sequence'][self.control_cursor];name=PORTS[kind];assert(self.facility,name)in self.members;packet=struct.pack('<6I',0,24,0,name,0,self.config.get('control_message_id',0))+struct.pack('<2I',0,68)+bytes(60);self.control_cursor+=1;return self.control_call(a,'declared_control_port_receive',0,[(USER,packet)],{'control_kind':kind,'control_ordinal':self.control_cursor,'packet_provenance':'synthetic 24-byte header and 68-byte zero audit trailer; no kernel producer'})
  if a in BOUNDARIES:
   if a==0x18472907c:assert self.reg(0)in self.collections;value=len(self.collections[self.reg(0)])
   else:assert self.reg(0)==QUEUE;value=0
   return self.control_call(a,BOUNDARIES[a],value)
  if a in self.control_code:
   raw=bytes(u.mem_read(a,4));assert raw==self.control_code[a]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['original_control_root_timer_and_mode_empty_visits_checked']+=1;i=next(CS.disasm(raw,a));op=i.mnemonic
   if op in('pacibsp','autibsp','autda','xpacd','pacia','pacda','paciza','autia','xpaci'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac'))
   return
  return super().hook(u,a,n,d)
 def run(self):
  super().run();assert self.ccfi==len(self.p['control_frames'])and self.ccmi==len(self.p['control_models'])and self.cbri==len(self.p['callback_returns'])and self.control_cursor==self.p['final_control_cursor']==len(self.config['control_sequence']);self.counts['finite_control_sequences_exhausted']=1;return dict(self.counts)
