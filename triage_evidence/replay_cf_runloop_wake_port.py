#!/usr/bin/env python3
"""Independent fresh-CPU wake constructor/member and CF factory/emitter replay.
No new probe import. Full CPU/RAM, options, states, call tuples and models are
recomputed. No native IPC/concurrency/allocator/PAC claim. Linear in evidence.
"""
import hashlib,struct
from unicorn import arm64_const as A
from replay_kernel_timer_port_create import Replay as Parent,CFReplay as CFParent,NODE3
from replay_kernel_portset_delivery import INSERT_ARGS,TASK_NAME,PS,TABLE,ALLOC_ARGS
from replay_rpc502_vm_handoff import decode,P as B,SIZE
from recover_kernel_root_port_construct import CONSTRUCT,COPYIN
from recover_kernel_portset_delivery import ALLOC,INSERT
from recover_cf_runloop_wake_port import CREATE,WAKE,CHECK,MACH,DEFAULT
WPORT=B+0xc2000;WNODE=B+0xc1000;WARGS=B+0xbb000;WOPTS=B+0xbb040;WOUT=B+0xbb080;KH=B+0xe0000;PORTZONE=0xfffffe000caec500
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.root_phase='wake_construct';self.wfi=self.wri=self.whi=self.wmi=0;self.wafter=None
 def wake_frame(self,e,a):
  assert e['pc']==hex(a)and e['phase']==self.root_phase;self.cpu(e)
  for at,n,key in((WPORT,144,'wake_port144_hex'),(WOUT,4,'wake_name4_hex'),(TABLE+192,24,'entry8_24_hex'),(WNODE,48,'wake_link48_hex')):assert e[key]==bytes(self.u.mem_read(at,n)).hex()
  self.counts['wake_objects_namespace_and_complete_CPU_frames_checked']+=1
 def code(self,u,a,n,d):
  self.finish()
  if self.wafter:self.wake_frame(self.wafter,a);self.wafter=None
  if self.wfi<len(self.p['wake_frames']):
   e=self.p['wake_frames'][self.wfi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.wake_frame(e,a);self.wfi+=1
  if self.wri<len(self.p['wake_returns']):
   e=self.p['wake_returns'][self.wri]
   if a==KH and e['source_visit_index']==self.seq:self.wake_frame(e,a);assert decode(e['private_RAM'])==bytes(u.mem_read(B,SIZE));self.wri+=1;self.counts['wake_return_whole_RAM_images_checked']+=1
  if self.whi<len(self.p['wake_handoffs']):
   e=self.p['wake_handoffs'][self.whi]
   if a==KH and e['before']['source_visit_index']==self.seq:
    if self.tri<len(self.p['timer_returns']):
     ret=self.p['timer_returns'][self.tri]
     if ret['source_visit_index']==self.seq:self.timer_frame(ret,a);assert ret['phase']=='timer_insert'and decode(ret['private_RAM'])==bytes(u.mem_read(B,SIZE));self.tri+=1;self.counts['timer_function_return_whole_RAM_images_checked']+=1
    self.cpu(e['before']);assert decode(e['private_RAM_before'])==bytes(u.mem_read(B,SIZE))and self.reg(0)==0;kind=e['kind'];patches=[]
    if kind=='wake_construct_to_set_allocate':assert self.root_phase=='wake_construct'and bytes(u.mem_read(WOUT,4))==struct.pack('<I',0x807);self.root_phase='allocate';target=ALLOC;args=(ALLOC_ARGS,)
    elif kind=='timer_insert_to_wake_insert':assert self.root_phase=='timer_insert';self.root_phase='wake_insert';target=INSERT;args=(INSERT_ARGS,);patches=[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,0x807,0x507))]
    else:assert kind=='wake_insert_to_service_insert'and self.root_phase=='wake_insert';self.root_phase='insert';target=INSERT;args=(INSERT_ARGS,);patches=[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,int(self.p['receive_name'],16),0x507))]
    assert len(e['patches'])==len(patches)
    for(at,b),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};u.mem_write(at,b)
    for j,v in enumerate(args):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    u.reg_write(A.UC_ARM64_REG_X30,KH);u.reg_write(A.UC_ARM64_REG_PC,target);self.cpu(e['after']);assert decode(e['private_RAM_after'])==bytes(u.mem_read(B,SIZE));self.whi+=1;self.counts['wake_function_entry_CPU_RAM_handoffs_checked']+=1;return
  if self.wmi<len(self.p['wake_models']):
   e=self.p['wake_models'][self.wmi]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    self.wake_frame(e['before'],a);patches=[]
    if a==COPYIN:assert self.root_phase=='wake_construct'and[self.reg(j)for j in(0,2)]==[WOPTS,24];name='declared_exact_wake_options24_copyin';value=0;assert bytes(u.mem_read(WOPTS,24))==struct.pack('<IIQQ',0x33,1,0,0);patches=[(self.reg(1),bytes(u.mem_read(WOPTS,24)))]
    elif a==0xfffffe000bd75c64:assert self.root_phase=='wake_construct'and[self.reg(j)for j in range(3)]==[PORTZONE,B+0xb1000,0x8004]and bytes(u.mem_read(WPORT,144))==bytes(144);name='declared_zeroed_raw_wake_port144';value=WPORT
    else:
     assert a==0xfffffe000bcfefc8 and self.link_allocations in(2,3)and[self.reg(j)for j in range(2)]==[0xfffffe0007e43358,4];value=WNODE if self.link_allocations==2 else NODE3;name='declared_raw_wake_link48'if value==WNODE else'declared_fourth_service_link48';assert bytes(u.mem_read(value,48))==bytes(48);self.link_allocations+=1
    assert e['name']==name and e['result']==hex(value)and len(e['patches'])==len(patches)
    for(at,b),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};u.mem_write(at,b)
    m=self.models[self.mi];want=[value]+[(((j+1)*0x123456789abcdef)^((self.mi+1)*0x8b3dc651))&((1<<64)-1)for j in range(1,18)];assert m['symbol']==name and m['return_value']==hex(value)and m['after_registers31'][:18]==[hex(v)for v in want]and m['after_NZCV']==('0xf0000000'if(self.mi+1)&1 else'0x0');self.wafter=e['after'];self.wmi+=1;self.counts['wake_copyin_raw_port_and_link_contracts_recomputed']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.wfi==len(self.p['wake_frames'])and self.wri==len(self.p['wake_returns'])and self.whi==len(self.p['wake_handoffs'])and self.wmi==len(self.p['wake_models'])and self.wafter is None
  for at,n,key in((WPORT,144,'final_wake_port144_hex'),(WOUT,4,'final_wake_name4_hex'),(TABLE+192,24,'final_entry8_24_hex'),(WNODE,48,'final_wake_link48_hex')):assert self.p[key]==bytes(self.u.mem_read(at,n)).hex();self.counts['complete_wake_object_namespace_and_link_bytes_checked']+=n
  assert self.p['wake_guards_hex']==b''.join(bytes(self.u.mem_read(at+n,1))for at,n in((WPORT,144),(WNODE,48))).hex();return dict(self.counts)

from replay_cf_source_scheduling import RL,MODE,SRC,HALT,USER
from replay_cf_runloop_handoff import LOW,LOW_SIZE
from replay_cf_mode_construction import REGISTRY
from recover_cf_mode_construction import CONSTRUCT_TRAP
from recover_cf_source_scheduling import INSERT_TRAP,ADD
from recover_cf_receive import RUN
COMMON=B+0xb5000;OWNER=0x1234;WAKER_SP=B-0x100000
class CFReplay(CFParent):
 def __init__(self,p,k,s):
  super().__init__(p,k,s);self.wfi=self.wri=self.wsi=0;self.wphase='installer';self.u.mem_write(RL,bytes(8192));self.u.mem_write(RL+0xaa0,b'\xa5');self.u.mem_write(COMMON,bytes(64));self.collections[COMMON]=set()
 def wake_frame(self,e,a):
  assert e['pc']==hex(a)and e['phase']==self.wphase;self.check_frame(e);assert e['runloop2720_hex']==bytes(self.u.mem_read(RL,0xaa0)).hex()and e['model_state']==self.state();self.counts['CF_wake_runloop_state_and_CPU_frames_checked']+=1
 def hook(self,u,a,n,d):
  self.finish_writes()
  if self.wfi<len(self.p['wake_frames']):
   e=self.p['wake_frames'][self.wfi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.wake_frame(e,a);self.wfi+=1
  if self.wri<len(self.p['wake_returns']):
   e=self.p['wake_returns'][self.wri]
   if a==HALT and e['source_visit_index']==self.seq:self.wake_frame(e,a);self.wri+=1
  if a==0x1848d4168 or(a==HALT and self.pi==len(self.p['public_handoffs'])):
   kind='before_original_wake_send_failure'if a==0x1848d4168 else'original_runloop_Create_null'if self.config.get('create_null')else'original_CFRunLoopWakeUp_returned';assert self.p['boundary']['kind']==kind and self.seq==len(self.p['source_visits']);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if a==HALT or(a==MACH and self.wphase=='runloop'):
   if a==HALT and self.rri<len(self.p['registration_returns']):
    f=self.p['registration_returns'][self.rri]
    if f['source_visit_index']==self.seq:self.check_schedule_frame(f);self.rri+=1
   e=self.p['public_handoffs'][self.pi];self.check_frame(e['before']);assert e['model_state']==self.state()
   for at,size,key in((B,0x100000,'private_RAM_sha256'),(LOW,LOW_SIZE,'lower_stack_sha256')):assert e[key]==hashlib.sha256(bytes(u.mem_read(at,size))).hexdigest()
   kind=e['kind']
   if kind=='installer_to_runloop_Create':assert self.wphase=='installer';target=CREATE;args=(OWNER,);self.wphase='create'
   elif kind=='Create_to_AddSource_default':assert self.wphase=='create'and self.reg(0)==RL;target=ADD;args=(RL,SRC,DEFAULT);self.wphase='registration'
   elif kind=='AddSource_to_WakeUp_suppressed':assert self.wphase=='registration'and bytes(u.mem_read(RL+0x153,1))==b'\1';target=WAKE;args=(RL,);self.wphase='wakeup'
   elif kind=='AddSource_to_waiting_runloop':assert self.wphase=='registration';target=RUN;args=(RL,MODE,1);self.wphase='runloop';self.transition=True
   else:
    assert kind=='waiting_receive_to_external_waker_entry'and self.wphase=='runloop'and a==MACH and[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,self.facility,0xffffffff,0]and bytes(u.mem_read(RL+0x153,1))==b'\0'and e['declared_waker_SP']==hex(WAKER_SP);target=WAKE;args=(RL,);self.wphase='wakeup';u.reg_write(A.UC_ARM64_REG_SP,WAKER_SP)
   for j,v in enumerate(args):self.setreg(j,v)
   self.setreg(30,HALT)
   if target==RUN:u.reg_write(A.UC_ARM64_REG_Q0,0x7ff0000000000000)
   u.reg_write(A.UC_ARM64_REG_PC,target);self.check_frame(e['after']);self.pi+=1;self.counts['CF_factory_registration_and_external_waker_entry_handoffs_checked']+=1;return
  if a==0x1846da4dc and self.reg(1)==43:assert[self.reg(j)for j in range(1,4)]==[43,0xa90,0];return self.mode_call(a,'declared_runloop_runtime_storage',0 if self.config.get('create_null')else RL)
  if a==0x1805884cc and self.reg(0)==RL+0x10:return self.mode_call(a,'declared_runloop_mutex_initialize',0)
  if a==0x184716d78 and self.reg(30)in(0x184717f64,0x184717f88):assert self.reg(1)==0;return self.mode_call(a,'declared_runloop_common_or_registry_set',COMMON if self.reg(30)==0x184717f64 else REGISTRY)
  if a==0x1846df2ec and self.reg(1)==DEFAULT:return self.mode_call(a,'declared_immutable_default_name_copy',DEFAULT)
  if a==CONSTRUCT_TRAP and self.reg(2)==RL:
   x=[self.reg(j)for j in range(4)];opts=bytes(u.mem_read(x[1],24));assert x[0]==TASK_NAME and opts==struct.pack('<IIQQ',0x33,1,0,0);ret=self.origin['wake_returns'][0];assert ret['registers31'][0]=='0x0'and ret['wake_name4_hex']=='07080000';return self.mode_call(a,'original_kernel_wake_construct_return',0,[(x[3],bytes.fromhex(ret['wake_name4_hex']))],{'original_options24_hex':opts.hex(),'wake_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'context':hex(RL),'name':'0x807'}})
  if a==INSERT_TRAP and self.reg(1)==0x807:
   assert[self.reg(j)for j in range(3)]==[TASK_NAME,0x807,self.facility];ret=self.origin['wake_returns'][1];assert ret['registers31'][0]=='0x0';before=self.state();self.members.add((self.facility,0x807));return self.mode_call(a,'original_kernel_wake_member_return',0,extra={'wake_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'arguments24_hex':struct.pack('<3Q',TASK_NAME,0x807,self.facility).hex()}},before=before)
  if a==MACH:
   assert self.wphase=='wakeup';x=[self.reg(j)for j in range(7)];raw=bytes(u.mem_read(x[0],24));assert x[1:]==[0x11,24,0,0,0,0]and raw==struct.pack('<6I',0x13,24,0x807,0,0,0);e=self.p['wake_send'][self.wsi];self.wake_frame(e['before'],a);assert e['arguments7']==[hex(v)for v in x]and e['header24_hex']==raw.hex()and e['declared_send_return']==hex(self.config['send_status']);self.wsi+=1;return self.mode_call(a,'declared_wake_mach_msg_send_result',self.config['send_status'],extra={'original_header24_hex':raw.hex()})
  return super().hook(u,a,n,d)
 def run(self):
  super().run();assert self.wfi==len(self.p['wake_frames'])and self.wri==len(self.p['wake_returns'])and self.wsi==len(self.p['wake_send'])and self.p['final_runloop2720_hex']==bytes(self.u.mem_read(RL,0xaa0)).hex()and self.p['runloop_guard_hex']==bytes(self.u.mem_read(RL+0xaa0,1)).hex();self.counts['CF_complete_runloop_final_bytes_checked']+=0xaa0;return dict(self.counts)
