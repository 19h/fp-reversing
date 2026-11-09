#!/usr/bin/env python3
"""Independent original CF descriptor/source/block/readiness replay.
No new probe import. Original bytes, full CPU/RAM/journals, block copies,
external contracts and explicit handler/perform entries are recomputed.
O(V*F+I+J+H*R) time,O(I+J+R) space. No native IPC, scheduler or PAC proof.
"""
import hashlib,struct
from unicorn import arm64_const as A
from daemon_receive_tools import CS
from replay_cf_wake_send_wrapper import Replay as Parent,RETURN,MACH
from replay_cf_runloop_wake_port import CFReplay as WakeBase,WAKER_SP
from replay_cf_source_scheduling import B,RL,MODE,SRC,BAG,HALT,USER
from replay_cf_source_wake_callers import Replay as SourceModels
from replay_cf_runloop_handoff import LOW,LOW_SIZE
from recover_cf_source_wake_callers import SIGNAL,WAKELOOPS,LOOP,COPY,APPLY,HASHAPPLY,INVOKE,WAKE
from recover_cf_descriptor_source_factory import FUNCS,CREATE,SOURCE,ENABLE,PERFORM,DAEMON
from recover_cf_receive import RUN
from recover_cf_runloop_wake_port import DEFAULT
FDO=B+0xc0000;READ=B+0xc1000;WRITE=B+0xc2000;QUEUE=B+0xc3000;EVREAD=B+0xc4000;CAREAD=B+0xc5000;EVWRITE=B+0xc6000;CAWRITE=B+0xc7000;FDSET=B+0xc8000;ERRNO=B+0xc9000;TRAMP=HALT+0x100
SELECTED=FUNCS|{SIGNAL,WAKELOOPS,LOOP,COPY,APPLY,HASHAPPLY,INVOKE}
class Replay(Parent):
 def __init__(self,p,k,s):
  super().__init__(p,k,s);self.stage='installer';self.ffi=self.fri=self.synci=0;self.sync_stack=[];self.dup_count=self.copy_count=self.clock_calls=self.source_calls=self.event_index=0;self.handlers={};self.suspended={};self.closed=[];self.poll_counts={};self.poll_failed=False;self.callback_checked=False
  wanted=[(at,bytes(n)+b'\xa5')for at,n in((FDO,112),(READ,192),(WRITE,192),(QUEUE,128),(EVREAD,64),(CAREAD,64),(EVWRITE,64),(CAWRITE,64),(FDSET,64),(ERRNO,4))]+[(0x1eb159db0,struct.pack('<Q',(1<<64)-1)),(SRC+184,b'\xa5'),(B+0xbf000,bytes(64)+b'\xa5')];assert len(p['factory_initial'])==len(wanted)
  for(at,b),e in zip(wanted,p['factory_initial'],strict=True):assert e['address']==hex(at)and e['bytes_hex']==b.hex();assert'before_hex'not in e or e['before_hex']==bytes(self.u.mem_read(at,len(b))).hex();self.u.mem_write(at,b)
 def fdstate(self):return{'duplicated':self.dup_count,'handlers':{hex(k):{n:hex(v)for n,v in x.items()}for k,x in self.handlers.items()},'suspended':{hex(k):v for k,v in self.suspended.items()},'closed':list(self.closed),'copy_multiplicity':self.copy_count,'poll_counts':dict(self.poll_counts),'poll_failed':self.poll_failed}
 def ff(self,e,a):
  assert e['pc']==hex(a)and e['stage']==self.stage;self.check_frame(e);assert e['descriptor112_hex']==bytes(self.u.mem_read(FDO,112)).hex()and e['source184_hex']==bytes(self.u.mem_read(SRC,184)).hex()and e['backend']==self.fdstate();self.counts['descriptor_source_backend_and_complete_CPU_frames_checked']+=1
 def restore(self,f):
  for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
  for j,v in enumerate(f['Q_registers32']):self.u.reg_write(getattr(A,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  self.u.reg_write(A.UC_ARM64_REG_SP,int(f['SP'],16))
 def sync_entry(self,a):
  q,b=self.reg(0),self.reg(1);assert q==QUEUE;e=self.p['dispatch_sync_calls'][self.synci];self.synci+=1;self.check_frame(e['before']);invoke=int.from_bytes(bytes(self.u.mem_read(b+16,8)),'little');desc=int.from_bytes(bytes(self.u.mem_read(b+24,8)),'little');size=int.from_bytes(bytes(self.u.mem_read(desc+8,8)),'little');assert 32<=size<=96 and e['pc']==hex(a)and e['queue']==hex(q)and e['block']==hex(b)and e['invoke']==hex(invoke)and e['block_bytes_hex']==bytes(self.u.mem_read(b,size)).hex();self.sync_stack.append((e,e['before']));self.setreg(0,b);self.setreg(30,TRAMP);self.u.reg_write(A.UC_ARM64_REG_PC,invoke);self.check_frame(e['entry']);self.counts['explicit_sync_original_block_entries_checked']+=1
 def sync_return(self):
  e,f=self.sync_stack.pop();self.check_frame(e['callback_return']);self.restore(f)
  for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
  self.setreg(0,0);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000);self.u.reg_write(A.UC_ARM64_REG_PC,int(f['registers31'][30],16));self.check_frame(e['after']);self.counts['explicit_sync_callback_returns_and_caller_contracts_checked']+=1
 def lower(self,a):
  x=[self.reg(j)for j in range(9)];value=0;patches=[];name=None;before=self.fdstate();extra={}
  if a in(0x184833380,0x184833694)and x[0]==FDO:name='declared_descriptor_type60'if a==0x184833694 else'declared_descriptor_validate';value=60 if a==0x184833694 else 0
  elif a==0x1846da4dc and x[1]in(60,46):
   kind=x[1];assert x[2:4]==([96,0]if kind==60 else[168,0]);name='descriptor_runtime_storage'if kind==60 else'source0_runtime_storage';value=0 if self.config.get('runtime_null'if kind==60 else'source_null')else FDO if kind==60 else SRC
   if value:patches=[(value,bytes(112 if kind==60 else 184))]
  elif a==0x18806c3e0:
   assert x[0]==7;name='declared_descriptor_fstat';value=0xffffffff if self.config.get('fstat_fail')else 0
   if not value:raw=bytearray(144);raw[4:6]=self.config.get('permissions',0x180).to_bytes(2,'little');patches=[(x[1],bytes(raw))]
  elif a==0x1880767f0:
   assert x[:2]==[7,67]and bytes(self.u.mem_read(self.u.reg_read(A.UC_ARM64_REG_SP),8))==struct.pack('<Q',3);name='declared_fcntl_duplicate';self.dup_count+=1;value=0xffffffff if self.config.get('dup_fail')and self.dup_count==1 else 10+self.dup_count;extra={'variadic_stack8_hex':struct.pack('<Q',3).hex()}
  elif a==0x188076590:assert x[1]==0;name='declared_descriptor_queue_create';value=QUEUE
  elif a==0x188076640:
   if x[3]!=QUEUE:return False
   assert x[0]in(0x1e24b2250,0x1e24b2290)and x[1]in(11,12)and x[2]==0;name='declared_descriptor_dispatch_source';value=READ if x[0]==0x1e24b2250 else WRITE;self.suspended[value]=True
  elif a in(0x188076680,0x188076670):
   if x[0]not in(READ,WRITE):return False
   tag='event'if a==0x188076680 else'cancel';name='declared_copy_dispatch_'+tag;desc=int.from_bytes(bytes(self.u.mem_read(x[1]+24,8)),'little');size=int.from_bytes(bytes(self.u.mem_read(desc+8,8)),'little');assert size==(48 if tag=='event'else 44);at={READ:{'event':EVREAD,'cancel':CAREAD},WRITE:{'event':EVWRITE,'cancel':CAWRITE}}[x[0]][tag];raw=bytes(self.u.mem_read(x[1],size));self.handlers.setdefault(x[0],{})[tag]=at;patches=[(at,raw)];extra={'original_block_size_bytes':size,'original_block_hex':raw.hex()}
  elif a in(0x1880766b0,0x1880765e0)and x[0]in(READ,WRITE):name='declared_dispatch_suspend'if a==0x1880766b0 else'declared_dispatch_resume';self.suspended[x[0]]=a==0x1880766b0
  elif a==0x18806c020:assert x[1]==8;name='declared_stack_byref_dispose'
  elif a==0x18806c310:name='declared_duplicate_close';self.closed.append(x[0]&0xffffffff)
  elif a==0x18806c4f0:assert 1<=x[0]<=64;name='declared_fdset_raw_storage';value=FDSET
  elif a==0x18806c2f0:assert x[0]==FDSET and x[1]<=64;name='declared_fdset_zero';patches=[(FDSET,bytes(x[1]))]
  elif a==0x188086880:assert x[0]in(7,11,12)and x[1:3]==[FDSET,1];name='declared_fdset_bounds';value=1
  elif a==0x188086d70:
   assert x[0]in(8,12,13)and x[3]==0 and x[5]==0;name='declared_pselect_readiness';ready=self.config.get('enable_ready',False)if self.stage=='enable'else self.config.get('perform_ready',True);self.poll_counts[self.stage]=self.poll_counts.get(self.stage,0)+1;value=int(ready);extra={'timespec16_hex':bytes(self.u.mem_read(x[4],16)).hex()}
   if self.stage=='perform'and self.config.get('poll_error')and not self.poll_failed:value=0xffffffff;self.poll_failed=True
   elif not ready:patches=[(FDSET,bytes(4))]
  elif a==0x18806c120:name='declared_private_errno';value=ERRNO;patches=[(ERRNO,struct.pack('<I',self.config['poll_error']))]
  elif a==0x18806c3d0:assert x[0]==FDSET;name='declared_fdset_retire'
  elif a in(0x1880773f0,0x188077400,0x1880773b0,0x18807b8a0):name='declared_source0_mutex_initialization'
  elif a==0x18471aa50:assert x[1:3]==[0,0x1e232d698];name='declared_empty_source_bag';value=BAG;self.collections[BAG]=set()
  if name:self.mode_call(a,name,value,patches,{'descriptor_backend_before':before,'descriptor_backend_after':self.fdstate(),**extra});self.counts['descriptor_lower_contracts_recomputed']+=1;return True
  return False
 def event_target(self):
  source=READ if self.config['events'][self.event_index]=='read'else WRITE;assert not self.suspended[source];return self.handlers[source]['event']
 def public_entry(self,e,a):
  kind=e['kind']
  if kind=='runloop_Create_to_descriptor_Create':
   assert self.wphase=='create'and self.reg(0)==RL;f=self.p['wake_returns'][self.wri];self.wake_frame(f,a);self.wri+=1;target=CREATE;args=(0,7,1,DAEMON,0);stage='fd_create'
  elif kind=='descriptor_Create_to_GetNativeDescriptor':assert self.reg(0)==FDO;target=0x1847b802c;args=(FDO,);stage='fd_get'
  elif kind=='descriptor_GetNative_to_Enable':assert self.reg(0)==7;target=ENABLE;args=(FDO,self.config.get('enable_mask',1));stage='enable'
  elif kind=='descriptor_Enable_to_source_Create':target=SOURCE;args=(0,FDO,0);stage='source_create'
  elif kind=='repeat_descriptor_source_Create':assert self.reg(0)==SRC;self.source_calls+=1;target=SOURCE;args=(0,FDO,17);stage='source_create'
  elif kind=='descriptor_source_to_original_AddSource0':assert self.reg(0)==SRC;self.source_calls+=1;target=0x18472d934;args=(RL,SRC,DEFAULT);stage='fd_register'
  elif kind=='AddSource0_to_waiting_runloop':target=RUN;args=(RL,MODE,1);stage='runloop';self.transition=True
  elif kind=='waiting_receive_to_declared_dispatch_handler':
   assert a==MACH and self.wphase=='runloop'and[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,self.facility,0xffffffff,0];b=self.event_target();target=int.from_bytes(bytes(self.u.mem_read(b+16,8)),'little');args=(b,);stage='event'
  elif kind=='next_declared_dispatch_handler':self.event_index+=1;b=self.event_target();target=int.from_bytes(bytes(self.u.mem_read(b+16,8)),'little');args=(b,);stage='event'
  else:
   assert kind in('source0_to_declared_Perform_entry','dispatch_handlers_to_source0_Perform');target=int.from_bytes(bytes(self.u.mem_read(SRC+0xb0,8)),'little');args=(int.from_bytes(bytes(self.u.mem_read(SRC+0x70,8)),'little'),);stage='perform'
  if self.stage=='fd_register':f=self.p['registration_returns'][self.rri];self.check_schedule_frame(f);self.rri+=1
  self.check_frame(e['before']);assert e['model_state']==self.state()
  for at,n,key in((B,0x100000,'private_RAM_sha256'),(LOW,LOW_SIZE,'lower_stack_sha256')):assert e[key]==hashlib.sha256(bytes(self.u.mem_read(at,n))).hexdigest()
  self.stage=self.wphase=stage
  for j,v in enumerate(args):self.setreg(j,v)
  self.setreg(30,HALT)
  if target==RUN:self.u.reg_write(A.UC_ARM64_REG_Q0,0x7ff0000000000000)
  if 'declared_waker_SP'in e:assert e['declared_waker_SP']==hex(WAKER_SP);self.u.reg_write(A.UC_ARM64_REG_SP,WAKER_SP)
  self.u.reg_write(A.UC_ARM64_REG_PC,target);self.check_frame(e['after']);self.pi+=1;self.counts['descriptor_component_CPU_and_whole_memory_entry_handoffs_checked']+=1
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==TRAMP:return self.sync_return()
  if a==0x1880766c0 and self.reg(0)==QUEUE:return self.sync_entry(a)
  if a==WAKE and self.stage=='event':self.wphase='wakeup'
  if a==0x184794f14 and self.stage=='event':self.wphase='event'
  if self.ffi<len(self.p['factory_frames']):
   e=self.p['factory_frames'][self.ffi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.ff(e,a);self.ffi+=1
  if self.fri<len(self.p['factory_returns']):
   e=self.p['factory_returns'][self.fri]
   if a==HALT and e['source_visit_index']==self.seq:self.ff(e,a);self.fri+=1
  if a==DAEMON:
   assert self.stage=='perform';e=self.p['descriptor_callback_entry'];self.ff(e,a);assert e['arguments3']==[hex(self.reg(j))for j in range(3)];self.callback_checked=True
  if self.pi<len(self.p['public_handoffs']):
   e=self.p['public_handoffs'][self.pi]
   if e['kind']not in('installer_to_runloop_Create',)and e['before']['source_visit_index']==self.seq and(a==HALT or a==MACH):return self.public_entry(e,a)
  if a in(HALT,DAEMON)and self.pi==len(self.p['public_handoffs']):
   assert self.seq==len(self.p['source_visits']);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if self.lower(a):return
  if SourceModels.new_model(self,a):return
  if a==RETURN:
   e=self.p['wrapper_returns'][self.xri];self.wrapper_frame(e,a);assert self.si and self.reg(0)==self.config['trap_results'][self.si-1];self.xri+=1;return WakeBase.hook(self,u,a,n,d)
  if a==MACH and self.wphase=='wakeup':
   saved=self.config['trap_results'];self.config['trap_results']=[*saved[:-1],saved[self.si]]
   try:return super().hook(u,a,n,d)
   finally:self.config['trap_results']=saved
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in SELECTED and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};i=next(CS.disasm(raw,a));self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['original_descriptor_source_readiness_and_block_visits_checked']+=1;op=i.mnemonic
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
  super().run();assert self.ffi==len(self.p['factory_frames'])and self.fri==len(self.p['factory_returns'])and self.synci==len(self.p['dispatch_sync_calls'])and not self.sync_stack and self.callback_checked==(self.p['descriptor_callback_entry']is not None);assert self.p['final_descriptor112_hex']==bytes(self.u.mem_read(FDO,112)).hex()and self.p['final_source184_hex']==bytes(self.u.mem_read(SRC,184)).hex()and self.p['final_descriptor_backend']==self.fdstate()
  for e in self.p['final_factory_globals']:assert e['bytes_hex']==bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()
  return dict(self.counts)
