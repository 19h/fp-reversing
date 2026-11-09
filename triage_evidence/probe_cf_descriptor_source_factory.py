#!/usr/bin/env python3
"""Original CF descriptor/source/registration/readiness/perform components.
Declared POSIX/dispatch/storage/collection/PAC/SVC effects; no native IPC,
scheduler or daemon callback execution. O(V*F+I+J+H*R) time,O(I+J+R) space.
"""
import json,struct,hashlib
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,CS
from probe_cf_wake_send_wrapper import Probe as Parent,RETURN,MACH
from probe_cf_runloop_wake_port import CFProbe as WakeBase
from probe_cf_source_scheduling import Probe as Public,B,RL,MODE,SRC,BAG,HALT
from probe_cf_source_wake_callers import Probe as SourceModels
from recover_cf_source_wake_callers import SIGNAL,WAKELOOPS,LOOP,COPY,APPLY,HASHAPPLY,INVOKE,WAKE
from recover_cf_descriptor_source_factory import P,FLAGS,sha,FUNCS,CREATE,SOURCE,ENABLE,PERFORM,SOURCECREATE,DAEMON
from recover_cf_receive import RUN
from recover_cf_runloop_wake_port import DEFAULT
FDO=B+0xc0000;READ=B+0xc1000;WRITE=B+0xc2000;QUEUE=B+0xc3000;EVREAD=B+0xc4000;CAREAD=B+0xc5000;EVWRITE=B+0xc6000;CAWRITE=B+0xc7000;FDSET=B+0xc8000;ERRNO=B+0xc9000;TRAMP=HALT+0x100
SELECTED=FUNCS|{SIGNAL,WAKELOOPS,LOOP,COPY,APPLY,HASHAPPLY,INVOKE};DISPATCH_SYNC=0x1880766c0
class Probe(Parent):
 def __init__(self,c,k,s):
  super().__init__(c,k,s);self.stage='installer';self.sync=[];self.sync_stack=[];self.fd_initial=[];self.copy_count=self.clock_calls=0;self.dup_count=0;self.handlers={};self.suspended={};self.closed=[];self.poll_counts={};self.poll_failed=False;self.factory_frames=[];self.factory_returns=[];self.event_index=0;self.source_calls=0;self.callback=None
  for at,n in((FDO,112),(READ,192),(WRITE,192),(QUEUE,128),(EVREAD,64),(CAREAD,64),(EVWRITE,64),(CAWRITE,64),(FDSET,64),(ERRNO,4)):
   raw=bytes(n)+b'\xa5';self.u.mem_write(at,raw);self.fd_initial.append({'address':hex(at),'bytes_hex':raw.hex()})
  at=0x1eb159db0;raw=struct.pack('<Q',(1<<64)-1);self.fd_initial.append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,8)).hex(),'bytes_hex':raw.hex()});self.u.mem_write(at,raw)
  for at,n in((SRC+184,1),(B+0xbf000,65)):
   b=b'\xa5'if n==1 else bytes(64)+b'\xa5';self.fd_initial.append({'address':hex(at),'bytes_hex':b.hex()});self.u.mem_write(at,b)
 def public_call(self,a,args,label):
  if label=='waiting_receive_to_external_waker_entry':
   self.stage='event';self.phase='event';a=self.event_target();args=(a,);target=int.from_bytes(bytes(self.u.mem_read(a+16,8)),'little');a=target;label='waiting_receive_to_declared_dispatch_handler'
  return Public.public_call(self,a,args,label)
 def fdstate(self):return{'duplicated':self.dup_count,'handlers':{hex(k):{n:hex(v)for n,v in x.items()}for k,x in self.handlers.items()},'suspended':{hex(k):v for k,v in self.suspended.items()},'closed':list(self.closed),'copy_multiplicity':self.copy_count,'poll_counts':dict(self.poll_counts),'poll_failed':self.poll_failed}
 def ff(self,a):return{'pc':hex(a),**self.frame('descriptor_factory'),'stage':self.stage,'descriptor112_hex':bytes(self.u.mem_read(FDO,112)).hex(),'source184_hex':bytes(self.u.mem_read(SRC,184)).hex(),'backend':self.fdstate()}
 def event_target(self):
  source=READ if self.config['events'][self.event_index]=='read'else WRITE;assert not self.suspended[source];return self.handlers[source]['event']
 def start(self,a,args,label,stage):self.stage=stage;self.phase=stage;return self.public_call(a,args,label)
 def sync_entry(self,a):
  queue,block=self.reg(0),self.reg(1);assert queue==QUEUE;invoke=int.from_bytes(bytes(self.u.mem_read(block+16,8)),'little');size=int.from_bytes(bytes(self.u.mem_read(int.from_bytes(bytes(self.u.mem_read(block+24,8)),'little')+8,8)),'little');assert 32<=size<=96
  e={'pc':hex(a),'before':self.frame('dispatch_sync_call'),'queue':hex(queue),'block':hex(block),'block_bytes_hex':bytes(self.u.mem_read(block,size)).hex(),'invoke':hex(invoke)};self.sync.append(e);self.sync_stack.append((e,e['before']));self.setreg(0,block);self.setreg(30,TRAMP);self.u.reg_write(A.UC_ARM64_REG_PC,invoke);e['entry']=self.frame('original_block_entry')
 def sync_return(self):
  e,f=self.sync_stack.pop();e['callback_return']=self.frame('original_block_return')
  for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
  for j,v in enumerate(f['Q_registers32']):self.u.reg_write(getattr(A,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  self.u.reg_write(A.UC_ARM64_REG_SP,int(f['SP'],16));self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000)
  for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
  self.setreg(0,0);self.u.reg_write(A.UC_ARM64_REG_PC,int(f['registers31'][30],16));e['after']=self.frame('dispatch_sync_return')
 def lower(self,a):
  x=[self.reg(j)for j in range(9)];result=0;patches=[];name=None;before=self.fdstate();extra={}
  if a in(0x184833380,0x184833694)and x[0]==FDO:name='declared_descriptor_type60'if a==0x184833694 else'declared_descriptor_validate';result=60 if a==0x184833694 else 0
  elif a==0x1846da4dc and x[1]in(60,46):
   kind=x[1];assert x[2:4]==([96,0]if kind==60 else[168,0]);name='descriptor_runtime_storage'if kind==60 else'source0_runtime_storage';result=0 if self.config.get('runtime_null'if kind==60 else'source_null')else FDO if kind==60 else SRC
   if result:patches=[(result,bytes(112 if kind==60 else 184))]
  elif a==0x18806c3e0:
   assert x[0]==7;name='declared_descriptor_fstat';result=0xffffffff if self.config.get('fstat_fail')else 0
   if not result:raw=bytearray(144);struct.pack_into('<H',raw,4,self.config.get('permissions',0x180));patches=[(x[1],bytes(raw))]
  elif a==0x1880767f0:
   assert x[:2]==[7,67]and bytes(self.u.mem_read(self.u.reg_read(A.UC_ARM64_REG_SP),8))==struct.pack('<Q',3);name='declared_fcntl_duplicate';self.dup_count+=1;result=(0xffffffff if self.config.get('dup_fail')and self.dup_count==1 else 10+self.dup_count);extra={'variadic_stack8_hex':struct.pack('<Q',3).hex()}
  elif a==0x188076590:assert x[1]==0;name='declared_descriptor_queue_create';result=QUEUE
  elif a==0x188076640:
   if x[3]!=QUEUE:return False
   assert x[0]in(0x1e24b2250,0x1e24b2290)and x[1]in(11,12)and x[2:4]==[0,QUEUE],(hex(a),[hex(v)for v in x[:4]],hex(self.reg(30)),self.fdstate());name='declared_descriptor_dispatch_source';result=READ if x[0]==0x1e24b2250 else WRITE;self.suspended[result]=True
  elif a in(0x188076680,0x188076670):
   if x[0]not in(READ,WRITE):return False
   assert x[0]in(READ,WRITE);tag='event'if a==0x188076680 else'cancel';name='declared_copy_dispatch_'+tag;size=int.from_bytes(bytes(self.u.mem_read(int.from_bytes(bytes(self.u.mem_read(x[1]+24,8)),'little')+8,8)),'little');assert size==(48 if tag=='event'else 44),(hex(a),size,bytes(self.u.mem_read(x[1],48)).hex());at={READ:{'event':EVREAD,'cancel':CAREAD},WRITE:{'event':EVWRITE,'cancel':CAWRITE}}[x[0]][tag];raw=bytes(self.u.mem_read(x[1],size));self.handlers.setdefault(x[0],{})[tag]=at;patches=[(at,raw)];extra={'original_block_size_bytes':size,'original_block_hex':raw.hex()}
  elif a in(0x1880766b0,0x1880765e0)and x[0]in(READ,WRITE):assert x[0]in(READ,WRITE);name='declared_dispatch_suspend'if a==0x1880766b0 else'declared_dispatch_resume';self.suspended[x[0]]=a==0x1880766b0
  elif a==0x18806c020:assert x[1]==8;name='declared_stack_byref_dispose'
  elif a==0x18806c310:name='declared_duplicate_close';self.closed.append(x[0]&0xffffffff)
  elif a==0x18806c4f0:assert 1<=x[0]<=64;name='declared_fdset_raw_storage';result=FDSET
  elif a==0x18806c2f0:assert x[0]==FDSET and x[1]<=64;name='declared_fdset_zero';patches=[(FDSET,bytes(x[1]))]
  elif a==0x188086880:assert x[0]in(7,11,12)and x[1:3]==[FDSET,1];name='declared_fdset_bounds';result=1
  elif a==0x188086d70:
   assert x[0]in(8,12,13)and x[3]==0 and x[5]==0;name='declared_pselect_readiness';ready=self.config.get('enable_ready',False)if self.stage=='enable'else self.config.get('perform_ready',True);self.poll_counts[self.stage]=self.poll_counts.get(self.stage,0)+1;result=int(ready);extra={'timespec16_hex':bytes(self.u.mem_read(x[4],16)).hex()}
   if self.stage=='perform'and self.config.get('poll_error')and not self.poll_failed:result=0xffffffff;self.poll_failed=True
   elif not ready:patches=[(FDSET,bytes(4))]
  elif a==0x18806c120:name='declared_private_errno';result=ERRNO;patches=[(ERRNO,struct.pack('<I',self.config['poll_error']))]
  elif a==0x18806c3d0:assert x[0]==FDSET;name='declared_fdset_retire'
  elif a in(0x1880773f0,0x188077400,0x1880773b0,0x18807b8a0):name='declared_source0_mutex_initialization'
  elif a==0x18471aa50:
   assert x[1:3]==[0,0x1e232d698];name='declared_empty_source_bag';result=BAG;self.collections[BAG]=set()
  if name:self.mode_model(a,name,result,patches,{'descriptor_backend_before':before,'descriptor_backend_after':self.fdstate(),**extra});return True
  return False
 def hook(self,u,a,n,d):
  self.flush()
  if a==TRAMP:return self.sync_return()
  if a==DISPATCH_SYNC and self.reg(0)==QUEUE:return self.sync_entry(a)
  if a==DAEMON and self.stage=='perform':self.callback={'arguments3':[hex(self.reg(j))for j in range(3)],**self.ff(a)};return self.finish('before_original_daemon_descriptor_callback',a)
  if a==WAKE and self.stage=='event':self.phase='wakeup'
  if a==0x184794f14 and self.stage=='event':self.phase='event'
  if a in(FUNCS|{SIGNAL,WAKELOOPS,WAKE}):self.factory_frames.append(self.ff(a))
  if a==HALT:
   if self.phase=='create':
    self.wake_returns.append(self.wake_frame(a));assert self.reg(0)==RL;return self.start(CREATE,(0,7,1,DAEMON,0),'runloop_Create_to_descriptor_Create','fd_create')
   if self.stage=='fd_create':
    self.factory_returns.append(self.ff(a))
    if self.reg(0)==0:return self.finish('original_descriptor_factory_null',a)
    assert self.reg(0)==FDO;return self.start(0x1847b802c,(FDO,),'descriptor_Create_to_GetNativeDescriptor','fd_get')
   if self.stage=='fd_get':
    self.factory_returns.append(self.ff(a));assert self.reg(0)==7;return self.start(ENABLE,(FDO,self.config.get('enable_mask',1)),'descriptor_GetNative_to_Enable','enable')
   if self.stage=='enable':self.factory_returns.append(self.ff(a));return self.start(SOURCE,(0,FDO,0),'descriptor_Enable_to_source_Create','source_create')
   if self.stage=='source_create':
    self.factory_returns.append(self.ff(a));self.source_calls+=1
    if self.reg(0)==0:return self.finish('original_descriptor_source_factory_null',a)
    assert self.reg(0)==SRC
    if self.source_calls<self.config.get('source_repeat',1):return self.start(SOURCE,(0,FDO,17),'repeat_descriptor_source_Create','source_create')
    self.add_calls=1;return self.start(0x18472d934,(RL,SRC,DEFAULT),'descriptor_source_to_original_AddSource0','fd_register')
   if self.stage=='fd_register':
    self.registration_returns.append(self.schedule_frame(a));self.factory_returns.append(self.ff(a))
    if self.config.get('factory_only'):return self.start(int.from_bytes(bytes(u.mem_read(SRC+0xb0,8)),'little'),(int.from_bytes(bytes(u.mem_read(SRC+0x70,8)),'little'),),'source0_to_declared_Perform_entry','perform')
    return self.start(RUN,(RL,MODE,1),'AddSource0_to_waiting_runloop','runloop')
   if self.stage=='event':
    self.factory_returns.append(self.ff(a));self.event_index+=1
    if self.event_index<len(self.config['events']):block=self.event_target();return self.start(int.from_bytes(bytes(u.mem_read(block+16,8)),'little'),(block,),'next_declared_dispatch_handler','event')
    return self.start(int.from_bytes(bytes(u.mem_read(SRC+0xb0,8)),'little'),(int.from_bytes(bytes(u.mem_read(SRC+0x70,8)),'little'),),'dispatch_handlers_to_source0_Perform','perform')
   if self.stage=='perform':self.factory_returns.append(self.ff(a));return self.finish('original_descriptor_Perform_without_daemon_call',a)
  if self.lower(a):return
  if SourceModels.new_model(self,a):return
  if a==RETURN:
   self.wrapper_returns.append(self.wrapper_frame(a));assert self.si and self.reg(0)==self.config['trap_results'][self.si-1];return WakeBase.hook(self,u,a,n,d)
  if a==MACH and self.phase=='wakeup':
   saved=self.config['trap_results'];self.config['trap_results']=[*saved[:-1],saved[self.si]]
   try:return super().hook(u,a,n,d)
   finally:self.config['trap_results']=saved
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in SELECTED and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4];i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autiza','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
   return
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();r.update(factory_initial=self.fd_initial,factory_frames=self.factory_frames,factory_returns=self.factory_returns,dispatch_sync_calls=self.sync,final_descriptor112_hex=bytes(self.u.mem_read(FDO,112)).hex(),final_source184_hex=bytes(self.u.mem_read(SRC,184)).hex(),final_descriptor_backend=self.fdstate(),descriptor_callback_entry=self.callback,final_factory_globals=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,8)).hex()}for a in(0x1eb159d50,0x1eb159db0)]);assert not self.sync_stack;return r

def configs():
 rows=[('read_ready',{'events':['read']}),('read_stale',{'events':['read'],'perform_ready':False}),('write_ready',{'events':['write'],'enable_mask':2}),('both_ready',{'events':['read','write'],'enable_mask':3}),('read_retry_EINTR',{'events':['read'],'poll_error':4}),('read_retry_EAGAIN',{'events':['read'],'poll_error':35}),('read_error_EIO',{'events':['read'],'poll_error':5}),('fstat_failure',{'fstat_fail':True}),('duplicate_failure',{'dup_fail':True}),('descriptor_storage_null',{'runtime_null':True}),('source_storage_null',{'source_null':True}),('source_reuse',{'source_repeat':2,'events':['read']}),('enable_already_ready',{'enable_ready':True,'factory_only':True}),('mode_no_owner_bits',{'permissions':0,'factory_only':True}),('owner_read_only',{'permissions':0x100,'events':['read']}),('owner_write_only',{'permissions':0x80,'events':['write'],'enable_mask':2})]
 for label,more in rows:
  fail=any(more.get(k)for k in('fstat_fail','dup_fail','runtime_null','source_null'));events=more.get('events',[]);traps=[0]+[0x10000004]*(len(events)-1)if events else[]
  yield{'kernel_case':2,'mode':'schedule_then_run','repeat':0 if fail else 1,'wake_case':'waiting','send_status':0,'aux':False,'trap_results':traps,'label':label,'events':events,'bag_multiplicity':1,'copy_null':False,'perform_ready':True,**more}
if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());prior=json.loads((ROOT/'cf_runloop_wake_port_profiles.json').read_text());cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};rows=[]
 for c in configs():
  try:r=Probe(c,prior['kernel_cases'][2],cs).run()
  except Exception as e:
   print('FAILED',c['label'],type(e).__name__,str(e),flush=True);raise
  rows.append(r);print(c['label'],len(r['source_visits']),r['boundary']['kind'],flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','recover_'+P+'.py','cf_runloop_wake_port_profiles.json','probe_cf_wake_send_wrapper.py','probe_cf_source_wake_callers.py']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
