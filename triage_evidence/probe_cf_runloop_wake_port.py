#!/usr/bin/env python3
"""Original wake-port constructor/member plus CF run-loop factory and wake emitter.
Lower allocation/copy/runtime/send returns and external-waker entry are declared.
No native kernel/daemon/IPC/concurrency/PAC effects. O(image+visits+RAM+journals).
"""
import json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT
from probe_kernel_timer_port_create import Probe as Parent,CFProbe as CFParent,Startup,NODE3
from probe_kernel_portset_delivery import ALLOC_ARGS,INSERT_ARGS,TASK_NAME,PS,TABLE
from probe_kernel_request_receive import SPACE
from probe_kernel_vm_mig import P as B,SIZE,HALT as KH
from probe_rpc502_vm_handoff import compressed
from recover_kernel_root_port_construct import CONSTRUCT,COPYIN
from recover_kernel_portset_delivery import ALLOC,INSERT
from recover_cf_runloop_wake_port import P,FLAGS,sha,CREATE,WAKE,CHECK,MACH,DEFAULT
from kernel_vm_mig_tools import Image
WPORT=B+0xc2000;WNODE=B+0xc1000;WARGS=B+0xbb000;WOPTS=B+0xbb040;WOUT=B+0xbb080;CONTEXT=B+0xa0000;PORTZONE=0xfffffe000caec500
class Probe(Parent):
 def __init__(self,im,s,c,parent,zones,startup):
  super().__init__(im,s,c,parent,zones,startup);self.wake_frames=[];self.wake_returns=[];self.wake_handoffs=[];self.wake_models=[]
  self.global_overlay(TABLE+12,struct.pack('<I',8),'Declared initial free entry8 for wake port');self.global_overlay(TABLE+8*24,struct.pack('<QIIII',0,0,5,0,0),'Declared entry8 then set5/root6/timer7/reply2');self.overlay(SPACE+0x18,struct.pack('<I',5),'Declared free count5')
  for at,n in((WPORT,144),(WNODE,48)):self.overlay(at,bytes(n),'Declared disjoint zero raw wake storage');self.overlay(at+n,b'\xa5','Declared wake raw guard')
  meta=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little');self.overlay(meta+((WPORT>>10)&0xffffffff0),struct.pack('<H',22),'Declared wake raw zone22 epoch');self.overlay(WOPTS,bytes.fromhex(s['wake_original_options24_hex']),'Exact original CF wake options24');self.overlay(WOUT,b'\xa5'*4,'Declared wake name output');self.overlay(WARGS,struct.pack('<4Q',TASK_NAME,WOPTS,CONTEXT,WOUT),'Declared complete wake construct trap argument record')
  self.phase='wake_construct';self.entry=CONSTRUCT;self.set(0,WARGS);self.set(30,KH);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(A.UC_ARM64_REG_NZCV));self.entryQ=[hex(self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
 def wake_frame(self,a):return{'pc':hex(a),**self.cpu(),'phase':self.phase,'wake_port144_hex':bytes(self.u.mem_read(WPORT,144)).hex(),'wake_name4_hex':bytes(self.u.mem_read(WOUT,4)).hex(),'entry8_24_hex':bytes(self.u.mem_read(TABLE+192,24)).hex(),'wake_link48_hex':bytes(self.u.mem_read(WNODE,48)).hex()}
 def wake_transition(self,a,args,label,patches=()):self.transition(a,args,label,patches);self.wake_handoffs.append(self.stage_handoffs.pop())
 def wake_model(self,a,name,value,patches=()):
  e={'pc':hex(a),'before_source_visit_index':len(self.visits),'name':name,'before':self.wake_frame(a),'patches':[]}
  for at,b in patches:e['patches'].append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
  self.model(a,name,value);e['result']=hex(value);e['after']=self.wake_frame(self.u.reg_read(A.UC_ARM64_REG_PC));self.wake_models.append(e)
 def timer_transition(self,a,args,label,patches=()):
  if label=='timer_insert_to_service_insert':self.phase='wake_insert';return self.wake_transition(INSERT,(INSERT_ARGS,),'timer_insert_to_wake_insert',[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,0x807,self.pset_name))])
  return super().timer_transition(a,args,label,patches)
 def code(self,u,a,n,d):
  self.flush()
  if a in(CONSTRUCT,0xfffffe000bce00b8,0xfffffe000bcc8c60,0xfffffe000bce0624,INSERT):self.wake_frames.append(self.wake_frame(a))
  if a==KH and self.phase in('wake_construct','wake_insert'):
   self.wake_returns.append({**self.wake_frame(a),'private_RAM':compressed(bytes(u.mem_read(B,SIZE)))});assert self.reg(0)==0
   if self.phase=='wake_construct':assert bytes(u.mem_read(WOUT,4))==struct.pack('<I',0x807);self.phase='allocate';return self.wake_transition(ALLOC,(ALLOC_ARGS,),'wake_construct_to_set_allocate')
   self.phase='insert';return self.wake_transition(INSERT,(INSERT_ARGS,),'wake_insert_to_service_insert',[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,self.receive_name,self.pset_name))])
  if a==COPYIN and self.phase=='wake_construct':assert self.reg(0)==WOPTS and self.reg(2)==24;return self.wake_model(a,'declared_exact_wake_options24_copyin',0,[(self.reg(1),bytes(u.mem_read(WOPTS,24)))])
  if a==0xfffffe000bd75c64 and self.phase=='wake_construct':assert[self.reg(j)for j in range(3)]==[PORTZONE,B+0xb1000,0x8004]and bytes(u.mem_read(WPORT,144))==bytes(144);return self.wake_model(a,'declared_zeroed_raw_wake_port144',WPORT)
  if a==0xfffffe000bcfefc8 and self.link_allocations>=2:
   assert self.link_allocations in(2,3)and[self.reg(j)for j in range(2)]==[0xfffffe0007e43358,4];at=WNODE if self.link_allocations==2 else NODE3;assert bytes(u.mem_read(at,48))==bytes(48);self.link_allocations+=1;return self.wake_model(a,'declared_raw_wake_link48'if at==WNODE else'declared_fourth_service_link48',at)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(wake_frames=self.wake_frames,wake_returns=self.wake_returns,wake_handoffs=self.wake_handoffs,wake_models=self.wake_models,final_wake_port144_hex=bytes(self.u.mem_read(WPORT,144)).hex(),final_wake_name4_hex=bytes(self.u.mem_read(WOUT,4)).hex(),final_entry8_24_hex=bytes(self.u.mem_read(TABLE+192,24)).hex(),final_wake_link48_hex=bytes(self.u.mem_read(WNODE,48)).hex(),wake_guards_hex=b''.join(bytes(self.u.mem_read(a+n,1))for a,n in((WPORT,144),(WNODE,48))).hex());return r

from probe_cf_source_scheduling import RL,MODE,SRC,HALT,USER,LOW,LOW_SIZE
from probe_cf_mode_construction import REGISTRY
from recover_cf_mode_construction import CONSTRUCT_TRAP
from recover_cf_source_scheduling import INSERT_TRAP,ADD
from recover_cf_receive import RUN
COMMON=B+0xb5000;OWNER=0x1234;WAKER_SP=B-0x100000
class CFProbe(CFParent):
 def __init__(self,c,k,s):
  super().__init__(c,k,s);self.wake_frames=[];self.wake_returns=[];self.wake_send=[];self.u.mem_write(RL,bytes(8192));self.u.mem_write(RL+0xaa0,b'\xa5');self.u.mem_write(COMMON,bytes(64));self.collections[COMMON]=set()
 def wake_frame(self,a):return{'pc':hex(a),**self.frame('wake_stage'),'phase':self.phase,'runloop2720_hex':bytes(self.u.mem_read(RL,0xaa0)).hex(),'model_state':self.state()}
 def hook(self,u,a,n,d):
  self.flush()
  if a in(CREATE,WAKE,CHECK,0x184717f38,0x184717f48,0x18473aefc,0x18473af08,0x18473af0c,0x18473af10,0x18473af30,0x18473af40,0x18473af50,0x1848d4168):self.wake_frames.append(self.wake_frame(a))
  if a==0x1848d4168:return self.finish('before_original_wake_send_failure',a)
  if a==HALT:
   if self.phase=='installer':self.phase='create';return self.public_call(CREATE,(OWNER,),'installer_to_runloop_Create')
   if self.phase=='create':
    self.wake_returns.append(self.wake_frame(a))
    if self.config.get('create_null'):assert self.reg(0)==0;return self.finish('original_runloop_Create_null',a)
    assert self.reg(0)==RL;self.phase='registration';self.add_calls=1;return self.public_call(ADD,(RL,SRC,DEFAULT),'Create_to_AddSource_default')
   if self.phase=='registration':
    self.registration_returns.append(self.schedule_frame(a));self.phase='wakeup'if self.config['wake_case']=='suppressed'else'runloop'
    return self.public_call(WAKE,(RL,),'AddSource_to_WakeUp_suppressed')if self.phase=='wakeup'else self.public_call(RUN,(RL,MODE,1),'AddSource_to_waiting_runloop')
   if self.phase=='wakeup':self.wake_returns.append(self.wake_frame(a));return self.finish('original_CFRunLoopWakeUp_returned',a)
  if a==0x1846da4dc and self.reg(1)==43:
   assert[self.reg(j)for j in range(1,4)]==[43,0xa90,0];return self.mode_model(a,'declared_runloop_runtime_storage',0 if self.config.get('create_null')else RL)
  if a==0x1805884cc and self.reg(0)==RL+0x10:return self.mode_model(a,'declared_runloop_mutex_initialize',0)
  if a==0x184716d78 and self.reg(30)in(0x184717f64,0x184717f88):
   assert self.reg(1)==0;return self.mode_model(a,'declared_runloop_common_or_registry_set',COMMON if self.reg(30)==0x184717f64 else REGISTRY)
  if a==0x1846df2ec and self.reg(1)==DEFAULT:return self.mode_model(a,'declared_immutable_default_name_copy',DEFAULT)
  if a==CONSTRUCT_TRAP and self.reg(2)==RL:
   x=[self.reg(j)for j in range(4)];opts=bytes(u.mem_read(x[1],24));assert x[0]==TASK_NAME and opts==struct.pack('<IIQQ',0x33,1,0,0);ret=self.input['wake_returns'][0];assert ret['registers31'][0]=='0x0'and ret['wake_name4_hex']=='07080000';return self.mode_model(a,'original_kernel_wake_construct_return',0,[(x[3],bytes.fromhex(ret['wake_name4_hex']))],{'original_options24_hex':opts.hex(),'wake_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'context':hex(RL),'name':'0x807'}})
  if a==INSERT_TRAP and self.reg(1)==0x807:
   assert[self.reg(j)for j in range(3)]==[TASK_NAME,0x807,self.facility];ret=self.input['wake_returns'][1];assert ret['registers31'][0]=='0x0';before=self.state();self.members.add((self.facility,0x807));return self.mode_model(a,'original_kernel_wake_member_return',0,extra={'model_state_before':before,'wake_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'arguments24_hex':struct.pack('<3Q',TASK_NAME,0x807,self.facility).hex()}})
  if a==MACH:
   if self.phase=='runloop':
    assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,self.facility,0xffffffff,0]and bytes(u.mem_read(RL+0x153,1))==b'\0';self.phase='wakeup';self.public_call(WAKE,(RL,),'waiting_receive_to_external_waker_entry');e=self.public[-1];e['declared_waker_SP']=hex(WAKER_SP);u.reg_write(A.UC_ARM64_REG_SP,WAKER_SP);e['after']=self.frame('public_entry');return
   assert self.phase=='wakeup';x=[self.reg(j)for j in range(7)];raw=bytes(u.mem_read(x[0],24));assert x[1:]==[0x11,24,0,0,0,0]and raw==struct.pack('<6I',0x13,24,0x807,0,0,0);self.wake_send.append({'before':self.wake_frame(a),'arguments7':[hex(v)for v in x],'header24_hex':raw.hex(),'declared_send_return':hex(self.config['send_status'])});return self.mode_model(a,'declared_wake_mach_msg_send_result',self.config['send_status'],extra={'original_header24_hex':raw.hex()})
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();r.update(wake_frames=self.wake_frames,wake_returns=self.wake_returns,wake_send=self.wake_send,final_runloop2720_hex=bytes(self.u.mem_read(RL,0xaa0)).hex(),runloop_guard_hex=bytes(self.u.mem_read(RL+0xaa0,1)).hex());return r
if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());im=Image();old=json.loads((ROOT/'kernel_request_delivery_profiles.json').read_text());zones=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'];startup=Startup(im,s,40).run();rows=[]
 for j in range(4):r=Probe(im,s,{'producer':j,'capacity':3072,'options':0x07000806},old['loans'][j],zones,startup).run();rows.append(r);print('KERNEL',j,r['boundary']['kind'],len(r['source_visits']),flush=True)
 cf=[];configs=[{'wake_case':'suppressed','send_status':0},{'wake_case':'waiting','send_status':0},{'wake_case':'waiting','send_status':0x10000004},{'wake_case':'waiting','send_status':0x10000007,'diagnostic_status_counterfactual':True},{'wake_case':'suppressed','send_status':0,'create_null':True}]
 for extra in configs:
  c={'kernel_case':2,'mode':'schedule_then_run','repeat':1,**extra};cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};r=CFProbe(c,rows[2],cs).run();cf.append(r);print('CF',extra,r['boundary']['kind'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','kernel_request_delivery_profiles.json','kernel_zone_startup_profiles.json','probe_kernel_timer_port_create.py','recover_'+P+'.py']},'startup_cases':[startup],'kernel_cases':rows,'CF_cases':cf,**{k:False for k in FLAGS}};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
