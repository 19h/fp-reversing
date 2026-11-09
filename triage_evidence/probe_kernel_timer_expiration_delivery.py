#!/usr/bin/env python3
"""Original timer arm -> conditional callback dispatch -> send -> set receive.
Raw counter100 and scheduler-newly-queued result are explicit contracts. Native
clock/scheduler/IPC/PAC effects never execute; original bytes produce the packet.
"""
import json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT
from probe_kernel_timer_port_create import Probe as Parent,TOBJ,TKMSG,TPORT,Startup
from probe_kernel_portset_delivery import INSERT_ARGS,TASK_NAME
from probe_kernel_request_receive import RECV,USER,TASK
from probe_kernel_vm_mig import P,SIZE,HALT
from probe_rpc502_vm_handoff import compressed
from recover_kernel_timer_expiration_delivery import P as PREFIX,FLAGS,sha,ARM,ARMCORE,CALLBACK,SEND,SCHEDULE
from recover_kernel_portset_delivery import INSERT
from kernel_vm_mig_tools import Image
ARGS=P+0xbb000;COUNTER=0xfffffe000bd13980
POINTS={ARM,ARMCORE,CALLBACK,SEND,0xfffffe000bd1396c,0xfffffe000bd13a28,0xfffffe000bd13520,0xfffffe000bd13528,0xfffffe000bd13580,0xfffffe000bcc7040,0xfffffe000bcc7c34}
class Probe(Parent):
 def __init__(self,im,s,c,parent,zones,startup):
  super().__init__(im,s,c,parent,zones,startup);self.exp_frames=[];self.exp_returns=[];self.exp_handoffs=[];self.exp_models=[];self.counter_contracts=[];self.overlay(ARGS,struct.pack('<2Q',0x707,c.get('deadline',0)),'Declared original Mach -93 argument record');self.overlay(RECV+0x6b1,b'\0','Declared thread no timebase-conversion flag');self.overlay(P+0xb4000+0x58,bytes(8),'Declared CPU counter offset0');self.overlay(P+0x5b000,bytes(64),'Declared disjoint per-CPU send-counter storage');self.overlay(TASK+0x3d0,struct.pack('<Q',P+0x5b000),'Declared task per-CPU send-counter pointer');self.overlay(RECV+0x1b8,bytes(2),'Declared current CPU index0')
 def exp_frame(self,a):return{'pc':hex(a),**self.cpu(),'phase':self.phase,'timer168_hex':bytes(self.u.mem_read(TOBJ,168)).hex(),'timer_port144_hex':bytes(self.u.mem_read(TPORT,144)).hex(),'timer_kmsg256_hex':bytes(self.u.mem_read(TKMSG,256)).hex(),'user148_hex':bytes(self.u.mem_read(USER,148)).hex()}
 def exp_transition(self,a,args,label,patches=()):
  self.transition(a,args,label,patches);e=self.stage_handoffs.pop()
  if label=='arm_to_expiration_callback':e['scheduler_contract']='Declared delivery of the newly queued original callback; no native scheduling';assert int.from_bytes(bytes(self.u.mem_read(TOBJ+0x68,8)),'little')==a
  self.exp_handoffs.append(e)
 def timer_transition(self,a,args,label,patches=()):
  if label=='timer_insert_to_service_insert':self.phase='timer_arm';return self.exp_transition(ARM,(ARGS,),'timer_insert_to_arm')
  return super().timer_transition(a,args,label,patches)
 def exp_model(self,a,name,result):
  e={'pc':hex(a),'before_source_visit_index':len(self.visits),'name':name,'before':self.exp_frame(a),'result':hex(result)};self.model(a,name,result);e['after']=self.exp_frame(self.u.reg_read(A.UC_ARM64_REG_PC));self.exp_models.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a in POINTS:self.exp_frames.append(self.exp_frame(a))
  if a==HALT and self.phase=='timer_arm':
   self.exp_returns.append({**self.exp_frame(a),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))});assert self.reg(0)==0 and bytes(u.mem_read(TOBJ+0x91,1))==b'\x01'and int.from_bytes(bytes(u.mem_read(TOBJ+0x94,4)),'little')==1;self.phase='timer_expiration';return self.exp_transition(CALLBACK,(TOBJ,),'arm_to_expiration_callback')
  if a==HALT and self.phase=='timer_expiration':
   self.exp_returns.append({**self.exp_frame(a),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))});self.phase='insert';return self.exp_transition(INSERT,(INSERT_ARGS,),'expiration_to_service_insert',[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,self.receive_name,self.pset_name))])
  if a==COUNTER:
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4)and(i.mnemonic,i.op_str)==('mrs','x9, s3_4_c15_c10_6');e={'pc':hex(a),'before':self.exp_frame(a),'raw_counter':100,'native_counter_executed':False};self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(9,100);u.reg_write(A.UC_ARM64_REG_PC,a+4);e['after']=self.exp_frame(a+4);self.counter_contracts.append(e);return
  if a==SCHEDULE:assert[self.reg(j)for j in range(2)]==[TOBJ+0x10,0];return self.exp_model(a,'declared_scheduler_newly_queued_timer_callback',0)
  if a in(0xfffffe000bcc0f9c,0xfffffe000bcd9f3c):return self.exp_model(a,'declared_send_preflight'if a==0xfffffe000bcc0f9c else'declared_message_tag_helper',0)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(expiration_frames=self.exp_frames,expiration_returns=self.exp_returns,expiration_handoffs=self.exp_handoffs,expiration_models=self.exp_models,counter_contracts=self.counter_contracts);return r
from probe_kernel_timer_port_create import CFProbe as CFParent
from recover_cf_receive_voucher import MACH
class CFProbe(CFParent):
 def __init__(self,c,k,s):super().__init__(c,k,s);self.timer_received=False;self.expiration_transfers=[]
 def hook(self,u,a,n,d):
  self.flush()
  if a==MACH and not self.timer_received:
   assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,self.facility,0xffffffff,0];ret=next(e for e in self.input['pset_stage_returns']if e['phase']=='first_receive');raw=bytes.fromhex(ret['user148_hex']);size=int.from_bytes(raw[4:8],'little');assert size==48 and int.from_bytes(raw[12:16],'little')==0x707;self.expiration_transfers.append(self.run_frame(a));self.timer_received=True;return self.mode_model(a,'original_kernel_timer_expiration_receive_return',0,[(USER,raw[:size+68])],{'timer_receive_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'wire_size_bytes':116}})
  if a==0x18472907c:
   assert self.reg(0)in self.collections;return self.mode_model(a,'declared_source_set_cardinality_after_timer_receive',len(self.collections[self.reg(0)]))
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();assert self.timer_received;r.update(expiration_transfers=self.expiration_transfers);return r
if __name__=='__main__':
 im=Image();s=json.loads((ROOT/(PREFIX+'_source.json')).read_text());old=json.loads((ROOT/'kernel_request_delivery_profiles.json').read_text());zones=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'];startup=json.loads((ROOT/'kernel_timer_port_create_profiles.json').read_text())['startup_cases'][0];rows=[]
 for j,deadline in[(j,0)for j in range(4)]+[(2,100)]:
  c={'producer':j,'capacity':3072,'options':0x07000806,'receive_twice':True,'deadline':deadline};r=Probe(im,s,c,old['loans'][j],zones,startup).run();rows.append(r);print('KERNEL',j,r['boundary']['kind'],r['boundary']['pc'],len(r['source_visits']),flush=True)
 cf=[]
 for j in range(4):
  cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};r=CFProbe({'kernel_case':j,'mode':'schedule_then_run','repeat':1},rows[j],cs).run();cf.append(r);print('CF',j,r['boundary']['kind'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_request_delivery_profiles.json','kernel_zone_startup_profiles.json','kernel_timer_port_create_profiles.json','probe_kernel_timer_port_create.py','recover_'+PREFIX+'.py']},'kernel_cases':rows,'CF_cases':cf,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
