#!/usr/bin/env python3
"""Independent original arm/callback/send/first timer and later service replay.
No new probe import. Clock/scheduler/preflight contracts are recomputed and all
inherited original CPU/RAM/object/read/write observations remain checked.
"""
import struct
from unicorn import arm64_const as A
from replay_kernel_timer_port_create import Replay as Parent,CFReplay as CFParent,TOBJ,TKMSG,TPORT
from replay_kernel_portset_delivery import INSERT_ARGS,TASK_NAME
from replay_kernel_request_receive import P,SIZE
from replay_rpc502_vm_handoff import decode
from recover_kernel_timer_expiration_delivery import ARM,CALLBACK,SCHEDULE
from recover_kernel_portset_delivery import INSERT
HALT=P+0xe0000;ARGS=P+0xbb000;USER=P+0x1000;COUNTER=0xfffffe000bd13980;FRONT=0xfffffe000bcdd4e4
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.efi=self.eri=self.ehi=self.emi=self.coi=0;self.exp_after=None
 def exp_frame(self,e,a):
  assert e['pc']==hex(a)and e['phase']==self.root_phase;self.cpu(e)
  for at,n,key in((TOBJ,168,'timer168_hex'),(TPORT,144,'timer_port144_hex'),(TKMSG,256,'timer_kmsg256_hex'),(USER,148,'user148_hex')):assert e[key]==bytes(self.u.mem_read(at,n)).hex()
  self.counts['expiration_objects_user_buffer_and_complete_CPU_frames_checked']+=1
 def code(self,u,a,n,d):
  self.finish()
  if self.exp_after:self.exp_frame(self.exp_after,a);self.exp_after=None
  if self.efi<len(self.p['expiration_frames']):
   e=self.p['expiration_frames'][self.efi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.exp_frame(e,a);self.efi+=1
  if self.eri<len(self.p['expiration_returns']):
   e=self.p['expiration_returns'][self.eri]
   if a==HALT and e['source_visit_index']==self.seq:self.exp_frame(e,a);assert decode(e['private_RAM'])==bytes(u.mem_read(P,SIZE));self.eri+=1;self.counts['arm_expiration_return_whole_RAM_images_checked']+=1
  if self.ehi<len(self.p['expiration_handoffs']):
   e=self.p['expiration_handoffs'][self.ehi]
   if a==HALT and e['before']['source_visit_index']==self.seq:
    if self.tri<len(self.p['timer_returns']):
     ret=self.p['timer_returns'][self.tri]
     if ret['source_visit_index']==self.seq:self.timer_frame(ret,a);assert ret['phase']=='timer_insert'and decode(ret['private_RAM'])==bytes(u.mem_read(P,SIZE));self.tri+=1;self.counts['timer_function_return_whole_RAM_images_checked']+=1
    self.cpu(e['before']);assert decode(e['private_RAM_before'])==bytes(u.mem_read(P,SIZE));kind=e['kind'];patches=[]
    if kind=='timer_insert_to_arm':assert self.root_phase=='timer_insert'and self.reg(0)==0;self.root_phase='timer_arm';target=ARM;args=(ARGS,)
    elif kind=='arm_to_expiration_callback':
     assert self.root_phase=='timer_arm'and self.reg(0)==0 and int.from_bytes(bytes(u.mem_read(TOBJ+0x68,8)),'little')==CALLBACK and bytes(u.mem_read(TOBJ+0x91,1))==b'\x01'and int.from_bytes(bytes(u.mem_read(TOBJ+0x94,4)),'little')==1 and e['scheduler_contract']=='Declared delivery of the newly queued original callback; no native scheduling';self.root_phase='timer_expiration';target=CALLBACK;args=(TOBJ,)
    else:assert kind=='expiration_to_service_insert'and self.root_phase=='timer_expiration';self.root_phase='insert';target=INSERT;args=(INSERT_ARGS,);patches=[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,int(self.p['receive_name'],16),0x507))]
    assert len(e['patches'])==len(patches)
    for(at,b),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};u.mem_write(at,b)
    for j,v in enumerate(args):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    u.reg_write(A.UC_ARM64_REG_X30,HALT);u.reg_write(A.UC_ARM64_REG_PC,target);self.cpu(e['after']);assert decode(e['private_RAM_after'])==bytes(u.mem_read(P,SIZE));self.ehi+=1;self.counts['arm_declared_scheduler_delivery_and_service_entry_CPU_RAM_handoffs_checked']+=1;return
  if self.phi<len(self.p['pset_stage_handoffs']):
   e=self.p['pset_stage_handoffs'][self.phi]
   if a==HALT and e['before']['source_visit_index']==self.seq and e['kind']=='second_set_receive':
    ret=self.p['pset_stage_returns'][self.pri];assert ret['phase']=='first_receive'and ret['source_visit_index']==self.seq;self.frame(ret);assert decode(ret['private_RAM'])==bytes(u.mem_read(P,SIZE));self.pri+=1;self.counts['complete_function_return_RAM_images_checked']+=1;self.cpu(e['before']);assert self.reg(0)==0 and decode(e['private_RAM_before'])==bytes(u.mem_read(P,SIZE))and not e['patches'];args=(USER,0,self.p['configuration']['options'],0,0,self.p['configuration']['capacity'],0,0x507)
    for j,v in enumerate(args):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    u.reg_write(A.UC_ARM64_REG_X30,HALT);u.reg_write(A.UC_ARM64_REG_PC,FRONT);self.cpu(e['after']);assert decode(e['private_RAM_after'])==bytes(u.mem_read(P,SIZE));self.phi+=1;self.counts['actual_timer_receive_to_service_receive_CPU_RAM_handoffs_checked']+=1;return
  if a==COUNTER:
   e=self.p['counter_contracts'][self.coi];self.exp_frame(e['before'],a);raw=bytes(u.mem_read(a,4));ins=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4)and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}and(ins.mnemonic,ins.op_str)==('mrs','x9, s3_4_c15_c10_6')and e['raw_counter']==100 and e['native_counter_executed']is False;self.current=self.seq;self.seq+=1;self.rc=self.wc=0;u.reg_write(A.UC_ARM64_REG_X9,100);u.reg_write(A.UC_ARM64_REG_PC,a+4);self.exp_frame(e['after'],a+4);self.coi+=1;self.counts['source_visits_checked']+=1;self.counts['declared_raw_counter_read_contracts_checked']+=1;return
  if self.emi<len(self.p['expiration_models']):
   e=self.p['expiration_models'][self.emi]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    self.exp_frame(e['before'],a);names={SCHEDULE:'declared_scheduler_newly_queued_timer_callback',0xfffffe000bcc0f9c:'declared_send_preflight',0xfffffe000bcd9f3c:'declared_message_tag_helper'};assert e['name']==names[a]and e['result']=='0x0'
    if a==SCHEDULE:assert[self.reg(j)for j in range(2)]==[TOBJ+0x10,0]
    model=self.models[self.mi];want=[0]+[(((j+1)*0x123456789abcdef)^((self.mi+1)*0x8b3dc651))&((1<<64)-1)for j in range(1,18)];assert model['symbol']==e['name']and model['return_value']=='0x0'and model['after_registers31'][:18]==[hex(v)for v in want]and model['after_NZCV']==('0xf0000000'if(self.mi+1)&1 else'0x0');self.exp_after=e['after'];self.emi+=1;self.counts['scheduler_tag_and_send_preflight_contracts_recomputed']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.efi==len(self.p['expiration_frames'])and self.eri==len(self.p['expiration_returns'])and self.ehi==len(self.p['expiration_handoffs'])and self.emi==len(self.p['expiration_models'])and self.coi==len(self.p['counter_contracts'])and self.exp_after is None;return dict(self.counts)

from recover_cf_receive_voucher import MACH
class CFReplay(CFParent):
 def __init__(self,p,k,s):super().__init__(p,k,s);self.timer_received=False;self.eti=0
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==MACH and not self.timer_received:
   assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,self.facility,0xffffffff,0];ret=next(e for e in self.origin['pset_stage_returns']if e['phase']=='first_receive');raw=bytes.fromhex(ret['user148_hex']);size=int.from_bytes(raw[4:8],'little');assert size==48 and int.from_bytes(raw[12:16],'little')==0x707;self.check_run_frame(self.p['expiration_transfers'][self.eti]);self.eti+=1;self.timer_received=True;self.mode_call(a,'original_kernel_timer_expiration_receive_return',0,[(USER,raw[:size+68])],{'timer_receive_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'wire_size_bytes':116}});self.counts['actual_kernel_timer_wire_return_contracts_checked']+=1;return
  if a==0x18472907c:
   assert self.reg(0)in self.collections;self.mode_call(a,'declared_source_set_cardinality_after_timer_receive',len(self.collections[self.reg(0)]));self.counts['source_cardinality_after_original_timer_message_contracts_checked']+=1;return
  return super().hook(u,a,n,d)
 def run(self):
  super().run();assert self.timer_received and self.eti==len(self.p['expiration_transfers'])==1;return dict(self.counts)
