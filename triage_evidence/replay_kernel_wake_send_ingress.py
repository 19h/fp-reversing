#!/usr/bin/env python3
"""Independent original Mach -47 wake ingress/send/set-delivery replay.
No new probe import. Original CF user epochs, copy/raw contracts and complete
CPU/RAM/port/message frames independently checked; no native IPC/PAC effects.
"""
import struct
from unicorn import arm64_const as A
from replay_cf_runloop_wake_port import Replay as Parent,WPORT,WNODE
from replay_kernel_portset_delivery import INSERT_ARGS,TASK_NAME
from replay_kernel_timer_port_create import KMSGZONE
from replay_kernel_request_delivery import P as B
from replay_rpc502_vm_handoff import decode,SIZE
from replay_cf_runloop_handoff import unpack,LOW,LOW_SIZE
from recover_kernel_wake_send_ingress import HANDLER
from recover_kernel_portset_delivery import INSERT
ARGS=B+0xbb100;RO=B+0xf0000;WKMSG=B+0xd4000;HALT=B+0xe0000;USER=B+0x1000
class Replay(Parent):
 def __init__(self,im,p,packet):
  super().__init__(im,p);assert p['original_CF_user_epoch']==packet;self.packet=packet;stack=unpack(packet['lower_stack'],LOW,LOW_SIZE);self.u.mem_map(LOW,LOW_SIZE);self.u.mem_write(LOW,stack);self.ifi=self.iri=self.ihi=self.imi=self.raw_wake_count=0;self.iafter=None
  original_start=self.u.emu_start;handoff_visits=sum(len(p[k])for k in('pset_stage_handoffs','root_handoffs','timer_handoffs','wake_handoffs','ingress_handoffs'))+1;complete_budget=len(p['source_visits'])+len(p['API_models'])+handoff_visits
  def start_with_complete_handoff_budget(begin,until,timeout=0,count=0):return original_start(begin,until,timeout=timeout,count=max(count,complete_budget))
  self.u.emu_start=start_with_complete_handoff_budget
  assert bytes(self.u.mem_read(ARGS,64))==b''.join(int(v,16).to_bytes(8,'little')for v in packet['arguments8'])and bytes(self.u.mem_read(B+0x947c0+0x3f8,8))==struct.pack('<Q',RO)and bytes(self.u.mem_read(RO+8,8))==struct.pack('<Q',B+0x947c0)and bytes(self.u.mem_read(0xfffffe0007e6d048,4))==struct.pack('<I',0x40000)
  for e in packet['regions']:assert bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()==e['bytes_hex']
 def ingress_frame(self,e,a):
  assert e['pc']==hex(a)and e['phase']==self.root_phase;self.cpu(e)
  for at,n,key in((WPORT,144,'wake_port144_hex'),(WKMSG,256,'wake_kmsg256_hex'),(USER,148,'user148_hex')):assert e[key]==bytes(self.u.mem_read(at,n)).hex()
  self.counts['wake_ingress_port_message_user_and_complete_CPU_frames_checked']+=1
 def code(self,u,a,n,d):
  self.finish()
  if self.iafter:self.ingress_frame(self.iafter,a);self.iafter=None
  if self.ifi<len(self.p['ingress_frames']):
   e=self.p['ingress_frames'][self.ifi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.ingress_frame(e,a);self.ifi+=1
  if self.iri<len(self.p['ingress_returns']):
   e=self.p['ingress_returns'][self.iri]
   if a==HALT and e['source_visit_index']==self.seq:self.ingress_frame(e,a);assert decode(e['private_RAM'])==bytes(u.mem_read(B,SIZE));self.iri+=1;self.counts['original_Mach47_return_whole_RAM_images_checked']+=1
  if self.ihi<len(self.p['ingress_handoffs']):
   e=self.p['ingress_handoffs'][self.ihi]
   if a==HALT and e['before']['source_visit_index']==self.seq:
    if self.wri<len(self.p['wake_returns']):
     ret=self.p['wake_returns'][self.wri]
     if ret['source_visit_index']==self.seq:self.wake_frame(ret,a);assert ret['phase']=='wake_insert'and decode(ret['private_RAM'])==bytes(u.mem_read(B,SIZE));self.wri+=1;self.counts['wake_return_whole_RAM_images_checked']+=1
    self.cpu(e['before']);assert decode(e['private_RAM_before'])==bytes(u.mem_read(B,SIZE))and self.reg(0)==0;kind=e['kind'];patches=[]
    if kind=='wake_insert_to_original_Mach47':assert self.root_phase=='wake_insert';self.root_phase='wake_send';target=HANDLER;args=(ARGS,)
    else:assert kind=='wake_send_to_service_insert'and self.root_phase=='wake_send';self.root_phase='insert';target=INSERT;args=(INSERT_ARGS,);patches=[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,int(self.p['receive_name'],16),0x507))]
    assert len(e['patches'])==len(patches)
    for(at,b),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};u.mem_write(at,b)
    for j,v in enumerate(args):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    u.reg_write(A.UC_ARM64_REG_X30,HALT);u.reg_write(A.UC_ARM64_REG_PC,target);self.cpu(e['after']);assert decode(e['private_RAM_after'])==bytes(u.mem_read(B,SIZE));self.ihi+=1;self.counts['wake_Mach47_and_service_entry_CPU_RAM_handoffs_checked']+=1;return
  if self.phi<len(self.p['pset_stage_handoffs']):
   e=self.p['pset_stage_handoffs'][self.phi]
   if a==HALT and e['before']['source_visit_index']==self.seq and e['kind']=='second_set_receive':
    ret=self.p['pset_stage_returns'][self.pri];assert ret['phase']=='first_receive'and ret['source_visit_index']==self.seq;self.frame(ret);assert decode(ret['private_RAM'])==bytes(u.mem_read(B,SIZE));self.pri+=1;self.counts['complete_function_return_RAM_images_checked']+=1;self.cpu(e['before']);assert self.reg(0)==0 and decode(e['private_RAM_before'])==bytes(u.mem_read(B,SIZE))and not e['patches'];args=(USER,0,self.p['configuration']['options'],0,0,self.p['configuration']['capacity'],0,0x507)
    for j,v in enumerate(args):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    u.reg_write(A.UC_ARM64_REG_X30,HALT);u.reg_write(A.UC_ARM64_REG_PC,0xfffffe000bcdd4e4);self.cpu(e['after']);assert decode(e['private_RAM_after'])==bytes(u.mem_read(B,SIZE));self.phi+=1;self.counts['actual_wake_to_service_receive_CPU_RAM_handoffs_checked']+=1;return
  if self.imi<len(self.p['ingress_models']):
   e=self.p['ingress_models'][self.imi]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    self.ingress_frame(e['before'],a);assert self.root_phase=='wake_send';patches=[]
    if a==0xfffffe000bd75c64:
     assert[self.reg(j)for j in range(3)]==[KMSGZONE,B+0xb1000,0x8004]and self.raw_wake_count==0 and bytes(u.mem_read(WKMSG,256))==bytes(256);self.raw_wake_count+=1;value=WKMSG;name='declared_raw_wake_kmsg256'
    elif a==0xfffffe000be76e18:
     src,dst,size=[self.reg(j)for j in range(3)];assert LOW<=src<=src+size<=LOW+LOW_SIZE and B<=dst<=dst+size<=B+SIZE and size<=256;value=int(bool(self.p['configuration'].get('vector_copyin_error')and self.reg(30)==0xfffffe000bcdd8a8));name='declared_exact_original_CF_user_copyin'
     if not value:patches=[(dst,bytes(u.mem_read(src,size)))]
    elif a==0xfffffe000c647f10:
     dst,src,size=[self.reg(j)for j in range(3)];assert B<=dst<=dst+size<=B+SIZE and size<=256 and(B<=src<=src+size<=B+SIZE or LOW<=src<=src+size<=LOW+LOW_SIZE);value=dst;name='declared_disjoint_wake_byte_copy';patches=[(dst,bytes(u.mem_read(src,size)))]
    else:assert a in(0xfffffe000bcc0f9c,0xfffffe000bcd9f3c);value=0;name='declared_wake_send_preflight'if a==0xfffffe000bcc0f9c else'declared_wake_message_tag_helper'
    assert e['name']==name and e['result']==hex(value)and len(e['patches'])==len(patches)
    for(at,b),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};u.mem_write(at,b)
    m=self.models[self.mi];want=[value]+[(((j+1)*0x123456789abcdef)^((self.mi+1)*0x8b3dc651))&((1<<64)-1)for j in range(1,18)];assert m['symbol']==name and m['return_value']==hex(value)and m['after_registers31'][:18]==[hex(v)for v in want]and m['after_NZCV']==('0xf0000000'if(self.mi+1)&1 else'0x0');self.iafter=e['after'];self.imi+=1;self.counts['wake_ingress_raw_user_copy_and_lower_contracts_recomputed']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.ifi==len(self.p['ingress_frames'])and self.iri==len(self.p['ingress_returns'])and self.ihi==len(self.p['ingress_handoffs'])and self.imi==len(self.p['ingress_models'])and self.iafter is None
  stack=unpack(self.p['final_CF_lower_stack'],LOW,LOW_SIZE);assert stack==bytes(self.u.mem_read(LOW,LOW_SIZE))==unpack(self.packet['lower_stack'],LOW,LOW_SIZE);self.counts['complete_CF_user_epoch_final_bytes_checked']+=LOW_SIZE;assert self.p['final_wake_kmsg256_hex']==bytes(self.u.mem_read(WKMSG,256)).hex()and self.p['wake_kmsg_guard_hex']==bytes(self.u.mem_read(WKMSG+256,1)).hex()and self.p['readonly_guard_hex']==bytes(self.u.mem_read(RO+128,1)).hex()and self.p['identity_guard_hex']==bytes(self.u.mem_read(B+0xf4000+32,1)).hex();return dict(self.counts)

from replay_cf_runloop_wake_port import CFReplay as CFParent
from recover_cf_wake_send_wrapper import MACH
from replay_cf_source_scheduling import OOL,HALT as CFHALT
class CFReplay(CFParent):
 def __init__(self,p,k,s):super().__init__(p,k,s);self.wake_received=False;self.wti=0;self.pool_tokens=[];self.pool_count=0
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==CFHALT and self.pi==len(self.p['public_handoffs']):assert self.p['boundary']['kind']=='original_runloop_returned'and self.seq==len(self.p['source_visits']);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  pools=self.source['pool_runtime_boundaries']
  if a==int(pools['push']['target'],16):
   before=list(self.pool_tokens);self.pool_count+=1;token=0x123400000+self.pool_count;self.pool_tokens.append(token);return self.mode_call(a,'declared_objc_autorelease_pool_push',token,extra={'pool_tokens_before':[hex(v)for v in before],'pool_tokens_after':[hex(v)for v in self.pool_tokens]})
  if a==int(pools['pop']['target'],16):
   before=list(self.pool_tokens);assert self.pool_tokens and self.reg(0)==self.pool_tokens[-1];self.pool_tokens.pop();return self.mode_call(a,'declared_objc_autorelease_pool_pop',0,extra={'pool_tokens_before':[hex(v)for v in before],'pool_tokens_after':[hex(v)for v in self.pool_tokens]})
  if a==MACH and self.wphase=='runloop':
   assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,self.facility,0xffffffff,0]
   if not self.wake_received:
    ret=next(e for e in self.origin['pset_stage_returns']if e['phase']=='first_receive');raw=bytes.fromhex(ret['user148_hex']);assert int.from_bytes(raw[4:8],'little')==24 and int.from_bytes(raw[12:16],'little')==0x807;self.check_run_frame(self.p['wake_receive_transfers'][self.wti]);self.wti+=1;self.wake_received=True;self.mode_call(a,'original_kernel_wake_set_receive_return',0,[(USER,raw[:92])],{'wake_receive_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'wire_size_bytes':92}});self.counts['original_kernel_wake_wire92_transfers_checked']+=1;return
   return super(CFParent,self).hook(u,a,n,d)
  if a==0x18472907c:assert self.reg(0)in self.collections;return self.mode_call(a,'declared_source_cardinality_after_wake_receive',len(self.collections[self.reg(0)]))
  return super().hook(u,a,n,d)
 def run(self):
  super().run();assert self.wake_received and self.wti==len(self.p['wake_receive_transfers'])==1 and self.p['final_pool_tokens']==[hex(v)for v in self.pool_tokens];return dict(self.counts)
