#!/usr/bin/env python3
"""Independent original port-set producer/dequeue replay; no new probe import.
O(image+visits+RAM+journals) time/space. Original source and full CPU/RAM
handoffs are checked; raw storage/task/VM/PAC remain declared contracts.
"""
import struct
from unicorn import arm64_const as A
from replay_kernel_request_delivery import Replay as Parent
from replay_rpc502_vm_handoff import decode,P,SIZE
from recover_kernel_portset_delivery import ALLOC,INSERT
PS=P+0xb8000;NODE=P+0xbc000;NODE2=P+0xbd000;ALLOC_ARGS=P+0xb9000;INSERT_ARGS=P+0xb9040;NAME_OUT=P+0xb9080;PSZONE=0xfffffe000caec5c0;TASK_NAME=0x103;TABLE=0x400000100000;HALT=P+0xe0000;FRONT=0xfffffe000bcdd4e4;TASK=P+0x947c0;USER=P+0x1000
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.pfi=self.pri=self.phi=self.pmi=self.link_allocations=0
 def cpu(self,e):
  assert e['source_visit_index']==self.seq and e['registers31']==[hex(self.reg(j))for j in range(31)]and e['SP']==hex(self.u.reg_read(A.UC_ARM64_REG_SP))and e['NZCV']==hex(self.u.reg_read(A.UC_ARM64_REG_NZCV))and e['Q_registers32']==[hex(self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(j))))for j in range(32)];self.counts['complete_pset_CPU_frames_checked']+=1
 def frame(self,e):
  self.cpu(e)
  for at,n,key in((PS,56,'pset56_hex'),(NODE,48,'node48_hex'),(NODE2,48,'node2_48_hex'),(int(self.p['destination'],16),144,'service144_hex'),(TABLE+120,24,'entry5_24_hex'),(USER,148,'user148_hex')):assert e[key]==bytes(self.u.mem_read(at,n)).hex()
  self.counts['pset_link_service_namespace_and_message_frames_checked']+=1
 def code(self,u,a,n,d):
  self.finish()
  if self.pri<len(self.p['pset_stage_returns']):
   e=self.p['pset_stage_returns'][self.pri]
   if a==HALT and e['source_visit_index']==self.seq:self.frame(e);assert decode(e['private_RAM'])==bytes(u.mem_read(P,SIZE));self.pri+=1;self.counts['complete_function_return_RAM_images_checked']+=1
  if self.phi<len(self.p['pset_stage_handoffs']):
   e=self.p['pset_stage_handoffs'][self.phi]
   if a==HALT and e['before']['source_visit_index']==self.seq:
    self.cpu(e['before']);assert decode(e['private_RAM_before'])==bytes(u.mem_read(P,SIZE));name=int(self.p['receive_facility_name'],16);service=int(self.p['receive_name'],16);kind=e['kind'];patches=[]
    if kind=='allocate_to_insert':assert self.phi==0 and self.reg(0)==0 and int.from_bytes(bytes(u.mem_read(NAME_OUT,4)),'little')==name;target=INSERT;args=(INSERT_ARGS,);patches=[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,service,name))]
    elif kind=='repeat_insert':assert self.p['configuration']['repeat_insert']and self.reg(0)==0;target=INSERT;args=(INSERT_ARGS,)
    else:
     assert kind in('insert_to_set_receive','second_set_receive')and self.reg(0)==0
     if kind=='second_set_receive':assert self.p['configuration']['receive_twice']
     target=FRONT;args=(USER,0,self.p['configuration']['options'],0,0,self.p['configuration']['capacity'],0,name)
    assert len(e['patches'])==len(patches)
    for(at,b),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};u.mem_write(at,b)
    for j,v in enumerate(args):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    u.reg_write(A.UC_ARM64_REG_X30,HALT);u.reg_write(A.UC_ARM64_REG_PC,target);self.cpu(e['after']);assert decode(e['private_RAM_after'])==bytes(u.mem_read(P,SIZE));self.phi+=1;self.counts['complete_function_entry_CPU_RAM_handoffs_checked']+=1;return
  if self.pfi<len(self.p['pset_frames']):
   e=self.p['pset_frames'][self.pfi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.frame(e);self.pfi+=1
  if self.pmi<len(self.p['pset_lower_models']):
   e=self.p['pset_lower_models'][self.pmi]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    assert e['arguments8']==[hex(self.reg(j))for j in range(8)]
    for at,n,key in((PS,56,'pset56_hex'),(NODE,48,'node48_hex'),(NODE2,48,'node2_48_hex')):assert e[key]==bytes(u.mem_read(at,n)).hex()
    if a==0xfffffe000bcfb4f0:assert self.reg(0)==TASK_NAME and self.reg(1)==0;result=TASK
    elif a==0xfffffe000bd75c64:assert[self.reg(j)for j in range(3)]==[PSZONE,P+0xb1000,0x8004];result=PS
    elif a==0xfffffe000bcfefc8:assert[self.reg(j)for j in range(2)]==[0xfffffe0007e43358,4];result=NODE if self.link_allocations==0 else NODE2;self.link_allocations+=1;assert bytes(u.mem_read(result,48))==bytes(48)
    else:assert a==0xfffffe000bd7a4b8 and[self.reg(j)for j in range(2)]==[0xfffffe0007e43358,NODE2];result=0
    model=self.models[self.mi];assert e['result']==hex(result)==model['return_value'];want=[result]+[(((j+1)*0x123456789abcdef)^((self.mi+1)*0x8b3dc651))&((1<<64)-1)for j in range(1,18)];assert model['after_registers31'][:18]==[hex(x)for x in want]and model['after_NZCV']==('0xf0000000'if(self.mi+1)&1 else'0x0');self.pmi+=1;self.counts['raw_storage_task_conversion_and_unused_retirement_models_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  out=super().run();assert self.pri==len(self.p['pset_stage_returns'])and self.phi==len(self.p['pset_stage_handoffs'])and self.pfi==len(self.p['pset_frames'])and self.pmi==len(self.p['pset_lower_models'])
  for at,n,key in((PS,56,'final_pset56_hex'),(NODE,48,'final_link48_hex'),(NODE2,48,'final_unused_link48_hex'),(TABLE+120,24,'final_entry5_24_hex'),(PS+56,1,'raw_pset_guard_hex'),(NODE+48,1,'raw_link_guard_hex'),(NODE2+48,1,'raw_unused_link_guard_hex')):assert self.p[key]==bytes(self.u.mem_read(at,n)).hex();self.counts['complete_pset_link_namespace_and_guard_final_bytes_checked']+=n
  return dict(self.counts)
from replay_cf_source_scheduling import Replay as CFParent,MODE as CF_MODE,USER as CF_USER,OOL as CF_OOL
from recover_cf_source_scheduling import INSERT_TRAP as CF_INSERT
from recover_cf_receive_voucher import MACH
class CFReplay(CFParent):
 def __init__(self,p,k,s):super().__init__(p,k,s);self.facility=int(k['receive_facility_name'],16);assert p['receive_facility_name']==hex(self.facility);self.u.mem_write(CF_MODE+0x88,struct.pack('<I',self.facility))
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==CF_INSERT:
   state=self.state();assert[self.reg(j)for j in range(3)]==[TASK_NAME,self.port,self.facility];ret=next(e for e in self.origin['pset_stage_returns']if e['phase']=='insert');result=int(ret['registers31'][0],16);assert result==0;self.members.add((self.facility,self.port));e=self.consume_model(a,result,[]);assert e==self.p['scheduling_models'][self.smi]and e['model_state_before']==state and e['model_state_after']==self.state()and e['name']=='original_kernel_member_return_contract'and e['kernel_oracle']=={'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'arguments24_hex':struct.pack('<3Q',TASK_NAME,self.port,self.facility).hex()};self.smi+=1;self.counts['original_kernel_member_return_contracts_checked']+=1;return
  if a==MACH:
   assert[self.reg(j)for j in range(7)]==[CF_USER,0x07000806,0,3072,self.facility,0xffffffff,0]and(self.facility,self.port)in self.members;self.check_run_frame(self.p['kernel_transfers'][self.kti]);self.kti+=1;result=int(self.origin['boundary']['registers31'][0],16);assert result==0;e=self.consume_model(a,result,[(CF_USER,bytes.fromhex(self.origin['final_user8192_hex'])[:148]),(CF_OOL,bytes.fromhex(self.origin['final_OOL16384_hex'])[:29])]);assert e['name']=='original_portset_receive_return_contract'and e['kernel_oracle']=={'case':self.config['kernel_case'],'return_PC':self.origin['boundary']['pc']};self.counts['original_kernel_set_receive_return_contracts_checked']+=1;return
  return super().hook(u,a,n,d)
