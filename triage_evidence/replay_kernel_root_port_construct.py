#!/usr/bin/env python3
"""Independent original root construct/member/set-delivery replay.
No new probe import; recompute options copy, raw allocation and function-entry
handoffs. Original CPU/RAM journals retain all inherited lower-contract limits.
"""
import struct
from unicorn import arm64_const as A
from replay_kernel_portset_delivery import Replay as Parent,PS,NODE,NODE2,TABLE,INSERT_ARGS,TASK_NAME,NAME_OUT,TASK
from replay_rpc502_vm_handoff import decode,P,SIZE
from recover_kernel_root_port_construct import CONSTRUCT,COPYIN
from recover_kernel_portset_delivery import INSERT
HALT=P+0xe0000;RPORT=P+0xbe000;RARGS=P+0xba000;OPTIONS=P+0xba040;ROUT=P+0xba080;CONTEXT=P+0xb6000;PORTZONE=0xfffffe000caec500
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.root_phase='allocate';self.rfi=self.rri=self.rhi=self.rmi=0;self.root_after=None
 def root_frame(self,e,a):
  assert e['pc']==hex(a)and e['phase']==self.root_phase;self.cpu(e)
  for at,n,key in((RPORT,144,'root144_hex'),(ROUT,4,'root_name4_hex'),(TABLE+144,24,'entry6_24_hex'),(PS,56,'pset56_hex'),(NODE,48,'root_link48_hex'),(NODE2,48,'service_link48_hex')):assert e[key]==bytes(self.u.mem_read(at,n)).hex()
  self.counts['root_port_namespace_links_and_complete_CPU_frames_checked']+=1
 def code(self,u,a,n,d):
  self.finish()
  if self.root_after:self.root_frame(self.root_after,a);self.root_after=None
  if self.rfi<len(self.p['root_frames']):
   e=self.p['root_frames'][self.rfi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.root_frame(e,a);self.rfi+=1
  if self.rri<len(self.p['root_returns']):
   e=self.p['root_returns'][self.rri]
   if a==HALT and e['source_visit_index']==self.seq:self.root_frame(e,a);assert decode(e['private_RAM'])==bytes(u.mem_read(P,SIZE));self.rri+=1;self.counts['root_function_return_whole_RAM_images_checked']+=1
  if self.rhi<len(self.p['root_handoffs']):
   e=self.p['root_handoffs'][self.rhi]
   if a==HALT and e['before']['source_visit_index']==self.seq:
    if self.pri<len(self.p['pset_stage_returns']):
     ret=self.p['pset_stage_returns'][self.pri]
     if ret['source_visit_index']==self.seq:self.frame(ret);assert ret['phase']=='allocate'and decode(ret['private_RAM'])==bytes(u.mem_read(P,SIZE));self.pri+=1;self.counts['complete_function_return_RAM_images_checked']+=1
    self.cpu(e['before']);assert decode(e['private_RAM_before'])==bytes(u.mem_read(P,SIZE))and self.reg(0)==0;kind=e['kind'];patches=[]
    if kind=='allocate_to_root_construct':assert self.root_phase=='allocate'and int.from_bytes(bytes(u.mem_read(NAME_OUT,4)),'little')==0x507;self.root_phase='root_construct';target=CONSTRUCT;args=(RARGS,)
    elif kind=='root_construct_to_root_insert':assert self.root_phase=='root_construct'and int.from_bytes(bytes(u.mem_read(ROUT,4)),'little')==0x607;self.root_phase='root_insert';target=INSERT;args=(INSERT_ARGS,);patches=[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,0x607,0x507))]
    else:assert kind=='root_insert_to_service_insert'and self.root_phase=='root_insert';self.root_phase='insert';target=INSERT;args=(INSERT_ARGS,);patches=[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,int(self.p['receive_name'],16),0x507))]
    assert len(e['patches'])==len(patches)
    for(at,b),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};u.mem_write(at,b)
    for j,v in enumerate(args):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    u.reg_write(A.UC_ARM64_REG_X30,HALT);u.reg_write(A.UC_ARM64_REG_PC,target);self.cpu(e['after']);assert decode(e['private_RAM_after'])==bytes(u.mem_read(P,SIZE));self.rhi+=1;self.counts['root_construction_membership_function_entry_CPU_RAM_handoffs_checked']+=1;return
  if self.rmi<len(self.p['root_models']):
   e=self.p['root_models'][self.rmi]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    self.root_frame(e['before'],a);patches=[]
    if a==COPYIN:
     assert self.root_phase=='root_construct'and[self.reg(j)for j in(0,2)]==[OPTIONS,24];value=1 if self.p['configuration'].get('copyin_error')else 0;name='declared_exact_options24_user_copyin'
     if not value:patches=[(self.reg(1),bytes(u.mem_read(OPTIONS,24)))]
    else:assert a==0xfffffe000bd75c64 and self.root_phase=='root_construct'and[self.reg(j)for j in range(3)]==[PORTZONE,P+0xb1000,0x8004]and bytes(u.mem_read(RPORT,144))==bytes(144);value=RPORT;name='declared_zeroed_raw_port144_storage'
    assert e['name']==name and e['result']==hex(value)and len(e['patches'])==len(patches)
    for(at,b),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};u.mem_write(at,b)
    model=self.models[self.mi];want=[value]+[(((j+1)*0x123456789abcdef)^((self.mi+1)*0x8b3dc651))&((1<<64)-1)for j in range(1,18)];assert model['symbol']==name and model['return_value']==hex(value)and model['after_registers31'][:18]==[hex(v)for v in want]and model['after_NZCV']==('0xf0000000'if(self.mi+1)&1 else'0x0');self.root_after=e['after'];self.rmi+=1;self.counts['root_copyin_and_raw_allocation_contracts_recomputed']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.rfi==len(self.p['root_frames'])and self.rri==len(self.p['root_returns'])and self.rhi==len(self.p['root_handoffs'])and self.rmi==len(self.p['root_models'])and self.root_after is None
  for a,n,key in((RPORT,144,'final_root144_hex'),(ROUT,4,'final_root_name4_hex'),(TABLE+144,24,'final_entry6_24_hex'),(RPORT+144,1,'raw_root_guard_hex')):assert self.p[key]==bytes(self.u.mem_read(a,n)).hex();self.counts['complete_root_namespace_name_and_guard_final_bytes_checked']+=n
  return dict(self.counts)

from replay_cf_mode_construction import Replay as CFParent,QUEUE
from recover_cf_mode_construction import CONSTRUCT_TRAP
from recover_cf_source_scheduling import INSERT_TRAP
class CFReplay(CFParent):
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==CONSTRUCT_TRAP:
   x=[self.reg(j)for j in range(4)];assert x[0]==TASK_NAME and x[2]==QUEUE;options=bytes(u.mem_read(x[1],24));assert options==bytes.fromhex(self.source['root_caller_options']['bytes24_hex']);ret=self.origin['root_returns'][0];value=int(ret['registers31'][0],16);assert value==0;name=bytes.fromhex(ret['root_name4_hex']);assert name==struct.pack('<I',0x607);self.mode_call(a,'original_kernel_root_construct_return',value,[(x[3],name)],{'original_options24_hex':options.hex(),'root_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'context':hex(QUEUE),'name':'0x607'}});self.counts['source_kernel_root_construct_options_context_and_name_oracles_checked']+=1;return
  if a==INSERT_TRAP and self.reg(1)==0x607:
   assert[self.reg(j)for j in range(3)]==[TASK_NAME,0x607,self.facility];ret=self.origin['root_returns'][1];value=int(ret['registers31'][0],16);assert value==0;before=self.state();self.members.add((self.facility,0x607));self.mode_call(a,'original_kernel_root_member_return',value,extra={'root_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'arguments24_hex':struct.pack('<3Q',TASK_NAME,0x607,self.facility).hex()}},before=before);self.counts['source_kernel_root_membership_scalar_and_status_oracles_checked']+=1;return
  return super().hook(u,a,n,d)
