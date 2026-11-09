#!/usr/bin/env python3
"""Independent original timer construction/member/shared-set/CF replay.
No new probe import; recompute raw timer/link contracts and full entry handoffs.
No native timer, IPC, allocator, ownership, scheduler or hardware PAC claims.
"""
import struct
from unicorn import arm64_const as A
from replay_kernel_root_port_construct import Replay as Parent,CFReplay as CFParent
from replay_kernel_portset_delivery import INSERT_ARGS,TASK_NAME,PS,NODE,NODE2,TABLE
from replay_rpc502_vm_handoff import decode,P,SIZE
from recover_kernel_timer_port_create import CREATE
from recover_kernel_portset_delivery import INSERT
HALT=P+0xe0000;TOBJ=P+0xc4000;TKMSG=P+0xc8000;TPORT=P+0xcc000;NODE3=P+0xbf000;PORTZONE=0xfffffe000caec500;KMSGZONE=0xfffffe000caec680
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.tfi=self.tri=self.thi=self.tmi=self.timer_raw=0;self.timer_after=None
 def timer_frame(self,e,a):
  assert e['pc']==hex(a)and e['phase']==self.root_phase;self.cpu(e)
  for at,n,key in((TOBJ,168,'timer168_hex'),(TPORT,144,'timer_port144_hex'),(TKMSG,256,'timer_kmsg256_hex'),(TABLE+168,24,'entry7_24_hex'),(PS,56,'pset56_hex')):assert e[key]==bytes(self.u.mem_read(at,n)).hex()
  assert e['links144_hex']==b''.join(bytes(self.u.mem_read(at,48))for at in(NODE,NODE2,NODE3)).hex();self.counts['timer_objects_namespace_links_and_complete_CPU_frames_checked']+=1
 def code(self,u,a,n,d):
  self.finish()
  if self.timer_after:self.timer_frame(self.timer_after,a);self.timer_after=None
  if self.tfi<len(self.p['timer_frames']):
   e=self.p['timer_frames'][self.tfi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.timer_frame(e,a);self.tfi+=1
  if self.tri<len(self.p['timer_returns']):
   e=self.p['timer_returns'][self.tri]
   if a==HALT and e['source_visit_index']==self.seq:self.timer_frame(e,a);assert decode(e['private_RAM'])==bytes(u.mem_read(P,SIZE));self.tri+=1;self.counts['timer_function_return_whole_RAM_images_checked']+=1
  if self.thi<len(self.p['timer_handoffs']):
   e=self.p['timer_handoffs'][self.thi]
   if a==HALT and e['before']['source_visit_index']==self.seq:
    if self.rri<len(self.p['root_returns']):
     ret=self.p['root_returns'][self.rri]
     if ret['source_visit_index']==self.seq:self.root_frame(ret,a);assert ret['phase']=='root_insert'and decode(ret['private_RAM'])==bytes(u.mem_read(P,SIZE));self.rri+=1;self.counts['root_function_return_whole_RAM_images_checked']+=1
    self.cpu(e['before']);assert decode(e['private_RAM_before'])==bytes(u.mem_read(P,SIZE));kind=e['kind'];patches=[]
    if kind=='root_insert_to_timer_create':assert self.root_phase=='root_insert'and self.reg(0)==0;self.root_phase='timer_create';target=CREATE;args=()
    elif kind=='timer_create_to_timer_insert':assert self.root_phase=='timer_create'and self.reg(0)==0x707;self.root_phase='timer_insert';target=INSERT;args=(INSERT_ARGS,);patches=[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,0x707,0x507))]
    else:assert kind=='timer_insert_to_service_insert'and self.root_phase=='timer_insert'and self.reg(0)==0;self.root_phase='insert';target=INSERT;args=(INSERT_ARGS,);patches=[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,int(self.p['receive_name'],16),0x507))]
    assert len(e['patches'])==len(patches)
    for(at,b),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};u.mem_write(at,b)
    for j,v in enumerate(args):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    u.reg_write(A.UC_ARM64_REG_X30,HALT);u.reg_write(A.UC_ARM64_REG_PC,target);self.cpu(e['after']);assert decode(e['private_RAM_after'])==bytes(u.mem_read(P,SIZE));self.thi+=1;self.counts['timer_create_member_and_service_entry_CPU_RAM_handoffs_checked']+=1;return
  if self.phi<len(self.p['pset_stage_handoffs']):
   e=self.p['pset_stage_handoffs'][self.phi]
   if a==HALT and e['before']['source_visit_index']==self.seq:assert e['kind']=='insert_to_set_receive';self.root_phase='receive'
  if self.tmi<len(self.p['timer_models']):
   e=self.p['timer_models'][self.tmi]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    self.timer_frame(e['before'],a)
    if a==0xfffffe000bd75c64:
     choices=[(int(self.p['timer_zone_address'],16),TOBJ,168),(KMSGZONE,TKMSG,256),(PORTZONE,TPORT,144)];zone,value,size=choices[self.timer_raw];assert self.root_phase=='timer_create'and[self.reg(j)for j in range(3)]==[zone,P+0xb1000,0x8004]and bytes(u.mem_read(value,size))==bytes(size);name='declared_timer_related_raw_storage_'+str(size);self.timer_raw+=1
    else:assert a==0xfffffe000bcfefc8 and self.link_allocations==2 and[self.reg(j)for j in range(2)]==[0xfffffe0007e43358,4]and bytes(u.mem_read(NODE3,48))==bytes(48);value=NODE3;name='declared_third_raw_membership_link48';self.link_allocations+=1
    m=self.models[self.mi];assert e['name']==m['symbol']==name and e['result']==m['return_value']==hex(value);want=[value]+[(((j+1)*0x123456789abcdef)^((self.mi+1)*0x8b3dc651))&((1<<64)-1)for j in range(1,18)];assert m['after_registers31'][:18]==[hex(v)for v in want]and m['after_NZCV']==('0xf0000000'if(self.mi+1)&1 else'0x0');self.timer_after=e['after'];self.tmi+=1;self.counts['timer_raw_allocations_and_third_link_contracts_recomputed']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.tfi==len(self.p['timer_frames'])and self.tri==len(self.p['timer_returns'])and self.thi==len(self.p['timer_handoffs'])and self.tmi==len(self.p['timer_models'])and self.timer_after is None
  for a,n,key in((TOBJ,168,'final_timer168_hex'),(TPORT,144,'final_timer_port144_hex'),(TKMSG,256,'final_timer_kmsg256_hex'),(TABLE+168,24,'final_entry7_24_hex'),(NODE3,48,'final_service_link48_hex')):assert self.p[key]==bytes(self.u.mem_read(a,n)).hex();self.counts['complete_timer_objects_namespace_and_service_link_final_bytes_checked']+=n
  assert self.p['timer_raw_guards_hex']==b''.join(bytes(self.u.mem_read(a+n,1))for a,n in((TOBJ,168),(TKMSG,256),(TPORT,144),(NODE3,48))).hex();return dict(self.counts)

from recover_cf_mode_construction import MK
from recover_cf_source_scheduling import INSERT_TRAP
class CFReplay(CFParent):
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==MK:
   ret=self.origin['timer_returns'][0];name=int(ret['registers31'][0],16);assert name==0x707;self.mode_call(a,'original_kernel_timer_create_name_return',name,extra={'timer_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'name':'0x707'}});self.counts['original_kernel_timer_name_return_contracts_checked']+=1;return
  if a==INSERT_TRAP and self.reg(1)==0x707:
   assert[self.reg(j)for j in range(3)]==[TASK_NAME,0x707,self.facility];ret=self.origin['timer_returns'][1];status=int(ret['registers31'][0],16);assert status==0;before=self.state();self.members.add((self.facility,0x707));self.mode_call(a,'original_kernel_timer_member_return',status,extra={'timer_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'arguments24_hex':struct.pack('<3Q',TASK_NAME,0x707,self.facility).hex()}},before=before);self.counts['original_kernel_timer_membership_return_contracts_checked']+=1;return
  return super().hook(u,a,n,d)

from replay_kernel_zone_startup import Replay as ZoneParent
class StartupReplay(ZoneParent):
 def code(self,u,a,n,d):
  if self.mi<len(self.models)and a==int(self.models[self.mi]['pc'],16):
   e=self.models[self.mi];name=e['symbol'];allowed={0xfffffe000bd71a20:'declared_raw_percpu_statistics_storage',0xfffffe000bd0bfa4:'declared_registry_lock',0xfffffe000bd0c2cc:'declared_registry_unlock',0xfffffe000bd0aab4:'declared_zone_lock',0xfffffe000bd0ab18:'declared_zone_unlock'};assert allowed[a]==name
   if a==0xfffffe000bd71a20:assert[self.reg(j)for j in range(3)]==[0xfffffe000caeb600,32,7];value=P+0xb1000
   else:value=0
   expected=[value]+[(((j+1)*0x123456789abcdef)^((self.mi+1)*0x8b3dc651))&((1<<64)-1)for j in range(1,18)];assert e['return_value']==hex(value)and e['after_registers31'][:18]==[hex(v)for v in expected]and e['after_NZCV']==('0xf0000000'if(self.mi+1)&1 else'0x0');self.counts['dynamic_zone_lower_contracts_recomputed']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();slot=self.p['configuration']['dynamic_timer_zone_slot'];zone=0xfffffe000caeb480+192*slot;assert self.p['requested_identifier']==65535 and self.p['identifier']==slot and self.p['zone_address']==hex(zone)and self.p['publication_pointer8_hex']==struct.pack('<Q',zone).hex()==bytes(self.u.mem_read(0xfffffe0007e64000,8)).hex()and int.from_bytes(bytes(self.u.mem_read(0xfffffe000caeb45a,2)),'little')==slot+1
  e=self.p['original_timer_specification'];assert self.image.k.read(int(e['specification_address'],16),48).hex()==e['specification_bytes48_hex'];self.counts['original_dynamic_timer_zone_specification_publication_and_counter_oracles_checked']+=1;return dict(self.counts)
