#!/usr/bin/env python3
"""Original port-set allocation -> membership/ready-ring -> set receive/copyout.
Whole original queued state is retained. Task conversion, raw storage and prior
VM/retirement/lock/PAC contracts are explicit; no native kernel or IPC effects.
O(image+visits+RAM+journals) time/space. Function-entry handoffs only.
"""
import json,struct
from unicorn import arm64_const as A
from probe_kernel_request_delivery import Probe as Parent,USER,OOL
from probe_kernel_request_receive import RECV,TASK,SPACE,TABLE,PSP,FRONT,RESULTS
from probe_kernel_vm_mig import P,SIZE,HALT
from probe_rpc502_vm_handoff import compressed
from kernel_vm_mig_tools import Image
from daemon_receive_tools import ROOT
from recover_kernel_portset_delivery import P as PREFIX,ALLOC,INSERT,PSET_CREATE,LINK,READY,SELECT,FLAGS,sha
PS=P+0xb8000;NODE=P+0xbc000;NODE2=P+0xbd000;ALLOC_ARGS=P+0xb9000;INSERT_ARGS=P+0xb9040;NAME_OUT=P+0xb9080;PSZONE=0xfffffe000caec5c0;TASK_NAME=0x103
WAITQ_LOCK=0xfffffe000cbca62c
WAITQ_HEAD=0xfffffe000cbca630
POINTS={ALLOC,PSET_CREATE,INSERT,0xfffffe000bcdfec8,0xfffffe000bcc936c,0xfffffe000bcc78a8,LINK,READY,SELECT,0xfffffe000bcc8560,0xfffffe000bcc857c,0xfffffe000bcc8758}
class Probe(Parent):
 def __init__(self,im,src,c,parent,zone):
  super().__init__(im,src,c,parent);self.phase='allocate';self.stage_returns=[];self.stage_handoffs=[];self.pset_frames=[];self.pset_models=[];self.link_allocations=0;self.insert_calls=0;self.pset_name=None;self.second_receive=False
  for a,n in((PS,56),(NODE,48),(NODE2,48)):assert bytes(self.u.mem_read(a,n))==bytes(n);self.overlay(a,bytes(n),'Declared disjoint zeroed raw allocation storage');self.overlay(a+n,b'\xa5','Declared raw-storage guard')
  self.overlay(ALLOC_ARGS,struct.pack('<3Q',TASK_NAME,3,NAME_OUT),'Declared complete allocation trap argument record');self.overlay(INSERT_ARGS,b'\xa5'*24,'Declared unused membership argument record');self.overlay(NAME_OUT,b'\xa5'*4,'Declared name output observation')
  self.global_overlay(PSZONE,bytes.fromhex(zone['final_zone192_hex']),'Exact source-produced fixed psets zone record only; remaining boot epoch not transferred');meta=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little');self.overlay(meta+((PS>>10)&0xffffffff0),struct.pack('<H',23),'Declared raw pset zone-type epoch')
  self.global_overlay(TABLE+12,struct.pack('<I',5),'Declared free-list head5, retaining free entry2 for reply publication');self.global_overlay(TABLE+5*24,struct.pack('<QIIII',0,0,2,0,0),'Declared free entry5 links to original free entry2');self.overlay(SPACE+0x18,struct.pack('<I',2),'Declared free-entry count2')
  self.global_overlay(WAITQ_LOCK,self.image.k.read(WAITQ_LOCK,4),'Original file-value shared waitq lock word; effective native epoch unknown')
  self.global_overlay(WAITQ_HEAD,self.image.k.read(WAITQ_HEAD,8),'Original file-value empty hashed-waitq queue head; native initialization unknown')
  for j in range(31):self.set(j,0)
  self.set(0,ALLOC_ARGS);self.set(30,HALT);self.entry=ALLOC;self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(A.UC_ARM64_REG_NZCV));self.entryQ=[hex(self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
 def cpu(self):return{'source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.u.reg_read(A.UC_ARM64_REG_SP)),'NZCV':hex(self.u.reg_read(A.UC_ARM64_REG_NZCV)),'Q_registers32':[hex(self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]}
 def write(self,u,t,a,n,v,d):
  if WAITQ_LOCK<=a<a+n<=WAITQ_LOCK+4 or WAITQ_HEAD<=a<a+n<=WAITQ_HEAD+8:e={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def pset_frame(self,a):
  return{'pc':hex(a),**self.cpu(),'pset56_hex':bytes(self.u.mem_read(PS,56)).hex(),'node48_hex':bytes(self.u.mem_read(NODE,48)).hex(),'node2_48_hex':bytes(self.u.mem_read(NODE2,48)).hex(),'service144_hex':bytes(self.u.mem_read(self.destination,144)).hex(),'entry5_24_hex':bytes(self.u.mem_read(TABLE+120,24)).hex(),'user148_hex':bytes(self.u.mem_read(USER,148)).hex()}
 def transition(self,a,args,label,patches=()):
  e={'kind':label,'before':self.cpu(),'private_RAM_before':compressed(bytes(self.u.mem_read(P,SIZE))),'patches':[]};self.stage_handoffs.append(e)
  for at,b in patches:e['patches'].append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
  for j,v in enumerate(args):self.set(j,v)
  self.set(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,a);e['after']=self.cpu();e['private_RAM_after']=compressed(bytes(self.u.mem_read(P,SIZE)))
 def declared(self,a,symbol,result):
  e={'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'result':hex(result),'pset56_hex':bytes(self.u.mem_read(PS,56)).hex(),'node48_hex':bytes(self.u.mem_read(NODE,48)).hex(),'node2_48_hex':bytes(self.u.mem_read(NODE2,48)).hex()};self.pset_models.append(e);return self.model(a,symbol,result)
 def code(self,u,a,n,d):
  self.flush()
  if a in POINTS:self.pset_frames.append(self.pset_frame(a))
  if a==HALT and self.phase=='receive'and self.c.get('receive_twice')and not self.second_receive:
   assert self.reg(0)==0;self.stage_returns.append({'phase':'first_receive',**self.pset_frame(a),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))});self.second_receive=True;return self.transition(FRONT,(USER,0,self.c['options'],0,0,self.c['capacity'],0,self.pset_name),'second_set_receive')
  if a==HALT and self.phase!='receive':
   self.stage_returns.append({'phase':self.phase,**self.pset_frame(a),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))})
   if self.phase=='allocate':
    assert self.reg(0)==0;self.pset_name=int.from_bytes(bytes(u.mem_read(NAME_OUT,4)),'little');self.phase='insert';self.insert_calls=1;return self.transition(INSERT,(INSERT_ARGS,),'allocate_to_insert',[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,self.receive_name,self.pset_name))])
   if self.c.get('repeat_insert')and self.insert_calls<2:self.insert_calls+=1;return self.transition(INSERT,(INSERT_ARGS,),'repeat_insert')
   if self.c.get('stop_after_insert'):return self.stop('original_membership_repeat_returned')
   assert self.reg(0)==0;self.phase='receive';return self.transition(FRONT,(USER,0,self.c['options'],0,0,self.c['capacity'],0,self.pset_name),'insert_to_set_receive')
  if a==0xfffffe000bcfb4f0:assert self.reg(0)==TASK_NAME and self.reg(1)==0;return self.declared(a,'declared_task_name_to_receiver_task',TASK)
  if a==0xfffffe000bd75c64 and self.phase=='allocate':assert self.reg(0)==PSZONE and self.reg(1)==P+0xb1000 and self.reg(2)==0x8004;return self.declared(a,'declared_zeroed_raw_pset56_storage',PS)
  if a==0xfffffe000bcfefc8:
   assert self.reg(0)==0xfffffe0007e43358 and self.reg(1)==4;at=NODE if self.link_allocations==0 else NODE2;assert bytes(u.mem_read(at,48))==bytes(48);self.link_allocations+=1;return self.declared(a,'declared_zeroed_raw_waitq_link48_storage',at)
  if a==0xfffffe000bd7a4b8:assert self.reg(0)==0xfffffe0007e43358 and self.reg(1)==NODE2;return self.declared(a,'declared_unused_raw_link_retirement',0)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(pset_frames=self.pset_frames,pset_stage_returns=self.stage_returns,pset_stage_handoffs=self.stage_handoffs,pset_lower_models=self.pset_models,receive_facility_name=hex(self.pset_name),final_pset56_hex=bytes(self.u.mem_read(PS,56)).hex(),final_link48_hex=bytes(self.u.mem_read(NODE,48)).hex(),final_unused_link48_hex=bytes(self.u.mem_read(NODE2,48)).hex(),final_entry5_24_hex=bytes(self.u.mem_read(TABLE+120,24)).hex(),raw_pset_guard_hex=bytes(self.u.mem_read(PS+56,1)).hex(),raw_link_guard_hex=bytes(self.u.mem_read(NODE+48,1)).hex(),raw_unused_link_guard_hex=bytes(self.u.mem_read(NODE2+48,1)).hex());return r
from probe_cf_source_scheduling import Probe as CFParent,MODE as CF_MODE,USER as CF_USER,OOL as CF_OOL
from recover_cf_source_scheduling import INSERT_TRAP as CF_INSERT
from recover_cf_receive_voucher import MACH
class CFProbe(CFParent):
 def __init__(self,j,k,s):
  c={'kernel_case':j,'mode':'schedule_then_run','insert_status':0,'repeat':1,'valid':True,'zero_port':False};super().__init__(c,k,s);self.facility=int(k['receive_facility_name'],16);self.u.mem_write(CF_MODE+0x88,struct.pack('<I',self.facility));self.kernel_index=j
 def hook(self,u,a,n,d):
  self.flush()
  if a==CF_INSERT:
   state=self.state();assert[self.reg(j)for j in range(3)]==[TASK_NAME,self.port,self.facility];ret=next(e for e in self.input['pset_stage_returns']if e['phase']=='insert');result=int(ret['registers31'][0],16);assert result==0;self.members.add((self.facility,self.port));self.runtime_model(a,'original_kernel_member_return_contract',result);e=self.events[-1];e['model_state_before']=state;e['model_state_after']=self.state();e['kernel_oracle']={'case':self.kernel_index,'return_source_visit_index':ret['source_visit_index'],'arguments24_hex':struct.pack('<3Q',TASK_NAME,self.port,self.facility).hex()};self.schedule_models.append(e);return
  if a==MACH:
   assert[self.reg(j)for j in range(7)]==[CF_USER,0x07000806,0,3072,self.facility,0xffffffff,0]and(self.facility,self.port)in self.members;self.kernel_transfers.append(self.run_frame(a));result=int(self.input['boundary']['registers31'][0],16);assert result==0;self.runtime_model(a,'original_portset_receive_return_contract',result,[(CF_USER,bytes.fromhex(self.input['final_user8192_hex'])[:148]),(CF_OOL,bytes.fromhex(self.input['final_OOL16384_hex'])[:29])]);self.events[-1]['kernel_oracle']={'case':self.kernel_index,'return_PC':self.input['boundary']['pc']};return
  return super().hook(u,a,n,d)
 def run(self):r=super().run();r['receive_facility_name']=hex(self.facility);return r
if __name__=='__main__':
 s=json.loads((ROOT/(PREFIX+'_source.json')).read_text());old=json.loads((ROOT/'kernel_request_delivery_profiles.json').read_text());zone=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'][2];im=Image();rows=[]
 configs=[{'producer':j,'capacity':3072,'options':0x07000806}for j in range(4)]+[{'producer':j,'capacity':147,'options':0x07000806,'stop_at_results':True}for j in(0,2)]+[{'producer':0,'capacity':3072,'options':0x07000806,'repeat_insert':True,'stop_after_insert':True},{'producer':0,'capacity':3072,'options':0x07000806,'receive_twice':True}]
 for c in configs:
  r=Probe(im,s,c,old['loans'][c['producer']],zone).run();rows.append(r);print(c,r['boundary']['kind'],r['boundary']['pc'],r['receive_facility_name'],len(r['source_visits']),flush=True)
 cf=[]
 for j in range(4):
  r=CFProbe(j,rows[j],s['CF_source']).run();cf.append(r);print('CF',j,r['boundary']['kind'],r['receive_facility_name'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_request_delivery_profiles.json','kernel_zone_startup_profiles.json','probe_kernel_request_delivery.py','probe_cf_source_scheduling.py','recover_'+PREFIX+'.py']},'kernel_cases':rows,'CF_cases':cf,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
