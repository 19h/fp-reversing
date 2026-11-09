#!/usr/bin/env python3
"""Original set allocation -> root construct/member -> service member/receive.
Shared private namespace, source zone records; task/raw/copyin and inherited
VM/lock/PAC contracts remain explicit. No native kernel or IPC effects.
"""
import json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT
from probe_kernel_portset_delivery import Probe as Parent,PS,NODE,NODE2,TABLE,INSERT_ARGS,TASK_NAME,NAME_OUT
from probe_kernel_request_receive import TASK,SPACE,RECV
from probe_kernel_vm_mig import P,SIZE,HALT
from probe_rpc502_vm_handoff import compressed
from kernel_vm_mig_tools import Image
from recover_kernel_root_port_construct import P as PREFIX,FLAGS,sha,CONSTRUCT,CORE,ALLOC,INIT,PUBLISH,GUARD,COPYIN
from recover_kernel_portset_delivery import INSERT
RPORT=P+0xbe000;RARGS=P+0xba000;OPTIONS=P+0xba040;ROUT=P+0xba080;CONTEXT=P+0xb6000;PORTZONE=0xfffffe000caec500
POINTS={CONSTRUCT,CORE,ALLOC,INIT,PUBLISH,GUARD,0xfffffe000bce0430,0xfffffe000bce04e8,0xfffffe000bcdbde8,0xfffffe000bcdbe38,0xfffffe000bcdbde4}
class Probe(Parent):
 def __init__(self,im,s,c,parent,zones):
  super().__init__(im,s,c,parent,zones[2]);self.root_frames=[];self.root_returns=[];self.root_handoffs=[];self.root_models=[];self.raw_root_allocations=0
  self.global_overlay(PORTZONE,bytes.fromhex(zones[1]['final_zone192_hex']),'Exact original port zone22 component record only; full bootstrap epoch unknown');self.global_overlay(TABLE+5*24+12,struct.pack('<I',6),'Declared free entry5 to free entry6');self.global_overlay(TABLE+6*24,struct.pack('<QIIII',0,0,2,0,0),'Declared free entry6 before retained reply entry2');self.overlay(SPACE+0x18,struct.pack('<I',3),'Declared free entry count3 for set/root/reply')
  self.overlay(RPORT,bytes(144),'Declared zeroed 144-byte raw port-zone storage');self.overlay(RPORT+144,b'\xa5','Declared raw port guard');meta=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little');self.overlay(meta+((RPORT>>10)&0xffffffff0),struct.pack('<H',22),'Declared raw port zone-type epoch')
  options=bytearray.fromhex(s['root_caller_options']['bytes24_hex']);struct.pack_into('<I',options,0,c.get('root_flags',0x31));self.overlay(OPTIONS,bytes(options),'Original complete caller options, or declared valid flag variation');self.overlay(RARGS,struct.pack('<4Q',TASK_NAME,OPTIONS,CONTEXT,ROUT),'Declared complete four-slot root-construct trap arguments');self.overlay(ROUT,b'\xa5'*4,'Declared root name output observation')
 def root_frame(self,a):return{'pc':hex(a),**self.cpu(),'phase':self.phase,'root144_hex':bytes(self.u.mem_read(RPORT,144)).hex(),'root_name4_hex':bytes(self.u.mem_read(ROUT,4)).hex(),'entry6_24_hex':bytes(self.u.mem_read(TABLE+144,24)).hex(),'pset56_hex':bytes(self.u.mem_read(PS,56)).hex(),'root_link48_hex':bytes(self.u.mem_read(NODE,48)).hex(),'service_link48_hex':bytes(self.u.mem_read(NODE2,48)).hex()}
 def root_transition(self,a,args,label,patches=()):
  before=len(self.stage_handoffs);self.transition(a,args,label,patches);assert len(self.stage_handoffs)==before+1;self.root_handoffs.append(self.stage_handoffs.pop())
 def root_model(self,a,name,result,patches=()):
  e={'pc':hex(a),'before_source_visit_index':len(self.visits),'name':name,'before':self.root_frame(a),'patches':[]}
  for at,b in patches:e['patches'].append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
  self.model(a,name,result);e['result']=hex(result);e['after']=self.root_frame(self.u.reg_read(A.UC_ARM64_REG_PC));self.root_models.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a in POINTS:self.root_frames.append(self.root_frame(a))
  if a==HALT and self.phase=='allocate':
   self.stage_returns.append({'phase':'allocate',**self.pset_frame(a),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))});assert self.reg(0)==0;self.pset_name=int.from_bytes(bytes(u.mem_read(NAME_OUT,4)),'little');self.phase='root_construct';return self.root_transition(CONSTRUCT,(RARGS,),'allocate_to_root_construct')
  if a==HALT and self.phase=='root_construct':
   self.root_returns.append({**self.root_frame(a),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))})
   if self.c.get('copyin_error'):assert self.reg(0)==10;return self.stop('original_root_construct_error_returned')
   assert self.reg(0)==0;name=int.from_bytes(bytes(u.mem_read(ROUT,4)),'little');self.phase='root_insert';return self.root_transition(INSERT,(INSERT_ARGS,),'root_construct_to_root_insert',[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,name,self.pset_name))])
  if a==HALT and self.phase=='root_insert':
   self.root_returns.append({**self.root_frame(a),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))});assert self.reg(0)==0;self.phase='insert';self.insert_calls=1;return self.root_transition(INSERT,(INSERT_ARGS,),'root_insert_to_service_insert',[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,self.receive_name,self.pset_name))])
  if a==COPYIN:
   assert self.phase=='root_construct'and self.reg(0)==OPTIONS and self.reg(2)==24;result=1 if self.c.get('copyin_error')else 0;return self.root_model(a,'declared_exact_options24_user_copyin',result,[]if result else[(self.reg(1),bytes(u.mem_read(OPTIONS,24)))])
  if a==0xfffffe000bd75c64 and self.phase=='root_construct':assert self.reg(0)==PORTZONE and self.reg(1)==P+0xb1000 and self.reg(2)==0x8004 and bytes(u.mem_read(RPORT,144))==bytes(144);self.raw_root_allocations+=1;return self.root_model(a,'declared_zeroed_raw_port144_storage',RPORT)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(root_frames=self.root_frames,root_returns=self.root_returns,root_handoffs=self.root_handoffs,root_models=self.root_models,final_root144_hex=bytes(self.u.mem_read(RPORT,144)).hex(),final_root_name4_hex=bytes(self.u.mem_read(ROUT,4)).hex(),final_entry6_24_hex=bytes(self.u.mem_read(TABLE+144,24)).hex(),raw_root_guard_hex=bytes(self.u.mem_read(RPORT+144,1)).hex());return r
from probe_cf_mode_construction import Probe as CFParent,QUEUE
from recover_cf_mode_construction import CONSTRUCT_TRAP
from recover_cf_source_scheduling import INSERT_TRAP
class CFProbe(CFParent):
 def hook(self,u,a,n,d):
  self.flush()
  if a==CONSTRUCT_TRAP:
   x=[self.reg(j)for j in range(4)];assert x[0]==TASK_NAME and x[2]==QUEUE;options=bytes(u.mem_read(x[1],24));assert options==bytes.fromhex(self.source['root_caller_options']['bytes24_hex']);ret=self.input['root_returns'][0];result=int(ret['registers31'][0],16);assert result==0;name=bytes.fromhex(ret['root_name4_hex']);assert name==struct.pack('<I',0x607);return self.mode_model(a,'original_kernel_root_construct_return',result,[(x[3],name)],{'original_options24_hex':options.hex(),'root_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'context':hex(QUEUE),'name':'0x607'}})
  if a==INSERT_TRAP and self.reg(1)==0x607:
   assert[self.reg(j)for j in range(3)]==[TASK_NAME,0x607,self.facility];ret=self.input['root_returns'][1];result=int(ret['registers31'][0],16);assert result==0;before=self.state();self.members.add((self.facility,0x607));return self.mode_model(a,'original_kernel_root_member_return',result,extra={'model_state_before':before,'root_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'arguments24_hex':struct.pack('<3Q',TASK_NAME,0x607,self.facility).hex()}})
  return super().hook(u,a,n,d)
if __name__=='__main__':
 im=Image();s=json.loads((ROOT/(PREFIX+'_source.json')).read_text());old=json.loads((ROOT/'kernel_request_delivery_profiles.json').read_text());zones=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'];rows=[]
 configs=[{'producer':j,'capacity':3072,'options':0x07000806}for j in range(4)]+[{'producer':2,'capacity':3072,'options':0x07000806,'root_flags':0x11},{'producer':2,'capacity':3072,'options':0x07000806,'copyin_error':True}]
 for c in configs:
  r=Probe(im,s,c,old['loans'][c['producer']],zones).run();rows.append(r);print(c,r['boundary']['kind'],r['boundary']['pc'],r['final_root_name4_hex'],len(r['source_visits']),flush=True)
 cf=[]
 for j in range(4):
  cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};r=CFProbe({'kernel_case':j,'mode':'schedule_then_run','repeat':1},rows[j],cs).run();cf.append(r);print('CF',j,r['boundary']['kind'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_request_delivery_profiles.json','kernel_zone_startup_profiles.json','probe_kernel_portset_delivery.py','recover_'+PREFIX+'.py']},'kernel_cases':rows,'CF_cases':cf,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
