#!/usr/bin/env python3
"""Original dynamic mk_timer zone -> timer port/member -> service receive.
Source-produced component records, declared raw backing and inherited contracts;
no native startup/kernel/IPC/timer firing or hardware PAC effects.
"""
import json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT
from probe_kernel_zone_startup import Probe as ZoneParent,ARRAY
from probe_kernel_root_port_construct import Probe as Parent,CFProbe as CFParent,PORTZONE,CONTEXT
from probe_kernel_portset_delivery import INSERT_ARGS,TASK_NAME,PS,NODE,NODE2,TABLE
from probe_kernel_request_receive import SPACE
from probe_kernel_vm_mig import P,SIZE,HALT
from probe_rpc502_vm_handoff import compressed
from recover_kernel_portset_delivery import INSERT,LINK,SELECT
from recover_kernel_timer_port_create import P as PREFIX,FLAGS,sha,CREATE,SENDREF,CALLBACK,PUBLICATION
from kernel_vm_mig_tools import Image
TOBJ=P+0xc4000;TKMSG=P+0xc8000;TPORT=P+0xcc000;NODE3=P+0xbf000;KMSGZONE=0xfffffe000caec680
class Startup(ZoneParent):
 def __init__(self,im,s,slot):
  e=s['timer_startup_specification'];super().__init__(im,{'dynamic_timer_zone_slot':slot},s,{**e,'identifier_u16':slot});self.catalog_entry=e;self.image_fixture(0xfffffe000caeb45a,struct.pack('<H',slot),'Declared dynamic-zone next slot; original specification retains identifier65535');self.image_fixture(PUBLICATION,bytes(8),'Original file-value unpublished timer-zone pointer')
 def write(self,u,t,a,n,v,d):
  if PUBLICATION<=a<a+n<=PUBLICATION+8:
   e={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def run(self):
  r=super().run();r.update(requested_identifier=65535,original_timer_specification=self.catalog_entry,publication_pointer8_hex=bytes(self.u.mem_read(PUBLICATION,8)).hex());return r
class Probe(Parent):
 def __init__(self,im,s,c,parent,zones,startup):
  super().__init__(im,s,c,parent,zones);self.timer_frames=[];self.timer_returns=[];self.timer_handoffs=[];self.timer_models=[];self.timer_raw=0;self.timer_zone=int(startup['zone_address'],16)
  self.global_overlay(self.timer_zone,bytes.fromhex(startup['final_zone192_hex']),'Exact source-produced timer dynamic-zone record component');self.global_overlay(PUBLICATION,bytes.fromhex(startup['publication_pointer8_hex']),'Exact original startup timer-zone publication');self.global_overlay(KMSGZONE,bytes.fromhex(zones[0]['final_zone192_hex']),'Exact source-produced kmsg zone24 component');self.global_overlay(TABLE+6*24+12,struct.pack('<I',7),'Declared free entry6 to free entry7');self.global_overlay(TABLE+7*24,struct.pack('<QIIII',0,0,2,0,0),'Declared free entry7 before retained reply entry2');self.overlay(SPACE+0x18,struct.pack('<I',4),'Declared free count4 for set/root/timer/reply')
  meta=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little')
  for a,n,ident in((TOBJ,168,startup['identifier']),(TKMSG,256,24),(TPORT,144,22),(NODE3,48,None)):
   self.overlay(a,bytes(n),'Declared disjoint zeroed timer-related raw storage');self.overlay(a+n,b'\xa5','Declared raw timer-related guard')
   if ident is not None:self.overlay(meta+((a>>10)&0xffffffff0),struct.pack('<H',ident),'Declared timer-related zone-type epoch')
 def timer_frame(self,a):return{'pc':hex(a),**self.cpu(),'phase':self.phase,'timer168_hex':bytes(self.u.mem_read(TOBJ,168)).hex(),'timer_port144_hex':bytes(self.u.mem_read(TPORT,144)).hex(),'timer_kmsg256_hex':bytes(self.u.mem_read(TKMSG,256)).hex(),'entry7_24_hex':bytes(self.u.mem_read(TABLE+168,24)).hex(),'pset56_hex':bytes(self.u.mem_read(PS,56)).hex(),'links144_hex':b''.join(bytes(self.u.mem_read(at,48))for at in(NODE,NODE2,NODE3)).hex()}
 def timer_transition(self,a,args,label,patches=()):
  self.transition(a,args,label,patches);self.timer_handoffs.append(self.stage_handoffs.pop())
 def root_transition(self,a,args,label,patches=()):
  if label=='root_insert_to_service_insert':self.phase='timer_create';return self.timer_transition(CREATE,(),'root_insert_to_timer_create')
  return super().root_transition(a,args,label,patches)
 def timer_model(self,a,name,result):
  e={'pc':hex(a),'before_source_visit_index':len(self.visits),'name':name,'before':self.timer_frame(a),'result':hex(result)};self.model(a,name,result);e['after']=self.timer_frame(self.u.reg_read(A.UC_ARM64_REG_PC));self.timer_models.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a in(CREATE,SENDREF,CALLBACK,LINK,SELECT,0xfffffe000bd133fc,0xfffffe000bd13428,0xfffffe000bd13450):self.timer_frames.append(self.timer_frame(a))
  if a==HALT and self.phase=='timer_create':
   self.timer_returns.append({**self.timer_frame(a),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))});name=self.reg(0);assert name==0x707;self.phase='timer_insert';return self.timer_transition(INSERT,(INSERT_ARGS,),'timer_create_to_timer_insert',[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,name,self.pset_name))])
  if a==HALT and self.phase=='timer_insert':
   self.timer_returns.append({**self.timer_frame(a),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))});assert self.reg(0)==0;self.phase='insert';return self.timer_transition(INSERT,(INSERT_ARGS,),'timer_insert_to_service_insert',[(INSERT_ARGS,struct.pack('<3Q',TASK_NAME,self.receive_name,self.pset_name))])
  if a==0xfffffe000bd75c64 and self.phase=='timer_create':
   zone,stats,flags=[self.reg(j)for j in range(3)];assert stats==P+0xb1000 and flags==0x8004;choices=[(self.timer_zone,TOBJ,168),(KMSGZONE,TKMSG,256),(PORTZONE,TPORT,144)];z,at,n=choices[self.timer_raw];assert zone==z and bytes(u.mem_read(at,n))==bytes(n);self.timer_raw+=1;return self.timer_model(a,'declared_timer_related_raw_storage_'+str(n),at)
  if a==0xfffffe000bcfefc8 and self.link_allocations==2:
   assert self.reg(0)==0xfffffe0007e43358 and self.reg(1)==4 and bytes(u.mem_read(NODE3,48))==bytes(48);self.link_allocations+=1;return self.timer_model(a,'declared_third_raw_membership_link48',NODE3)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(timer_frames=self.timer_frames,timer_returns=self.timer_returns,timer_handoffs=self.timer_handoffs,timer_models=self.timer_models,final_timer168_hex=bytes(self.u.mem_read(TOBJ,168)).hex(),final_timer_port144_hex=bytes(self.u.mem_read(TPORT,144)).hex(),final_timer_kmsg256_hex=bytes(self.u.mem_read(TKMSG,256)).hex(),final_entry7_24_hex=bytes(self.u.mem_read(TABLE+168,24)).hex(),final_service_link48_hex=bytes(self.u.mem_read(NODE3,48)).hex(),timer_zone_address=hex(self.timer_zone),timer_raw_guards_hex=b''.join(bytes(self.u.mem_read(a+n,1))for a,n in((TOBJ,168),(TKMSG,256),(TPORT,144),(NODE3,48))).hex());return r
from recover_cf_mode_construction import MK
from recover_cf_source_scheduling import INSERT_TRAP
class CFProbe(CFParent):
 def hook(self,u,a,n,d):
  self.flush()
  if a==MK:
   ret=self.input['timer_returns'][0];name=int(ret['registers31'][0],16);assert name==0x707;return self.mode_model(a,'original_kernel_timer_create_name_return',name,extra={'timer_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'name':'0x707'}})
  if a==INSERT_TRAP and self.reg(1)==0x707:
   assert[self.reg(j)for j in range(3)]==[TASK_NAME,0x707,self.facility];ret=self.input['timer_returns'][1];status=int(ret['registers31'][0],16);assert status==0;before=self.state();self.members.add((self.facility,0x707));return self.mode_model(a,'original_kernel_timer_member_return',status,extra={'model_state_before':before,'timer_kernel_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'arguments24_hex':struct.pack('<3Q',TASK_NAME,0x707,self.facility).hex()}})
  return super().hook(u,a,n,d)
if __name__=='__main__':
 im=Image();s=json.loads((ROOT/(PREFIX+'_source.json')).read_text());startups=[]
 for slot in(40,41):
  r=Startup(im,s,slot).run();startups.append(r);print('STARTUP',slot,r['boundary']['kind'],len(r['source_visits']),flush=True)
 old=json.loads((ROOT/'kernel_request_delivery_profiles.json').read_text());zones=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'];rows=[]
 for j in range(4):
  r=Probe(im,s,{'producer':j,'capacity':3072,'options':0x07000806},old['loans'][j],zones,startups[0]).run();rows.append(r);print('KERNEL',j,r['boundary']['kind'],len(r['source_visits']),flush=True)
 cf=[]
 for j in range(4):
  cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};r=CFProbe({'kernel_case':j,'mode':'schedule_then_run','repeat':1},rows[j],cs).run();cf.append(r);print('CF',j,r['boundary']['kind'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_request_delivery_profiles.json','kernel_zone_startup_profiles.json','probe_kernel_root_port_construct.py','probe_kernel_zone_startup.py','recover_'+PREFIX+'.py']},'startup_cases':startups,'kernel_cases':rows,'CF_cases':cf,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
