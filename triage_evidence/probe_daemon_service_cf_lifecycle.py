#!/usr/bin/env python3
"""Original check-in -> CF Mach source1 -> stored service -> signal invalidation.
One private epoch alongside original descriptor/source0/public RUN/callback.
Explicit entry joins, bootstrap/CF runtime/hash/retention/locks/Mach/PAC models;
no native startup, IPC, retirement or successful FairPlay transaction.
O(V*F+J+H*R), O(S+J+R).
"""
import json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,IMAGE,CS
from probe_daemon_cf_descriptor_bridge import Probe as Parent,FDO,B,RL,MODE,SRC,SET0,SET1,BAG,HALT,HEADER,CALLBACK
from probe_cf_runloop_handoff import DICT
from recover_daemon_service_cf_lifecycle import P,FLAGS,sha,FUNCS,CHECKIN,TYPE_TRAP,EXTRACT_TRAP
from recover_cf_source_scheduling import INSERT_TRAP
SOBJ=B+0xe1000;SSRC=B+0xe2000;SARG=B+0xe3000;SNAME=B+0xe3100;SBAG=B+0xe4000;ARRAY=B+0xe5000;SERVICE_SP=B+0x60000;SERVICE_RETURN=HALT+0x500;BOOTSTRAP=0x1703
class Probe(Parent):
 def __init__(self,c,k,s):
  super().__init__(c,k,s);self.service_done=False;self.service_active=False;self.service_saved=None;self.service_initial=[];self.service_entries=[];self.service_frames=[];self.service_models=[];self.service_registry=[];self.service_mutations=[];self.service_callback_returns=[];self.service_before_callbacks=[];self.service_name=c.get('service_name',0xe03);self.service_constructor_started=False;self.collections[SBAG]=set()
  raw=struct.pack('<QQQQII',HEADER+0x18,SNAME,0,0,(0x2e4c-0x316f29c1*((SARG&0xffffffff)^0x987eac8a))&0xffffffff,0)+b'\xa5'
  for a,b in[(SARG,raw),(SNAME,b'com.apple.unfreed\0\xa5'),(SOBJ,bytes(128)+b'\xa5'),(SSRC,bytes(184)+b'\xa5'),(SBAG,bytes(64)+b'\xa5'),(ARRAY,bytes(64)+b'\xa5'),(0x1ed890e90,struct.pack('<Q',ARRAY)),(0x1ed891742,b'\x02'),(self.import_addresses['libSystem/_bootstrap_port'],struct.pack('<Q',BOOTSTRAP))]:self.service_fixture(a,b)
  self.service_fixture(SBAG+0x12,struct.pack('<H',1))
 def service_fixture(self,a,b):self.service_initial.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
 def service_frame(self,a):return{'pc':hex(a),**self.frame('service_CF_lifecycle'),'daemon_phase':self.daemon_phase,'service_active':self.service_active,'header96_hex':bytes(self.u.mem_read(HEADER,96)).hex(),'record40_hex':bytes(self.u.mem_read(SARG,40)).hex(),'object128_hex':bytes(self.u.mem_read(SOBJ,128)).hex(),'service_source184_hex':bytes(self.u.mem_read(SSRC,184)).hex(),'service_bag64_hex':bytes(self.u.mem_read(SBAG,64)).hex(),'registry':[hex(v)for v in self.service_registry],'model_state':self.state()}
 def start_setup(self):
  if self.service_done:return super().start_setup()
  self.service_saved=self.bf(HALT);self.service_active=True;self.daemon_phase='service_registration';self.stage='service_registration';self.setreg(0,SARG);self.setreg(1,SARG+0x80);self.setreg(30,SERVICE_RETURN);self.u.reg_write(A.UC_ARM64_REG_SP,SERVICE_SP);self.u.reg_write(A.UC_ARM64_REG_PC,CHECKIN);self.service_entries.append({'kind':'declared_original_checkin_helper_entry','before':self.service_saved,'entry':self.service_frame(CHECKIN)})
 def daemon_model(self,a,name):
  if name!='libSystem/_bootstrap_check_in':return super().daemon_model(a,name)
  assert self.service_active and self.daemon_phase=='service_registration';x=[self.reg(j)for j in range(8)];assert x[:2]==[BOOTSTRAP,SNAME]and bytes(self.u.mem_read(SNAME,18)).split(b'\0')[0]==b'com.apple.unfreed';status=self.config.get('bootstrap_status',0);before=self.service_frame(a);patch=[]if status else[(x[2],struct.pack('<I',self.service_name))];self.mode_model(a,'declared_bootstrap_check_in_return',status,patch,{'service_before':before,'arguments8':[hex(v)for v in x]});self.service_models.append(self.events[-1])
 def service_lower(self,a):
  if a not in{0x1846da4dc,0x184833380,0x184833694,0x184833260,0x1846f5978,0x1846f7424,0x1846f5c74,0x18472ef50,0x18471aa50,0x1846fb960,0x1846dcd84,0x1846dc364,0x18471c584,0x1847170cc,TYPE_TRAP,INSERT_TRAP,EXTRACT_TRAP,0x18476f510,0x1880770a0}:return False
  x=[self.reg(j)for j in range(9)];name=None;value=0;patch=[];extra={};before=self.service_frame(a)
  if a==0x1846da4dc and x[1]==36:
   assert x[:4]==[0,36,112,0];name='declared_service_CF_runtime_type36';value=0 if self.config.get('service_object_null')else SOBJ
   if value:raw=bytearray(128);struct.pack_into('<Q',raw,8,36<<8);patch=[(SOBJ,bytes(raw))]
  elif a==0x1846da4dc and x[1]==46 and self.service_active:
   assert x[:4]==[0,46,168,0];name='declared_service_source1_runtime_type46';value=0 if self.config.get('service_source_null')else SSRC
   if value:raw=bytearray(184);struct.pack_into('<Q',raw,8,46<<8);patch=[(SSRC,bytes(raw))]
  elif a in(0x184833380,0x184833694)and x[0]in(SOBJ,SSRC):name='declared_service_CF_info_or_type';value=(36 if x[0]==SOBJ else 46)if a==0x184833694 else 0
  elif a==0x184833260 and x[1]in(SOBJ,SSRC):assert x[0]==(36 if x[1]==SOBJ else 46);name='declared_service_non_ObjC'
  elif a==0x1846f5978 and x[0]==ARRAY:name='declared_service_registry_count';value=len(self.service_registry)
  elif a==0x1846f7424 and x[0]==ARRAY:assert x[1]<len(self.service_registry);name='declared_service_registry_value';value=self.service_registry[x[1]]
  elif a==0x1846f5c74 and x[:2]==[ARRAY,SOBJ]:name='declared_service_registry_append';self.service_registry.append(SOBJ)
  elif a==0x18472ef50 and x[0]==ARRAY:assert x[1]<len(self.service_registry);name='declared_service_registry_remove';self.service_registry.pop(x[1])
  elif a==0x18471aa50 and self.service_active:
   assert x[1:3]==[0,0x1e232d698];name='declared_service_source_bag_storage';value=SBAG
  elif a==0x1846fb960 and x[0]in(SET1,SBAG):
   assert x[1]==x[2]and(x[0],x[1])in[(SET1,SSRC),(SBAG,RL)];name='declared_service_source1_hash_add';self.collections[x[0]].add(x[1]);patch=[(x[0]+0x14,struct.pack('<I',len(self.collections[x[0]]))),(x[0]+0x1a,b'\x01')]
  elif a==0x1846dcd84 and x[0]==DICT and x[1]==self.service_name:
   assert x[2]==SSRC;name='declared_service_port_dictionary_set';self.dictionary[x[1]]=x[2];patch=[(DICT+0x14,struct.pack('<I',len(self.dictionary)))]
  elif a==0x1846dc364 and x[:2]==[SBAG,4]:name='declared_service_bag_type4'
  elif a==0x18471c584 and x[0]==SBAG:
   assert x[1]==0 and self.collections[SBAG]=={RL};name='declared_service_bag_bucket';patch=[(x[8],struct.pack('<4Q',0,RL,RL,1))]
  elif a==0x1847170cc and(x[0]==DICT and x[1]==self.service_name or x[0]in(SET0,SET1)and x[1]==SSRC or x[0]==SBAG and x[1]==RL):
   name='declared_service_hash_remove'
   if x[0]==DICT:value=int(x[1]in self.dictionary);self.dictionary.pop(x[1],None);count=len(self.dictionary)
   else:value=int(x[1]in self.collections[x[0]]);self.collections[x[0]].discard(x[1]);count=len(self.collections[x[0]])
   patch=[(x[0]+0x14,struct.pack('<I',count))];self.service_mutations.append({'kind':'hash_remove','container':hex(x[0]),'key':hex(x[1]),'removed':bool(value),'visit':len(self.visits)})
  elif a==TYPE_TRAP and x[1]==self.service_name:
   assert x[0]==0x103;name='declared_service_name_receive_type';patch=[(x[2],struct.pack('<I',0x20000))]
  elif a==INSERT_TRAP and x[1]==self.service_name:
   assert x[:3]==[0x103,self.service_name,self.facility];name='declared_service_insert_member';value=self.config.get('service_insert_status',0)
   if not value:self.members.add((self.facility,self.service_name))
   self.service_mutations.append({'kind':'insert_member','name':hex(x[1]),'facility':hex(x[2]),'status':value,'visit':len(self.visits)})
  elif a==EXTRACT_TRAP:
   assert x[:3]==[0x103,self.service_name,self.facility];name='declared_service_extract_member';value=self.config.get('service_extract_status',0)
   if not value:self.members.discard((self.facility,self.service_name))
   self.service_mutations.append({'kind':'extract_member','name':hex(x[1]),'facility':hex(x[2]),'status':value,'visit':len(self.visits)})
  elif a==0x18476f510 and self.service_active:name='declared_service_log_object';value=ARRAY+0x100
  elif a==0x1880770a0 and self.service_active:name='declared_service_log_disabled'
  if name:
   self.mode_model(a,name,value,patch,{'model_state_before':before['model_state'],'service_before':before,'arguments8':[hex(v)for v in x[:8]],**extra});self.events[-1]['service_after']=self.service_frame(self.u.reg_read(A.UC_ARM64_REG_PC));self.service_models.append(self.events[-1]);return True
  return False
 def hook(self,u,a,n,d):
  self.flush()
  if a==SERVICE_RETURN:
   e=self.service_entries[0];e['returned']=self.service_frame(a);self.restore(self.service_saved);self.daemon_phase=None;self.service_active=False;self.service_done=True;self.phase='create';e['resume']=self.service_frame(HALT);return super().start_setup()
  if a==CALLBACK and self.active_callback is None:
   assert self.reg(0)==FDO;self.service_before_callbacks.append(self.service_frame(a));self.daemon_phase='callback';e={'entry_before':self.bf(a),'return_pc':hex(self.reg(30)),'patches':[]};self.callbacks.append(e);self.active_callback=e;e['entry_after']=self.bf(a)
  if self.active_callback and a==int(self.active_callback['return_pc'],16):self.service_callback_returns.append(self.service_frame(a))
  if a in FUNCS|{CHECKIN,0x100315354,0x1001f4d0c}or a==0x18472d31c and self.service_active:
   f=self.service_frame(a)
   if a==0x18472cfe8 and self.service_active:f['public_context40_hex']=bytes(u.mem_read(self.reg(3),40)).hex()
   if a==0x18472d31c and self.service_active:f['source1_input_context72_hex']=bytes(u.mem_read(self.reg(2),72)).hex()
   self.service_frames.append(f)
  if self.service_lower(a):return
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in FUNCS and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));off=a-int(f['start'],16);assert raw==bytes.fromhex(f['bytes'])[off:off+4];i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});op=i.mnemonic
   if op in('pacibsp','paciasp','autibsp','autiasp','paciza','pacia','pacda','autia','autiza','autda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op in('retab','retaa'):u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
   return
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();assert self.service_done;r.update(service_initial=self.service_initial,service_component_entries=self.service_entries,service_frames=self.service_frames,service_lower_models=self.service_models,service_state_mutations=self.service_mutations,service_before_original_callbacks=self.service_before_callbacks,service_original_callback_returns=self.service_callback_returns,final_service=self.service_frame(self.u.reg_read(A.UC_ARM64_REG_PC)));return r
def configs():
 for label,more in[('registered_signal15',{}),('registered_other_signal',{'ident':2}),('bootstrap_failure',{'bootstrap_status':1102}),('source_creation_failure',{'service_source_null':True}),('CF_object_failure',{'service_object_null':True}),('member_insert_failure',{'service_insert_status':4,'service_extract_status':4}),('member_extract_failure',{'service_extract_status':5}),('high_service_name',{'service_name':0x80000e03})]:
  yield{'kernel_case':2,'mode':'schedule_then_run','repeat':1,'wake_case':'waiting','send_status':0,'aux':False,'trap_results':[]if label=='registered_other_signal'else[0],'label':label,'events':[],'bag_multiplicity':1,'copy_null':False,'enable_ready':True,'perform_ready':True,'entry':'specific'if label=='registered_other_signal'else'run','callback_stop':False,**more}
def inputs():
 s=json.loads((ROOT/(P+'_source.json')).read_text());k=json.loads((ROOT/'cf_runloop_wake_port_profiles.json').read_text())['kernel_cases'][2];binds=[{'slot':e['binding']['slot'],'target':hex(e['captured_CF_export']['address'])}for e in s['daemon_to_CF_bindings']];return s,k,{**s['CF_source'],'root_caller_options':s['root_caller_options'],'bridge_bindings':binds}
if __name__=='__main__':
 s,k,cs=inputs();rows=[]
 for c in configs():
  try:r=Probe(c,k,cs).run()
  except Exception as e:print('FAILED',c['label'],type(e).__name__,str(e),flush=True);raise
  rows.append(r);print(c['label'],len(r['source_visits']),r['boundary']['kind'],r['final_service']['registry'],r['final_service']['model_state']['members'],flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','recover_'+P+'.py','probe_daemon_cf_descriptor_bridge.py','cf_runloop_wake_port_profiles.json']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
