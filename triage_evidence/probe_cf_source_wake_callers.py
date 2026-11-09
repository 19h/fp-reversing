#!/usr/bin/env python3
"""Original source signal, bag-copy/apply and callback-to-wake execution.
Private entry, clock, hash storage and SVC returns are declared. No native
caller attribution, scheduler, CF collections, Mach IPC or hardware PAC proof.
O(V*F + I + R + J) time, O(I + R + J) space: visits V, captured
function count F, captured image I, private RAM R and retained journals J.
"""
import json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,CS
from probe_cf_wake_send_wrapper import Probe as Parent,RETURN,MACH
from probe_cf_runloop_wake_port import CFProbe as WakeBase
from probe_cf_source_scheduling import B,RL,SRC,BAG,HALT
from probe_cf_daemon_request import ALLOC
from recover_cf_source_wake_callers import P,FLAGS,sha,SIGNAL,WAKELOOPS,LOOP,COPY,APPLY,HASHAPPLY,INVOKE,WAKE
COPYBAG=B+0xbf000;SELECTED={SIGNAL,WAKELOOPS,LOOP,COPY,APPLY,HASHAPPLY,INVOKE}
POINTS=SELECTED|{0x184751c90,0x184751c94,0x1847b7a24,0x1847b7a44,0x184794f10,0x184794f14}
def configurations():
 rows=[('signal_only',False,1,1,False,False,False,[]),('signal_twice',False,2,1,False,False,False,[]),('signal_then_wake',True,1,1,False,False,False,[0]),('helper_without_signal',True,0,1,False,False,False,[0]),('suppressed',True,1,1,False,False,False,[]),('invalid_source',True,1,1,True,False,False,[]),('missing_bag',True,1,1,False,True,False,[]),('empty_bag',True,1,0,False,False,False,[]),('copy_null',True,1,1,False,False,True,[]),('duplicate_bag',True,1,2,False,False,False,[0,0x10000004])]
 return[dict(kernel_case=2,mode='schedule_then_run',repeat=1,wake_case='suppressed'if n=='suppressed'else'waiting',send_status=0,label=n,trap_results=t,aux=False,call_helper=h,signal_repeats=r,bag_multiplicity=b,source_invalid=i,missing_bag=m,copy_null=z)for n,h,r,b,i,m,z,t in rows]
class Probe(Parent):
 def __init__(self,c,k,s):
  super().__init__(c,k,s);self.source_frames=[];self.source_returns=[];self.source_fixture=None;self.signal_calls=0;self.clock_calls=0;self.copy_count=0;self.u.mem_write(COPYBAG,bytes(64)+b'\xa5')
 def source_frame(self,a):return{'pc':hex(a),**self.frame('source_wake_stage'),'phase':self.phase,'source256_hex':bytes(self.u.mem_read(SRC,256)).hex(),'copy64_hex':bytes(self.u.mem_read(COPYBAG,64)).hex(),'model_state':self.state()}
 def prepare(self):
  assert self.source_fixture is None and self.collections[BAG]=={RL}and self.bag_counts[RL]==1
  e={'before':self.source_frame(self.u.reg_read(A.UC_ARM64_REG_PC)),'patches':[]};cfg=self.config
  for at,b in((SRC+8,struct.pack('<Q',0 if cfg['source_invalid']else 8)),(SRC+0x60,struct.pack('<Q',0 if cfg['missing_bag']else BAG))):
   e['patches'].append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
  self.collections[BAG]={RL}if cfg['bag_multiplicity']else set();self.bag_counts[RL]=cfg['bag_multiplicity'];e['after']=self.source_frame(self.u.reg_read(A.UC_ARM64_REG_PC));self.source_fixture=e
 def public_call(self,a,args,label):
  if a==WAKE and label in('waiting_receive_to_external_waker_entry','AddSource_to_WakeUp_suppressed'):
   self.prepare();self.phase='signal'if self.config['signal_repeats']else'wake_loops';a=SIGNAL if self.phase=='signal'else WAKELOOPS;args=(SRC,);label='declared_source_entry_from_'+label
  return super().public_call(a,args,label)
 def new_model(self,a):
  x=[self.reg(j)for j in range(9)];before=self.state();value=0;patches=[];name=None
  if a==0x184833380 and x[0]==SRC:name='declared_source_runtime_validate'
  elif a==0x184833694 and x[0]==SRC:name='declared_source_runtime_type46';value=46
  elif a==0x184833260 and x[0]==4 and x[1]==BAG:name='declared_source_bag_nonObjC';value=1
  elif a==0x1847290e4 and x[0]==BAG:name='declared_source_bag_total_count';value=self.config['bag_multiplicity']
  elif a==0x184749a88 and x[0]==BAG:
   assert x[1:3]==[self.config['bag_multiplicity'],0];name='declared_source_bag_elements';patches=[(x[3],struct.pack('<'+'Q'*x[1],*([RL]*x[1])))]if x[1]else[]
  elif a==0x18471aab0:
   assert x[:2]==[ALLOC,0x1e232d698];name='declared_source_copy_hash_storage';value=0 if self.config['copy_null']else COPYBAG
   if value:self.collections[COPYBAG]=set();self.copy_count=0;raw=bytearray(64);raw[0x1a]=1;patches=[(COPYBAG,bytes(raw))]
  elif a==0x1846f3564 and x[0]==COPYBAG:assert x[1]==self.config['bag_multiplicity'];name='declared_source_copy_capacity'
  elif a==0x1846fb960 and x[0]==COPYBAG:
   assert x[1:3]==[RL,RL];name='declared_source_copy_add';self.collections[COPYBAG].add(RL);self.copy_count+=1;patches=[(COPYBAG+0x14,struct.pack('<I',1))]
  elif a==0x1846dc364 and x[:2]==[COPYBAG,4]:name='declared_source_copy_type4'
  elif a==0x18471c584 and x[0]==COPYBAG:
   assert x[1]==0 and self.copy_count in(1,2);name='declared_source_copy_bucket';patches=[(x[8],struct.pack('<4Q',0,RL,RL,self.copy_count))]
  elif a==0x18054808c and self.phase=='signal':self.clock_calls+=1;name='declared_source_signal_clock';value=100*self.clock_calls
  if name:return self.mode_model(a,name,value,patches,{'model_state_before':before,'declared_copy_multiplicity':self.copy_count})or True
  return False
 def hook(self,u,a,n,d):
  self.flush()
  if a==WAKE and self.phase=='wake_loops':self.phase='wakeup'
  if a==0x184794f14:self.phase='wake_loops'
  if a in POINTS:self.source_frames.append(self.source_frame(a))
  if a==HALT and self.phase in('signal','wake_loops'):
   self.source_returns.append(self.source_frame(a))
   if self.phase=='signal':
    self.signal_calls+=1
    if self.signal_calls<self.config['signal_repeats']:return self.public_call(SIGNAL,(SRC,),'repeat_source_signal')
    if self.config['call_helper']:self.phase='wake_loops';return self.public_call(WAKELOOPS,(SRC,),'signal_to_source_wake_helper')
   return self.finish('original_source_wake_contract_returned',a)
  if self.new_model(a):return
  if a==RETURN:
   self.wrapper_returns.append(self.wrapper_frame(a));assert self.si and self.reg(0)==self.config['trap_results'][self.si-1];return WakeBase.hook(self,u,a,n,d)
  if a==MACH and self.phase=='wakeup':
   saved=self.config['trap_results'];self.config['trap_results']=[*saved[:-1],saved[self.si]]
   try:return super().hook(u,a,n,d)
   finally:self.config['trap_results']=saved
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in SELECTED and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4];i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
   return
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();r.update(source_wake_frames=self.source_frames,source_wake_returns=self.source_returns,declared_source_fixture=self.source_fixture,final_copy64_hex=bytes(self.u.mem_read(COPYBAG,64)).hex(),copy_guard_hex=bytes(self.u.mem_read(COPYBAG+64,1)).hex(),declared_copy_multiplicity=self.copy_count,signal_clock_calls=self.clock_calls);return r
if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());prior=json.loads((ROOT/'cf_runloop_wake_port_profiles.json').read_text());cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};rows=[]
 for c in configurations():
  r=Probe(c,prior['kernel_cases'][2],cs).run();rows.append(r);print(c['label'],len(r['source_visits']),len(r['SVC_return_contracts']),r['boundary']['kind'],flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','cf_runloop_wake_port_profiles.json','probe_cf_wake_send_wrapper.py','recover_'+P+'.py']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
