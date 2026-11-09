#!/usr/bin/env python3
"""Original mode miss/create/publish -> AddSource -> original run-loop consumer.
Raw CF/dispatch storage, strings, locks, timer/control ports and collections are
declared; pset allocation/service delivery use original-kernel return oracles.
O(image+visits+RAM+journals) time/space. No native APIs or hardware PAC execute.
"""
import json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,CS
from probe_kernel_portset_delivery import CFProbe as Parent
from probe_cf_source_scheduling import B,USER,MODE,RL,SRC,SET0,SET1,DICT,NAME,HALT
from recover_cf_mode_construction import P,FLAGS,sha,COPYMODE,SETGET,ROOTCREATE,ROOTINIT,ROOTGET,CALLBACK,FORK,ALLOC_TRAP,CONSTRUCT_TRAP,MK,BOUNDARIES
from recover_cf_source_scheduling import INSERT_TRAP
REGISTRY=B+0xb4000;QUEUE=B+0xb6000;TLS=B+0xb7000;TIMER_SOURCE=B+0xb8000;BLOCK=B+0xb9000;BYREF=B+0xb9100;ROOT_PORT=0x607;TIMER_PORT=0x707;WAKE_PORT=0x807
NEWFUNCS={COPYMODE,SETGET,CALLBACK,ROOTCREATE,ROOTINIT,ROOTGET,0x185549410,FORK,0x180549ee0,0x180548e9c,MK}
FATALS={0x1848d3ee4:'portset_allocation',0x1848d4020:'root_port_zero',0x1848d3fd0:'root_member',0x1848d400c:'timer_port_zero',0x1848d3fe4:'timer_member',0x1848d3ff8:'wake_port_or_member',0x185522f38:'fork_flag_bit1'}
MODE_POINTS={COPYMODE,0x184831790,0x1848317f8,0x184831858,0x184831868,0x184831884,0x184831888,0x184831940,0x18483194c,0x184831960,0x184831978,0x184831980,ROOTCREATE,ROOTINIT,ROOTGET,CALLBACK,CALLBACK+0x10}
def configurations():
 out=[{'kernel_case':j,'mode':'schedule_then_run','repeat':1}for j in range(4)]
 out+=[{'kernel_case':2,'mode':name,'repeat':rep}for name,rep in[('repeat_mode',2),('no_create',1),('runtime_null',1),('pset_error',1),('root_member_error',1),('timer_member_error',1),('wake_member_error',1),('timer_zero',1),('timer_callback',1),('fork_flag2',1)]]
 out.append({'kernel_case':2,'mode':'schedule_then_run','repeat':1,'tls_priority_word':0x1501})
 return out
class Probe(Parent):
 def __init__(self,c,k,s):
  super().__init__(c['kernel_case'],k,s);self.config={**self.config,**c};self.mode_models=[];self.mode_frames=[];self.mode_returns=[];self.source_set_allocs=0;self.timer_handler=None;self.collections[REGISTRY]=set();self.callback_phase=False
  self.u.mem_write(MODE,bytes(512));self.u.mem_write(MODE+200,b'\xa5');self.u.mem_write(RL+0xa68,struct.pack('<Q',REGISTRY));self.u.mem_write(RL+0x50,struct.pack('<I',WAKE_PORT));self.u.mem_write(REGISTRY,bytes(64));self.u.mem_write(REGISTRY+0x12,struct.pack('<H',1));self.u.mem_write(REGISTRY+0x1a,b'\x01')
  for a,n in((QUEUE,120),(TLS,64),(TIMER_SOURCE,128),(BLOCK,40),(BYREF,32)):self.u.mem_write(a,bytes(n))
  self.u.mem_write(QUEUE+120,b'\xa5');self.u.mem_write(TLS+0x18,struct.pack('<Q',0x100));self.u.mem_write(TLS+0x20,struct.pack('<Q',c.get('tls_priority_word',0)));self.u.reg_write(A.UC_ARM64_REG_TPIDRRO_EL0,TLS)
  if c['mode']=='fork_flag2':self.u.mem_write(0x1ed8999d0,b'\x02')
 def mode_frame(self,a):return{'pc':hex(a),**self.frame('mode_construction_stage'),'mode512_hex':bytes(self.u.mem_read(MODE,512)).hex(),'queue128_hex':bytes(self.u.mem_read(QUEUE,128)).hex(),'model_state':self.state(),'fork_flag1_hex':bytes(self.u.mem_read(0x1ed8999d0,1)).hex(),'queue_serial_counter8_hex':bytes(self.u.mem_read(0x1ed8991c0,8)).hex()}
 def mode_model(self,a,name,result,patches=(),extra=None):
  before=self.state();self.runtime_model(a,name,result,patches);e=self.events[-1];e['model_state_before']=before;e['model_state_after']=self.state()
  if extra:e.update(extra)
  self.mode_models.append(e)
 def hook(self,u,a,n,d):
  self.flush();cfg=self.config['mode']
  if a in FATALS:self.mode_frames.append(self.mode_frame(a));return self.finish('before_original_mode_failure_'+FATALS[a],a)
  if a==HALT and cfg not in('schedule_then_run','repeat_mode'):
   if self.phase=='installer':self.phase='mode_direct';return self.public_call(COPYMODE,(RL,NAME,0 if cfg=='no_create'else 1),'installer_to_internal_CopyMode')
   self.mode_returns.append(self.mode_frame(a))
   if cfg=='timer_callback'and self.phase=='mode_direct':self.phase='timer_callback';return self.public_call(CALLBACK,(BLOCK,),'CopyMode_to_timer_callback')
   return self.finish('original_mode_timer_handler_returned'if self.phase=='timer_callback'else'original_CopyMode_returned',a)
  if a==HALT and cfg=='repeat_mode'and self.phase=='registration'and self.add_calls>=self.config['repeat']:
   self.registration_returns.append(self.schedule_frame(a));self.phase='runloop';from recover_cf_receive import RUN
   return self.public_call(RUN,(RL,MODE,1),'AddSource_to_runloop')
  if a in MODE_POINTS:self.mode_frames.append(self.mode_frame(a))
  if a==0x18489b724 and self.reg(0)==REGISTRY:
   key=self.reg(1);name=int.from_bytes(bytes(u.mem_read(key+0x50,8)),'little');found=next((v for v in self.collections[REGISTRY]if int.from_bytes(bytes(u.mem_read(v+0x50,8)),'little')==name),0);return self.mode_model(a,'mode_registry_bucket_contract',0,[(self.reg(8),struct.pack('<4Q',0,key,found,int(bool(found))))])
  if a==INSERT_TRAP and self.reg(1)!=self.port:
   port=self.reg(1);assert self.reg(0)==0x103 and self.reg(2)==self.facility and port in(ROOT_PORT,TIMER_PORT,WAKE_PORT);bad={'root_member_error':ROOT_PORT,'timer_member_error':TIMER_PORT,'wake_member_error':WAKE_PORT}.get(cfg);value=4 if port==bad else 0
   before=self.state()
   if not value:self.members.add((self.facility,port))
   self.mode_model(a,'declared_mode_control_port_member',value,extra={'model_state_before':before});return
  if a in BOUNDARIES:
   x=[self.reg(j)for j in range(9)];value=0;patches=[];extra=None
   if a==0x1846dc364:assert x[1]==44
   elif a==0x1846da4dc:assert x[1:4]==[44,184,0];value=0 if cfg=='runtime_null'else MODE
   elif a==0x1846df2ec:assert x[1]==NAME;value=NAME
   elif a==0x1805887c8:assert x[1]==2
   elif a==0x1805884cc:assert x[0]==MODE+0x10
   elif a==0x1855140c8:assert x[:2]==[0x1ed897df0,120];value=QUEUE;patches=[(QUEUE,struct.pack('<Q',x[0]))]
   elif a==ALLOC_TRAP:
    assert x[:2]==[0x103,3];ret=self.input['pset_stage_returns'][0];value=4 if cfg=='pset_error'else int(ret['registers31'][0],16)
    if not value:patches=[(x[2],struct.pack('<I',self.facility))]
    extra={'kernel_allocate_oracle':{'case':self.index,'return_source_visit_index':ret['source_visit_index'],'name':hex(self.facility)}if not value else None}
   elif a==CONSTRUCT_TRAP:assert x[0]==0x103 and x[2]==QUEUE;patches=[(x[3],struct.pack('<I',ROOT_PORT))];extra={'original_options16_hex':bytes(u.mem_read(x[1],16)).hex()}
   elif a==MK:value=0 if cfg=='timer_zero'else TIMER_PORT
   elif a==0x18552896c:assert x[0]==0x1e24b2310 and x[1:4]==[0,0,QUEUE];value=TIMER_SOURCE
   elif a==0x18552955c:
    assert x[0]==TIMER_SOURCE;raw=bytearray(u.mem_read(x[1],40));by=int.from_bytes(raw[32:40],'little');br=bytearray(u.mem_read(by,32));extra={'original_block40_hex':raw.hex(),'original_byref32_hex':br.hex()};assert int.from_bytes(br[24:32],'little')==MODE+0xa8;br[8:16]=struct.pack('<Q',BYREF);raw[32:40]=struct.pack('<Q',BYREF);patches=[(BLOCK,bytes(raw)),(BYREF,bytes(br))];self.timer_handler=extra
   elif a==0x185528b10:assert x[:4]==[TIMER_SOURCE,0xffffffffffffffff,0xffffffffffffffff,0x141]
   elif a==0x185514684:assert x[0]==TIMER_SOURCE
   elif a==0x18550ebf8:assert x[1]==8
   elif a==0x184716d78:assert x[1]==0;value=SET0 if self.source_set_allocs==0 else SET1;self.source_set_allocs+=1
   elif a==0x1846dbcac:assert x[1:4]==[0,0,0];value=DICT
   return self.mode_model(a,BOUNDARIES[a],value,patches,extra)
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in NEWFUNCS and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));off=a-int(f['start'],16);assert raw==bytes.fromhex(f['bytes'])[off:off+4];i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   elif op=='mrs':assert i.op_str=='x21, tpidrro_el0'and u.reg_read(A.UC_ARM64_REG_TPIDRRO_EL0)==TLS
   else:assert op not in('svc','hvc','smc','brk','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
   return
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();r.update(mode_configuration=self.config,mode_models=self.mode_models,mode_frames=self.mode_frames,mode_returns=self.mode_returns,final_mode512_hex=bytes(self.u.mem_read(MODE,512)).hex(),final_queue128_hex=bytes(self.u.mem_read(QUEUE,128)).hex(),final_block40_hex=bytes(self.u.mem_read(BLOCK,40)).hex(),final_byref32_hex=bytes(self.u.mem_read(BYREF,32)).hex(),final_fork_flag1_hex=bytes(self.u.mem_read(0x1ed8999d0,1)).hex(),final_queue_serial_counter8_hex=bytes(self.u.mem_read(0x1ed8991c0,8)).hex(),private_TPIDRRO_EL0=hex(TLS));return r
if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());ks=json.loads((ROOT/'kernel_portset_delivery_profiles.json').read_text())['kernel_cases'][:4];rows=[]
 for c in configurations():
  r=Probe(c,ks[c['kernel_case']],s).run();rows.append(r);print(c,r['boundary']['kind'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','kernel_portset_delivery_profiles.json','probe_kernel_portset_delivery.py','recover_'+P+'.py']},'kernel_cases':ks,'cases':rows,**FLAGS};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
