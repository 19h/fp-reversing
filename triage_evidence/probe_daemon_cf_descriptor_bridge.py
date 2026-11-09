#!/usr/bin/env python3
"""Original daemon init/setup and CF public source callback in one private CPU.
Logical bind targets, explicit initializer/setup component entries, raw storage,
main/TSD registration, syscall/dispatch/hash/array contracts remain declared.
No native IPC/PAC or whole-startup proof. O(V*F+J+H*R),O(I+J+R).
"""
import json,struct,hashlib
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,IMAGE,CS,TABLE as DTABLE
from probe_cf_public_runloop import Probe as Parent
from probe_cf_wake_send_wrapper import Probe as Wrapper,MACH
from probe_cf_descriptor_source_factory import FDO,READ,WRITE
from probe_cf_source_scheduling import B,RL,MODE,SRC,SET0,SET1,BAG,HALT
from recover_cf_runloop_wake_port import DEFAULT
from recover_cf_public_runloop import STOP
from recover_cf_source_wake_callers import WAKE
from recover_daemon_cf_descriptor_bridge import P,FLAGS,sha,FUNCS,INIT,SETUP,CALLBACK,HEADER,SETUP_END,GETMAIN
from probe_rpc502_vm_handoff import compressed
HEAP=0x5000000000;ARG=B+0xd0000;MODES=B+0xd1000;SETUP_SP=B+0x70000;OPAQUE=HEAP+0x30000;INIT_RETURN=HALT+0x300;CANCEL_RETURN=HALT+0x400
EXTRA=[(0x101038000,0x7c000),(0x1010b4000,0x18000),(HEAP,0x40000),(0x70000000,0x80000),(0x6000000000,0x100000)]
class Probe(Parent):
 def __init__(self,c,k,s):
  super().__init__(c,k,s);self.daemon_phase=None;self.init_done=self.setup_done=False;self.init_saved=self.setup_saved=None;self.bridge_initial=[];self.bridge_frames=[];self.entries=[];self.daemon_models=[];self.callbacks=[];self.active_callback=None;self.cancelled=[];self.remove_calls=[];self.callback_seed=None;self.bridge_source=s;self.main_created=False;self.drains=[];self.drain_saved=None;self.drain_index=0;self.drain_done=False
  original_start=self.u.emu_start
  self.u.emu_start=lambda start,end,timeout=0,count=0:original_start(start,end,timeout,count=150000)
  self.u.mem_map(HEAP,0x40000)
  raw=bytes([c.get('heap_fill',0)])*89600+b'\xa5';self.fixture(HEAP,raw)
  self.fixture(ARG,struct.pack('<II',(0x5973a279*((ARG&0xffffffff)^0xdc40790b)+0x267e)&0xffffffff,0)+b'\xa5')
  for at in(SET0,SET1,BAG):self.fixture(at+0x12,struct.pack('<H',1))
  self.fixture(MODES,bytes(64)+b'\xa5');self.fixture(OPAQUE,bytes(8)+b'\xa5')
  for e in s['bridge_bindings']:self.fixture(int(e['slot'],16),struct.pack('<Q',int(e['target'],16)))
  self.fixture(self.import_addresses['CoreFoundation/_kCFRunLoopDefaultMode'],struct.pack('<Q',DEFAULT))
  self.fixture(0x1ed8912b8,b'\xff'*8);self.fixture(0x1ed8913f0,struct.pack('<Q',RL))
 def fixture(self,a,b):self.bridge_initial.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
 def bf(self,a):return{'pc':hex(a),**self.frame('daemon_CF_bridge'),'daemon_phase':self.daemon_phase,'header96_hex':bytes(self.u.mem_read(HEADER,96)).hex(),'descriptor112_hex':bytes(self.u.mem_read(FDO,112)).hex(),'source184_hex':bytes(self.u.mem_read(SRC,184)).hex(),'runloop2720_hex':bytes(self.u.mem_read(RL,2720)).hex(),'model_state':self.state()}
 def restore(self,f):
  for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
  for j,v in enumerate(f['Q_registers32']):self.u.reg_write(getattr(A,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  self.u.reg_write(A.UC_ARM64_REG_SP,int(f['SP'],16));self.u.reg_write(A.UC_ARM64_REG_NZCV,int(f['NZCV'],16));self.u.reg_write(A.UC_ARM64_REG_PC,int(f['pc'],16))
 def start_init(self):
  self.init_done=True;self.init_saved=self.bf(HALT);self.daemon_phase='initializer';self.setreg(0,ARG);self.setreg(30,INIT_RETURN);self.u.reg_write(A.UC_ARM64_REG_PC,INIT);self.entries.append({'kind':'declared_initializer_entry','before':self.init_saved,'after':self.bf(INIT)})
 def start_setup(self):
  self.setup_saved=self.bf(HALT);self.daemon_phase='setup';self.stage='daemon_setup';patches=[]
  for off,v in[(0x198,0x1010c4e08),(0x1a0,0x1010c4670),(0x190,0x100fc4230),(0x188,0x101031fa0),(0xe0,0x100fc4130),(0xb8,0x101031ea0),(0x108,0x100e99a00),(0x100,0x100f4e390),(0x170,0x101031da0),(0x178,0x100e99900)]:
   a=SETUP_SP+off;b=struct.pack('<Q',v);patches.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,8)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
  for j,v in{19:0xa6,21:HEADER,22:0x3a74,23:0x0a5cd4cf,28:DTABLE}.items():self.setreg(j,v)
  self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,SETUP_SP);self.u.reg_write(A.UC_ARM64_REG_PC,SETUP);self.entries.append({'kind':'declared_setup_component_entry','before':self.setup_saved,'patches':patches,'after':self.bf(SETUP)})
 def daemon_model(self,a,name):
  x=[self.reg(j)for j in range(8)];result=0;patches=[];meta={};preserve=name=='libSystem/___chkstk_darwin'
  if preserve:pass
  elif name=='libSystem/_pthread_once':assert x[:2]==[0x1010b8cd0,0x10040ebd4];meta={'initializer_body_executed':False}
  elif name in('libSystem/_pthread_rwlock_wrlock','libSystem/_pthread_rwlock_unlock'):assert x[0]==0x1010b7478
  elif name=='libSystem/_malloc':assert self.daemon_phase=='initializer'and x[0]==89600;result=HEAP
  elif name=='libSystem/_kqueue':assert self.daemon_phase=='setup';result=7
  elif name=='libSystem/_signal':assert x[:2]==[15,1]
  elif name=='libSystem/_kevent':
   assert x[0]==7
   if self.daemon_phase=='setup':assert x[2:6]==[1,0,0,0];meta={'change32_hex':bytes(self.u.mem_read(x[1],32)).hex()};result=self.config.get('registration_status',0)&0xffffffff
   else:
    assert self.daemon_phase=='callback'and x[1:3]==[0,0]and x[4:6]==[1,0];result=self.config.get('event_result',1)&0xffffffff;meta={'event_output':hex(x[3])}
    if self.config.get('event_result',1)>0:patches=[(x[3],struct.pack('<QhHIqQ',self.config.get('ident',15),self.config.get('filter',-6),0,0,0,0))]
  elif name=='CoreFoundation/_CFMachPortInvalidate':assert self.config.get('mach_object')and x[0]==OPAQUE;meta={'opaque_CF_object':True}
  else:raise AssertionError(('unreviewed daemon import',name,self.daemon_phase,hex(self.reg(30))))
  e={'pc':hex(a),'name':name,'before':self.bf(a),'arguments8':[hex(v)for v in x],'result':None if preserve else hex(result),'preserve_all_tracked_CPU':preserve,'patches':[],**meta};self.daemon_models.append(e)
  for at,b in patches:e['patches'].append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
  ret=self.reg(30)
  if not preserve:
   for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
   self.setreg(0,result);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000)
  self.u.reg_write(A.UC_ARM64_REG_PC,ret);e['after']=self.bf(ret)
 def bridge_lower(self,a):
  x=[self.reg(j)for j in range(9)];before=self.state();value=0;patches=[];name=None
  if a==0x1846fb960 and x[0]==BAG:
   assert x[1:3]==[RL,RL];name='declared_bridge_bag_add_metadata';self.collections[BAG].add(RL);self.bag_counts[RL]=self.bag_counts.get(RL,0)+1;patches=[(BAG+0x14,struct.pack('<I',1)),(BAG+0x1a,b'\x01')]
  elif a==0x1846dc364 and x[:2]==[BAG,4]:name='declared_bridge_bag_type4'
  elif a==0x18471c584 and x[0]==BAG:assert x[1]==0;name='declared_bridge_bag_bucket';patches=[(x[8],struct.pack('<4Q',0,RL,RL,1))]
  elif a==0x184757e4c:assert x[0]==RL;name='declared_bridge_registered_mode_array';value=MODES
  elif a==0x1846f5978 and x[0]==MODES:name='declared_bridge_mode_array_count';value=1
  elif a==0x1846f7424 and x[0]==MODES:assert x[1]==0;name='declared_bridge_mode_array_value';value=DEFAULT
  elif a==0x1847170cc:
   assert x[0]in(SET0,SET1)and x[1]==SRC;name='declared_bridge_hash_remove';value=int(SRC in self.collections[x[0]]);self.collections[x[0]].discard(SRC);patches=[(x[0]+0x14,struct.pack('<I',len(self.collections[x[0]])))];self.remove_calls.append({'set':hex(x[0]),'key':hex(SRC),'removed':bool(value),'source_visit_index':len(self.visits)})
  elif a==0x188076630:assert x[0]in(READ,WRITE);name='declared_bridge_dispatch_cancel';self.cancelled.append(x[0])
  elif a==0x188084be0:assert x[:2]==[7,2];name='declared_bridge_shutdown_request'
  elif a==0x18806c5c0:assert bytes(self.u.mem_read(x[0],10))==b'/dev/null\0'and x[1]==0;name='declared_bridge_null_device_open';value=13
  elif a==0x188085b10:assert x[:2]==[13,7];name='declared_bridge_dup2_request';value=7
  elif a==0x1880765d0 and x[0]in(READ,WRITE):name='declared_bridge_dispatch_release'
  if name:self.mode_model(a,name,value,patches,{'model_state_before':before});return True
  return False
 def lower(self,a):
  if a==0x188086d70 and self.active_callback:
   stage=self.stage;ready=self.config['perform_ready'];self.stage='enable';self.config['enable_ready']=False
   try:return super().lower(a)
   finally:self.stage=stage;self.config['enable_ready']=True;self.config['perform_ready']=ready
  return super().lower(a)
 def next_cancel(self):
  if self.drain_index==len(self.cancelled):
   self.restore(self.drain_saved);self.drain_done=True;self.drains[-1]['public_observation_restored']=self.bf(HALT);return
  source=self.cancelled[self.drain_index];block=self.handlers[source]['cancel'];raw=bytes(self.u.mem_read(block,44));target=int.from_bytes(raw[16:24],'little');e={'source':hex(source),'block':hex(block),'copied44_hex':raw.hex(),'before':self.bf(self.u.reg_read(A.UC_ARM64_REG_PC))};self.drains.append(e);self.setreg(0,block);self.setreg(30,CANCEL_RETURN);self.u.reg_write(A.UC_ARM64_REG_PC,target);e['entry']=self.bf(target)
 def hook(self,u,a,n,d):
  self.flush()
  if a==CANCEL_RETURN:self.drains[-1]['returned']=self.bf(a);self.drain_index+=1;return self.next_cancel()
  if a==HALT and self.stage=='runloop'and self.config.get('drain_cancel')and not self.drain_done and self.drain_saved is None:
   self.drain_saved=self.bf(a);return self.next_cancel()
  if a==HALT and self.phase=='installer'and not self.init_done:return self.start_init()
  if a==INIT_RETURN:
   self.entries[0]['returned']=self.bf(a);self.restore(self.init_saved);self.daemon_phase=None;self.entries[0]['resume']=self.bf(HALT);return
  if a==HALT and self.phase=='create'and not self.setup_done:
   self.wake_returns.append(self.wake_frame(a));assert self.reg(0)==RL;return self.start_setup()
  if a==SETUP_END and self.daemon_phase=='setup':
   self.entries[1]['returned']=self.bf(a);self.restore(self.setup_saved);self.daemon_phase=None;self.setup_done=True;self.stage=self.phase='fd_register';self.add_calls=1;self.entries[1]['resume']=self.bf(HALT);return
  if a==CALLBACK and self.active_callback is None:
   assert self.daemon_phase is None and self.reg(0)==FDO and int.from_bytes(bytes(u.mem_read(HEADER+0x50,8)),'little')==FDO;self.daemon_phase='callback';e={'entry_before':self.bf(a),'return_pc':hex(self.reg(30)),'patches':[]};self.callbacks.append(e);self.active_callback=e
   changes=[(HEADER+0x18,struct.pack('<Q',OPAQUE if self.config.get('mach_object')else 0))]
   if self.config.get('event_result',1)<=0:
    raw=struct.pack('<QhHIqQ',self.config.get('ident',15),self.config.get('filter',-6),0,0,0,0)if self.config.get('seed_event')else bytes(32);changes.append((u.reg_read(A.UC_ARM64_REG_SP)-0x149c,raw))
   for at,b in changes:e['patches'].append({'address':hex(at),'before_hex':bytes(u.mem_read(at,len(b))).hex(),'after_hex':b.hex()});u.mem_write(at,b)
   e['entry_after']=self.bf(a)
  if self.active_callback and a==int(self.active_callback['return_pc'],16):self.active_callback['returned']=self.bf(a);self.active_callback=None;self.daemon_phase=None
  if a==WAKE and self.active_callback:self.phase='wakeup'
  if a==MACH and self.active_callback and self.reg(1)==0x11:return Wrapper.hook(self,u,a,n,d)
  if self.daemon_phase and a in self.imports:return self.daemon_model(a,self.imports[a])
  if self.bridge_lower(a):return
  if self.daemon_phase and 0x100001058<=a<0x100e2ac40:
   if self.phase=='wakeup':self.phase='runloop'
   if a in(INIT,SETUP,CALLBACK,0x10044f4d4,0x10044f574,0x10044f5ec,0x1003c12a8,0x1003c12ec,0x1003c132c):self.bridge_frames.append(self.bf(a))
   raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});op=i.mnemonic
   if op in('pacibsp','paciasp','autibsp','autiasp','paciza','pacia','pacda','autia','autiza','autda','xpaci','xpacd','xpaclri','bti'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op in('retab','retaa'):u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('braa','braaz','brab','brabz','blraa','blraaz','blrab','blrabz'):
    target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
   return
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in FUNCS and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   if a==int(f['start'],16):self.bridge_frames.append(self.bf(a))
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4];i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autiza','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
   return
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();assert self.init_done and self.setup_done and self.active_callback is None;r.update(declared_cancel_deliveries=self.drains,public_return_before_cancel_delivery=self.drain_saved,bridge_initial=self.bridge_initial,bridge_frames=self.bridge_frames,bridge_component_entries=self.entries,daemon_external_models=self.daemon_models,original_daemon_callbacks=self.callbacks,cancel_requests=[hex(v)for v in self.cancelled],hash_remove_calls=self.remove_calls,final_daemon_regions=[{**compressed(bytes(self.u.mem_read(a,n))),'address':hex(a)}for a,n in EXTRA],final_header96_hex=bytes(self.u.mem_read(HEADER,96)).hex());return r

if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());k=json.loads((ROOT/'cf_runloop_wake_port_profiles.json').read_text())['kernel_cases'][2];binds=[{'slot':e['binding']['slot'],'target':hex(e['captured_CF_export']['address'])}for e in s['daemon_to_CF_bindings']];cs={**s['CF_source'],'root_caller_options':s['root_caller_options'],'bridge_bindings':binds};rows=[]
 for label,more in[('signal15',{}),('other_signal',{'filter':-6,'ident':2}),('process_event',{'filter':-5,'ident':15}),('other_filter',{'filter':-1}),('no_event',{'event_result':0}),('error_event',{'event_result':-1}),('retained_signal_on_error',{'event_result':-1,'seed_event':True}),('signal15_opaque_mach',{'mach_object':True}),('signal15_poison',{'heap_fill':165}),('signal15_drain_cancel',{'drain_cancel':True}),('signal15_registration_error',{'registration_status':-1})]:
  stop=label.startswith('signal15')or label=='retained_signal_on_error';cfg={'kernel_case':2,'mode':'schedule_then_run','repeat':1,'wake_case':'waiting','send_status':0,'aux':False,'trap_results':[0]if stop else[],'label':label,'events':[],'bag_multiplicity':1,'copy_null':False,'enable_ready':True,'perform_ready':True,'entry':'run'if stop else'specific','callback_stop':False,**more}
  try:r=Probe(cfg,k,cs).run()
  except Exception as e:print('FAILED',label,type(e).__name__,str(e),flush=True);raise
  rows.append(r);print(label,len(r['source_visits']),r['boundary']['kind'],len(r['original_daemon_callbacks']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','recover_'+P+'.py','probe_cf_public_runloop.py','cf_runloop_wake_port_profiles.json']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
