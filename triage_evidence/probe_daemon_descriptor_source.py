#!/usr/bin/env python3
"""Private original initializer, descriptor setup and source-created callback.
All external calls are declared, PAC logical, kernel events supplied. Fresh
component copies retain whole mutable RAM and CPU. No native IPC or scheduling.
O(V+H*R+J+I) time, O(R+J+I) space; visits V, full snapshots H, RAM R,
journals J and original image I. Original decoding cached per PC.
"""
import json,struct,zlib,base64,hashlib
import unicorn as uc
from unicorn import arm64_const as A
from daemon_rpc502_probe import Probe as Loader
from daemon_receive_tools import ROOT,IMAGE,SOURCE,CS,TABLE,FIXUPS
from recover_daemon_descriptor_source import P,FLAGS,sha,INIT,SETUP,CALLBACK,WRAPPER,HEADER,STACK,STACK_SIZE,HEAP,IMPORTS,HALT,CFREF,CFSRC,MACHREF,RL,MODE,ARG,CBSP,OUT,REGIONS

def zipbytes(b):return{'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'zlib_base64':base64.b64encode(zlib.compress(b)).decode()}
def unzip(e):
 b=zlib.decompress(base64.b64decode(e['zlib_base64']));assert len(b)==e['size_bytes']and hashlib.sha256(b).hexdigest()==e['sha256'];return b
def configurations():
 setup=[{'phase':'setup','label':n,'fd':fd,**extra}for n,fd,extra in[('setup_fd7',7,{}),('setup_fd0',0,{}),('setup_negative_fd',-1,{}),('setup_null_CF',7,{'null_cf':True}),('setup_null_source',7,{'null_source':True}),('setup_kevent_error',7,{'registration_status':-1})]]
 callbacks=[{'phase':'callback','label':n,'filter':f,'ident':i,'event_result':ret,'mach_object':m,'event_seed':seed}for n,f,i,ret,m,seed in[('signal15',-6,15,1,True,False),('signal15_no_mach',-6,15,1,False,False),('other_signal',-6,2,1,True,False),('process_event',-5,15,1,True,False),('other_filter',-1,15,1,True,False),('empty_event',-6,15,0,True,False),('error_event',-6,15,-1,True,False),('empty_with_declared_output',-6,15,0,True,True)]]
 return setup,callbacks
class Probe(Loader):
 def __init__(self,c,origin=None):
  super().__init__();self.c=c;self.phase=c['phase'];self.visits=[];self.reads=[];self.writes_all=[];self.pending=[];self.models=[];self.boundary=None;self.dec={};self.current=-1;self.u.mem_map(HEAP,0x40000)
  name='CoreFoundation/_kCFRunLoopDefaultMode';self.u.mem_write(self.import_addresses[name],struct.pack('<Q',MODE));self.data_import_values.append({'name':name,'value':hex(MODE)})
  if origin:
   for e in origin['final_regions']:self.u.mem_write(int(e['address'],16),unzip(e))
   f=origin['boundary'];self.restore_cpu(f)
  self.origin=None if origin is None else {'label':origin['configuration']['label'],'boundary':origin['boundary'],'region_sha256':[e['sha256']for e in origin['final_regions']]}
  self.fixture=[];self.handoff_before=self.frame();self.fixture_state()
  self.entry=self.frame();self.u.mem_protect(0x100000000,0x1038000,5);self.u.mem_protect(0x1010cc000,0x14000,1)
 def regbytes(self,a,n):return bytes(self.u.mem_read(a,n))
 def frame(self):return{'pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.u.reg_read(A.UC_ARM64_REG_SP)),'NZCV':hex(self.u.reg_read(A.UC_ARM64_REG_NZCV)),'Q_registers32':[hex(self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]}
 def restore_cpu(self,f):
  for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
  for j,v in enumerate(f['Q_registers32']):self.u.reg_write(getattr(A,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  for k in('PC','SP','NZCV'):self.u.reg_write(getattr(A,'UC_ARM64_REG_'+k),int(f['pc'if k=='PC'else k],16))
 def patch(self,a,b):self.fixture.append({'address':hex(a),'before_hex':self.regbytes(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
 def fixture_state(self):
  if self.phase=='initializer':
   if self.c.get('raw_heap_fill'):self.patch(HEAP,bytes([self.c['raw_heap_fill']])*0x15e00)
   self.patch(ARG,struct.pack('<II',(0x5973a279*((ARG&0xffffffff)^0xdc40790b)+0x267e)&0xffffffff,0));self.setreg(0,ARG);target=INIT;sp=STACK+0x78000
  elif self.phase=='setup':
   target=SETUP;sp=STACK+0x78000
   for j,v in{19:0xa6,21:HEADER,22:0x3a74,23:0x0a5cd4cf,28:TABLE}.items():self.setreg(j,v)
   for off,v in[(0x198,0x1010c4e08),(0x1a0,0x1010c4670),(0x190,0x100fc4230),(0x188,0x101031fa0),(0xe0,0x100fc4130),(0xb8,0x101031ea0),(0x108,0x100e99a00),(0x100,0x100f4e390),(0x170,0x101031da0),(0x178,0x100e99900)]:self.patch(sp+off,struct.pack('<Q',v))
  else:
   target=CALLBACK;sp=CBSP;self.setreg(0,CFREF);self.setreg(1,1);self.setreg(2,0);self.patch(HEADER+0x18,struct.pack('<Q',MACHREF if self.c['mach_object']else 0));self.patch(OUT,self.event_bytes()if self.c['event_seed']else bytes(32))
  self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,sp);self.u.reg_write(A.UC_ARM64_REG_PC,target);self.target=target
 def event_bytes(self):return struct.pack('<QhHIqQ',self.c['ident'],self.c['filter'],0,0,0,0)
 def flush(self):
  for e in self.pending:e['after_hex']=self.regbytes(int(e['address'],16),e['size_bytes']).hex()
  self.pending=[]
 def write_hook(self,u,access,a,n,v,d):
  assert any(lo<=a and a+n<=lo+size for lo,size in REGIONS),(hex(a),n)
  e={'visit':self.current,'address':hex(a),'size_bytes':n,'before_hex':self.regbytes(a,n).hex()};self.writes_all.append(e);self.pending.append(e)
 def read_hook(self,u,access,a,n,v,d):
  self.reads.append({'visit':self.current,'address':hex(a),'size_bytes':n,'bytes_hex':self.regbytes(a,n).hex()})
 def finish(self,kind):self.flush();self.boundary={'kind':kind,**self.frame()};self.u.emu_stop()
 def model(self,a,name):
  x=[self.reg(j)for j in range(8)];patches=[];result=0;preserve=False;meta={}
  if name=='libSystem/___chkstk_darwin':preserve=True
  elif name=='libSystem/_pthread_once':assert x[:2]==[0x1010b8cd0,0x10040ebd4];meta={'initializer_executed':False}
  elif name in('libSystem/_pthread_rwlock_wrlock','libSystem/_pthread_rwlock_unlock'):assert x[0]==0x1010b7478
  elif name=='libSystem/_malloc':assert self.phase=='initializer'and x[0]==0x15e00;result=HEAP
  elif name=='libSystem/_kqueue':assert self.phase=='setup';result=self.c['fd']&0xffffffff
  elif name=='libSystem/_signal':assert x[:2]==[15,1]
  elif name=='libSystem/_kevent':
   if self.phase=='setup':assert x[:1]==[self.c['fd']]and x[2:6]==[1,0,0,0];meta={'change32_hex':self.regbytes(x[1],32).hex()};result=self.c.get('registration_status',0)&0xffffffff
   else:
    assert x[:6]==[7,0,0,OUT,1,0];result=self.c['event_result']&0xffffffff
    if self.c['event_result']>0:patches=[(OUT,self.event_bytes())]
  elif name=='CoreFoundation/_CFFileDescriptorCreate':assert x[:5]==[0,self.c['fd'],1,CALLBACK,0];result=0 if self.c.get('null_cf')else CFREF
  elif name=='CoreFoundation/_CFFileDescriptorCreateRunLoopSource':assert x[:3]==[0,CFREF,0];result=0 if self.c.get('null_source')else CFSRC
  elif name=='CoreFoundation/_CFFileDescriptorGetNativeDescriptor':assert x[0]==CFREF;result=7
  elif name=='CoreFoundation/_CFFileDescriptorEnableCallBacks':assert x[:2]==[CFREF,1]
  elif name=='CoreFoundation/_CFFileDescriptorInvalidate':assert x[0]==CFREF
  elif name=='CoreFoundation/_CFMachPortInvalidate':assert x[0]==MACHREF
  elif name=='CoreFoundation/_CFRunLoopGetMain':result=RL
  elif name=='CoreFoundation/_CFRunLoopStop':assert x[0]==RL
  elif name=='CoreFoundation/_CFRunLoopAddSource':assert x[:3]==[RL,CFSRC,MODE]
  elif name=='CoreFoundation/_CFRelease':assert x[0]in(CFSRC,CFREF)
  else:raise AssertionError(('unmodeled import',name,hex(self.reg(30))))
  e={'pc':hex(a),'name':name,'before':self.frame(),'arguments8':[hex(v)for v in x],'result':None if preserve else hex(result),'preserve_all_CPU':preserve,'patches':[],**meta};self.models.append(e)
  for at,b in patches:e['patches'].append({'address':hex(at),'before_hex':self.regbytes(at,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
  target=self.reg(30)
  if not preserve:
   for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
   self.setreg(0,result);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000)
  self.u.reg_write(A.UC_ARM64_REG_PC,target);e['after']=self.frame()
 def hook(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.finish('original_return_to_declared_caller')
  if self.phase=='setup'and a in(0x100027310,0x100093518):return self.finish('before_original_setup_continuation')
  if a in self.imports:return self.model(a,self.imports[a])
  assert 0x100001058<=a<0x100e2ac40,(hex(a),'outside original executable span')
  raw=self.regbytes(a,4);assert raw==IMAGE.read(a,4);self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if a not in self.dec:self.dec[a]=next(CS.disasm(raw,a))
  i=self.dec[a];op=i.mnemonic
  if op in('pacibsp','paciasp','autibsp','autiasp','paciza','pacia','pacda','autia','autiza','autda','xpaci','xpacd','xpaclri','bti'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
  elif op in('retab','retaa'):u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
  elif op in('braa','braaz','brab','brabz','blraa','blraaz','blrab','blrabz'):
   target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
   if op.startswith('blr'):self.setreg(30,a+4)
   u.reg_write(A.UC_ARM64_REG_PC,target)
  else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
 def run(self):
  self.u.emu_start(self.target,0,count=100000);self.flush();assert self.boundary is not None
  return{'configuration':self.c,'origin':self.origin,'handoff_before':self.handoff_before,'fixture_patches':self.fixture,'entry':self.entry,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes_all,'imports':self.models,'boundary':self.boundary,'final_regions':[{'address':hex(a),**zipbytes(self.regbytes(a,n))}for a,n in REGIONS],'final_header96_hex':self.regbytes(HEADER,96).hex(),'final_event32_hex':self.regbytes(OUT,32).hex()}
from probe_cf_wake_send_wrapper import Probe as CFParent
from probe_cf_source_scheduling import B as CFB,RL as CFRL,MODE as CFMODE,HALT as CFHALT
from recover_cf_runloop_wake_port import WAKE
CFSTOP=0x184784250
class CFProbe(CFParent):
 def __init__(self,c,k,s):super().__init__(c,k,s);self.stop_fixture=None
 def public_call(self,a,args,label):
  if a==WAKE:
   assert self.stop_fixture is None;at=CFRL+0xa60;raw=struct.pack('<Q',CFMODE if self.config['active_mode']else 0);self.stop_fixture={'before':self.frame('before_Stop_entry'),'address':hex(at),'before_hex':bytes(self.u.mem_read(at,8)).hex(),'after_hex':raw.hex()};self.u.mem_write(at,raw);a=CFSTOP;label='declared_original_Stop_entry'
  return super().public_call(a,args,label)
 def hook(self,u,a,n,d):
  self.flush()
  if a==CFHALT and self.phase=='wakeup':self.wake_returns.append(self.wake_frame(a));return self.finish('original_CFRunLoopStop_returned',a)
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();r.update(CF_stop_fixture=self.stop_fixture,final_stop_flag_byte_hex=bytes(self.u.mem_read(CFRL+0x55,1)).hex(),final_current_mode8_hex=bytes(self.u.mem_read(CFRL+0xa60,8)).hex());return r

if __name__=='__main__':
 source=json.loads((ROOT/(P+'_source.json')).read_text());init=Probe({'phase':'initializer','label':'context_initializer'}).run();print('initializer',len(init['source_visits']),flush=True);setup,cb=configurations();setups=[];callbacks=[]
 for c in setup:r=Probe(c,init).run();setups.append(r);print(c['label'],len(r['source_visits']),flush=True)
 for c in cb:r=Probe(c,setups[0]).run();callbacks.append(r);print(c['label'],len(r['source_visits']),flush=True)
 poison=Probe({'phase':'initializer','label':'context_initializer_poison','raw_heap_fill':165}).run();print('poison_initializer',len(poison['source_visits']),flush=True);ps=Probe({'phase':'setup','label':'setup_poison','fd':7},poison).run();pc=[]
 for original in(cb[0],cb[3]):
  c={**original,'label':original['label']+'_poison'};r=Probe(c,ps).run();pc.append(r);print(c['label'],len(r['source_visits']),flush=True)
 cf=[];prior=json.loads((ROOT/'cf_runloop_wake_port_profiles.json').read_text());cs={**source['CF_source'],'root_caller_options':source['root_caller_options']}
 for label,wake,active in[('CF_Stop_dormant','suppressed',False),('CF_Stop_waiting_without_mode','waiting',False),('CF_Stop_waiting_active_mode','waiting',True)]:
  c={'kernel_case':2,'mode':'schedule_then_run','repeat':1,'wake_case':wake,'send_status':0,'label':label,'trap_results':[0]if active else[],'aux':False,'active_mode':active};r=CFProbe(c,prior['kernel_cases'][2],cs).run();cf.append(r);print(label,len(r['source_visits']),flush=True)
 out={'CF_cases':cf,'poison_initializer':poison,'poison_setup':ps,'poison_callback_cases':pc,'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','recover_'+P+'.py','daemon_rpc502_probe.py','cf_runloop_wake_port_profiles.json','probe_cf_wake_send_wrapper.py']},'initializer':init,'setup_cases':setups,'callback_cases':callbacks,**{k:False for k in FLAGS}};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
