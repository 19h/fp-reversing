#!/usr/bin/env python3
"""Independent original daemon descriptor lifecycle replay; no new probe import.
Fresh original loader/CPU, recomputed external contracts, complete CPU/RAM
and instruction/read/write journals. Native IPC, event/PAC effects unknown.
O(V+H*R+J+I) time and O(R+J+I) space for visits, snapshots, RAM, journals,image.
"""
import base64,zlib,hashlib,struct
from collections import Counter
import unicorn as uc
from unicorn import arm64_const as A
from daemon_rpc502_probe import Probe as Loader
from daemon_receive_tools import IMAGE,CS,TABLE
from recover_daemon_descriptor_source import INIT,SETUP,CALLBACK,HEADER,STACK,HEAP,HALT,CFREF,CFSRC,MACHREF,RL,MODE,ARG,CBSP,OUT,REGIONS

def decode(e):
 b=zlib.decompress(base64.b64decode(e['zlib_base64']));assert len(b)==e['size_bytes']and hashlib.sha256(b).hexdigest()==e['sha256'];return b
class Replay(Loader):
 def __init__(self,p,origin=None):
  super().__init__();self.p=p;self.c=p['configuration'];self.phase=self.c['phase'];self.seq=self.ri=self.wi=self.mi=0;self.current=-1;self.pending=[];self.done=False;self.counts=Counter();self.dec={};self.u.mem_map(HEAP,0x40000);self.u.mem_write(self.import_addresses['CoreFoundation/_kCFRunLoopDefaultMode'],struct.pack('<Q',MODE))
  if origin:
   for(at,n),e in zip(REGIONS,origin['final_regions'],strict=True):assert e['address']==hex(at)and e['size_bytes']==n;self.u.mem_write(at,decode(e))
   f=origin['boundary']
   for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
   for j,v in enumerate(f['Q_registers32']):self.u.reg_write(getattr(A,'UC_ARM64_REG_Q'+str(j)),int(v,16))
   for k,key in(('PC','pc'),('SP','SP'),('NZCV','NZCV')):self.u.reg_write(getattr(A,'UC_ARM64_REG_'+k),int(f[key],16))
  expected=None if origin is None else {'label':origin['configuration']['label'],'boundary':origin['boundary'],'region_sha256':[e['sha256']for e in origin['final_regions']]};assert p['origin']==expected;self.frame(p['handoff_before']);self.fixtures();self.frame(p['entry']);self.target=self.u.reg_read(A.UC_ARM64_REG_PC);self.u.mem_protect(0x100000000,0x1038000,5);self.u.mem_protect(0x1010cc000,0x14000,1)
 def frame(self,e):
  assert e['pc']==hex(self.u.reg_read(A.UC_ARM64_REG_PC))and e['source_visit_index']==self.seq and e['registers31']==[hex(self.reg(j))for j in range(31)]and e['SP']==hex(self.u.reg_read(A.UC_ARM64_REG_SP))and e['NZCV']==hex(self.u.reg_read(A.UC_ARM64_REG_NZCV))and e['Q_registers32']==[hex(self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(j))))for j in range(32)];self.counts['complete_CPU_frames_checked']+=1
 def event(self):return struct.pack('<QhHIqQ',self.c['ident'],self.c['filter'],0,0,0,0)
 def fixtures(self):
  patches=[]
  if self.phase=='initializer':patches=([(HEAP,bytes([self.c['raw_heap_fill']])*89600)]if self.c.get('raw_heap_fill')else[])+[(ARG,struct.pack('<II',(0x5973a279*((ARG&0xffffffff)^0xdc40790b)+0x267e)&0xffffffff,0))];target=INIT;sp=STACK+0x78000;self.setreg(0,ARG)
  elif self.phase=='setup':
   target=SETUP;sp=STACK+0x78000
   for j,v in{19:0xa6,21:HEADER,22:0x3a74,23:0x0a5cd4cf,28:TABLE}.items():self.setreg(j,v)
   patches=[(sp+off,struct.pack('<Q',v))for off,v in[(0x198,0x1010c4e08),(0x1a0,0x1010c4670),(0x190,0x100fc4230),(0x188,0x101031fa0),(0xe0,0x100fc4130),(0xb8,0x101031ea0),(0x108,0x100e99a00),(0x100,0x100f4e390),(0x170,0x101031da0),(0x178,0x100e99900)]]
  else:target=CALLBACK;sp=CBSP;self.setreg(0,CFREF);self.setreg(1,1);self.setreg(2,0);patches=[(HEADER+24,struct.pack('<Q',MACHREF if self.c['mach_object']else 0)),(OUT,self.event()if self.c['event_seed']else bytes(32))]
  assert len(self.p['fixture_patches'])==len(patches)
  for(at,b),e in zip(patches,self.p['fixture_patches'],strict=True):assert e=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
  self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,sp);self.u.reg_write(A.UC_ARM64_REG_PC,target);self.counts['declared_full_state_component_entries_checked']+=1
 def finish_writes(self):
  for e in self.pending:assert e['after_hex']==bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def read_hook(self,u,access,a,n,v,d):
  e=self.p['source_reads'][self.ri];self.ri+=1;assert e=={'visit':self.current,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()};self.counts['original_reads_checked']+=1
 def write_hook(self,u,access,a,n,v,d):
  assert any(lo<=a and a+n<=lo+size for lo,size in REGIONS);e=self.p['source_writes'][self.wi];self.wi+=1;assert{key:e[key]for key in('visit','address','size_bytes','before_hex')}=={'visit':self.current,'address':hex(a),'size_bytes':n,'before_hex':bytes(u.mem_read(a,n)).hex()};self.pending.append(e);self.counts['original_writes_checked']+=1
 def external(self,a,name):
  args=[self.reg(j)for j in range(8)];result=0;patches=[];preserve=name=='libSystem/___chkstk_darwin';meta={}
  if preserve:pass
  elif name=='libSystem/_pthread_once':assert args[:2]==[0x1010b8cd0,0x10040ebd4];meta={'initializer_executed':False}
  elif name in('libSystem/_pthread_rwlock_wrlock','libSystem/_pthread_rwlock_unlock'):assert args[0]==0x1010b7478
  elif name=='libSystem/_malloc':assert self.phase=='initializer'and args[0]==89600;result=HEAP
  elif name=='libSystem/_kqueue':assert self.phase=='setup';result=self.c['fd']&0xffffffff
  elif name=='libSystem/_signal':assert args[:2]==[15,1]
  elif name=='libSystem/_kevent':
   if self.phase=='setup':assert args[0]==self.c['fd']and args[2:6]==[1,0,0,0];meta={'change32_hex':bytes(self.u.mem_read(args[1],32)).hex()};result=self.c.get('registration_status',0)&0xffffffff
   else:
    assert args[:6]==[7,0,0,OUT,1,0];result=self.c['event_result']&0xffffffff
    if self.c['event_result']>0:patches=[(OUT,self.event())]
  elif name=='CoreFoundation/_CFFileDescriptorCreate':assert args[:5]==[0,self.c['fd'],1,CALLBACK,0];result=0 if self.c.get('null_cf')else CFREF
  elif name=='CoreFoundation/_CFFileDescriptorCreateRunLoopSource':assert args[:3]==[0,CFREF,0];result=0 if self.c.get('null_source')else CFSRC
  elif name=='CoreFoundation/_CFFileDescriptorGetNativeDescriptor':assert args[0]==CFREF;result=7
  elif name=='CoreFoundation/_CFFileDescriptorEnableCallBacks':assert args[:2]==[CFREF,1]
  elif name=='CoreFoundation/_CFFileDescriptorInvalidate':assert args[0]==CFREF
  elif name=='CoreFoundation/_CFMachPortInvalidate':assert args[0]==MACHREF
  elif name=='CoreFoundation/_CFRunLoopGetMain':result=RL
  elif name=='CoreFoundation/_CFRunLoopStop':assert args[0]==RL
  elif name=='CoreFoundation/_CFRunLoopAddSource':assert args[:3]==[RL,CFSRC,MODE]
  elif name=='CoreFoundation/_CFRelease':assert args[0]in(CFREF,CFSRC)
  else:raise AssertionError(('unreviewed external',name))
  e=self.p['imports'][self.mi];self.mi+=1;assert e['pc']==hex(a)and e['name']==name and e['arguments8']==[hex(v)for v in args]and e['result']==(None if preserve else hex(result))and e['preserve_all_CPU']==preserve;self.frame(e['before'])
  for key,v in meta.items():assert e[key]==v
  assert len(e['patches'])==len(patches)
  for(at,b),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
  target=self.reg(30)
  if not preserve:
   for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
   self.setreg(0,result);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000)
  self.u.reg_write(A.UC_ARM64_REG_PC,target);self.frame(e['after']);self.counts['external_ABI_and_declared_effect_contracts_recomputed']+=1
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==HALT or(self.phase=='setup'and a in(0x100027310,0x100093518)):
   assert self.p['boundary']['kind']==('original_return_to_declared_caller'if a==HALT else'before_original_setup_continuation');self.frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if a in self.imports:return self.external(a,self.imports[a])
  assert 0x100001058<=a<0x100e2ac40;raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4)and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1
  if a not in self.dec:self.dec[a]=next(CS.disasm(raw,a))
  i=self.dec[a];op=i.mnemonic
  if op in('pacibsp','paciasp','autibsp','autiasp','paciza','pacia','pacda','autia','autiza','autda','xpaci','xpacd','xpaclri','bti'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
  elif op in('retab','retaa'):u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
  elif op in('braa','braaz','brab','brabz','blraa','blraaz','blrab','blrabz'):
   target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
   if op.startswith('blr'):self.setreg(30,a+4)
   u.reg_write(A.UC_ARM64_REG_PC,target)
  else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac'))
 def run(self):
  self.u.emu_start(self.target,0,count=100000);self.finish_writes();assert self.done and self.seq==len(self.p['source_visits'])and self.ri==len(self.p['source_reads'])and self.wi==len(self.p['source_writes'])and self.mi==len(self.p['imports'])
  for(at,n),e in zip(REGIONS,self.p['final_regions'],strict=True):assert e['address']==hex(at)and e['size_bytes']==n and decode(e)==bytes(self.u.mem_read(at,n));self.counts['complete_final_mutable_RAM_bytes_checked']+=n
  assert self.p['final_header96_hex']==bytes(self.u.mem_read(HEADER,96)).hex()and self.p['final_event32_hex']==bytes(self.u.mem_read(OUT,32)).hex();return dict(self.counts)

from replay_cf_wake_send_wrapper import Replay as CFParent
from replay_cf_source_scheduling import B as CFB,RL as CFRL,MODE as CFMODE,HALT as CFHALT,USER as CFUSER
from replay_cf_runloop_handoff import LOW,LOW_SIZE
from replay_cf_runloop_wake_port import WAKER_SP
from recover_cf_wake_send_wrapper import MACH
CFSTOP=0x184784250
class CFReplay(CFParent):
 def __init__(self,p,k,s):super().__init__(p,k,s);self.stop_fixture_checked=False
 def hook(self,u,a,n,d):
  self.finish_writes()
  if self.pi<len(self.p['public_handoffs']):
   e=self.p['public_handoffs'][self.pi]
   if e['kind']=='declared_original_Stop_entry'and e['before']['source_visit_index']==self.seq:
    assert not self.stop_fixture_checked
    if a==CFHALT:
     assert self.wphase=='registration'and self.config['wake_case']=='suppressed';f=self.p['registration_returns'][self.rri];self.check_schedule_frame(f);self.rri+=1
    else:assert a==MACH and self.wphase=='runloop'and[self.reg(j)for j in range(7)]==[CFUSER,0x07000806,0,3072,self.facility,0xffffffff,0]
    self.wphase='wakeup';f=self.p['CF_stop_fixture'];self.check_frame(f['before']);at=CFRL+0xa60;raw=struct.pack('<Q',CFMODE if self.config['active_mode']else 0);assert f['address']==hex(at)and f['before_hex']==bytes(u.mem_read(at,8)).hex()and f['after_hex']==raw.hex();u.mem_write(at,raw);self.stop_fixture_checked=True;self.check_frame(e['before']);assert e['model_state']==self.state()
    for at,n,key in((CFB,0x100000,'private_RAM_sha256'),(LOW,LOW_SIZE,'lower_stack_sha256')):assert e[key]==hashlib.sha256(bytes(u.mem_read(at,n))).hexdigest()
    self.setreg(0,CFRL);self.setreg(30,CFHALT)
    if a==MACH:assert e['declared_waker_SP']==hex(WAKER_SP);u.reg_write(A.UC_ARM64_REG_SP,WAKER_SP)
    u.reg_write(A.UC_ARM64_REG_PC,CFSTOP);self.check_frame(e['after']);self.pi+=1;self.counts['declared_CF_Stop_entry_CPU_RAM_and_current_mode_premises_checked']+=1;return
  if a==CFHALT and self.wphase=='wakeup':
   f=self.p['wake_returns'][self.wri];self.wake_frame(f,a);self.wri+=1;assert self.p['boundary']['kind']=='original_CFRunLoopStop_returned'and self.seq==len(self.p['source_visits']);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  return super().hook(u,a,n,d)
 def run(self):
  super().run();assert self.stop_fixture_checked and self.p['final_stop_flag_byte_hex']==bytes(self.u.mem_read(CFRL+0x55,1)).hex()and self.p['final_current_mode8_hex']==bytes(self.u.mem_read(CFRL+0xa60,8)).hex();return dict(self.counts)
