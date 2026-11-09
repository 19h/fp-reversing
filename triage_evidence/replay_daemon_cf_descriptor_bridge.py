#!/usr/bin/env python3
"""Independent original daemon/CF initializer/setup/callback/cleanup replay.
No new probe import. Complete tracked CPU, original reads/writes, logical CF
binds, syscall/array/hash contracts and explicit cancel delivery recomputed.
No native startup/IPC/thread/PAC. O(V*F+J+H*R),O(I+J+R).
"""
import struct,hashlib,zlib,base64
from unicorn import arm64_const as A
from daemon_receive_tools import IMAGE,CS,TABLE as DTABLE
from replay_cf_public_runloop import Replay as Parent
from replay_cf_wake_send_wrapper import Replay as Wrapper,MACH
from replay_cf_descriptor_source_factory import FDO,READ,WRITE
from replay_cf_source_scheduling import B,RL,MODE,SRC,SET0,SET1,BAG,HALT
from recover_cf_runloop_wake_port import DEFAULT
from recover_cf_source_wake_callers import WAKE
from recover_daemon_cf_descriptor_bridge import FUNCS,INIT,SETUP,CALLBACK,HEADER,SETUP_END
HEAP=0x5000000000;ARG=B+0xd0000;MODES=B+0xd1000;SETUP_SP=B+0x70000;OPAQUE=HEAP+0x30000;INIT_RETURN=HALT+0x300;CANCEL_RETURN=HALT+0x400
EXTRA=[(0x101038000,0x7c000),(0x1010b4000,0x18000),(HEAP,0x40000),(0x70000000,0x80000),(0x6000000000,0x100000)]
class Replay(Parent):
 def __init__(self,p,k,s):
  super().__init__(p,k,s);self.daemon_phase=None;self.init_done=self.setup_done=False;self.init_saved=self.setup_saved=None;self.bfi=self.dmi=self.cbi_bridge=self.dri=0;self.active_callback=None;self.cancelled=[];self.remove_calls=[];self.drain_saved=None;self.drain_index=0;self.drain_done=False
  original_start=self.u.emu_start;self.u.emu_start=lambda start,end,timeout=0,count=0:original_start(start,end,timeout,count=150000);self.u.mem_map(HEAP,0x40000)
  wanted=[(HEAP,bytes([self.config.get('heap_fill',0)])*89600+b'\xa5'),(ARG,struct.pack('<II',(0x5973a279*((ARG&0xffffffff)^0xdc40790b)+0x267e)&0xffffffff,0)+b'\xa5')]+[(at+0x12,struct.pack('<H',1))for at in(SET0,SET1,BAG)]+[(MODES,bytes(64)+b'\xa5'),(OPAQUE,bytes(8)+b'\xa5')]+[(int(e['slot'],16),struct.pack('<Q',int(e['target'],16)))for e in s['bridge_bindings']]+[(self.import_addresses['CoreFoundation/_kCFRunLoopDefaultMode'],struct.pack('<Q',DEFAULT)),(0x1ed8912b8,b'\xff'*8),(0x1ed8913f0,struct.pack('<Q',RL))];assert len(p['bridge_initial'])==len(wanted)
  for(at,b),e in zip(wanted,p['bridge_initial'],strict=True):assert e=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
 def bf(self,e,a):
  assert e['pc']==hex(a)and e['daemon_phase']==self.daemon_phase;self.check_frame(e)
  for at,n,key in((HEADER,96,'header96_hex'),(FDO,112,'descriptor112_hex'),(SRC,184,'source184_hex'),(RL,2720,'runloop2720_hex')):assert e[key]==bytes(self.u.mem_read(at,n)).hex()
  assert e['model_state']==self.state();self.counts['same_epoch_daemon_CF_tracked_CPU_header_source_frames_checked']+=1
 def restore_component(self,f):
  for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
  for j,v in enumerate(f['Q_registers32']):self.u.reg_write(getattr(A,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  self.u.reg_write(A.UC_ARM64_REG_SP,int(f['SP'],16));self.u.reg_write(A.UC_ARM64_REG_NZCV,int(f['NZCV'],16));self.u.reg_write(A.UC_ARM64_REG_PC,int(f['pc'],16))
 def start_init(self):
  e=self.p['bridge_component_entries'][0];assert e['kind']=='declared_initializer_entry';self.bf(e['before'],HALT);self.init_saved=e['before'];self.init_done=True;self.daemon_phase='initializer';self.setreg(0,ARG);self.setreg(30,INIT_RETURN);self.u.reg_write(A.UC_ARM64_REG_PC,INIT);self.bf(e['after'],INIT)
 def start_setup(self):
  e=self.p['bridge_component_entries'][1];assert e['kind']=='declared_setup_component_entry';self.bf(e['before'],HALT);self.setup_saved=e['before'];self.daemon_phase='setup';self.stage='daemon_setup';items=[(0x198,0x1010c4e08),(0x1a0,0x1010c4670),(0x190,0x100fc4230),(0x188,0x101031fa0),(0xe0,0x100fc4130),(0xb8,0x101031ea0),(0x108,0x100e99a00),(0x100,0x100f4e390),(0x170,0x101031da0),(0x178,0x100e99900)];assert len(e['patches'])==len(items)
  for(off,v),row in zip(items,e['patches'],strict=True):a=SETUP_SP+off;b=struct.pack('<Q',v);assert row=={'address':hex(a),'before_hex':bytes(self.u.mem_read(a,8)).hex(),'after_hex':b.hex()};self.u.mem_write(a,b)
  for j,v in{19:0xa6,21:HEADER,22:0x3a74,23:0x0a5cd4cf,28:DTABLE}.items():self.setreg(j,v)
  self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,SETUP_SP);self.u.reg_write(A.UC_ARM64_REG_PC,SETUP);self.bf(e['after'],SETUP)
 def daemon_model(self,a,name):
  x=[self.reg(j)for j in range(8)];value=0;patches=[];meta={};preserve=name=='libSystem/___chkstk_darwin'
  if preserve:pass
  elif name=='libSystem/_pthread_once':assert x[:2]==[0x1010b8cd0,0x10040ebd4];meta={'initializer_body_executed':False}
  elif name in('libSystem/_pthread_rwlock_wrlock','libSystem/_pthread_rwlock_unlock'):assert x[0]==0x1010b7478
  elif name=='libSystem/_malloc':assert self.daemon_phase=='initializer'and x[0]==89600;value=HEAP
  elif name=='libSystem/_kqueue':assert self.daemon_phase=='setup';value=7
  elif name=='libSystem/_signal':assert x[:2]==[15,1]
  elif name=='libSystem/_kevent':
   assert x[0]==7
   if self.daemon_phase=='setup':assert x[2:6]==[1,0,0,0];meta={'change32_hex':bytes(self.u.mem_read(x[1],32)).hex()};value=self.config.get('registration_status',0)&0xffffffff
   else:
    assert self.daemon_phase=='callback'and x[1:3]==[0,0]and x[4:6]==[1,0];value=self.config.get('event_result',1)&0xffffffff;meta={'event_output':hex(x[3])}
    if self.config.get('event_result',1)>0:patches=[(x[3],struct.pack('<QhHIqQ',self.config.get('ident',15),self.config.get('filter',-6),0,0,0,0))]
  elif name=='CoreFoundation/_CFMachPortInvalidate':assert self.config.get('mach_object')and x[0]==OPAQUE;meta={'opaque_CF_object':True}
  else:raise AssertionError(('unreviewed daemon import',name))
  e=self.p['daemon_external_models'][self.dmi];self.dmi+=1;assert e['pc']==hex(a)and e['name']==name and e['arguments8']==[hex(v)for v in x]and e['result']==(None if preserve else hex(value))and e['preserve_all_tracked_CPU']==preserve;self.bf(e['before'],a)
  for k,v in meta.items():assert e[k]==v
  assert len(e['patches'])==len(patches)
  for(at,b),row in zip(patches,e['patches'],strict=True):assert row=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
  ret=self.reg(30)
  if not preserve:
   for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
   self.setreg(0,value);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000)
  self.u.reg_write(A.UC_ARM64_REG_PC,ret);self.bf(e['after'],ret);self.counts['daemon_external_contracts_recomputed_in_CF_epoch']+=1
 def bridge_lower(self,a):
  x=[self.reg(j)for j in range(9)];before=self.state();value=0;patches=[];name=None
  if a==0x1846fb960 and x[0]==BAG:assert x[1:3]==[RL,RL];name='declared_bridge_bag_add_metadata';self.collections[BAG].add(RL);self.bag_counts[RL]=self.bag_counts.get(RL,0)+1;patches=[(BAG+0x14,struct.pack('<I',1)),(BAG+0x1a,b'\x01')]
  elif a==0x1846dc364 and x[:2]==[BAG,4]:name='declared_bridge_bag_type4'
  elif a==0x18471c584 and x[0]==BAG:assert x[1]==0;name='declared_bridge_bag_bucket';patches=[(x[8],struct.pack('<4Q',0,RL,RL,1))]
  elif a==0x184757e4c:assert x[0]==RL;name='declared_bridge_registered_mode_array';value=MODES
  elif a==0x1846f5978 and x[0]==MODES:name='declared_bridge_mode_array_count';value=1
  elif a==0x1846f7424 and x[0]==MODES:assert x[1]==0;name='declared_bridge_mode_array_value';value=DEFAULT
  elif a==0x1847170cc:
   assert x[0]in(SET0,SET1)and x[1]==SRC;name='declared_bridge_hash_remove';value=int(SRC in self.collections[x[0]]);self.collections[x[0]].discard(SRC);patches=[(x[0]+0x14,struct.pack('<I',len(self.collections[x[0]])))];self.remove_calls.append({'set':hex(x[0]),'key':hex(SRC),'removed':bool(value),'source_visit_index':self.seq})
  elif a==0x188076630:assert x[0]in(READ,WRITE);name='declared_bridge_dispatch_cancel';self.cancelled.append(x[0])
  elif a==0x188084be0:assert x[:2]==[7,2];name='declared_bridge_shutdown_request'
  elif a==0x18806c5c0:assert bytes(self.u.mem_read(x[0],10))==b'/dev/null\0'and x[1]==0;name='declared_bridge_null_device_open';value=13
  elif a==0x188085b10:assert x[:2]==[13,7];name='declared_bridge_dup2_request';value=7
  elif a==0x1880765d0 and x[0]in(READ,WRITE):name='declared_bridge_dispatch_release'
  if name:self.mode_call(a,name,value,patches,before=before);self.counts['bridge_array_hash_cancel_POSIX_contracts_recomputed']+=1;return True
  return False
 def lower(self,a):
  if a==0x188086d70 and self.active_callback:
   stage=self.stage;ready=self.config['perform_ready'];self.stage='enable';self.config['enable_ready']=False
   try:return super().lower(a)
   finally:self.stage=stage;self.config['enable_ready']=True;self.config['perform_ready']=ready
  return super().lower(a)
 def next_cancel(self):
  if self.drain_index==len(self.cancelled):self.restore_component(self.drain_saved);self.drain_done=True;self.bf(self.p['declared_cancel_deliveries'][-1]['public_observation_restored'],HALT);return
  e=self.p['declared_cancel_deliveries'][self.dri];self.dri+=1;source=self.cancelled[self.drain_index];block=self.handlers[source]['cancel'];raw=bytes(self.u.mem_read(block,44));target=int.from_bytes(raw[16:24],'little');assert e['source']==hex(source)and e['block']==hex(block)and e['copied44_hex']==raw.hex();self.bf(e['before'],self.u.reg_read(A.UC_ARM64_REG_PC));self.setreg(0,block);self.setreg(30,CANCEL_RETURN);self.u.reg_write(A.UC_ARM64_REG_PC,target);self.bf(e['entry'],target)
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==CANCEL_RETURN:self.bf(self.p['declared_cancel_deliveries'][self.dri-1]['returned'],a);self.drain_index+=1;return self.next_cancel()
  if a==HALT and self.stage=='runloop'and self.config.get('drain_cancel')and not self.drain_done and self.drain_saved is None:self.drain_saved=self.p['public_return_before_cancel_delivery'];self.bf(self.drain_saved,a);return self.next_cancel()
  if a==HALT and self.wphase=='installer'and not self.init_done:return self.start_init()
  if a==INIT_RETURN:
   e=self.p['bridge_component_entries'][0];self.bf(e['returned'],a);self.restore_component(self.init_saved);self.daemon_phase=None;self.bf(e['resume'],HALT);return
  if a==HALT and self.wphase=='create'and not self.setup_done:
   self.wake_frame(self.p['wake_returns'][self.wri],a);self.wri+=1;assert self.reg(0)==RL;return self.start_setup()
  if a==SETUP_END and self.daemon_phase=='setup':
   e=self.p['bridge_component_entries'][1];self.bf(e['returned'],a);self.restore_component(self.setup_saved);self.daemon_phase=None;self.setup_done=True;self.stage=self.wphase='fd_register';self.bf(e['resume'],HALT);return
  if a==CALLBACK and self.active_callback is None:
   assert self.daemon_phase is None and self.reg(0)==FDO and int.from_bytes(bytes(u.mem_read(HEADER+0x50,8)),'little')==FDO;self.daemon_phase='callback';e=self.p['original_daemon_callbacks'][self.cbi_bridge];self.cbi_bridge+=1;self.bf(e['entry_before'],a);assert e['return_pc']==hex(self.reg(30));self.active_callback=e;changes=[(HEADER+0x18,struct.pack('<Q',OPAQUE if self.config.get('mach_object')else 0))]
   if self.config.get('event_result',1)<=0:
    raw=struct.pack('<QhHIqQ',self.config.get('ident',15),self.config.get('filter',-6),0,0,0,0)if self.config.get('seed_event')else bytes(32);changes.append((u.reg_read(A.UC_ARM64_REG_SP)-0x149c,raw))
   assert len(e['patches'])==len(changes)
   for(at,b),row in zip(changes,e['patches'],strict=True):assert row=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};u.mem_write(at,b)
   self.bf(e['entry_after'],a)
  if self.active_callback and a==int(self.active_callback['return_pc'],16):self.bf(self.active_callback['returned'],a);self.active_callback=None;self.daemon_phase=None;self.counts['original_daemon_callback_returns_to_original_CF_checked']+=1
  if a==WAKE and self.active_callback:self.wphase='wakeup'
  if a==MACH and self.active_callback and self.reg(1)==0x11:return Wrapper.hook(self,u,a,n,d)
  if self.daemon_phase and a in self.imports:return self.daemon_model(a,self.imports[a])
  if self.bridge_lower(a):return
  if self.bfi<len(self.p['bridge_frames']):
   e=self.p['bridge_frames'][self.bfi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    if self.daemon_phase and 0x100001058<=a<0x100e2ac40 and self.wphase=='wakeup':self.wphase='runloop'
    self.bf(e,a);self.bfi+=1
  if self.daemon_phase and 0x100001058<=a<0x100e2ac40:
   if self.wphase=='wakeup':self.wphase='runloop'
   raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4)and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};i=next(CS.disasm(raw,a));self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['original_daemon_in_CF_epoch_visits_checked']+=1;op=i.mnemonic
   if op in('pacibsp','paciasp','autibsp','autiasp','paciza','pacia','pacda','autia','autiza','autda','xpaci','xpacd','xpaclri','bti'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op in('retab','retaa'):u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('braa','braaz','brab','brabz','blraa','blraaz','blrab','blrabz'):
    target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac'))
   return
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in FUNCS and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};i=next(CS.disasm(raw,a));self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['original_CF_invalidation_removal_GetMain_cancel_visits_checked']+=1;op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autiza','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac'))
   return
  return super().hook(u,a,n,d)
 def run(self):
  super().run();assert self.init_done and self.setup_done and self.active_callback is None and self.bfi==len(self.p['bridge_frames'])and self.dmi==len(self.p['daemon_external_models'])and self.cbi_bridge==len(self.p['original_daemon_callbacks'])and self.p['cancel_requests']==[hex(v)for v in self.cancelled]and self.p['hash_remove_calls']==self.remove_calls and self.dri==len(self.p['declared_cancel_deliveries'])
  assert self.p['final_header96_hex']==bytes(self.u.mem_read(HEADER,96)).hex()
  for(at,n),e in zip(EXTRA,self.p['final_daemon_regions'],strict=True):raw=zlib.decompress(base64.b64decode(e['zlib_base64']));assert e['address']==hex(at)and len(raw)==e['size_bytes']==n and hashlib.sha256(raw).hexdigest()==e['sha256']and raw==bytes(self.u.mem_read(at,n));self.counts['whole_final_additional_daemon_mutable_bytes_checked']+=n
  return dict(self.counts)
