#!/usr/bin/env python3
"""Original type3 VM-copyout/discard control with declared VM/copy/free effects.
Private metadata and map state are premises; effects do not operate native VM.
O(cases*visits+copied bytes) time, O(private map+journals) space.
"""
import json,struct
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
from probe_kernel_vm_mig import Probe as Base,P,SIZE,SP,HALT
MAP=P+0x3000;THREAD=P+0x4000;OTHER=P+0x5000;OUT=P+0x10000;COPY=P+0x68000;DATA=P+0x70000;DEST=P+0x50000;ZONE=P+0x60000;AUX=P+0x62000;META=P+0x90000
COUNTER=0xfffffe000cb810f0
def pack(v,n=8):return v.to_bytes(n,'little')
class Probe(Base):
 def __init__(self,image,cfg):
  super().__init__(image,'stub',{'port_class':'null','bits':0,'request_size':56,'address':0,'size':0,'body_placement':'joined'});self.kind=cfg['kind'];self.c=cfg;self.u.mem_write(P,bytes(SIZE));self.initial=[];self.image_initial=[];self.effects=[];self.auth=[];self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD);self.sysregs=[{'register':'TPIDR_EL1','value':hex(THREAD)}]
  for j in range(31):self.set(j,0)
  self.set(30,HALT);n=cfg['extent'];self.payload=bytes((j*37+17)&255 for j in range(n));self.fixture(DATA,self.payload);self.fixture(DEST,bytes([0xa5])*max(n,64));self.fixture(OUT,pack(0xa5a5a5a5));self.fixture(COPY,pack(DATA)+bytes(24)+pack(n)+bytes(4)+bytes([14,3,int(n>32768),0]));self.fixture(MAP+0x2c,bytes([14]));self.fixture(MAP+0x88,pack(3,4));self.fixture(THREAD+0x428,pack(MAP if cfg['same_map']else OTHER));self.fixture(THREAD+0x1c0,pack(P+0x6000));self.fixture(ZONE+0x34,pack(48,2))
  metabase=META-((COPY>>10)&0xffffffff0)
  for a,tag in [(COPY,0x13),(MAP,0x10)]:self.fixture(metabase+((a>>10)&0xffffffff0),pack(tag,2))
  globals_=[(0xfffffe0007e66e50,struct.pack('<QQ',P,P+SIZE)),(0xfffffe0007e66f00,pack(metabase)),(0xfffffe0007f860a8,pack(MAP)),(0xfffffe000caec2c0,struct.pack('<QQ',ZONE,AUX)),(COUNTER,pack(7,4))]
  for a,b in globals_:self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'declared private zone/map/global state'})
  if self.kind=='discard':self.entry=0xfffffe000bdc6308;self.set(0,0 if cfg['null']else COPY)
  else:
   self.entry=0xfffffe000bdd1574 if cfg['consume']and not cfg['mismatch']else 0xfffffe000bdcb374;self.set(0,MAP);self.set(1,OUT);self.set(2,0 if cfg['null']else COPY);self.set(3,n+int(cfg['mismatch']));self.set(4,cfg['consume'])
  funcs=[0xfffffe000bdd1574,0xfffffe000bdcb374,0xfffffe000bdcbbb0,0xfffffe000bdc6308,0xfffffe000bdcc234,0xfffffe000bdcc374];self.allowed=[(a,int(image.k.function(a)['end'],16))for a in funcs];self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def effect(self,a,symbol,result,patches=()):
  event={'pc':hex(a),'before_source_visit_index':len(self.visits),'symbol':symbol,'patches':[],'native_effects_executed':False}
  if a==0xfffffe000bdc76b4:event['stack_prefix12_hex']=bytes(self.u.mem_read(self.u.reg_read(ar.UC_ARM64_REG_SP),12)).hex()
  for ptr,b,role in patches:event['patches'].append({'address':hex(ptr),'before_hex':bytes(self.u.mem_read(ptr,len(b))).hex(),'after_hex':b.hex(),'role':role});self.u.mem_write(ptr,b)
  self.effects.append(event);self.model(a,symbol,result)
 def write(self,u,t,a,n,v,d):
  if a==COUNTER:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('returned')
  if a==0xfffffe000bdc76b4:return self.effect(a,'VM_allocate_model',self.c['allocation_result'],[]if self.c['allocation_result']else[(self.reg(1),pack(DEST),'allocated address')])
  if a==0xfffffe000be7798c:return self.effect(a,'copyout_model',self.c['copy_result'],[]if self.c['copy_result']else[(self.reg(1),bytes(u.mem_read(self.reg(0),self.reg(2))),'private copied bytes')])
  if a==0xfffffe000c6480c0:return self.effect(a,'bzero_model',0,[(self.reg(0),bytes(self.reg(1)),'private header zeroing')])
  if a==0xfffffe000be63ea0:return self.effect(a,'map_switch_leaf_model',0,[(self.reg(0)+0x428,pack(self.reg(1)),'private current-map switch/restore')])
  calls={0xfffffe000bcfec48:'payload_release_request',0xfffffe000bd74fcc:'copy_header_release_request',0xfffffe000bd098c8:'map_lock_model',0xfffffe000bd0a08c:'map_unlock_model',0xfffffe000bdc3c2c:'map_range_remove_model',0xfffffe000bdc37f8:'removed_entry_release_model',0xfffffe000c266d34:'VM_error_observer_model'}
  if a in calls:return self.model(a,calls[a],0)
  assert any(lo<=a<hi for lo,hi in self.allowed),hex(a);raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['pacibsp','autibsp']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif i.mnemonic=='retab':u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  elif i.mnemonic=='autda':self.auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  assert i.mnemonic not in ['svc','hvc','smc','brk','pacda','blraa']
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason=='returned'
  return {'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'declared_effects':self.effects,'logical_data_authentication':self.auth,'private_system_register_fixtures':self.sysregs,'boundary':self.boundary,'return_u32':self.reg(0)&0xffffffff,'copy_header_hex':bytes(self.u.mem_read(COPY,48)).hex(),'mapped_address':int.from_bytes(bytes(self.u.mem_read(OUT,8)),'little'),'mapped_bytes_hex':bytes(self.u.mem_read(DEST,max(self.c['extent'],64))).hex(),'map_refs':int.from_bytes(bytes(self.u.mem_read(MAP+0x88,4)),'little'),'current_map':hex(int.from_bytes(bytes(self.u.mem_read(THREAD+0x428,8)),'little')),'copy_error_counter':int.from_bytes(bytes(self.u.mem_read(COUNTER,4)),'little'),'native_target_executed':False,'native_VM_effects_executed':False,'hardware_PAC_executed':False}

def configurations():
 base={'kind':'copyout','extent':37,'same_map':True,'consume':1,'mismatch':False,'allocation_result':0,'copy_result':0,'null':False};out=[]
 for n in [1,37,32768,32769]:
  for same in [True,False]:
   for label,changes in [('success',{}),('allocation_error',{'allocation_result':6}),('copy_error',{'copy_result':5}),('borrowed_success',{'consume':0})]:out.append({**base,'case':label,'extent':n,'same_map':same,**changes})
 for n in [1,37,32768,32769]:out.append({**base,'kind':'discard','case':'discard','extent':n})
 for kind in ['copyout','discard']:out.append({**base,'kind':kind,'case':'null','null':True})
 for n in [1,32769]:
  for same in [True,False]:out.append({**base,'case':'extent_mismatch','extent':n,'same_map':same,'mismatch':True})
 return out
if __name__=='__main__':
 image=Image();rows=[]
 for j,cfg in enumerate(configurations()):
  r=Probe(image,cfg).run();rows.append(r);print(j,cfg['case'],cfg['same_map'],r['return_u32'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_reply_copyout_source.json','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/'kernel_reply_copyout_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
