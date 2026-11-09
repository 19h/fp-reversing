#!/usr/bin/env python3
"""Original descriptor normalization, OOL conversion, VM factory and cleanup.
Header/namespace state and map/global/API/PAC premises are explicit fixtures.
O(visits+copied bytes) time, O(private RAM+journals) space. No native IPC/VM.
"""
import json,struct
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
from probe_kernel_vm_mig import Probe as Base,P,SIZE,SP,HALT
USER=P+0x10000;OUT=P+0x12000;CTX=P+0x14000;MSG=P+0x18000;EXT=P+0x20000;SPACE=P+0x28000;MAP=P+0x2a000;THREAD=P+0x2c000;KMAP=P+0x2e000
SOURCES=[P+0x50000,P+0x60000];COPIES=[P+0x68000,P+0x69000];BACKS=[P+0x70000,P+0x78000];ZONE=P+0x86000;AUX=P+0x88000;META=P+0x90000
def pack(x,n=8):return x.to_bytes(n,'little')
class Probe(Base):
 def __init__(self,image,cfg,fixture):
  super().__init__(image,'stub',{'port_class':'null','bits':0,'request_size':56,'address':0,'size':0,'body_placement':'joined'});self.kind=cfg['kind'];self.c=cfg;self.u.mem_write(P,bytes(SIZE));self.initial=[];self.image_initial=[];self.effects=[];self.auth=[];self.sign=[];self.cuts=[];self.active=None
  for j in range(31):self.set(j,0)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD);self.sysregs=[{'register':'TPIDR_EL1','value':hex(THREAD)}]
  if self.kind=='normalize':
   self.entry=0xfffffe000bcc3fe8;self.fixture(USER,bytes(fixture));self.fixture(OUT,bytes([0xa5])*16);self.fixture(CTX,bytes(88));self.set(0,OUT);self.set(1,USER);self.set(2,CTX);self.set(3,1);self.allowed=[(self.entry,0xfffffe000bcc4194)]
  else:
   self.entry=0xfffffe000bcc42f0;self.header=EXT if cfg['storage_class']==2 else MSG+0x40;self.fixture(MSG+0x3f,bytes([cfg['storage_class']<<6]));self.fixture(self.header,bytes(fixture))
   if cfg['storage_class']==2:self.fixture(MSG+0xe8,pack(self.header))
   for j,n in enumerate(cfg['lengths']):self.fixture(SOURCES[j],bytes((j*71+k*37+17)&255 for k in range(n)));self.fixture(COPIES[j],bytes([0xa5])*48);self.fixture(BACKS[j],bytes([0xa5])*min(max(n,64),32768))
   self.fixture(MAP+0x10,struct.pack('<QQ',P,P+SIZE));self.fixture(MAP+0x2c,bytes([14]));self.fixture(MAP+0xb0,pack(1<<25 if cfg['map_flag']else 0,4));self.fixture(ZONE+0x34,pack(48,2))
   metabase=META-((COPIES[0]>>10)&0xffffffff0)
   for a,tag in [(COPIES[0],0x13),(COPIES[1],0x13),(MAP,0x10)]:self.fixture(metabase+((a>>10)&0xffffffff0),pack(tag,2))
   for a,b in [(0xfffffe0007e66e50,struct.pack('<QQ',P,P+SIZE)),(0xfffffe0007e66f00,pack(metabase)),(0xfffffe0007f860a8,pack(KMAP)),(0xfffffe000caec2c0,struct.pack('<QQ',ZONE,AUX)),(0xfffffe0007e6a01c,pack(0,4))]:self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'declared map/zone/global initial state'})
   for j,x in enumerate([MSG,2,0,SPACE,MAP,0]):self.set(j,x)
   starts=[0xfffffe000bcc42f0,0xfffffe000bdd15a4,0xfffffe000bcc2a1c,0xfffffe000bdc6308];self.allowed=[(a,int(image.k.function(a)['end'],16))for a in starts]
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def effect(self,a,symbol,result,patches=()):
  e={'pc':hex(a),'before_source_visit_index':len(self.visits),'descriptor_index':self.active,'symbol':symbol,'patches':[],'native_effects_executed':False}
  for ptr,b,role in patches:e['patches'].append({'address':hex(ptr),'before_hex':bytes(self.u.mem_read(ptr,len(b))).hex(),'after_hex':b.hex(),'role':role});self.u.mem_write(ptr,b)
  self.effects.append(e);self.model(a,symbol,result);self.models[-1]['descriptor_index']=self.active
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('returned')
  if a==0xfffffe000be318e8:return self.stop('before_entry_list_lookup',{'working_copy':hex(COPIES[self.active])})
  if a==0xfffffe000bdd15a4:self.active=SOURCES.index(self.reg(1));self.cuts.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments5':[hex(self.reg(j))for j in range(5)],'descriptor_index':self.active})
  failed=self.active==self.c.get('failure_descriptor')
  if a==0xfffffe000bcfe5b8:return self.effect(a,'backing_allocate_model',0 if failed and self.c['failure']=='allocation'else BACKS[self.active])
  if a==0xfffffe000bd75c64:return self.effect(a,'copy_header_allocate_model',COPIES[self.active])
  if a==0xfffffe000bdc2fc0:
   error=5 if failed and self.c['failure']=='copy'else 0;return self.effect(a,'copyin_map_bytes_model',error,[]if error else[(self.reg(2),bytes(u.mem_read(self.reg(1),self.reg(3))),'private source bytes copied')])
  if a==0xfffffe000c6480c0:return self.effect(a,'header_bzero_model',0,[(self.reg(0),bytes(self.reg(1)),'private header zeroing')])
  calls={0xfffffe000bd098c8:'map_lock_model',0xfffffe000bd08ec0:'map_read_lock_model',0xfffffe000bdc3c2c:'source_region_remove_request',0xfffffe000bdc37f8:'removed_entry_release_model',0xfffffe000bcfec48:'backing_release_request',0xfffffe000bd74fcc:'copy_header_release_request',0xfffffe000bcc2f70:'message_pre_cleanup_model'}
  if a in calls:return self.model(a,calls[a],0)
  assert any(lo<=a<hi for lo,hi in self.allowed),hex(a);raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['pacibsp','autibsp']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif i.mnemonic=='retab':u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  elif i.mnemonic=='autda':self.auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif i.mnemonic=='pacda':self.sign.append({'pc':hex(a),'pointer':hex(self.reg(17)),'modifier':hex(self.reg(16)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  assert i.mnemonic not in ['svc','hvc','smc','brk','blraa']
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=30000);self.flush();assert self.reason in ['returned','before_entry_list_lookup'],self.boundary
  r={'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'declared_effects':self.effects,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'private_system_register_fixtures':self.sysregs,'VM_copyin_entries':self.cuts,'boundary':self.boundary,'return_u32':self.reg(0)&0xffffffff,'native_target_executed':False,'native_VM_effects_executed':False,'hardware_PAC_executed':False}
  if self.kind=='normalize':r['normalized_descriptor_hex']=bytes(self.u.mem_read(OUT,16)).hex();r['normalization_context_hex']=bytes(self.u.mem_read(CTX,88)).hex()
  else:r.update({'message_header_address':hex(self.header),'message_inline_hex':bytes(self.u.mem_read(self.header,392)).hex(),'copy_headers_hex':[bytes(self.u.mem_read(a,48)).hex()for a in COPIES],'backing_bytes_hex':[bytes(self.u.mem_read(a,min(max(n,64),32768))).hex()for a,n in zip(BACKS,self.c['lengths'],strict=True)]})
  return r

def main():
 image=Image();prior=json.loads((ROOT/'rpc502_reply_bridge_profiles.json').read_text());seed=next(r for r in prior['cases']if r['kind']=='daemon_completion'and r['configuration']['application_status']==0 and r['configuration']['count0']==1);rows=[];patterns=[(0,0),(1,37),(4096,8192),(32768,1),(32769,1)];fixtures=[];normalization=[]
 for pi,lens in enumerate(patterns):
  raw=bytearray.fromhex(seed['reply_storage_hex'])
  for j,n in enumerate(lens):raw[40+16*j:44+16*j]=pack(n,4);raw[376+4*j:380+4*j]=pack(n,4)
  out=[];indices=[]
  for j in range(2):
   cfg={'kind':'normalize','pattern_index':pi,'descriptor_index':j,'lengths':list(lens)};r=Probe(image,cfg,raw[28+16*j:44+16*j]).run();indices.append(len(rows));rows.append(r);out.append(bytes.fromhex(r['normalized_descriptor_hex']))
  header=struct.pack('<IIQQII',0x80000012,392,P+0x24000,0,0,602)+raw[24:384];header=bytearray(header);header[36:68]=b''.join(out);fixtures.append(bytes(header));normalization.append(indices)
 base={'kind':'body','failure':'none','failure_descriptor':None}
 configs=[]
 for pi in range(4):
  for storage in [0,2]:
   for flag in [False,True]:configs.append({**base,'pattern_index':pi,'lengths':list(patterns[pi]),'storage_class':storage,'map_flag':flag,'case':'success'})
 for failure in ['allocation','copy']:
  for which in [0,1]:
   for storage in [0,2]:
    for flag in [False,True]:configs.append({**base,'pattern_index':1,'lengths':list(patterns[1]),'storage_class':storage,'map_flag':flag,'case':failure+'_failure','failure':failure,'failure_descriptor':which})
 for storage in [0,2]:
  for flag in [False,True]:configs.append({**base,'pattern_index':4,'lengths':list(patterns[4]),'storage_class':storage,'map_flag':flag,'case':'entry_list_frontier'})
 for cfg in configs:
  cfg['normalization_cases']=normalization[cfg['pattern_index']];r=Probe(image,cfg,fixtures[cfg['pattern_index']]).run();rows.append(r);print(len(rows)-1,cfg['case'],cfg['failure_descriptor'],r['boundary']['kind'],r['return_u32'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_reply_copyin_source.json','rpc502_reply_bridge_profiles.json','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'seed_emitter_case_sha256':sha(ROOT/'rpc502_reply_bridge_profiles.json'),'pattern_lengths':patterns,'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_namespace_conversion_executed':False,'native_source_region_removal_executed':False,'native_IPC_executed':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/'rpc502_reply_copyin_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
