#!/usr/bin/env python3
"""Private original allocator/free delegates and conditional FairPlay caller.
No allocation/free or native PAC executes. Runtime zone/stats/CPU fields and
caller seed W20=0xc96 are explicit premises. O(image bytes+visits) time/space.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as Base,P,SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,TABLE
from recover_kext_security_record import sha
PREFIX='kext_security_record';REC=P+0x4000;THREAD=P+0x5000;ZONE=P+0x6000;ALT=P+0x7000;C=P+0x9000;STATS=P+0x10000;AMBIENT=P+0x3000
class Probe(Base):
 def __init__(self,image,kind,cfg):
  super().__init__(image,'selector',{'id':0});self.kind=kind;self.c=cfg;self.initial=[];self.initial_image=[];self.image_initial=[];self.edges=[]
  for j in range(31):self.set(j,0)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0);self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  self.allowed=[(0xfffffe000c4ba154,0xfffffe000c4ba170),(0xfffffe000bcfeb8c,0xfffffe000bcfec2c),(0xfffffe000c4ba368,0xfffffe000c4ba370),(0xfffffe000bcff010,0xfffffe000bcff054),(0xfffffe000a60aaa0,0xfffffe000a60abb8),(0xfffffe000a5a21ec,0xfffffe000a5a2228)]
  view=0xfffffe000847bc60 if kind=='free'else 0xfffffe000847bd60
  self.fixture(REC,bytes([0xa5])*152);self.fixture(THREAD+0x1b8,struct.pack('<H',cfg['cpu_index']));self.fixture(STATS+cfg['cpu_index']*0x4000+0x1c,struct.pack('<I',1 if cfg['route']=='zone'else 0));self.fixture(C,bytes([0x5a])*0xa0);self.fixture(AMBIENT,struct.pack('<II',0x12345678,0xabcdef01))
  if cfg['route']!='heap':
   for a,b in [(view,struct.pack('<QQ',ZONE,STATS)),(view+0x30,struct.pack('<Q',ALT))]:self.image_fixture(a,b)
  if kind=='copy':
   self.entry=0xfffffe000a5a21ec;self.set(21,REC);self.fixture(REC,bytes.fromhex(cfg['record_initial152_hex']));self.fixture(SP+0x54,bytes.fromhex(cfg['input_record136_hex']))
  elif kind=='caller':
   self.entry=0xfffffe000a60aaa0;fp=SP+0x2d0
   for a,b in [(SP+0x1a8,struct.pack('<Q',C)),(SP+0x1b0,struct.pack('<QQ',0xfffffe000792fcc0,0xfffffe00079391f0)),(fp-0xf8,struct.pack('<QQ',0xfffffe000792fec0,0xfffffe0007949ed0)),(fp-0xa0,struct.pack('<QQ',AMBIENT,AMBIENT+4)),(fp-0xb8,struct.pack('<QQ',0xfffffe0007949dd0,0xfffffe000792fbc0)),(fp-0x90,struct.pack('<Q',TABLE))]:self.fixture(a,b)
   for j,v in {10:AMBIENT,11:AMBIENT+4,12:TABLE,13:0xa41a4d891208c018,20:0xc96,22:0x87,28:C,29:fp}.items():self.set(j,v)
  elif kind=='allocate':self.entry=0xfffffe000c4ba154;self.set(0,view)
  else:assert kind=='free';self.entry=0xfffffe000c4ba368;self.set(0,view);self.set(1,cfg['record_value'])
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def image_fixture(self,a,b):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'Explicit private runtime-view field premise; native initialization unknown.'})
 def code(self,u,a,n,d):
  self.flush()
  if a in [HALT,0xfffffe000a60abb8,0xfffffe000a608958,0xfffffe000bcfec48,0xfffffe000bd7a4b8,0xfffffe000a5a2228]:return self.stop('component_boundary')
  if a in [0xfffffe000bcfe5b8,0xfffffe000bd75c64]:return self.model(a,'typed_allocator_lower_model',self.c['record_value'])
  assert any(x<=a<z for x,z in self.allowed),hex(a)
  self.ensure(a,4);raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);ins=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if ins.mnemonic in ['pacibsp','autibsp','retab']:
   return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30)if ins.mnemonic=='retab'else a+4)
  if ins.mnemonic in ['braa','blraa']:
   target=self.reg(int(ins.op_str.split(',')[0][1:]));self.edges.append({'pc':hex(a),'visit':len(self.visits)-1,'kind':ins.mnemonic,'target':hex(target),'modifier':hex(self.reg(17))})
   if ins.mnemonic=='blraa':assert(a,target,self.reg(17))==(0xfffffe000a60ab2c,0xfffffe000c4ba154,0xd0c8);self.set(30,a+4)
   else:assert a==0xfffffe000a60ab70 and target in [0xfffffe000a60ab74,0xfffffe000a608958]
   return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert ins.mnemonic not in ['svc','hvc','smc','autda','brk']
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=10000);self.flush();assert self.reason=='component_boundary'
  return {'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'private_TPIDR_EL1':hex(THREAD),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_edges':self.edges,'boundary':self.boundary,'final_record152_hex':bytes(self.u.mem_read(REC,152)).hex(),'final_C160_hex':bytes(self.u.mem_read(C,160)).hex(),'native_target_executed':False,'native_allocation_executed':False,'native_free_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();rows=[]
 for kind in ['allocate','caller','free']:
  for route in ['heap','zone','alternate']:
   for cpu in [0,3]:
    for value in [0,REC]:rows.append(Probe(im,kind,{'route':route,'cpu_index':cpu,'record_value':value}).run())
 for j,row in list(enumerate(rows)):
  if row['kind']=='caller'and row['configuration']['record_value']:
   cfg={**row['configuration'],'source_caller_case_index':j,'record_initial152_hex':row['final_record152_hex'],'input_record136_hex':bytes((n*17+j)&255 for n in range(136)).hex()};rows.append(Probe(im,'copy',cfg).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['probe_kernel_vm_mig.py','kext_security_record_source.json','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_allocation_executed':False,'native_free_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
