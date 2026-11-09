#!/usr/bin/env python3
"""Original close suffix in private CPU state. O(mapped bytes+visits) time/space.
Entry follows a declared parent/tag/registry premise; no successful native close
or lookup is asserted. VM/unwire/typed-free calls are no-effect return models.
Logical authenticated edges do not test hardware PAC. No native API executes.
"""
import hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
import unicorn as uc
from probe_kext_close import Close
from kext_port_tools import ROOT,IMAGE,CS,TABLE
PREFIX='kext_mapped_cleanup';START=0xfffffe000a5c0d78;STOP=0xfffffe000a5c119c
RAM=0x6100000000;PARENT=RAM+0x1000;RECORD=RAM+0x2000;AMBIENT=RAM+0x3000;KMAP=RAM+0x4000
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
class Probe(Close):
 def __init__(self,fixture):
  super().__init__(0,1);self.fixture=fixture;self.initial_memory=[];self.allreads=[];self.models=[];self.edges=[];self.u.mem_map(RAM,0x10000);self.sp=self.u.reg_read(ar.UC_ARM64_REG_SP)
  def put(a,b):
   for pg in range(a&~4095,(a+len(b)+4095)&~4095,4096):
    if not any(x<=pg<z for x,z,_ in self.u.mem_regions()):self.u.mem_map(pg,4096)
   self.u.mem_write(a,b);self.initial_memory.append({'address':hex(a),'bytes_hex':b.hex()})
  self.put=put
  parent=bytearray(0x300);struct.pack_into('<Q',parent,0x2e8,RECORD if fixture['record_present']else 0);put(PARENT,bytes(parent))
  record=bytearray([0xa5]*0x80)
  for off,fmt,v in [(0x48,'Q',fixture['address']),(0x50,'I',fixture['extent']),(0x58,'Q',fixture['aux_address']),(0x60,'I',fixture['aux_extent'])]:struct.pack_into('<'+fmt,record,off,v)
  put(RECORD,bytes(record));put(AMBIENT,struct.pack('<II',*fixture['ambient_words']))
  put(0xfffffe0007f860a8,struct.pack('<Q',KMAP));put(0xfffffe0007e6d9c0,struct.pack('<I',fixture['page_shift']))
  for off,v in [(8,0xfffffe00079391f0),(0x10,0xfffffe000792fcc0),(0x48,0xfffffe0007949dd0),(0x50,0xfffffe000792fbc0),(0x58,0xfffffe000792ffc0)]:put(self.sp+off,struct.pack('<Q',v))
  regs={0:0xcb262240,13:0xfffffe0007949dd0,14:0xfffffe000792fbc0,15:0xa41a4d891208c018,19:0xfffffe0007949fd0,20:PARENT,21:0x1eb,24:AMBIENT,25:AMBIENT+4,26:TABLE}
  for n,v in regs.items():self.setreg(n,v)
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,0x20000000);self.initial_registers=[hex(self.reg(j))for j in range(31)]
 def hook(self,u,a,n,d):
  self.flush()
  if a==STOP:return self.stop('post_record_cleanup_boundary',X20=hex(self.reg(20)))
  assert START<=a<STOP,hex(a)
  raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.pool[a]=raw;self.visits.append(a);i=next(CS.disasm(raw,a));m=i.mnemonic
  if m in ['blraa','braa']:
   target=self.reg(int(i.op_str.split(',')[0][1:]));modifier=self.reg(17);self.edges.append({'pc':hex(a),'target':hex(target),'modifier':hex(modifier),'kind':m,'visit':len(self.visits)-1})
   if m=='braa':assert START<=target<=STOP;return u.reg_write(ar.UC_ARM64_REG_PC,target)
   expected={0xfffffe000a5c0f7c:(0xfffffe000a508e14,0xdff5,'unwire'),0xfffffe000a5c0fe8:(0xfffffe000a508e1c,0x8bbb,'deallocate_primary'),0xfffffe000a5c10cc:(0xfffffe000a508e1c,0x8bbb,'deallocate_aux'),0xfffffe000a5c1170:(0xfffffe000c4ba368,0x4d6a,'typed_free_record')}
   t,mod,name=expected[a];assert(target,modifier)==(t,mod);args=[hex(self.reg(j))for j in range(8)];ret=self.fixture['return_status'];clobbers={j:(0xc100000000000000|((len(self.models)+1)<<32)|j)for j in range(1,18)}
   self.models.append({'pc':hex(a),'target':hex(target),'modifier':hex(modifier),'name':name,'arguments8':args,'return_status':hex(ret),'clobbers':{str(j):hex(v)for j,v in clobbers.items()},'NZCV':hex(0xa0000000),'visit':len(self.visits)-1,'memory_effect':'none; requested operation only'})
   for j,v in clobbers.items():self.setreg(j,v)
   self.setreg(0,ret);self.setreg(30,a+4);u.reg_write(ar.UC_ARM64_REG_NZCV,0xa0000000);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def read(self,u,access,a,n,value,d):
  self.allreads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'visit':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def run(self):
  self.u.emu_start(START,0,count=10000);self.flush();assert self.reason=='post_record_cleanup_boundary'
  return {'fixture':self.fixture,'start':hex(START),'stop':hex(STOP),'initial_SP':hex(self.sp),'initial_NZCV':hex(0x20000000),'initial_registers31':self.initial_registers,'initial_memory':self.initial_memory,'source_visits':[hex(a)for a in self.visits],'reads':self.allreads,'writes':self.writes,'logical_edges':self.edges,'models':self.models,'final_registers31':[hex(self.reg(j))for j in range(31)],'final_SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'final_NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),'final_record_bytes_hex':bytes(self.u.mem_read(RECORD,0x80)).hex(),'final_parent_bytes_hex':bytes(self.u.mem_read(PARENT,0x300)).hex(),'stop_reason':self.reason}
def main():
 cases=[];pool={}
 shapes=[(False,0,0,0,0),(True,0,0,0,0),(True,0,17,0x6200000007,19),(True,0x6200000000,0,0,0),(True,0x6200000007,0,0,0),(True,0x6200000007,17,0,0),(True,0x6200000000,16384,0x6300000000,31),(True,0x6200003fff,2,0x6300000005,0),(True,0x6200000007,0xffffffff,0,0),(True,0xfffffffffffffff0,32,0x6300000001,0xffffffff)]
 for p in [12,14,16]:
  for j,(present,a,n,b,m)in enumerate(shapes):
   for status in [0,4]:
    f={'record_present':present,'address':a,'extent':n,'aux_address':b,'aux_extent':m,'page_shift':p,'ambient_words':[(j*0x1234567+status)&0xffffffff,(~j*0xa987654)&0xffffffff],'return_status':status};q=Probe(f);cases.append(q.run());pool.update(q.pool)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['probe_kext_close.py','kext_port_tools.py','kext_mapped_cleanup_source.json']},'cases':cases,'source_instructions':[{'ea':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pool.items())],'native_target_executed':False,'native_VM_effects_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/f'{PREFIX}_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(cases),'visits':sum(len(r['source_visits'])for r in cases),'models':sum(len(r['models'])for r in cases),'instructions':len(pool)}),flush=True)
if __name__=='__main__':main()
