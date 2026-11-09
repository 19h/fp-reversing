#!/usr/bin/env python3
"""Original kernel getBytesNoCopy leaf in private declared object fixtures.

Original getter only; no allocator, provider, prepare, PAC, IPC or native API.
Fields and pointer values are declared, not constructor/native-reachable state.
Enumerates all 256 flag bytes x 16 selected type nibbles, plus u64 sentinels.
O(C*I) execution time and O(C*I) retained events for bounded instruction count I.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
ROOT=Path(__file__).resolve().parent
ENTRY=0xfffffe000c524b60;OBJ=0x7100000000;TABLE=0x7200000000;HALT=0x7300000000
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cases():
 for flag in range(256):
  for nibble in range(16):
   number=flag*16+nibble
   yield {'case':number,'flag8':flag,'type32':((0xa5a5000f^(flag<<8))|(nibble<<4))&0xffffffff,'direct64':0x1234567800000000^(number<<16)^0x1234,'indirect64':0xfedcba9800000000^(number<<16)^0x5678,'family':'decision_grid'}
 number=4096
 for direct,indirect in[(0,0),((1<<64)-1,0),(0,(1<<64)-1),(1<<63,1),((1<<64)-1,1<<63)]:
  for flag,typ in[(0,0x20),(0,0x10),(0x40,0x20)]:
   yield {'case':number,'flag8':flag,'type32':typ,'direct64':direct,'indirect64':indirect,'family':'u64_sentinel'};number+=1
class Getter:
 def __init__(self,k):
  self.k=k;self.f=k.function(ENTRY);self.raw=bytes.fromhex(self.f['bytes']);self.end=int(self.f['end'],16);self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
  for a in[ENTRY&~4095,OBJ,TABLE,HALT]:self.u.mem_map(a,4096)
  self.u.mem_write(ENTRY,self.raw);self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.unmapped)
 def stop(self,why):self.reason=why;self.u.emu_stop()
 def code(self,u,a,n,d):
  if a==HALT:return self.stop('return')
  if not ENTRY<=a<a+4<=self.end:return self.stop('code_extent')
  assert n==4 and bytes(u.mem_read(a,4))==self.k.read(a,4);self.visits.append(hex(a))
 def read(self,u,access,a,n,value,d):
  expected={(OBJ+0xe0,1),(OBJ+0x20,4),(OBJ+0xb8,8),(OBJ+0x60,8),(TABLE,8)}
  if(a,n)not in expected:return self.stop('unknown_or_extent_read')
  self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,access,a,n,value,d):self.stop('unexpected_source_write')
 def unmapped(self,u,access,a,n,value,d):self.stop('unmapped');return False
 def run(self,c):
  self.visits=[];self.reads=[];self.reason=None;self.u.mem_write(OBJ,b'\xa5'*232);self.u.mem_write(OBJ+0xe0,bytes([c['flag8']]));self.u.mem_write(OBJ+0x20,struct.pack('<I',c['type32']));self.u.mem_write(OBJ+0xb8,struct.pack('<Q',c['direct64']));self.u.mem_write(OBJ+0x60,struct.pack('<Q',TABLE));self.u.mem_write(TABLE,struct.pack('<Q',c['indirect64']))
  for j in range(31):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),0)
  self.u.reg_write(ar.UC_ARM64_REG_X0,OBJ);self.u.reg_write(ar.UC_ARM64_REG_X30,HALT);self.u.emu_start(ENTRY,0,count=32);self.reason=self.reason or'instruction_budget';assert self.reason=='return',self.reason
  return {'input':c,'source_visits':self.visits,'data_reads':self.reads,'return64':hex(self.u.reg_read(ar.UC_ARM64_REG_X0)),'stop_reason':self.reason,'native_API_executed':False}
def main():
 k=Kernel();g=Getter(k);rows=[g.run(c)for c in cases()];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','resolve_kernel_collection_interfaces.py','kext_buffer_contracts.json']},'cases':rows,'distinct_source_instructions':sorted(set(a for r in rows for a in r['source_visits'])),'native_target_executed':False,'native_prepare_executed':False,'constructor_reachability_proved':False,'full_goal_complete':False};(ROOT/'kext_buffer_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'original_instructions':len(out['distinct_source_instructions'])}),flush=True)
if __name__=='__main__':main()
