#!/usr/bin/env python3
"""Guarded original 360-byte fill helper; no native call or task access.

O(C*(V+L)) time, O(max(L)+retained events) space. The private mapped object
and bounded extents are declared; full64 loop identities are checked separately.
"""
import hashlib,json
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
ENTRY=0xfffffe000a687d64;END=0xfffffe000a687ecc
DATA=0x7900000000;HALT=(ENTRY&~4095)+0x800
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Fill:
 def __init__(self):
  self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.u.mem_map(ENTRY&~4095,4096);self.u.mem_write(ENTRY,IMAGE.read(ENTRY,END-ENTRY));self.u.mem_map(DATA,0x5000);self.pool={};self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read)
 def code(self,u,a,n,d):
  if a==HALT:self.done=True;u.emu_stop();return
  assert ENTRY<=a<a+4<=END,hex(a);raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.pool[a]=raw;self.visits.append(a)
 def read(self,u,access,a,n,v,d):raise AssertionError(('unexpected_data_read',hex(a),n))
 def write(self,u,access,a,n,v,d):
  assert self.dest<=a<a+n<=self.dest+self.case['length64'],(hex(a),n,self.case)
  self.stores.append([u.reg_read(ar.UC_ARM64_REG_PC)-ENTRY,a-self.dest,n,(v&((1<<(n*8))-1)).to_bytes(n,'little').hex()])
 def run(self,c):
  self.case=c;self.dest=DATA+0x800+c['alignment'];length=c['length64'];assert length<=8192;self.u.mem_write(DATA,bytes([0xa5])*0x5000);self.visits=[];self.stores=[];self.done=False
  for i in range(31):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(i)),0)
  self.u.reg_write(ar.UC_ARM64_REG_X0,self.dest);self.u.reg_write(ar.UC_ARM64_REG_X1,c['fill64']);self.u.reg_write(ar.UC_ARM64_REG_X2,length);self.u.reg_write(ar.UC_ARM64_REG_X30,HALT);self.u.emu_start(ENTRY,0,count=20000);assert self.done
  before=bytes(self.u.mem_read(self.dest-16,16));after=bytes(self.u.mem_read(self.dest+length,16));actual=bytes(self.u.mem_read(self.dest,length));assert before==after==bytes([0xa5])*16
  return {'input':c,'destination64':hex(self.dest),'return_X0':hex(self.u.reg_read(ar.UC_ARM64_REG_X0)),'source_visits_count':len(self.visits),'source_visits_sha256':hashlib.sha256(b''.join(a.to_bytes(8,'little')for a in self.visits)).hexdigest(),'stores':self.stores,'final_data_sha256':hashlib.sha256(actual).hexdigest(),'before_guard16_hex':before.hex(),'after_guard16_hex':after.hex(),'native_API_executed':False}
def cases():
 seen=set()
 groups=[((a,n,0)for a in range(8)for n in range(193)),((a,n,v)for a in range(8)for n in[7,129]for v in range(256)),((a,n,v)for a in range(8)for n in[0,1,7,8,15,64,65,168]for v in[0x100,0x101,0x12345678,0xffffffff,0x100000001]),((a,n,v)for a in range(8)for n in[255,256,257,511,512,513,1023,1024,4096,8192]for v in[0,255])]
 for group in groups:
  for triple in group:
   if triple not in seen:seen.add(triple);a,n,v=triple;yield {'alignment':a,'length64':n,'fill64':v}
def main():
 q=Fill();rows=[q.run(c)for c in cases()];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'cases':rows,'source_instructions':[{'ea':hex(a),'bytes_hex':b.hex(),'mnemonic':next(CS.disasm(b,a)).mnemonic,'operands':next(CS.disasm(b,a)).op_str}for a,b in sorted(q.pool.items())],'native_target_executed':False,'full_goal_complete':False};(ROOT/'sample_state_fill_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'fill_cases':len(rows),'source_visits':sum(r['source_visits_count']for r in rows),'source_store_events':sum(len(r['stores'])for r in rows)}),flush=True)
if __name__=='__main__':main()
