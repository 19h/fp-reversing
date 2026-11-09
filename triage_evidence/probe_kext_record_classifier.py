#!/usr/bin/env python3
"""Original record-classifier leaf on declared pointer/field combinations.

No authenticated branch, target API, accepted operation or native record.
O(C*31) source instructions; fixed 32 cases cover four predicate combinations
and eight full64 record addresses, including low32 rollover.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
ENTRY=0xfffffe000a5a962c;END=0xfffffe000a5a96a8;HALT=0x7b00000000
POINTERS=[0x7900000000,0x7900000004,0x790000007c,0x790000fffc,0x7900010000,0x7912345000,0x79ffff0000,0x79fffffff0]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Classifier:
 def __init__(self):
  self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.u.mem_map(ENTRY&~4095,4096);self.u.mem_write(ENTRY,IMAGE.read(ENTRY,END-ENTRY));self.u.mem_protect(ENTRY&~4095,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC);self.u.mem_map(HALT,4096);pages={a for p in POINTERS for a in range(p&~4095,(p+0x34+4095)&~4095,4096)}
  for a in sorted(pages):self.u.mem_map(a,4096)
  self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def code(self,u,a,n,d):
  if a==HALT:self.reason='return';return u.emu_stop()
  assert ENTRY<=a<a+4<=END and bytes(u.mem_read(a,4))==IMAGE.read(a,4);self.visits.append(hex(a))
 def read(self,u,access,a,n,value,d):assert(a,n)in[(self.pointer+0x10,4),(self.pointer+0x30,4)];self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'offset':a-self.pointer,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,access,a,n,value,d):assert(a,n)==(self.pointer+0x24,4);self.writes.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'offset':a-self.pointer,'size_bytes':n})
 def run(self,p,first,second):
  self.pointer=p;self.reason=None;self.visits=[];self.reads=[];self.writes=[];key=0x91c952ff*((p&0xffffffff)^0x0e12cee6)&0xffffffff;f10=(key+0x1baf36fd+(0 if first else 1))&0xffffffff;f30=key^(0x16941447 if second else 0x16941446);self.u.mem_write(p,b'\xa5'*0x34);self.u.mem_write(p+0x10,struct.pack('<I',f10));self.u.mem_write(p+0x30,struct.pack('<I',f30))
  for j in range(31):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),0)
  self.u.reg_write(ar.UC_ARM64_REG_X0,p);self.u.reg_write(ar.UC_ARM64_REG_X30,HALT);self.u.emu_start(ENTRY,0,count=40);assert self.reason=='return'
  return {'record_pointer':hex(p),'first_predicate':first,'second_predicate':second,'field10_u32':hex(f10),'field30_u32':hex(f30),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'marker24_u32':hex(struct.unpack('<I',self.u.mem_read(p+0x24,4))[0]),'return_pointer':hex(self.u.reg_read(ar.UC_ARM64_REG_X0)),'native_API_executed':False}
def main():
 g=Classifier();rows=[g.run(p,a,b)for p in POINTERS for a in[False,True]for b in[False,True]];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','kext_aes_dispatch_contracts.json']},'cases':rows,'native_target_executed':False,'native_reachability_proved':False,'full_goal_complete':False};(ROOT/'kext_record_classifier_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'classifier_cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
