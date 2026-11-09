#!/usr/bin/env python3
"""Original mapping cleanup helper at its declared 24-byte argument ABI.

Record fixtures are isolated ABI inputs, not complete worker/native executions.
Original helpers run privately; PAC is bypassed and close/munmap requests are
modeled without native effects. Mapping extents need not be backed/mapped.
O(C*(B+F+V+E)) time/space for 24 bounded helper cases.
"""
import hashlib,json,struct
from pathlib import Path
from daemon_rpc502_probe import Probe,STACK,HALT,ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS

ARG=0x5900000000;RECORD=0x5a00000000;MAPPING=0x5b00000000;SIZE_XOR=0xb3800b93c8bcf32b
def key(p):return (((((0x3c642ede|((p<<1)&0xffffffff))-p+0xe1cde891)&0xffffffff)^0x885c4f7d)*0x592e2f77)&0xffffffff
def cases():
 out=[]
 for off,extent in[(8,64),(24,0x100000009)]:
  for flag in[0,1,2,3,126,127,254,255]:out.append({'argument_offset':off,'extent_bytes':extent,'mode_byte':flag,'close_result':0,'unmap_result':0})
  for flag,unmap,close in[(0,0,-1),(1,-1,0),(1,0,-1),(1,-1,-1)]:out.append({'argument_offset':off,'extent_bytes':extent,'mode_byte':flag,'close_result':close,'unmap_result':unmap})
 return out
class Cleanup(Probe):
 def __init__(self,c):
  self.case=c;self.observed=[];self.original={};self.visits=[];self.consumed={};self.stores=[];self.pending=[]
  super().__init__();self.p=ARG+c['argument_offset'];self.u.mem_map(ARG,4096);self.u.mem_map(RECORD,4096);self.u.mem_write(ARG,b'\xa5'*64);self.u.mem_write(RECORD,b'\xa5'*32)
  self.u.mem_write(self.p+8,struct.pack('<Q',RECORD));self.u.mem_write(self.p+16,struct.pack('<I',key(self.p)^0x6922));self.u.mem_write(self.p+20,bytes([c['mode_byte']]))
  self.u.mem_write(RECORD,struct.pack('<I',8));self.u.mem_write(RECORD+8,struct.pack('<QQQ',MAPPING,c['extent_bytes']^SIZE_XOR,0x123456789abcdef0));self.initial_argument=bytes(self.u.mem_read(self.p,24));self.initial_mapping_record=bytes(self.u.mem_read(RECORD,32))
 def flush_local(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def hook(self,u,a,n,d):
  self.flush_local()
  if 0x100000000<=a<0x102000000:
   raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.original[a]=raw;self.visits.append(a)
  name=self.imports.get(a)
  if name in['libSystem/_close','libSystem/_munmap']:
   args=[self.reg(j)for j in range(2)];result=self.case['close_result']if name.endswith('_close')else self.case['unmap_result'];self.observed.append({'name':name,'site':hex(self.reg(30)-4),'args':[hex(v)for v in args],'result_signed32':result,'native_API_executed':False});return self.return_model(result)
  return super().hook(u,a,n,d)
 def read_hook(self,u,access,a,n,value,d):
  if a in FIXUPS:self.consumed[a]={'address':hex(a),'word_hex':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}
  return super().read_hook(u,access,a,n,value,d)
 def write_hook(self,u,access,a,n,value,d):
  if RECORD<=a<a+n<=RECORD+32:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n};self.stores.append(e);self.pending.append(e)
  return super().write_hook(u,access,a,n,value,d)
 def execute(self):
  self.setreg(0,self.p);self.setreg(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x78000);self.u.emu_start(0x100444704,0,count=20000);self.flush_local();assert self.stop_reason=='returned_to_fixture',self.records[-2:]
  return {'fixture':self.case,'argument_pointer':hex(self.p),'initial_argument24_hex':self.initial_argument.hex(),'final_argument24_hex':bytes(self.u.mem_read(self.p,24)).hex(),'initial_mapping_record32_hex':self.initial_mapping_record.hex(),'final_mapping_record32_hex':bytes(self.u.mem_read(RECORD,32)).hex(),'API_requests':self.observed,'source_record_stores':self.stores,'source_visits':[hex(a)for a in self.visits],'source_fixups':list(self.consumed.values()),'PAC_model':self.pac,'stop_reason':self.stop_reason,'native_target_executed':False,'full_worker_executed':False}
def main():
 rows=[];pool={}
 for c in cases():
  q=Cleanup(c);r=q.execute();rows.append(r);pool.update(q.original);print('CASE',c,[e['name']for e in r['API_requests']],flush=True)
 out={'scope':__doc__,'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'dependencies':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest()for n in['daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt']},'source_instructions':[{'ea':hex(a),'bytes':b.hex(),'mnemonic':next(CS.disasm(b,a)).mnemonic,'operands':next(CS.disasm(b,a)).op_str}for a,b in sorted(pool.items())],'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_cleanup_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
