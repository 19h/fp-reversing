#!/usr/bin/env python3
"""Original lock adapters and caller-built records; stop before lock calls.

Private guest only, PAC abstracted. Synthetic opaque lock pointers and cached
pointer overrides are declared fixtures. No lock/synchronization/provider/crypto
or native API executes. O(C*(B+V+E)) time/space; 20000-visit case cap.
"""
import hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE
from probe_kext_close import Close,STACK,HALT
from probe_carrier_control import Carrier
ACQ=0xfffffe000a5b403c;REL=0xfffffe000a5bfc6c;GLOBAL=0xfffffe000ccceab8
ENDPOINTS={0xfffffe000a5b4218:0xfffffe000a508dd4,0xfffffe000a5b42f0:0xfffffe000a508d94,0xfffffe000a5bfe84:0xfffffe000a508de4,0xfffffe000a5bff64:0xfffffe000a508d9c}
L=0xfffffe0007949dd0;R=0xfffffe000792fbc0;EL=0xfffffe0007941f60;ER=0xfffffe000794a0d0
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def encoded(p,phase):
 if phase=='acquire':return(0x729-((p^0x6133a0c8)*0x84d77373))&0xffffffff
 return 0xc33^(((p^0x734a22b2)*0x8c229611)&0xffffffff)
class Lock(Close):
 def __init__(self,c):
  super().__init__(0,0);self.case=c;self.known=bytearray(0x21000);self.seeds=[];self.private_reads=[];self.boundary=None;self.p=STACK+0x1000+c['record_shift'];self.sp=STACK+0x15000;self.cell=STACK+0x7000;self.explicit=STACK+0x8000 if c['explicit']else 0;self.cached=STACK+0x9000 if c['cached']else 0;self.u.reg_write(ar.UC_ARM64_REG_SP,self.sp)
  for j in range(31):self.setreg(j,0x100000000+0x1111*j)
  self.setreg(30,HALT);self.setreg(0,self.p);self.u.mem_write(GLOBAL,struct.pack('<Q',self.cached));self.seed(self.cell,struct.pack('<Q',self.explicit));rec=bytearray((0xa5+13*i)&255 for i in range(128));struct.pack_into('<Q',rec,0,self.explicit);struct.pack_into('<I',rec,8,c['status32']if c['caller']else encoded(self.p,c['phase']));self.initial_record=bytes(rec);self.seed(self.p,self.initial_record)
  self.start=ACQ if c['phase']=='acquire'else REL;self.finish=HALT;self.allowed=[(ACQ,0xfffffe000a5b4314),(REL,0xfffffe000a5bff88)]
  caller=c['caller'];phase=c['phase'];frame={}
  if caller=='first':
   self.setreg(24,0x510);self.setreg(29,self.sp+0x10e0);self.setreg(6,0xfffffe000ccc3630);self.setreg(5,0xa41a4d891208c018);self.setreg(7,TABLE)
   if phase=='acquire':self.start=0xfffffe000a64b284;self.finish=0xfffffe000a64b348;frame={0x880:self.cell,0x998:self.p,0xa38:0xfffffe000ccc32f8,0xa48:L,0xa40:R}
   else:
    self.start=0xfffffe000a64b49c;self.finish=0xfffffe000a64b560;self.setreg(25,self.p);self.setreg(28,self.cell);self.setreg(22,0xfffffe000ccc32f8);frame={0xa30:0xfffffe000ccc3630,0xa50:EL,0xa58:ER,0xa60:TABLE}
  elif caller=='second':
   self.setreg(21,0x753);self.setreg(29,self.sp+0x650)
   if phase=='acquire':self.start=0xfffffe000a68f448;self.finish=0xfffffe000a68f510;frame={0x3c8:self.cell,0x3b8:self.p,0x438:0xfffffe000ccc3630,0x430:0xfffffe000ccc32f8,0x428:L,0x418:R,0x440:TABLE}
   else:
    self.start=0xfffffe000a68f6b4;self.finish=0xfffffe000a68f764;self.setreg(27,self.p);self.setreg(26,0xfffffe000ccc3630);self.setreg(22,0xfffffe000ccc32f8);self.setreg(23,0xa41a4d891208c018);self.setreg(19,0x4d08a3fb);frame={0x3c8:self.cell,0x410:EL,0x3a8:ER,0x440:TABLE}
  elif caller is not None:raise AssertionError(caller)
  if caller:self.allowed.append((self.start,self.finish))
  for off,value in frame.items():self.seed(self.sp+off,struct.pack('<Q',value))
 def seed(self,a,b):self.u.mem_write(a,b);self.known[a-STACK:a-STACK+len(b)]=b'\1'*len(b);self.seeds.append({'address':hex(a),'bytes_hex':b.hex()})
 def hook(self,u,a,n,d):
  self.flush()
  if a==self.finish:
   self.boundary={'kind':'return_without_primitive','pc':hex(a),'registers31':[hex(self.reg(j))for j in range(31)]};return self.stop('declared_boundary')
  if a in ENDPOINTS:
   assert self.reg(8)==ENDPOINTS[a];self.boundary={'kind':'before_lock_primitive_wrapper','pc':hex(a),'target_wrapper':hex(self.reg(8)),'modifier':hex(self.reg(17)),'X0_argument':hex(self.reg(0)),'registers31':[hex(self.reg(j))for j in range(31)],'call_instruction_hex':IMAGE.read(a,4).hex(),'target_executed':False};return self.stop('declared_boundary')
  assert any(x<=a<a+4<=z for x,z in self.allowed),('unmodeled code',hex(a));i=next(CS.disasm(IMAGE.read(a,4),a))
  if i.mnemonic in['bl','blr','blraa']:assert self.reg(8)in[ACQ,REL],('unmodeled call',hex(a),hex(self.reg(8)))
  return super().hook(u,a,n,d)
 def read(self,u,access,a,n,v,d):
  if STACK<=a<a+n<=STACK+0x21000:
   assert all(self.known[a-STACK:a-STACK+n]),('undefined private read',hex(a),n);self.private_reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
  return super().read(u,access,a,n,v,d)
 def write(self,u,access,a,n,v,d):
  if STACK<=a<a+n<=STACK+0x21000:self.known[a-STACK:a-STACK+n]=b'\1'*n
  else:assert any(x<=a<a+n<=z for x,z in self.data)
  return super().write(u,access,a,n,v,d)
 def run(self):
  self.u.emu_start(self.start,0,count=20000);self.flush();assert self.reason=='declared_boundary';return {'input':self.case,'record_pointer':hex(self.p),'initial_record_hex':self.initial_record.hex(),'final_record_hex':bytes(self.u.mem_read(self.p,128)).hex(),'explicit_lock_fixture':hex(self.explicit),'cached_lock_fixture':hex(self.cached),'cached_cell':hex(GLOBAL),'fixtures':self.seeds,'source_visits':[hex(a)for a in self.visits],'source_writes':self.writes,'private_reads':self.private_reads,'calls':self.calls,'boundary':self.boundary,'native_lock_executed':False,'native_API_executed':False,'undefined_private_reads':[],'entry_reachability_proved':False}
class Gate(Carrier):
 def __init__(self,c):
  super().__init__({'mode':'preparer_entry','alignment':0,'fill':0xa5,'record_shift':c['record_shift'],'selector':0xa07});self.gate_case=c;self.stop_at=HALT;self.allowed=[(0xfffffe000a621118,0xfffffe000a62259c),(0xfffffe000a687ecc,0xfffffe000a687ee0)];self.outcome=None
  if c['kind']=='null':self.seed(self.p,bytes(8))
  else:self.seed(STACK+0xa000,c['tag32'].to_bytes(4,'little'))
 def hook(self,u,a,n,d):
  if a in[0xfffffe000a621388,0xfffffe000a621720]:
   self.flush();self.outcome='recognized_42059342'if a==0xfffffe000a621388 else'recognized_85283019';self.boundary={'pc':hex(a),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))};return self.stop('declared_boundary')
  if a==HALT:self.outcome='return'
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();r.update(gate_input=self.gate_case,gate_outcome=self.outcome,final_preparer_record64_hex=bytes(self.u.mem_read(self.p,64)).hex(),native_lock_executed=False);return r
def lock_cases():
 for caller in[None,'first','second']:
  for phase in['acquire','release']:
   for explicit in[False,True]:
    for cached in[False,True]:
     for shift in[0,0x10,0x100]:
      for status in([0x31ae0066,0xce515bb2]if caller and phase=='release'else[0x31ae0066]):yield {'caller':caller,'phase':phase,'explicit':explicit,'cached':cached,'record_shift':shift,'status32':status}
def gate_cases():
 for shift in[0,0x10,0x100,0x1000]:
  yield {'kind':'null','record_shift':shift}
  for tag in[0,0xffffffff,0x85283019,0x42059342]:yield {'kind':'word','record_shift':shift,'tag32':tag}
def main():
 locks=[Lock(c).run()for c in lock_cases()];gates=[Gate(c).run()for c in gate_cases()];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_kext_close.py','probe_carrier_control.py','kext_port_tools.py','sample_lock_contracts.json']},'source_sha256':sha(SOURCE),'lock_cases':locks,'gate_cases':gates,'native_target_executed':False,'native_lock_executed':False,'crypto_operation_executed':False,'full_goal_complete':False};(ROOT/'sample_lock_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'lock_cases':len(locks),'gate_cases':len(gates),'source_visits':sum(len(r['source_visits'])for r in locks+gates)}),flush=True)
if __name__=='__main__':main()
