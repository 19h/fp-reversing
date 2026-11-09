#!/usr/bin/env python3
"""Original carrier reset and bounded producer/entry prefixes in private Unicorn.

Opaque synthetic bytes only; no crypto/provider/native API runs. PAC is
abstracted. All executed instructions are original-byte checked. Non-stack
loads are limited to file-backed image data; stack reads require source writes
or explicit fixture bytes. O(C*(B+V+E)) time/space with 20000 visits per case.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from probe_kext_close import Close,STACK,HALT
RESET=0xfffffe000a62309c;FILL=0xfffffe000a687d64;FILL_END=0xfffffe000a687ecc
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def key64(p):return((p^0xe10934e57abbf985)*0xded29631)&((1<<64)-1)
class Carrier(Close):
 def __init__(self,c):
  super().__init__(0,0);self.case=c;self.known=bytearray(0x21000);self.fixture=[];self.private_reads=[];self.data_reads=[];self.fill_calls=[];self.boundary=None;self.h=STACK+0x5000+c['alignment'];self.p=STACK+0x2000+c.get('record_shift',0);self.sp=STACK+0x18000;self.known_writes=[];self.pattern=bytes((c['fill']+17*i)&255 for i in range(104));self.mode=c['mode'];self.u.reg_write(ar.UC_ARM64_REG_SP,self.sp)
  for j in range(31):self.setreg(j,0x100000000+0x1111*j)
  self.setreg(30,HALT);self.seed(self.h,self.pattern);self.setreg(0,self.p)
  self.start=RESET;self.stop_at=HALT;self.allowed=[(RESET,0xfffffe000a623314),(FILL,FILL_END)]
  if self.mode=='reset':self.seed(self.p,struct.pack('<Q',self.h))
  elif self.mode=='preparer_entry':
   self.start=0xfffffe000a621118;self.stop_at=0xfffffe000a621338;self.allowed=[(self.start,self.stop_at)]
   rec=bytearray(64)
   for o,v in[(0,STACK+0xa000),(8,STACK+0xb000),(0x10,STACK+0xc000),(0x18,self.h),(0x28,STACK+0xd000),(0x38,STACK+0xf000)]:struct.pack_into('<Q',rec,o,v)
   struct.pack_into('<I',rec,0x30,c['selector']^(key64(self.p)&0xffffffff));self.seed(self.p,bytes(rec))
  elif self.mode=='heap_controls_11':
   self.start=0xfffffe000a69d954;self.stop_at=0xfffffe000a69d978;self.allowed=[(self.start,self.stop_at)];self.setreg(0,self.h)
  elif self.mode=='stack_controls_01':
   self.start=0xfffffe000a69825c;self.stop_at=0xfffffe000a698278;self.allowed=[(self.start,self.stop_at)];self.sp+=c['alignment']*16;self.u.reg_write(ar.UC_ARM64_REG_SP,self.sp);self.setreg(29,self.sp+0x650);self.h=self.sp+0x568;self.seed(self.h,self.pattern)
  elif self.mode=='preparer_operation_zero':
   self.start=0xfffffe000a6221c4;self.stop_at=0xfffffe000a6221cc;self.allowed=[(self.start,self.stop_at)];self.setreg(26,self.h);self.setreg(11,0x12345678)
  elif self.mode=='preparer_kind_zero':
   self.start=0xfffffe000a621490;self.stop_at=0xfffffe000a6214a0;self.allowed=[(self.start,self.stop_at)];self.setreg(19,self.p);self.setreg(12,0xabcdef01);self.seed(self.p+0x18,struct.pack('<Q',self.h))
  elif self.mode=='preparer_kind_three':
   self.start=0xfffffe000a621a78;self.stop_at=0xfffffe000a621a8c;self.allowed=[(self.start,self.stop_at)];self.setreg(2,self.h);self.setreg(13,0xabcdef01)
  elif self.mode=='wrapper_reset_prefix':
   self.start=0xfffffe000a67c54c;self.stop_at=0xfffffe000a67c808;self.allowed=[(self.start,self.stop_at),(RESET,0xfffffe000a623314),(FILL,FILL_END),(FILL_END,FILL_END+20)]
   self.work=STACK+0x3000;rec=bytearray(0x50)
   for o,v in[(0,self.work),(8,STACK+0xa000),(0x18,self.h),(0x30,STACK+0xb000),(0x40,STACK+0xe000),(0x48,STACK+0xc000)]:struct.pack_into('<Q',rec,o,v)
   self.seed(self.p,bytes(rec));self.seed(self.work,bytes(64))
  else:raise AssertionError(self.mode)
 def seed(self,a,b):
  assert STACK<=a<a+len(b)<=STACK+0x21000;self.u.mem_write(a,b);self.known[a-STACK:a-STACK+len(b)]=b'\1'*len(b);self.fixture.append({'address':hex(a),'bytes_hex':b.hex()})
 def hook(self,u,a,n,d):
  self.flush()
  if a==self.stop_at:
   self.boundary={'pc':hex(a),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))};return self.stop('declared_boundary')
  if not any(x<=a<a+4<=z for x,z in self.allowed):return self.stop('unmodeled_code_boundary',pc=hex(a))
  i=next(CS.disasm(IMAGE.read(a,4),a))
  if i.mnemonic in['bl','blr','blraa','blrab']:
   t=int(i.op_str[1:],16)if i.mnemonic=='bl'else self.reg(int(i.op_str.split(',')[0][1:]));assert any(x<=t<z for x,z in self.allowed),('unmodeled call',hex(a),hex(t))
   if t==FILL:self.fill_calls.append({'pc':hex(a),'arguments3':[hex(self.reg(j))for j in range(3)],'source_visit_index':len(self.visits),'original_pure_helper_executed':True})
  return super().hook(u,a,n,d)
 def read(self,u,access,a,n,v,d):
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()}
  if STACK<=a<a+n<=STACK+0x21000:
   assert all(self.known[a-STACK:a-STACK+n]),('undefined private read',e);self.private_reads.append(e)
  else:
   assert IMAGE.read(a,n)==bytes(u.mem_read(a,n))or any(int(w['address'],16)<=a and a+n<=int(w['address'],16)+w['size_bytes']for w in self.writes),('unmodeled data',e);self.data_reads.append(e)
  return super().read(u,access,a,n,v,d)
 def write(self,u,access,a,n,v,d):
  if STACK<=a<a+n<=STACK+0x21000:self.known[a-STACK:a-STACK+n]=b'\1'*n
  else:assert any(x<=a<a+n<=z for x,z in self.data),('non-data write',hex(a),n)
  return super().write(u,access,a,n,v,d)
 def run(self):
  self.u.emu_start(self.start,0,count=20000);self.flush();assert self.reason=='declared_boundary',(self.mode,self.reason,self.events[-2:])
  return {'input':self.case,'H':hex(self.h),'record':hex(self.p),'initial_carrier_hex':self.pattern.hex(),'final_carrier_hex':bytes(self.u.mem_read(self.h,104)).hex(),'fixtures':self.fixture,'source_visits':[hex(a)for a in self.visits],'source_writes':self.writes,'private_reads':self.private_reads,'data_reads':self.data_reads,'pure_fill_calls':self.fill_calls,'boundary':self.boundary,'stop_reason':self.reason,'undefined_private_reads':[],'native_API_executed':False,'crypto_operation_executed':False,'entry_reachability_proved':False}
def cases():
 for mode in['reset','heap_controls_11','stack_controls_01','preparer_operation_zero','preparer_kind_zero','preparer_kind_three','wrapper_reset_prefix']:
  for a in range(8):
   for fill in[0,0xa5,0xff]:yield {'mode':mode,'alignment':a,'fill':fill}
 for shift in[0,0x10,0x100,0x1000]:
  for selector in[0,1,0x510,0x753,0x80000000,0xffffffff]:yield {'mode':'preparer_entry','alignment':0,'fill':0xa5,'record_shift':shift,'selector':selector}
def main():
 rows=[Carrier(c).run()for c in cases()];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_kext_close.py','kext_port_tools.py','carrier_control_contracts.json']},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'crypto_operation_executed':False,'full_goal_complete':False};(ROOT/'carrier_control_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
