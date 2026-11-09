#!/usr/bin/env python3
"""Fresh-CPU replay of ordered source/read/write/ABI journals; no new probe import.
Only the frozen image/fixup loader is shared. O(image+visits+journals), O(image+
private RAM+journals). Private malloc and logical authentication only.
"""
import hashlib
from collections import Counter
from unicorn import arm64_const as A
from daemon_rpc502_probe import Probe as ImageLoader,STACK,STACK_SIZE,HALT
from daemon_receive_tools import IMAGE,CS
B=0x6500000000;USER=B+0x1000;OOL=B+0x4000;REPLY=B+0x80000;OBJ=B+0x90000
class Replay(ImageLoader):
 def __init__(self,p,origin,source):
  self.p=p;self.origin=origin;self.source=source;self.seq=0;self.ri=0;self.wi=0;self.mi=0;self.hi=0;self.pending=[];self.counts=Counter();self.current=-1;self.done=False
  super().__init__();self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20);self.u.mem_map(B,0x100000);self.u.mem_write(STACK,b'\xa5'*STACK_SIZE)
  self.u.mem_write(USER,bytes.fromhex(origin['final_user8192_hex']));self.u.mem_write(OOL,bytes.fromhex(origin['final_OOL16384_hex']));self.u.mem_write(REPLY,b'\xa5'*384)
  for j in range(31):self.setreg(j,0)
  for j,v in enumerate((OBJ,USER,80,0)):self.setreg(j,v)
  self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x78000);self.u.reg_write(A.UC_ARM64_REG_NZCV,0x40000000);self.check_frame(p['entry'])
 def check_frame(self,f):
  assert f['registers31']==[hex(self.reg(j))for j in range(31)]and f['SP']==hex(self.u.reg_read(A.UC_ARM64_REG_SP))and f['NZCV']==hex(self.u.reg_read(A.UC_ARM64_REG_NZCV))and f['Q_registers32']==[hex(self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
  assert f['source_visit_index']==self.seq;self.counts['complete_CPU_frames_checked']+=1
 def finish_writes(self):
  for e in self.pending:assert e['after_hex']==bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex();self.counts['write_after_images_checked']+=1
  self.pending=[]
 def read_hook(self,u,t,a,n,v,d):
  e=self.p['source_reads'][self.ri];self.ri+=1
  assert e=={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'source_visit_index':self.current,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()};self.counts['ordered_reads_checked']+=1;self.counts['read_bytes_checked']+=n
 def write_hook(self,u,t,a,n,v,d):
  e=self.p['source_writes'][self.wi];self.wi+=1
  assert e['pc']==hex(u.reg_read(A.UC_ARM64_REG_PC))and e['source_visit_index']==self.current and e['address']==hex(a)and e['size_bytes']==n and e['before_hex']==bytes(u.mem_read(a,n)).hex();self.pending.append(e);self.counts['ordered_writes_checked']+=1;self.counts['write_bytes_checked']+=n
 def hook(self,u,a,n,d):
  self.finish_writes()
  if self.seq==len(self.p['source_visits']):
   end=self.p['boundary'];assert end['pc']==hex(a);self.check_frame(end)
   if a in self.imports:
    e=self.p['imports'][self.mi];self.mi+=1;assert e['name']==self.imports[a]=='libSystem/_mach_msg_destroy'and e['pc']==hex(a);self.check_frame(e['before']);self.counts['unexecuted_destruction_boundaries_checked']+=1
   else:assert a in (HALT,0x100422d48)
   self.done=True;u.emu_stop();return
  if a in self.imports:
   e=self.p['imports'][self.mi];self.mi+=1;assert self.imports[a]==e['name']=='libSystem/_malloc'and e['pc']==hex(a)and self.reg(0)==384 and e['result']==hex(REPLY);self.check_frame(e['before']);target=self.reg(30);assert e['return_pc']==hex(target)
   for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
   self.setreg(0,REPLY);u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000);u.reg_write(A.UC_ARM64_REG_PC,target);self.check_frame(e['after']);self.counts['declared_allocation_contracts_checked']+=1;return
  e=self.p['source_visits'][self.seq];raw=bytes(u.mem_read(a,4));assert e=={'pc':hex(a),'bytes_hex':raw.hex()}and raw==IMAGE.read(a,4);self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1
  if self.hi<len(self.p['handoffs']):
   f=self.p['handoffs'][self.hi]
   if f['pc']==hex(a)and f['source_visit_index']==self.seq:self.check_frame(f);self.hi+=1
  i=next(CS.disasm(raw,a));op=i.mnemonic
  if op in ('pacibsp','paciasp','autibsp','autiasp','xpaclri','bti'):u.reg_write(A.UC_ARM64_REG_PC,a+4);self.counts['logical_authentication_or_hint_steps_checked']+=1
  elif op in ('retab','retaa'):u.reg_write(A.UC_ARM64_REG_PC,self.reg(30));self.counts['logical_return_authentication_steps_checked']+=1
  elif op in ('braa','braaz','brab','brabz','blraa','blraaz','blrab','blrabz'):
   reg=int(i.op_str.split(',')[0].strip()[1:]);destination=self.reg(reg)
   if op.startswith('blr'):self.setreg(30,a+4)
   u.reg_write(A.UC_ARM64_REG_PC,destination);self.counts['logical_authenticated_branches_checked']+=1
  else:assert not op.startswith(('pac','aut','xpac'))and op not in ('svc','hvc','smc','brk')
 def run(self):
  self.u.emu_start(0x100425f78,0,count=30000);self.finish_writes();assert self.done and self.ri==len(self.p['source_reads'])and self.wi==len(self.p['source_writes'])and self.mi==len(self.p['imports'])and self.hi==len(self.p['handoffs'])
  for a,n,key in [(USER,8192,'final_user8192_hex'),(OOL,16384,'final_OOL16384_hex'),(REPLY,384,'reply384_hex')]:assert self.p[key]==bytes(self.u.mem_read(a,n)).hex();self.counts['complete_final_buffer_bytes_checked']+=n
  for a,n,key in [(B,0x100000,'final_private1048576_sha256'),(STACK,STACK_SIZE,'final_stack524288_sha256')]:assert self.p[key]==hashlib.sha256(bytes(self.u.mem_read(a,n))).hexdigest();self.counts['whole_private_RAM_bytes_checked']+=n
  self.counts['final_boundaries_checked']+=1;return self.counts
