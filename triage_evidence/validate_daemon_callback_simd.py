#!/usr/bin/env python3
"""Compare the callback's scalar/AdvSIMD lane model against isolated A64 opcodes.
O(instructions*patterns+USHL byte-count cases) time, O(registers) space.
Original source bytes, ARM64 MAX emulator; no native API or authentication.
"""
import hashlib,json,struct
from pathlib import Path
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from daemon_callback_simd import apply
from lskd_values_symbolic import resize

class Tiny:
 def __init__(self):self.regs={};self.written={}
 def key(self,name):
  if name.startswith('w'):return'x'+name[1:]
  if name[:1]in 'qvsdhb'and name[1:].isdigit():return'q'+name[1:]
  return name
 def width(self,name):return 128 if name[:1]in ['q','v']else 32 if name.startswith('w')or name.startswith('s')else 16 if name.startswith('h')else 8 if name.startswith('b')else 64
 def read(self,name):return resize(self.regs[self.key(name)],self.width(name))
 def write(self,name,value):
  key=self.key(name);value=z3.simplify(resize(resize(value,self.width(name)),128 if key.startswith('q')else 64));self.regs[key]=value;self.written[key]=value

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set();rows=[];total=0;ushl=0
 instructions=list(cs.disasm(IMAGE.read(0x1004626f0,0x310),0x1004626f0))
 for i in instructions:
  # Apply selects only the explicitly supported register operations. It does
  # not execute memory accesses, branches or host operations.
  if i.mnemonic not in ['fmov','mov','movi','dup','add','sub','mul','mla','mls','umull','shrn','ushr','ushl','ushll','xtn','uzp1','tbl','eor','eor3','and','orr','bic','eon','orn']:continue
  scenarios=list(range(32))
  if i.mnemonic=='ushl':scenarios.extend(range(32,32+256*3))
  completed=0
  for pattern in scenarios:
   v=Tiny()
   for reg in ['x'+str(j)for j in range(31)]+['q'+str(j)for j in range(32)]:
    bits=128 if reg.startswith('q')else 64
    val=0 if pattern==0 else(1<<bits)-1 if pattern==1 else int.from_bytes(hashlib.sha256((reg+':'+str(pattern)).encode()).digest(),'little')&((1<<bits)-1);v.regs[reg]=z3.BitVecVal(val,bits);u.reg_write(getattr(ar,'UC_ARM64_REG_'+reg.upper()),val)
   if i.mnemonic=='ushl'and pattern>=32:
    p=pattern-32;byte=p%256;high=[0,0x123456,0xffffff][p//256];word=(high<<8)|byte;value=word|(word<<32);reg=i.reg_name(i.operands[2].reg);v.regs['q'+reg[1:]]=z3.BitVecVal(value,128);u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+reg[1:]),value)
   if i.mnemonic=='tbl'and 2<=pattern<18:
    table_count=len(i.operands)-2;index_reg=i.reg_name(i.operands[-1].reg);value=int.from_bytes(bytes((j+pattern-2)%(16*table_count+2)for j in range(16)),'little');v.regs['q'+index_reg[1:]]=z3.BitVecVal(value,128);u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+index_reg[1:]),value)
   if not apply(v,i):break
   pg=i.address&~4095
   if pg not in pages:u.mem_map(pg,4096);u.mem_write(pg,IMAGE.read(pg,4096));pages.add(pg)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0xa0000000);u.emu_start(i.address,i.address+4,count=1)
   for reg,expression in v.written.items():assert u.reg_read(getattr(ar,'UC_ARM64_REG_'+reg.upper()))==z3.simplify(expression).as_long(),(hex(i.address),i.mnemonic,i.op_str,pattern,reg)
   assert u.reg_read(ar.UC_ARM64_REG_NZCV)==0xa0000000;completed+=1
  if completed:rows.append({'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str,'cases':completed});total+=completed;ushl+=completed if i.mnemonic=='ushl'else 0
 deps=['daemon_callback_simd.py','daemon_receive_tools.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'instructions':rows,'verified_counts':{'source_opcodes':len(rows),'isolated_instruction_cases':total,'USHL_cases':ushl,'USHL_low_byte_counts':256,'USHL_upper24_patterns':3},'primary_USHL_reference':'https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab','all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_callback_simd_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)
if __name__=='__main__':main()
