#!/usr/bin/env python3
"""Independent command parser/oracle and fresh CPU replay; no probe import.
O(commands + visits + journal + RAM bytes) time/space; no native target work.
"""
import struct
from hashlib import sha256
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as ar
import recover_kernel_collection_header_publication as R
P=0x6500000000;SIZE=0x100000;SP=P+0xf0000;HALT=P+0xff000
def oracle(row):
 c=row['configuration'];kind=c['kind']&0xffffffff;valid=kind in [1,2,3];before=bytearray.fromhex(row['initial_banks_hex']);expected=bytearray(before);checks=[];minimum=(1<<64)-1;count=0;slot=None
 def ok(label,p):assert p,('collection_header_contract',label);checks.append(label)
 if valid:
  index={1:0,2:1,3:3}[kind];slot=8*index;raw=bytes.fromhex(c['header']['bytes_hex']);commands=struct.unpack_from('<I',raw,16)[0];off=32
  for _ in range(commands):
   command,n=struct.unpack_from('<II',raw,off);assert n>=8 and off+n<=len(raw)
   if command==0x19:minimum=min(minimum,struct.unpack_from('<Q',raw,off+24)[0]);count+=1
   off+=n
  if row['mode']=='set':
   for at,value in [(slot,int(c['header']['address'],16)),(32+slot,c['slide']),(64+slot,(minimum+c['slide'])&((1<<64)-1))]:struct.pack_into('<Q',expected,at,value)
  else:ok('getter_result',int(row['final_registers31'][0],16)==struct.unpack_from('<Q',before,slot)[0])
  ok('normal_return',row['boundary']=={'PC':hex(HALT),'returned':True} and row['final_SP']==hex(SP))
 else:
  wanted=0xfffffe000c66291c if row['mode']=='set' else 0xfffffe000c5e5684;ok('invalid_kind_stops_before_panic_BL',row['boundary']=={'PC':hex(wanted),'returned':False});ok('invalid_kind_has_no_header_reads',not row['source_reads'])
 ok('all96_bank_bytes',row['final_banks_hex']==expected.hex());ok('returned_case_callee_saved_GPRs',not valid or row['final_registers31'][19:30]==row['initial_registers31'][19:30]);ok('no_native_execution',not row['native_target_executed'])
 return {'checks':checks,'valid_low32_kind':valid,'bank_index':None if slot is None else slot//8,'segment_commands':count,'minimum_segment_VM_address':hex(minimum),'expected_banks_hex':expected.hex()}
class Replay:
 def __init__(self,im,row):
  self.im=im;self.row=row;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.seq=0;self.ri=0;self.wi=0;self.pending=[];self.stopped=False;self.u.mem_map(P,SIZE)
  self.ensure(R.SLOT,96);self.u.mem_write(R.SLOT,bytes.fromhex(row['initial_banks_hex']));self.ensure(R.MAP,24);h=row['configuration']['header'];a=int(h['address'],16);b=bytes.fromhex(h['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b)
  for j,v in enumerate(row['initial_registers31']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(v,16))
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0);self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_READ,self.read);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.missing)
 def ensure(self,a,n=1):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   self.u.mem_map(pg,4096);self.u.mem_write(pg,self.im.logical_page(pg));self.pages.add(pg)
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def read(self,u,t,a,n,v,d):
  e=self.row['source_reads'][self.ri];self.ri+=1;assert e=={'visit':self.seq-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()}
 def write(self,u,t,a,n,v,d):
  e=self.row['source_writes'][self.wi];self.wi+=1;assert e['visit']==self.seq-1 and e['address']==hex(a) and e['size_bytes']==n;self.pending.append(e)
 def code(self,u,a,n,d):
  for e in self.pending:assert bytes(u.mem_read(int(e['address'],16),e['size_bytes'])).hex()==e['after_hex']
  self.pending=[]
  if self.seq==len(self.row['source_visits']):assert hex(a)==self.row['boundary']['PC'];self.stopped=True;return u.emu_stop()
  raw=bytes(u.mem_read(a,4));assert self.row['source_visits'][self.seq]=={'PC':hex(a),'bytes_hex':raw.hex()} and raw==self.im.k.read(a,4);self.seq+=1;i=next(self.im.k.cs.disasm(raw,a))
  if i.mnemonic in ['pacibsp','retab']:u.reg_write(ar.UC_ARM64_REG_PC,a+4 if i.mnemonic=='pacibsp' else u.reg_read(ar.UC_ARM64_REG_X30))
 def run(self):
  entry=R.SET if self.row['mode']=='set' else R.GET;self.ensure(entry,0x300);self.u.emu_start(entry,0,count=len(self.row['source_visits'])+1);assert self.stopped and self.ri==len(self.row['source_reads']) and self.wi==len(self.row['source_writes']);assert [hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))) for j in range(31)]==self.row['final_registers31'];assert hex(self.u.reg_read(ar.UC_ARM64_REG_SP))==self.row['final_SP'] and hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))==self.row['final_NZCV'];assert bytes(self.u.mem_read(R.SLOT,96)).hex()==self.row['final_banks_hex'] and sha256(bytes(self.u.mem_read(P,SIZE))).hexdigest()==self.row['final_private_sha256'];return {'source_visits_checked':self.seq,'reads_checked':self.ri,'writes_checked':self.wi,'bank_bytes_checked':96,'private_bytes_checked':SIZE}
