#!/usr/bin/env python3
"""Original header walker and pointer signer on private logical-PAC fixtures.
Worst-case quadratic child-command rescans plus linear pointer visits/RAM.
"""
import struct
from hashlib import sha256
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as ar
import recover_kernel_initializer_pointer_signing as R
P=0x6600000000;SIZE=0x100000;SP=P+0xf0000;HALT=P+0xff000
def segment(sections):
 raw=bytearray(72+80*len(sections));struct.pack_into('<II',raw,0,0x19,len(raw));struct.pack_into('<I',raw,64,len(sections))
 for j,(flags,address,size) in enumerate(sections):
  off=72+80*j;struct.pack_into('<QQ',raw,off+32,address,size);struct.pack_into('<I',raw,off+64,flags)
 return bytes(raw)
def header(commands):
 raw=bytearray(32);struct.pack_into('<8I',raw,0,0xfeedfacf,0x100000c,2,12,len(commands),sum(map(len,commands)),0,0);return bytes(raw)+b''.join(commands)
def configurations():
 out=[{'label':'original_collection','mode':'walk','argument':hex(R.HEADER),'fixtures':[]}]
 def fixture(a,b):return {'address':hex(a),'bytes_hex':bytes(b).hex()}
 for size in [0,1,7,8,9,56,63,64,65,72,127,128,136]:
  data=bytearray([0x5c])*160
  for j in range(size//8):struct.pack_into('<Q',data,j*8,0 if j%3==1 else 0xfffffe000a000000+j*4)
  out.append({'label':'leaf_size'+str(size),'mode':'sign','argument':hex(P+0x10000),'fixtures':[fixture(P+0x10000,segment([(9,P+0x20000,size)])),fixture(P+0x20000,data)]})
 for label,records in [('zero_sections',[]),('ignored_types',[(8,P+0x20000,16),(11,P+0x20000,16)]),('null_address',[(9,0,64)]),('type10',[(10,P+0x20000,16)]),('flags_high_bits',[(0x109,P+0x20000,16),(0x10a,P+0x20020,16)])]:
  out.append({'label':'leaf_'+label,'mode':'sign','argument':hex(P+0x10000),'fixtures':[fixture(P+0x10000,segment(records)),fixture(P+0x20000,struct.pack('<8Q',1,0,3,4,5,6,0,8))]})
 out.append({'label':'leaf_null','mode':'sign','argument':'0x0','fixtures':[]})
 ignored=struct.pack('<II',2,8);child=P+0x30000;array=P+0x20000;seg=segment([(9,array,72),(10,array+0x100,16)]);fileset=struct.pack('<IIQQII',0x80000035,32,child,0,0,0)
 for label,outer,inner in [('zero',[],[]),('ignored',[ignored],[]),('direct_segment',[seg],[]),('empty_fileset',[fileset],[]),('fileset_no_segment',[fileset],[ignored]),('fileset_first',[fileset],[seg,ignored]),('fileset_middle',[ignored,fileset,ignored],[ignored,seg,ignored]),('fileset_last',[fileset],[ignored,seg]),('fileset_multiple',[seg,fileset],[seg,ignored,seg,fileset,seg])]:
  out.append({'label':'walk_'+label,'mode':'walk','argument':hex(P+0x10000),'fixtures':[fixture(P+0x10000,header(outer)),fixture(child,header(inner)),fixture(array,struct.pack('<9Q',1,0,3,4,0,6,7,0,9)),fixture(array+0x100,struct.pack('<2Q',10,11))]})
 return out
class Probe:
 def __init__(self,im,e,c,mutate=None):
  self.im=im;self.e=e;self.c=c;self.mutate=mutate;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.envelopes=[];self.calls=[];self.returned=False
  self.u.mem_map(P,SIZE)
  for f in c['fixtures']:self.u.mem_write(int(f['address'],16),bytes.fromhex(f['bytes_hex']))
  self.before=bytes(self.u.mem_read(P,SIZE));self.initial=[((j+1)*0x1234567812345679)&((1<<64)-1) for j in range(31)];self.initial[0]=int(c['argument'],16);self.initial[30]=HALT
  for j,v in enumerate(self.initial):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v)
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  if mutate:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
  self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.missing);self.u.hook_add(UC_HOOK_MEM_READ,self.read);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write)
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def ensure(self,a,n=1):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   self.u.mem_map(pg,4096);self.u.mem_write(pg,self.im.logical_page(pg));self.pages.add(pg)
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def flush(self):
  for row in self.pending:row['after_hex']=bytes(self.u.mem_read(int(row['address'],16),row['size_bytes'])).hex()
  self.pending=[]
 def read(self,u,t,a,n,v,d):self.reads.append({'visit':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or any(int(x['address'],16)<=a<a+n<=int(x['address'],16)+x['size_bytes'] for x in self.e['pointer_tables'])
  row={'visit':len(self.visits)-1,'PC':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n};self.writes.append(row);self.pending.append(row)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:self.returned=True;return u.emu_stop()
  assert any(int(f['start'],16)<=a<int(f['end'],16) for f in self.e['functions']),hex(a)
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.im.k.read(a,4));i=next(self.im.k.cs.disasm(raw,a));index=len(self.visits);self.visits.append({'PC':hex(a),'bytes_hex':raw.hex()})
  if a==R.SIGN:self.calls.append({'visit':index,'PC':hex(a),'argument':hex(self.reg(0)),'return_PC':hex(self.reg(30))})
  if i.mnemonic in ['pacibsp','autibsp','xpaci','pacia1716']:
   self.envelopes.append({'visit':index,'PC':hex(a),'kind':i.mnemonic,'X16':hex(self.reg(16)),'X17':hex(self.reg(17)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'LR':hex(self.reg(30)),'logical_identity':True});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def run(self):
  entry=R.WALK if self.c['mode']=='walk' else R.SIGN;self.ensure(entry,4);self.u.emu_start(entry,0,count=3000000);self.flush();assert self.returned
  final=bytes(self.u.mem_read(P,SIZE));assert final[:SP-P-0x100]==self.before[:SP-P-0x100] and final[SP-P:]==self.before[SP-P:]
  return {'configuration':self.c,'entry_PC':hex(entry),'initial_registers31':list(map(hex,self.initial)),'initial_SP':hex(SP),'initial_NZCV':'0x0','initial_private_sha256':sha256(self.before).hexdigest(),'source_word_mutated_to_NOP':None if self.mutate is None else hex(self.mutate),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'logical_PAC_envelopes':self.envelopes,'signer_entries':self.calls,'final_registers31':[hex(self.reg(j)) for j in range(31)],'final_SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'final_NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),'final_private_sha256':sha256(final).hexdigest(),'final_page_sha256':{hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)},'boundary':{'PC':hex(HALT),'returned':True},'private_nonstack_bytes_unchanged':SIZE-0x100,'native_target_executed':False,'hardware_PAC_executed':False}
