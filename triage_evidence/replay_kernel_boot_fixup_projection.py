#!/usr/bin/env python3
"""Independent packed-word oracle and raw-image fresh CPU replay.
O(source visits + journals + RAM/pages); no full boot or native signing.
"""
import struct
from hashlib import sha256
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as ar
import recover_kernel_boot_fixup_projection as R
P=0x6800000000;SIZE=0x100000;SP=P+0xf0000;SLOT=P+0x20000;META=P+0x10000;BASES=P+0x30000
def oracle(row,e):
 c=row['configuration'];checks=[]
 def ok(label,p):assert p,('boot_fixup_contract',label);checks.append(label)
 if c['mode']=='prefix':
  registers=list(map(lambda x:int(x,16),row['final_registers31']));first=e['chain_page_receipts'][0];ok('prefix_stops_before_first_fixup',row['boundary_PC']==hex(R.HEAD));ok('prefix_derives_root_and_zero_slide',registers[19:21]==[0,R.BANK]);ok('first_chain_slot_and_metadata',registers[0]==int(first['first_slot'],16) and registers[13]==int(first['metadata_address'],16));ok('source_prefix_frame_and_base_array',int(row['final_SP'],16)==SP-160 and registers[12]==SP-136);ok('prefix_writes_only_its_frame',all(SP-160<=int(w['address'],16)<int(w['address'],16)+w['size_bytes']<=SP for w in row['source_writes']))
 else:
  word=c['word'];fmt=c['format']&0xffff;level=(word>>30)&3;base=c['bases'][level];valid=fmt in [8,11] and base!=0;offset=word&0x3fffffff;target=(base+offset)&((1<<64)-1);next_count=(word>>51)&4095;step=next_count*(4 if fmt==8 else 1);div=(word>>32)&65535;modifier=div if not word&(1<<48) else (SLOT if div==0 else (SLOT&0xffffffffffff)|(div<<48));auth=word>>63;key=(word>>49)&3
  wanted=target if valid else word;ok('exact_logical_slot_bytes',row['final_slot_hex']==wanted.to_bytes(8,'little').hex());ok('one_or_zero_source_pointer_stores',len(row['source_writes'])==int(valid) and all(w['PC']=='0xfffffe000c660974' and w['address']==hex(SLOT) and w['size_bytes']==8 for w in row['source_writes']));ok('boundary_and_next_slot',row['boundary_PC']==hex(R.FAIL if not valid else R.END if next_count==0 else R.HEAD) and int(row['final_registers31'][0],16)==SLOT+(step if valid and next_count else 0));signs=row['logical_PAC_envelopes'];ok('sign_event_count',len(signs)==int(valid and auth))
  if valid and auth:ok('key_modifier_and_target_custody',signs[0]['kind']==['pacia1716','pacib1716','pacda','pacdb'][key] and int(signs[0]['X16'],16)==modifier and int(signs[0]['X17'],16)==target)
  ok('cut_SP_unchanged',row['final_SP']==hex(SP))
 ok('native_and_hardware_unexecuted',not row['native_target_executed'] and not row['hardware_PAC_executed']);return {'checks':checks}
class Replay:
 def __init__(self,k,row):
  self.k=k;self.row=row;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.seq=self.ri=self.wi=self.ei=0;self.pending=[];self.stopped=False;self.u.mem_map(P,SIZE);c=row['configuration']
  if c['mode']=='word':self.u.mem_write(SLOT,struct.pack('<Q',c['word']));self.u.mem_write(META+6,struct.pack('<H',c['format']));self.u.mem_write(BASES,struct.pack('<4Q',*c['bases']))
  assert sha256(bytes(self.u.mem_read(P,SIZE))).hexdigest()==row['initial_private_sha256']
  for j,v in enumerate(row['initial_registers31']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(v,16))
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0);self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_READ,self.read);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.missing)
 def ensure(self,a,n=1):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   self.u.mem_map(pg,4096);self.u.mem_write(pg,self.k.read(pg,4096));self.pages.add(pg)
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def read(self,u,t,a,n,v,d):
  want=self.row['source_reads'][self.ri];self.ri+=1;assert want=={'visit':self.seq-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()}
 def write(self,u,t,a,n,v,d):
  want=self.row['source_writes'][self.wi];self.wi+=1;assert all(want[k]==v for k,v in {'visit':self.seq-1,'PC':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n}.items());self.pending.append(want)
 def code(self,u,a,n,d):
  for w in self.pending:assert bytes(u.mem_read(int(w['address'],16),w['size_bytes'])).hex()==w['after_hex']
  self.pending=[]
  if self.seq==len(self.row['source_visits']):assert hex(a)==self.row['boundary_PC'];self.stopped=True;return u.emu_stop()
  raw=bytes(u.mem_read(a,4));assert self.row['source_visits'][self.seq]=={'PC':hex(a),'bytes_hex':raw.hex()} and raw==self.k.read(a,4);index=self.seq;self.seq+=1;i=next(self.k.cs.disasm(raw,a))
  if i.mnemonic in ['pacibsp','pacia1716','pacib1716','pacda','pacdb']:
   reg=lambda j:u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)));assert self.row['logical_PAC_envelopes'][self.ei]=={'visit':index,'PC':hex(a),'kind':i.mnemonic,'X16':hex(reg(16)),'X17':hex(reg(17)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'logical_identity':True};self.ei+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def run(self):
  entry=int(self.row['entry_PC'],16);self.ensure(entry);self.u.emu_start(entry,0,count=len(self.row['source_visits'])+1);assert self.stopped and self.ri==len(self.row['source_reads']) and self.wi==len(self.row['source_writes']) and self.ei==len(self.row['logical_PAC_envelopes']);assert [hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))) for j in range(31)]==self.row['final_registers31'];assert hex(self.u.reg_read(ar.UC_ARM64_REG_SP))==self.row['final_SP'] and hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))==self.row['final_NZCV'];assert sha256(bytes(self.u.mem_read(P,SIZE))).hexdigest()==self.row['final_private_sha256'];assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in self.pages}==self.row['final_raw_page_sha256'];return {'source_visits_checked':self.seq,'reads_checked':self.ri,'writes_checked':self.wi,'PAC_envelopes_checked':self.ei,'private_bytes_checked':SIZE,'raw_image_page_bytes_checked':4096*len(self.pages)}
