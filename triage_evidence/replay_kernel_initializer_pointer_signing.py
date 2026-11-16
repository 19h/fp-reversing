#!/usr/bin/env python3
"""Independent bounded command/section oracle and fresh logical-PAC replay.
Parsing is linear in records/pointers; CPU follows quadratic child rescans.
"""
import struct
from hashlib import sha256
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as ar
import recover_kernel_initializer_pointer_signing as R
P=0x6600000000;SIZE=0x100000;SP=P+0xf0000;HALT=P+0xff000
def oracle(im,row):
 fixtures=[(int(f['address'],16),bytes.fromhex(f['bytes_hex'])) for f in row['configuration']['fixtures']];cache={};checks=[]
 def read(a,n):
  if P<=a<a+n<=P+SIZE:
   b=bytearray(n)
   for at,raw in fixtures:
    lo,hi=max(a,at),min(a+n,at+len(raw))
    if lo<hi:b[lo-a:hi-a]=raw[lo-at:hi-at]
   return bytes(b)
  b=bytearray()
  while n:
   pg=a&~4095
   if pg not in cache:cache[pg]=im.logical_page(pg)
   count=min(n,4096-(a&4095));b+=cache[pg][a&4095:(a&4095)+count];a+=count;n-=count
  return bytes(b)
 def commands(h):
  n=struct.unpack('<I',read(h+16,4))[0];at=h+32
  for _ in range(n):
   c,size=struct.unpack('<II',read(at,8));assert size>=8;yield at,c;at+=size
 argument=int(row['configuration']['argument'],16);segments=[]
 if row['configuration']['mode']=='sign':segments=[argument]
 else:
  for at,c in commands(argument):
   if c==0x19:segments.append(at)
   elif c==0x80000035:
    child=struct.unpack('<Q',read(at+8,8))[0];segments += [a for a,c in commands(child) if c==0x19]
 wanted=[];section_count=0
 for segment in segments:
  if not segment:continue
  n=struct.unpack('<I',read(segment+64,4))[0]
  for j in range(n):
   at=segment+72+80*j;flags=read(at+64,1)[0]
   if flags not in [9,10]:continue
   section_count+=1;a,size=struct.unpack('<QQ',read(at+32,16))
   if not a:continue
   for index in range(size//8):
    value=struct.unpack('<Q',read(a+8*index,8))[0]
    if value:wanted.append({'slot':a+8*index,'value':value,'segment':segment,'section_index':j})
 def ok(label,p):assert p,('initializer_pointer_contract',label);checks.append(label)
 ok('exact_segment_signer_entry_sequence',[int(c['argument'],16) for c in row['signer_entries']]==segments)
 stores=[w for w in row['source_writes'] if not SP-0x100<=int(w['address'],16)<SP];xpac=[x for x in row['logical_PAC_envelopes'] if x['kind']=='xpaci'];pac=[x for x in row['logical_PAC_envelopes'] if x['kind']=='pacia1716']
 ok('exact_nonzero_target_store_count',len(stores)==len(wanted));ok('one_strip_and_sign_per_nonzero_pointer',len(xpac)==len(pac)==len(wanted))
 for index,(w,x,s,q) in enumerate(zip(stores,xpac,pac,wanted)):
  ok('slot_'+str(index),int(w['address'],16)==q['slot'] and w['size_bytes']==8 and w['after_hex']==q['value'].to_bytes(8,'little').hex())
  ok('PAC_custody_'+str(index),int(x['X16'],16)==q['value'] and int(s['X17'],16)==q['value'] and int(s['X16'],16)==0x4a27 and x['visit']<s['visit']<w['visit'])
 ok('normal_return_and_SP',row['boundary']=={'PC':hex(HALT),'returned':True} and row['final_SP']==hex(SP));ok('callee_saved_GPRs',row['final_registers31'][19:30]==row['initial_registers31'][19:30]);ok('private_nonstack_unchanged',row['private_nonstack_bytes_unchanged']==SIZE-256)
 for pg,digest in row['final_page_sha256'].items():
  original=bytearray(im.logical_page(int(pg,16)));mutate=row['source_word_mutated_to_NOP']
  if mutate and int(mutate,16)&~4095==int(pg,16):original[int(mutate,16)&4095:(int(mutate,16)&4095)+4]=bytes.fromhex('1f2003d5')
  ok('logical_page_unchanged_'+pg,sha256(original).hexdigest()==digest)
 ok('native_and_hardware_unexecuted',not row['native_target_executed'] and not row['hardware_PAC_executed'])
 return {'checks':checks,'segment_signer_entries':len(segments),'eligible_sections':section_count,'nonzero_pointer_stores':len(wanted),'logical_pointer_bytes_unchanged':8*len(wanted),'expected_pointer_sequence':[{'slot':hex(q['slot']),'value':hex(q['value']),'segment':hex(q['segment']),'section_index':q['section_index']} for q in wanted]}
class Replay:
 def __init__(self,im,row):
  self.im=im;self.row=row;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.seq=self.ri=self.wi=self.ei=self.ci=0;self.pending=[];self.returned=False;self.u.mem_map(P,SIZE)
  for f in row['configuration']['fixtures']:self.u.mem_write(int(f['address'],16),bytes.fromhex(f['bytes_hex']))
  assert sha256(bytes(self.u.mem_read(P,SIZE))).hexdigest()==row['initial_private_sha256']
  for j,v in enumerate(row['initial_registers31']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(v,16))
  self.u.reg_write(ar.UC_ARM64_REG_SP,int(row['initial_SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(row['initial_NZCV'],16));self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_READ,self.read);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.missing)
 def ensure(self,a,n=1):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   self.u.mem_map(pg,4096);self.u.mem_write(pg,self.im.logical_page(pg));self.pages.add(pg)
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def read(self,u,t,a,n,v,d):
  expected=self.row['source_reads'][self.ri];self.ri+=1;assert expected=={'visit':self.seq-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()}
 def write(self,u,t,a,n,v,d):
  expected=self.row['source_writes'][self.wi];self.wi+=1;assert all(expected[k]==v for k,v in {'visit':self.seq-1,'PC':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n}.items());self.pending.append(expected)
 def code(self,u,a,n,d):
  for e in self.pending:assert bytes(u.mem_read(int(e['address'],16),e['size_bytes'])).hex()==e['after_hex']
  self.pending=[]
  if self.seq==len(self.row['source_visits']):assert a==HALT;self.returned=True;return u.emu_stop()
  raw=bytes(u.mem_read(a,4));assert self.row['source_visits'][self.seq]=={'PC':hex(a),'bytes_hex':raw.hex()} and raw==self.im.k.read(a,4);index=self.seq;self.seq+=1;i=next(self.im.k.cs.disasm(raw,a))
  reg=lambda j:u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
  if a==R.SIGN:
   assert self.row['signer_entries'][self.ci]=={'visit':index,'PC':hex(a),'argument':hex(reg(0)),'return_PC':hex(reg(30))};self.ci+=1
  if i.mnemonic in ['pacibsp','autibsp','xpaci','pacia1716']:
   assert self.row['logical_PAC_envelopes'][self.ei]=={'visit':index,'PC':hex(a),'kind':i.mnemonic,'X16':hex(reg(16)),'X17':hex(reg(17)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'LR':hex(reg(30)),'logical_identity':True};self.ei+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def run(self):
  entry=int(self.row['entry_PC'],16);self.ensure(entry);self.u.emu_start(entry,0,count=len(self.row['source_visits'])+1);assert self.returned and self.seq==len(self.row['source_visits']) and self.ri==len(self.row['source_reads']) and self.wi==len(self.row['source_writes']) and self.ei==len(self.row['logical_PAC_envelopes']) and self.ci==len(self.row['signer_entries'])
  assert [hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))) for j in range(31)]==self.row['final_registers31'] and hex(self.u.reg_read(ar.UC_ARM64_REG_SP))==self.row['final_SP'] and hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))==self.row['final_NZCV'];assert sha256(bytes(self.u.mem_read(P,SIZE))).hexdigest()==self.row['final_private_sha256'];assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in self.pages}==self.row['final_page_sha256']
  return {'source_visits_checked':self.seq,'reads_checked':self.ri,'writes_checked':self.wi,'PAC_envelopes_checked':self.ei,'signer_entries_checked':self.ci,'private_bytes_checked':SIZE,'image_page_bytes_checked':4096*len(self.pages)}
