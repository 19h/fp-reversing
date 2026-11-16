#!/usr/bin/env python3
"""Original publisher prefixes on bounded private fixtures; O(visits+RAM) space/time.
No native kernel, device-tree traversal or IPC. Stops before later helpers.
"""
import json,struct
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_rpc502_vm_handoff import compressed,decode
from probe_kernel_vm_mig import Probe as Core,P,SIZE,SP,HALT
import recover_kernel_boot_environment_publication as R

INPUT=P+0x4000;HEADER_INPUT=P+0x6000;OTHER=P+0x8000;CPU=0xfffffe000cac7520
REGIONS=[(0xfffffe0007f8b500,0x200),(0xfffffe0007e6d000,0x1000),(0xfffffe0007ef9000,0x1000),(CPU,0x1000)]
LEAVES={0xfffffe000c621194:'declared_vector_registration_no_RAM_effect',0xfffffe000c47cce0:'declared_early_registration_no_RAM_effect'}

def arguments(c):
 b=bytearray((j*17+3)&255 for j in range(1152));struct.pack_into('<QQI',b,0x28,0x1122334455667788,0x2233445566778899,0x12345678)
 struct.pack_into('<Q',b,0x50,c.get('packed',0x1020304050607080));struct.pack_into('<Q',b,0x60,c['base']);struct.pack_into('<I',b,0x68,c['extent']);b[0x6c:0x6c+8]=b'cpus=2\0\0';return bytes(b)

class Probe(Core):
 def __init__(self,image,c,parent=None,mutate=None):
  super().__init__(image,'selector',{'id':0});self.c=c;self.parent=parent;self.mutate=mutate;self.events=[];self.envelopes=[]
  e=json.loads(read(ROOT/(R.P+'_checks.json')));self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in e['functions']]
  self.initial=[];self.image_initial=[];self.fixture(INPUT,arguments(c));self.fixture(HEADER_INPUT,bytes((j*29+7)&255 for j in range(856)));self.fixture(OTHER,bytes([0xd3])*1152)
  if parent:
   for r in parent['final_image_globals']:self.image_fixture(int(r['address'],16),bytes.fromhex(r['bytes_hex']),'Exact predecessor mutable image state; private call-frame epoch is explicit')
  else:
   for a,n in REGIONS:self.image_fixture(a,bytes([0xa5])*n,'Declared poisoned mutable image storage; native ownership unknown')
   self.u.mem_write(R.STATE,struct.pack('<I',c.get('guard',0)))
   for r in self.image_initial:
    if int(r['address'],16)<=R.STATE<int(r['address'],16)+len(bytes.fromhex(r['bytes_hex'])):
     r['bytes_hex']=bytes(self.u.mem_read(int(r['address'],16),len(bytes.fromhex(r['bytes_hex'])))).hex()
  self.entry=R.MAIN if c.get('main') else R.PLATFORM
  for j in range(31):self.set(j,0x2020202000000000+j)
  for j in range(32):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),0)
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,0);self.set(30,HALT)
  self.set(0,INPUT if c.get('main') else c.get('mode',0));self.set(1,HEADER_INPUT if c.get('main') else c.get('argument',INPUT))
  self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.entry_NZCV='0x0';self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def image_fixture(self,a,b,why):
  self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':bytes(b).hex(),'provenance':why})
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or any(lo<=a<a+n<=lo+length for lo,length in REGIONS),(hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a in [R.NEXT_TREE,R.NEXT_CONTEXT,0xfffffe000c5e6afc]:return self.stop('before_later_helper' if a!=0xfffffe000c5e6afc else 'before_tree_carry_diagnostic_setup')
  if a in LEAVES:return self.model(a,LEAVES[a],0)
  if a in [R.PLATFORM,R.STRLCPY,R.STRLEN,R.COPY]:self.events.append({'PC':hex(a),'arguments3':[hex(self.reg(j)) for j in range(3)],'return_PC':hex(self.reg(30)),'source_visit_index':len(self.visits)})
  assert any(lo<=a<hi for lo,hi in self.allowed),hex(a)
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4));ins=list(self.image.k.cs.disasm(raw,a));assert ins
  if ins[0].mnemonic in ['paciza','xpaci']:
   self.envelopes.append({'PC':hex(a),'kind':ins[0].mnemonic,'source_visit_index':len(self.visits)});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason in ['before_later_helper','before_tree_carry_diagnostic_setup'],self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_NZCV':self.entry_NZCV,'entry_registers31':self.entry_regs,'initial_vectors':['0x0']*32,
   'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in REGIONS],
   'final_page_sha256':{hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)},
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_envelopes':self.envelopes,'original_call_entries':self.events,
   'final_vectors':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)],'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,
   'same_mutable_image_predecessor':self.parent['configuration']['label'] if self.parent else None,**{n:False for n in R.FALSE}}

def cases():
 return [
  {'label':'main_normal','main':True,'base':P+0x10000,'extent':0x190},
  {'label':'main_null_tree','main':True,'base':0,'extent':0},
  {'label':'main_u32_extent_and_flags','main':True,'base':0x10000000,'extent':0xffffffff,'packed':0xffffffffffffffff},
  {'label':'main_tree_addition_carry','main':True,'base':0xfffffffffffffff0,'extent':0x20},
  {'label':'first_mode1','mode':1,'base':P+0x10000,'extent':0x190},
  {'label':'mode_uses_low32','mode':0x100000000,'base':P+0x10000,'extent':0x190},
  {'label':'reenter_mode0_ignores_new_argument','parent':'main_normal','mode':0,'argument':OTHER,'base':0,'extent':7},
  {'label':'reenter_mode1_null_context','parent':'main_normal','mode':1,'argument':0,'base':0,'extent':7},
  {'label':'reenter_mode1_CPU_context','parent':'main_normal','mode':1,'argument':CPU,'base':0,'extent':7}]
