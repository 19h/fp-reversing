#!/usr/bin/env python3
"""Original dispatch slices on declared source-derived frame contexts.

Stops before each authenticated call: no PAC bypass, target routine, provider,
crypto, allocator, object lifetime, Mach or native API action. Does not prove
entry reachability, frame reaching definitions or alias preservation.
O(C*I+E+B) time/space; 64-instruction cap per independent slice.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE
from resolve_kernel_collection_interfaces import commands
STACK=0x7700000000;OBJ=0x7800000000
UPPER=[0,0xa5a5a500,0x80000000,0xffffff00]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Slice:
 def __init__(self,contracts):
  self.c=contracts;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set()
  for va,off,n in IMAGE.segments:pages.update(range(va&~4095,(va+n+4095)&~4095,4096))
  for a in sorted(pages):self.u.mem_map(a,4096)
  for va,off,n in IMAGE.segments:self.u.mem_write(va,IMAGE.data[off:off+n])
  for a in sorted(pages):self.u.mem_protect(a,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
  self.u.mem_map(STACK,0x4000);self.u.mem_map(OBJ,4096);self.u.mem_write(OBJ+0x10,struct.pack('<2Q',0x1111222233334444,0x5555666677778888));self.u.mem_protect(OBJ,4096,uc.UC_PROT_READ)
  self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.unmapped)
 def reg(self,n):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(n)))
 def stop(self,reason):self.reason=reason;self.u.emu_stop()
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def code(self,u,a,n,d):
  self.flush();s=self.site
  if a==int(s['call_pc'],16):
   ins=next(CS.disasm(IMAGE.read(a,4),a));assert ins.mnemonic=='blraa'and ins.op_str=='x8, x17';self.observation={'call_pc':hex(a),'target':hex(self.reg(8)),'modifier':hex(self.reg(17)),'registers8':[hex(self.reg(j))for j in range(8)],'authenticated_call_executed':False};return self.stop('before_authenticated_call')
  if not int(s['start'],16)<=a<a+4<=int(s['call_pc'],16):return self.stop('code_extent')
  assert bytes(u.mem_read(a,4))==IMAGE.read(a,4);ins=next(CS.disasm(IMAGE.read(a,4),a));assert ins.mnemonic not in['bl','b','br','braa','ret','retab','svc','hvc','smc','brk']and not ins.mnemonic.startswith(('pac','aut','xpac'));self.visits.append(hex(a))
 def read(self,u,access,a,n,value,d):
  sp=STACK+0x2000;s=self.site;family=self.c['families'][s['family']];l,r=int(family['left'],16),int(family['right'],16)
  if STACK<=a<a+n<=STACK+0x4000:assert all(self.known[a-STACK:a-STACK+n])
  else:
   assert(n==1 and(l<=a<l+256 or r<=a<r+256))or(n==8 and(a==int(s['choice']['slot'],16)or(a in[0xfffffe0008472740,0xfffffe0008472ab8,POOL+0xb70,POOL+0xa10])or(a in[OBJ+0x10,OBJ+0x18]))),(hex(a),n)
  self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,access,a,n,value,d):
  assert STACK<=a<a+n<=STACK+0x4000;(self.known).__setitem__(slice(a-STACK,a-STACK+n),b'\1'*n);e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def unmapped(self,u,access,a,n,value,d):self.stop('unmapped');return False
 def run(self,site,byte,upper):
  self.site=site;self.reason=None;self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.observation=None;self.known=bytearray(0x4000);self.u.mem_write(STACK,b'\xa5'*0x4000)
  for j in range(31):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),0)
  sp=STACK+0x2000;self.u.reg_write(ar.UC_ARM64_REG_SP,sp);family=self.c['families'][site['family']];values={'L':int(family['left'],16),'R':int(family['right'],16),'T':TABLE,'O':OBJ}
  for j in[20,24,25,28]:self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),OBJ)
  self.u.reg_write(ar.UC_ARM64_REG_X0,OBJ+2);self.u.reg_write(ar.UC_ARM64_REG_X1,OBJ+0x12);self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(site['table_X_register'])),TABLE)
  for key,value in site['extra_register_seeds'].items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+key),values[value]if isinstance(value,str)else value)
  for key,value in site['stack_qword_seeds'].items():off=int(key);self.u.mem_write(sp+off,struct.pack('<Q',values[value]));self.known[sp+off-STACK:sp+off-STACK+8]=b'\1'*8
  word=upper|byte;self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(site['input_W_register'])),word);self.u.emu_start(int(site['start'],16),0,count=64);self.flush();self.reason=self.reason or'instruction_budget';assert self.reason=='before_authenticated_call',self.reason
  return {'call_pc':site['call_pc'],'input_word32':hex(word),'byte_input':byte,'upper_bits32':hex(upper),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'call_observation':self.observation,'stop_reason':self.reason,'native_API_executed':False,'entry_reachability_proved':False}
def main():
 c=json.loads((ROOT/'kext_aes_dispatch_contracts.json').read_text());g=Slice(c);rows=[]
 for s in c['sites']:
  for upper in UPPER:
   for byte in range(256):rows.append(g.run(s,byte,upper))
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['kext_aes_dispatch_contracts.json','kext_port_tools.py','resolve_kernel_collection_interfaces.py']},'cases':rows,'native_target_executed':False,'authentication_executed':False,'all_native_dispatch_contexts_proved':False,'full_goal_complete':False};(ROOT/'kext_aes_dispatch_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'stopped_before_authentication':len(rows)}),flush=True)
if __name__=='__main__':main()
