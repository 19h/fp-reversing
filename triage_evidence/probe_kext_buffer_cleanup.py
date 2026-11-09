#!/usr/bin/env python3
"""Original cleanup control flow with declared objects and call-result models.

Source globals/vtable targets are pinned. Objects are fixtures, not native
receiver state. PAC is abstracted; complete/release are recorded and modeled
at original indirect-call sites. No native completion/reference/API runs.
O(C*I+E) time/space, 128-instruction cap per case.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
ENTRY=0xfffffe000a5085e0;END=0xfffffe000a5086a0
OBJ=0x7400000000;PROV=0x7500000000;STACK=0x7600000000;HALT=STACK+0x1000
BVT=0xfffffe0007f85d80;PVT=0xfffffe0007f89198
FLAG=0xfffffe000ccceb00;SERVICE=FLAG+8;DESC=FLAG+16;BYTES=0xfffffe000ccc7848
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cases():
 n=0
 for flag in[0,1]:
  for desc in[False,True]:
   for byteptr in[False,True]:
    for provider in[False,True]:
     yield {'case':n,'flag8':flag,'descriptor_present':desc,'bytes_present':byteptr,'provider_present':provider,'complete_return32':0,'release_return64':0,'family':'presence_grid'};n+=1
 for result in[1,0xe00002bc,0xffffffff]:
  yield {'case':n,'flag8':1,'descriptor_present':True,'bytes_present':True,'provider_present':True,'complete_return32':result,'release_return64':0xffffffffffffffff,'family':'return_status'};n+=1
class Cleanup:
 def __init__(self):
  self.contract=json.loads((ROOT/'kext_buffer_contracts.json').read_text());slots=self.contract['nominal_slots'];self.slots={int(e['slot'],16):int(e['target'],16)for e in slots if e['kind']in['buffer','provider']};self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages={ENTRY&~4095,OBJ,PROV,STACK,HALT,FLAG&~4095,BYTES&~4095,BVT&~4095,PVT&~4095}
  for a in sorted(pages):self.u.mem_map(a,4096)
  self.raw=IMAGE.read(ENTRY,END-ENTRY);self.u.mem_write(ENTRY,self.raw);self.u.mem_write(OBJ,struct.pack('<Q',BVT));self.u.mem_write(PROV,struct.pack('<Q',PVT))
  for a in[BVT+0x28,BVT+0x220,PVT+0x28]:self.u.mem_write(a,struct.pack('<Q',self.slots[a]))
  self.decoded={i.address:i for i in CS.disasm(self.raw,ENTRY)};self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.unmapped)
 def reg(self,n):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(n)))
 def stop(self,why):self.reason=why;self.u.emu_stop()
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('return')
  if not ENTRY<=a<a+4<=END:return self.stop('code_extent')
  assert bytes(u.mem_read(a,4))==IMAGE.read(a,4);self.visits.append(hex(a));i=self.decoded[a];m=i.mnemonic
  if m in['bti','pacibsp','autda']:
   if m!='bti':self.abstracted.append({'pc':hex(a),'instruction':m})
   return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m=='retab':self.abstracted.append({'pc':hex(a),'instruction':m});return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  if m=='blraa':
   target=self.reg(8);receiver=self.reg(0);kind='complete'if a==0xfffffe000a508630 else'release';assert a in[0xfffffe000a508630,0xfffffe000a508654,0xfffffe000a508680]
   assert receiver==(PROV if a==0xfffffe000a508680 else OBJ)and receiver not in self.retired
   expected=self.slots[(BVT+0x220)if kind=='complete'else(PVT+0x28)if receiver==PROV else(BVT+0x28)];assert target==expected
   e={'pc':hex(a),'kind':kind,'target':hex(target),'receiver':hex(receiver),'W1':hex(self.reg(1)&0xffffffff),'source_visit_index':len(self.visits)-1,'native_API_executed':False};self.calls.append(e)
   if kind=='complete':assert self.reg(1)==0;value=self.case['complete_return32']
   else:self.retired.add(receiver);value=self.case['release_return64']
   e['modeled_return64']=hex(value);u.reg_write(ar.UC_ARM64_REG_X0,value);u.reg_write(ar.UC_ARM64_REG_X30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def read(self,u,access,a,n,value,d):
  if STACK<=a<a+n<=STACK+4096:assert all(self.stack_known[a-STACK:a-STACK+n])
  else:
   assert(a,n)in{(DESC,8),(SERVICE,8),(BYTES,8),(OBJ,8),(PROV,8),(BVT+0x28,8),(BVT+0x220,8),(PVT+0x28,8)},(hex(a),n)
   assert a not in self.retired
  self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),'source_visit_index':len(self.visits)-1})
 def write(self,u,access,a,n,value,d):
  if STACK<=a<a+n<=STACK+4096:self.stack_known[a-STACK:a-STACK+n]=b'\1'*n
  else:assert(a,n)in{(DESC,8),(SERVICE,8),(BYTES,8),(FLAG,1)},(hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'source_visit_index':len(self.visits)-1};self.writes.append(e);self.pending.append(e)
 def unmapped(self,u,access,a,n,value,d):self.stop('unmapped');return False
 def run(self,c):
  self.case=c;self.reason=None;self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.calls=[];self.retired=set();self.abstracted=[];self.stack_known=bytearray(4096)
  for j in range(31):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),0)
  self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0xf00);self.u.reg_write(ar.UC_ARM64_REG_X30,HALT)
  for a,value,n in[(FLAG,c['flag8'],1),(DESC,OBJ if c['descriptor_present']else 0,8),(SERVICE,PROV if c['provider_present']else 0,8),(BYTES,0x123456789abcdef0 if c['bytes_present']else 0,8)]:self.u.mem_write(a,value.to_bytes(n,'little'))
  self.u.emu_start(ENTRY,0,count=128);self.flush();self.reason=self.reason or'instruction_budget';assert self.reason=='return',self.reason
  return {'input':c,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'modeled_calls':self.calls,'abstracted_authentication':self.abstracted,'return64':hex(self.reg(0)),'final_globals':{hex(a):bytes(self.u.mem_read(a,n)).hex()for a,n in[(FLAG,1),(DESC,8),(SERVICE,8),(BYTES,8)]},'retired_in_model':[hex(a)for a in sorted(self.retired)],'stop_reason':self.reason,'native_API_executed':False}
def main():
 g=Cleanup();rows=[g.run(c)for c in cases()];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','kext_buffer_contracts.json','resolve_kernel_collection_interfaces.py']},'cases':rows,'native_target_executed':False,'native_reference_effects_proved':False,'native_reachability_proved':False,'full_goal_complete':False};(ROOT/'kext_buffer_cleanup_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cleanup_cases':len(rows),'cleanup_source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
