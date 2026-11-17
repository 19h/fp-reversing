#!/usr/bin/env python3
"""Continuous original _PRnut72j9 entry in a private, defined-byte guest.

Only two register-only nonnull allocation results are supplied. Source words,
reads, writes and all GPR/NZCV epochs are retained. Stop before unmodeled calls,
undefined private value loads or unlisted source; no native heap, IPC or crypto
operation executes. PAC is logical. O(C*(B+V+E)) time and retained space.
"""
import json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM,ARM64_EXT_SXTW
from probe_legacy_stack import Bridge,P,M64,kernel,HALT
from kext_port_tools import ROOT,IMAGE

ENTRY=0xfffffe000a635208;END=0xfffffe000a666930
PROBE=0xfffffe000a5a1cc4;ORDER=0xfffffe000a687ecc
WORK=P+0x8000;AUX=P+0xc000
CONTROLLERS=[0xfffffe000ccc30d0,0xfffffe000ccc32f8]
class Entry(Bridge):
 def __init__(self,c,mutation=None):
  super().__init__(c);self.mutation=mutation;self.ranges=[(ENTRY,END),(PROBE,PROBE+0x34),(ORDER,ORDER+0x14)];self.decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);self.decoder.detail=True;self.frames=[];self.edges=[];self.models=[];self.frame_base=None;self.unknown_read=None;self.outside_call=None;self.probe_entries=[];self.extra_initial_globals=[]
  for j,a in enumerate(CONTROLLERS):
   v=int.from_bytes(kernel().read(a,8),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else (0x12345678a5a50000+(j+6)*0x111111111)&M64
   b=struct.pack('<Q',v);self.u.mem_write(a,b);self.allowed.append((a,a+8));self.extra_initial_globals.append({'address':hex(a),'bytes_hex':b.hex()})
  for j in range(32):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),(j+1)*0x112233445566778899aabbccddeeff)
  self.initial_registers31=[hex(self.reg(j))for j in range(31)];self.initial_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.initial_Q_registers32=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
  if mutation:
   a=mutation['pc'];self.u.mem_write(a,b'\x1f\x20\x03\xd5')
 def stop(self,a,kind):
  self.flush();self.reason=kind;self.boundary={'kind':kind,'pc':hex(a),'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)],'NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))};return self.u.emu_stop()
 def visit(self,a,raw):
  self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.frames.append({'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)],'NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))});self.seq+=1
 def edge(self,a,target,kind):
  self.edges.append({'pc':hex(a),'target':hex(target),'kind':kind,'source_visit_index':self.seq-1,'modifier64':hex(self.reg(17))if kind in ['blraa','braa']else None})
  if kind in ['bl','blraa']:self.setreg(30,a+4)
  self.u.reg_write(ar.UC_ARM64_REG_PC,target)
 def model(self,a,target,kind,value):
  self.models.append({'pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'kind':kind,'arguments8':[hex(self.reg(j))for j in range(8)],'result_X0_fixture':hex(value),'target_executed':False,'model_memory_writes':0})
  self.setreg(0,value)
  for j in range(1,18):self.setreg(j,0xf000000000000000+j*0x1111)
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.setreg(30,a+4);return self.u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def effective_load(self,i):
  m=next(o for o in i.operands if o.type==ARM64_OP_MEM);name=i.reg_name(m.mem.base);base=self.u.reg_read(ar.UC_ARM64_REG_SP)if name=='sp'else self.reg(int({'fp':'x29','lr':'x30'}.get(name,name)[1:]));at=base+m.mem.disp
  if m.mem.index:
   name=i.reg_name(m.mem.index);ix=self.reg(int(name[1:]));ix=ix&0xffffffff if name.startswith('w')else ix
   if m.ext==ARM64_EXT_SXTW and ix&0x80000000:ix-=1<<32
   at+=ix<<m.shift.value
  dest=i.reg_name(i.operands[0].reg);width=1 if i.mnemonic in ['ldrb','ldurb']else 2 if i.mnemonic in ['ldrh','ldurh']else 4 if dest.startswith(('w','s'))else 16 if dest.startswith(('q','v'))else 8
  return at&M64,width*(2 if i.mnemonic=='ldp'else 1),dest
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop(a,'original_return')
  if not any(x<=a<a+4<=z for x,z in self.ranges):return self.stop(a,'before_unlisted_source')
  raw=kernel().read(a,4);actual=bytes(u.mem_read(a,4))
  if self.mutation and a==self.mutation['pc']:assert actual==b'\x1f\x20\x03\xd5';raw=actual
  else:assert actual==raw==IMAGE.read(a,4)
  i=next(self.decoder.disasm(raw,a));m=i.mnemonic
  if a==0xfffffe000a63524c:self.frame_base=u.reg_read(ar.UC_ARM64_REG_SP)
  if m in ['ldr','ldp','ldur','ldrb','ldrh','ldurb','ldurh']:
   at,width,dest=self.effective_load(i)
   if P<=at<at+width<=P+0x20000 and dest not in ['wzr','xzr']and not all(self.known[at-P:at-P+width]):self.unknown_read={'pc':hex(a),'operands':i.op_str,'snapshot':self.snapshot(at,width)};return self.stop(a,'before_undefined_private_value_load')
  if m in ['bl','blraa','blr']:
   target=i.operands[0].imm if m=='bl'else self.reg(int(i.op_str.split(',',1)[0][1:]))
   if a==0xfffffe000a6353dc:
    assert target==0xfffffe000c4b9a08 and self.reg(0)==0x4000 and self.reg(1)==64;self.visit(a,raw);return self.model(a,target,'aligned16384_register_return',WORK)
   if a==0xfffffe000a635470:
    assert target==0xfffffe000c4ba154 and self.reg(0)==0xfffffe000847bea0;self.visit(a,raw);return self.model(a,target,'typed4096_register_return',AUX)
   if target not in [PROBE,ORDER]:self.outside_call={'pc':hex(a),'target':hex(target),'arguments8':[hex(self.reg(j))for j in range(8)]};return self.stop(a,'before_unmodeled_call')
   if target==PROBE:self.probe_entries.append({'pc':hex(a),'probe_size_bytes':self.reg(9),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
   self.visit(a,raw);return self.edge(a,target,m)
  if m in ['braa','br','brab']:
   assert m!='brab';target=self.reg(int(i.op_str.split(',',1)[0][1:]));self.visit(a,raw);return self.edge(a,target,m)
  if m in ['ret','retab','retaa']:
   self.visit(a,raw);return self.edge(a,self.reg(30),m)
  if m in ['bti','pacibsp','paciasp','autibsp','autiasp']:
   self.visit(a,raw);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in ['brk','svc','hvc','smc','mrs','msr']:return self.stop(a,'before_unsupported_architectural_effect')
  assert not m.startswith(('pac','aut','xpac')),(hex(a),m)
  self.visit(a,raw)
 def run(self):
  self.u.emu_start(ENTRY,0,count=30000);self.flush();assert self.reason is not None and self.frame_base is not None
  return {'input':self.case,'entry_PC':hex(ENTRY),'entry_SP':hex(self.sp0),'entry_registers31':self.initial_registers31,'entry_NZCV':self.initial_NZCV,'entry_Q_registers32':self.initial_Q_registers32,'boundary_D_registers32':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_D'+str(j)))) for j in range(32)],'frame_base_SP':hex(self.frame_base),'extra_initial_globals':self.extra_initial_globals,'source_visits':self.visits,'source_frames':self.frames,'source_reads':self.reads,'source_writes':self.writes,'logical_edges':self.edges,'API_models':self.models,'probe_entries':self.probe_entries,'boundary':self.boundary,'unknown_read':self.unknown_read,'unexecuted_call':self.outside_call,'frame':self.snapshot(self.frame_base,0x10f0),'workspace':self.snapshot(WORK,0x4000),'typed_region':self.snapshot(AUX,0x1000),'model_memory_writes':0,'native_target_executed':False,'native_PAC_authenticated':False,'full_goal_complete':False}
def cases():
 for globals in ['original','zero','declared_noise']:
  for placement in [0,0x100]:
   for pointer,length in [(0,0),(0,M64),(P+0x2000,0),(P+0x2000,1),(P+0x2000,16),(P+0x2000,65536),(P+0x2000,0x1234567800000010),(M64,M64)]:
    yield {'family':'userclient_entry','global_fixture':globals,'placement':placement,'inputs8':[pointer,length,P+0x3000 if length else 0,0,0,0,0,0],'delta_units32':0}
def main():
 rows=[]
 for c in cases():
  f=Entry(c);r=f.run();rows.append(r);del f;print(json.dumps({'case':len(rows),'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'pc':r['boundary']['pc'],'call':r['unexecuted_call']}),flush=True)
 (ROOT/'userclient_entry_execution_profiles.json').write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
