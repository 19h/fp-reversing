#!/usr/bin/env python3
"""Original six-register entry prefix through source bank-pointer publication.

Stop before the first allocator call. Original stack probing executes in the
private guest; WZR probe loads supply no values. No API/allocator/free model,
model memory write, native business/crypto operation or IPC executes.
O(C*(B+V+E)) time/space;30000 visits/case. PAC is abstract.
"""
import hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from probe_legacy_stack import Bridge,P,M64,kernel
from kext_port_tools import ROOT,SOURCE,CS
ENTRY=0xfffffe000a5302e4;END=0xfffffe000a5304c8
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Prefix(Bridge):
 def __init__(self,c):
  super().__init__(c);self.ranges=[(ENTRY,END+4),(0xfffffe000a5a1cc4,0xfffffe000a5a1cf8),(0xfffffe000a505828,0xfffffe000a505848)];self.arg_inputs=list(c['inputs8']);self.call_sites=[];self.frame_base=None;self.start=0xfffffe000a505828 if c['entry_kind']=='provider'else ENTRY
  if c['entry_kind']=='provider':
   for j,v in enumerate([0x1234000012340000,*c['inputs8'][:6],0]):self.setreg(j,v)
  self.initial_regs8=[hex(self.reg(j))for j in range(8)]
  a=0xfffffe000ccc2d98;v=int.from_bytes(kernel().read(a,8),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else(0x12345678a5a50000+6*0x111111111)&M64;self.u.mem_write(a,struct.pack('<Q',v));self.allowed.append((a,a+8));self.extra_initial_globals=[{'address':hex(a),'bytes_hex':struct.pack('<Q',v).hex()}]
 def code(self,u,a,n,d):
  self.flush()
  if a==END:
   self.reason='before_original_allocator_call';self.boundary={'kind':self.reason,'pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]};assert self.reg(0)==0x4000 and self.reg(1)==0x40 and self.reg(8)==0xfffffe000c4b9a08;return u.emu_stop()
  assert any(x<=a<a+4<=z for x,z in self.ranges),('source escape',hex(a));raw=kernel().read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1;ins=next(CS.disasm(raw,a));m=ins.mnemonic
  if a==0xfffffe000a530330:self.frame_base=u.reg_read(ar.UC_ARM64_REG_SP)
  if m=='blraa':
   assert a==0xfffffe000a530324 and self.reg(16)==0xfffffe000a5a1cc4 and self.reg(17)==0xfffffe000847c610;self.call_sites.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(self.reg(16)),'X9_probe_size_bytes':hex(self.reg(9)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))});self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(16))
  if m=='b':
   target=int(ins.op_str[1:],16);assert any(x<=target<z for x,z in self.ranges);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m in['bti','pacibsp','paciasp','autibsp','autiasp']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in['ret','retab','retaa']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  assert not m.startswith(('pac','aut','xpac'))and m not in['blr','braa','bl'],('unhandled control',hex(a),m)
 def run(self):
  self.u.emu_start(self.start,0,count=30000);self.flush();assert self.reason=='before_original_allocator_call'and self.frame_base is not None
  F=self.frame_base;return {'input':self.case,'entry_SP':hex(self.sp0),'entry_registers8':self.initial_regs8,'expected_core_inputs6':[hex(x)for x in self.arg_inputs[:6]],'frame_base_SP':hex(F),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'source_calls':self.call_sites,'probe_only_reads':self.probe_reads,'extra_initial_globals':self.extra_initial_globals,'boundary':self.boundary,'frame':self.snapshot(F,0x13c0),'saved_left_bank':self.snapshot(F+0xc28,8),'saved_right_bank':self.snapshot(F+0xc30,8),'model_memory_writes':0,'API_models':[],'native_allocator_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False}
def cases():
 args=[[0]*8,[(1<<64)-1]*8,[0x1234567887654321,0x13579bdf,0x33445566778899aa,0x2468ace0,0xabcdef0112345678,0x1020304050607080,0,0]]
 for entry in['core','provider']:
  for g in['original','zero','declared_noise']:
   for placement in[0,0x100]:
    for values in args:yield {'family':'writer_prefix','entry_kind':entry,'inputs8':values,'global_fixture':g,'placement':placement,'delta_units32':0}
def main():
 rows=[]
 for c in cases():
  f=Prefix(c);r=f.run();del f;rows.append(r);print(json.dumps({'case':len(rows),'source_visits':len(r['source_visits']),'frame':r['frame_base_SP'],'left':r['saved_left_bank']['bytes_hex'],'right':r['saved_right_bank']['bytes_hex']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_legacy_stack.py','legacy_stack_contracts.json','kernel_native_reader.py','kext_port_tools.py']},'kernel_collection_sha256':kernel().sha256,'source_sha256':sha(SOURCE),'cases':rows,'model_memory_writes':0,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_writers_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
