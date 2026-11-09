#!/usr/bin/env python3
"""Selector18 core workspace continuation with register-only allocator returns.

Original source initializes all observed memory. Uninitialized private values,
unlisted source and unmodeled calls stop before execution. Both allocator
results are explicit nonnull fixtures; no failure/crash or accepted context
is constructed. No model memory write/native heap/crypto/IPC operation.
O(C*(B+V+E)) time/space;30000 visits per case, abstract PAC.
"""
import hashlib,json
from pathlib import Path
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM
from probe_lskd_writers import Prefix,cases as prefix_cases
from probe_legacy_stack import P,kernel
from kext_port_tools import ROOT,SOURCE,CS
WORK=P+0x8000;AUX=P+0xc000
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Workspace(Prefix):
 def __init__(self,c):
  super().__init__(c);self.ranges.extend([(0xfffffe000a5304c8,0xfffffe000a530ac4),(0xfffffe000a561058,0xfffffe000a56106c),(0xfffffe000a56d11c,0xfffffe000a56d14c),(0xfffffe000a594c70,0xfffffe000a594d18)]);self.prior_boundary=None;self.models=[];self.more_calls=[];self.bounds=[];self.dispatch=None;self.dispatches=[];self.unknown_read=None;self.decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);self.decoder.detail=True
 def stop(self,a,kind):
  self.flush();self.reason=kind;self.boundary={'kind':kind,'pc':hex(a),'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]};return self.u.emu_stop()
 def visit(self,a):
  raw=kernel().read(a,4);assert bytes(self.u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1
 def register_return(self,a,target,kind,value):
  self.visit(a);self.models.append({'kind':kind,'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'registers8':[hex(self.reg(j))for j in range(8)],'result_X0_fixture':hex(value),'target_executed':False,'memory_effects_modeled':False});self.setreg(0,value)
  for j in range(1,18):self.setreg(j,0xf000000000000000+j*0x1111)
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.setreg(30,a+4);return self.u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000a5304c8:
   self.prior_boundary={'kind':'before_original_allocator_call','pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]};assert self.reg(0)==16384 and self.reg(1)==64 and self.reg(8)==0xfffffe000c4b9a08;return self.register_return(a,self.reg(8),'aligned_workspace_register_return',WORK)
  if self.prior_boundary is None:return super().code(u,a,n,d)
  if a==0xfffffe000a530564:
   assert self.reg(0)==0xfffffe000847ae20 and self.reg(10)==0xfffffe000c4ba154;return self.register_return(a,self.reg(10),'typed4096_register_return',AUX)
  if a==0xfffffe000a561068:return self.stop(a,'before_unsigned_order_trap')
  if not any(x<=a<a+4<=z for x,z in self.ranges):return self.stop(a,'before_undeclared_core_continuation')
  ins=next(self.decoder.disasm(kernel().read(a,4),a));m=ins.mnemonic
  if m in['ldr','ldp','ldur','ldrb','ldrh','ldurb','ldurh']:
   mem=next((x for x in ins.operands if x.type==ARM64_OP_MEM),None)
   if mem is not None:
    base=self.u.reg_read(ar.UC_ARM64_REG_SP)if ins.reg_name(mem.mem.base)=='sp'else self.reg(29 if ins.reg_name(mem.mem.base)=='fp'else int(ins.reg_name(mem.mem.base)[1:]));at=base+mem.mem.disp
    if mem.mem.index:
     idx=self.reg(int(ins.reg_name(mem.mem.index)[1:]));idx=idx&0xffffffff if ins.reg_name(mem.mem.index).startswith('w')else idx;at+=idx<<mem.shift.value
    dest=ins.reg_name(ins.operands[0].reg);width=(1 if m in['ldrb','ldurb']else 2 if m in['ldrh','ldurh']else 4 if dest.startswith(('w','s'))else 16 if dest.startswith(('q','v'))else 8)*(2 if m=='ldp'else 1)
    if P<=at<at+width<=P+0x20000 and not all(self.known[at-P:at-P+width]):self.unknown_read={'pc':hex(a),'operands':ins.op_str,'snapshot':self.snapshot(at,width)};return self.stop(a,'before_uninitialized_core_private_read')
  if m in['bl','blraa']:
   target=int(ins.op_str[1:],16)if m=='bl'else self.reg(int(ins.op_str.split(',',1)[0][1:]));row={'pc':hex(a),'source_visit_index':self.seq,'target':hex(target),'registers8':[hex(self.reg(j))for j in range(8)],'target_executed':False};self.more_calls.append(row)
   if target!=0xfffffe000a561058:return self.stop(a,'before_unmodeled_core_call')
   assert self.reg(0)<=self.reg(1);row['target_executed']=True;self.bounds.append(row);self.visit(a);self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m=='braa':
   target=self.reg(int(ins.op_str.split(',',1)[0][1:]))
   if a in[0xfffffe000a530ac0,0xfffffe000a56d148]:
    assert target in[0xfffffe000a56d11c,0xfffffe000a594c70];self.dispatches.append({'pc':hex(a),'source_visit_index':self.seq,'target':hex(target),'modifier16':hex(self.reg(17)),'X8_after_iteration':hex(self.reg(8)),'target_executed':True});self.visit(a);return u.reg_write(ar.UC_ARM64_REG_PC,target)
   self.dispatch={'pc':hex(a),'source_visit_index':self.seq,'target':hex(target),'registers31':[hex(self.reg(j))for j in range(31)],'target_executed':False};return self.stop(a,'before_core_input_guard_selected_fragment')
  if m in['ret','retab','retaa']:self.visit(a);return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  self.visit(a)
 def run(self):
  self.u.emu_start(self.start,0,count=30000);self.flush();assert self.reason is not None and self.frame_base is not None
  F=self.frame_base;return {'input':self.case,'entry_SP':hex(self.sp0),'entry_registers8':self.initial_regs8,'expected_core_inputs6':[hex(x)for x in self.arg_inputs[:6]],'frame_base_SP':hex(F),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'source_calls':self.call_sites,'additional_calls':self.more_calls,'bounds_calls':self.bounds,'models':self.models,'probe_only_reads':self.probe_reads,'extra_initial_globals':self.extra_initial_globals,'prior_boundary':self.prior_boundary,'boundary':self.boundary,'frame':self.snapshot(F,0x13c0),'workspace':self.snapshot(WORK,16384),'typed_auxiliary':self.snapshot(AUX,4096),'saved_left_bank':self.snapshot(F+0xc28,8),'saved_right_bank':self.snapshot(F+0xc30,8),'source_dispatches':self.dispatches,'unexecuted_dispatch':self.dispatch,'uninitialized_read_boundary':self.unknown_read,'model_memory_writes':0,'native_target_executed':False,'native_heap_executed':False,'complete_core_operation_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False}
def cases():
 yield from prefix_cases()
 base=next(prefix_cases())
 for pointer,length in[(P+0x2000,15),(P+0x2000,16),(P+0x2000,65536),(P+0x2000,65537),(P+0x2000,0xffffffff),(P+0x2000,0),(0,16)]:
  c=json.loads(json.dumps(base));c['inputs8'][:2]=[pointer,length];yield c
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Workspace(c);r=f.run();del f;rows.append(r);print(json.dumps({'case':j+1,'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'pc':r['boundary']['pc'],'dispatch':None if r['unexecuted_dispatch']is None else r['unexecuted_dispatch']['target']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_lskd_writers.py','probe_legacy_stack.py','legacy_stack_contracts.json','kernel_native_reader.py','kext_port_tools.py']},'kernel_collection_sha256':kernel().sha256,'source_sha256':sha(SOURCE),'cases':rows,'model_memory_writes':0,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_core_workspace_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
