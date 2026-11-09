#!/usr/bin/env python3
"""Independent continuation replay, cache source and full producer-state checks.
No application-probe import. Frozen loader and preceding journal replayer are
shared; stack preservation/library binding are explicit. O(image+visits+RAM+
journals) time/space. No native library, IPC or API execution.
"""
import hashlib,struct
import unicorn as uc
from unicorn import arm64_const as A
from replay_daemon_request_consumption import Replay as Parent,B,USER,OOL,REPLY,STACK,STACK_SIZE
BSM=0x20638d758;SLOT=0x1010a0500
class Replay(Parent):
 def __init__(self,p,origin,source):
  super().__init__(p,origin,source);self.ai=0;self.application_checked=False;f=source['cache_function'];self.libstart=int(f['start'],16);self.libend=int(f['end'],16);self.libraw=bytes.fromhex(f['bytes'])
  binding=p['logical_library_binding'];assert binding['slot']==hex(SLOT)and binding['before_logical_hex']==bytes(self.u.mem_read(SLOT,8)).hex()and binding['after_logical_hex']==struct.pack('<Q',BSM).hex();self.u.mem_write(SLOT,struct.pack('<Q',BSM));self.counts['explicit_library_binding_contracts_checked']+=1
  for a in range(self.libstart&~4095,(self.libend+4095)&~4095,4096):self.u.mem_map(a,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
  self.u.mem_write(self.libstart,self.libraw)
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==0x100422d48:
   f=self.p['application_handoff'];assert f['pc']==hex(a);self.check_frame(f);assert f['private1048576_sha256']==hashlib.sha256(bytes(u.mem_read(B,0x100000))).hexdigest()and f['stack524288_sha256']==hashlib.sha256(bytes(u.mem_read(STACK,STACK_SIZE))).hexdigest();self.application_checked=True;self.counts['continuous_application_CPU_and_whole_RAM_handoffs_checked']+=1
  if self.ai<len(self.p['application_frames']):
   f=self.p['application_frames'][self.ai]
   if f['pc']==hex(a)and f['source_visit_index']==self.seq:
    self.check_frame(f)
    if 'argument_record120_hex'in f:assert f['argument_record120_hex']==bytes(u.mem_read(int(f['argument_record_address'],16),120)).hex()
    if 'audit_copy_arguments3'in f:assert f['audit_copy_arguments3']==[hex(self.reg(j))for j in range(3)]and f['audit_source32_hex']==bytes(u.mem_read(self.reg(0),32)).hex()
    if 'control_record32_hex'in f:assert f['control_record_address']==hex(self.reg(0))and f['control_record32_hex']==bytes(u.mem_read(self.reg(0),32)).hex()
    if 'stack_argument0_hex'in f:assert f['stack_argument0_hex']==bytes(u.mem_read(u.reg_read(A.UC_ARM64_REG_SP),8)).hex()
    if 'audit_input32_hex'in f:assert f['audit_input32_hex']==bytes(u.mem_read(self.reg(0),32)).hex()and f['PID_output_address']==hex(self.reg(6))
    if 'copy_arguments3'in f:assert f['copy_arguments3']==[hex(self.reg(j))for j in range(3)]and f['copy_source32_hex']==bytes(u.mem_read(self.reg(0),32)).hex()
    self.ai+=1;self.counts['complete_application_record_and_ABI_frames_checked']+=1
  if a in self.imports and self.imports[a]=='libSystem/___chkstk_darwin':
   e=self.p['imports'][self.mi];self.mi+=1;assert e['name']==self.imports[a]and e['pc']==hex(a)and e['return_pc']==hex(self.reg(30));self.check_frame(e['before']);u.reg_write(A.UC_ARM64_REG_PC,self.reg(30));self.check_frame(e['after']);assert e['before']['registers31']==e['after']['registers31']and e['before']['SP']==e['after']['SP']and e['before']['NZCV']==e['after']['NZCV']and e['before']['Q_registers32']==e['after']['Q_registers32'];self.counts['explicit_stack_preservation_contracts_checked']+=1;return
  if self.seq==len(self.p['source_visits']):
   e=self.p['imports'][self.mi];self.mi+=1;assert self.imports[a]==e['name']=='libSystem/_pthread_self'and e['pc']==hex(a)and self.p['boundary']['kind']=='before_pthread_self'and self.p['boundary']['pc']==hex(a);self.check_frame(e['before']);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();self.counts['unexecuted_pthread_identity_boundaries_checked']+=1;return
  if self.libstart<=a<self.libend:
   raw=bytes(u.mem_read(a,4));off=a-self.libstart;assert raw==self.libraw[off:off+4]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['cached_libbsm_instruction_visits_checked']+=1
   if raw==bytes.fromhex('7f2303d5'):u.reg_write(A.UC_ARM64_REG_PC,a+4);self.counts['logical_authentication_or_hint_steps_checked']+=1
   elif raw==bytes.fromhex('ff0f5fd6'):u.reg_write(A.UC_ARM64_REG_PC,self.reg(30));self.counts['logical_return_authentication_steps_checked']+=1
   return
  return super().hook(u,a,n,d)
 def run(self):
  out=super().run();assert self.application_checked and self.ai==len(self.p['application_frames'])and self.p['final_argument_record120_hex']==bytes(self.u.mem_read(int(self.p['argument_record_address'],16),120)).hex();return out
