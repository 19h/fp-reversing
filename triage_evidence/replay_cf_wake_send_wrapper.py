#!/usr/bin/env python3
"""Independent original wake/wrapper/aux/retry replay; no new probe import.
Recompute all packed slots and original vectors, SVC status-only return contract,
full CPU/RAM and journal checks. No native Mach/PAC/concurrency effects.
"""
import hashlib,struct
from unicorn import arm64_const as A
from daemon_receive_tools import CS
from replay_cf_runloop_wake_port import CFReplay as Parent
from replay_cf_source_scheduling import B
from replay_cf_mode_construction import TLS
from replay_cf_runloop_handoff import LOW,LOW_SIZE
from recover_cf_wake_send_wrapper import MACH,OVERWRITE,INTERNAL,TRAP,SVC,AUX
VOUCHER=B+0xbb000;SELECTED={MACH,OVERWRITE,INTERNAL,TRAP,AUX};RETURN=0x18473af34
class Replay(Parent):
 def __init__(self,p,k,s):
  super().__init__(p,k,s);self.xfi=self.xri=self.si=0;self.msg=None;v=bytearray(72);struct.pack_into('<Q',v,0x30,0x1122334455667788);v[0x38:0x48]=bytes(range(1,17));wanted=[(TLS+0xe0,struct.pack('<Q',VOUCHER if self.config.get('aux')else 0)),(VOUCHER,bytes(v))];assert p['wrapper_initial_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in wanted]
  for at,b in wanted:self.u.mem_write(at,b)
 def wrapper_frame(self,e,a):
  assert e['pc']==hex(a);self.check_frame(e);assert e['original_header24_hex']==(None if self.msg is None else bytes(self.u.mem_read(self.msg,24)).hex())and e['hook_root8_hex']==bytes(self.u.mem_read(0x1ed83e8d8,8)).hex()and e['voucher_TLS8_hex']==bytes(self.u.mem_read(TLS+0xe0,8)).hex();self.counts['wrapper_header_hook_TLS_and_complete_CPU_frames_checked']+=1
 def hashes(self):return{'private_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(B,0x100000))).hexdigest(),'lower_stack_sha256':hashlib.sha256(bytes(self.u.mem_read(LOW,LOW_SIZE))).hexdigest()}
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==MACH and self.wphase=='wakeup':
   x=[self.reg(j)for j in range(7)];self.msg=x[0];raw=bytes(u.mem_read(self.msg,24));assert x[1:]==[0x11,24,0,0,0,0]and raw==struct.pack('<6I',0x13,24,0x807,0,0,0);e=self.p['wake_send'][self.wsi];self.wake_frame(e['before'],a);assert e['arguments7']==[hex(v)for v in x]and e['header24_hex']==raw.hex()and e['expected_wrapper_status_under_declared_SVC_stream']==hex(self.config['trap_results'][-1]);self.wsi+=1;self.counts['CF_header_to_original_wrapper_entry_contracts_checked']+=1
  if self.xfi<len(self.p['wrapper_frames']):
   e=self.p['wrapper_frames'][self.xfi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:self.wrapper_frame(e,a);self.xfi+=1
  if a==RETURN:e=self.p['wrapper_returns'][self.xri];self.wrapper_frame(e,a);assert self.si==len(self.config['trap_results'])and self.reg(0)==self.config['trap_results'][-1];self.xri+=1;self.counts['original_wrapper_to_CF_status_returns_checked']+=1
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in SELECTED and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f and not(a==MACH and self.wphase!='wakeup'):
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};i=next(CS.disasm(raw,a));self.current=self.seq
   if a==SVC:
    assert(i.mnemonic,i.op_str)==('svc','#0x80')and self.reg(16)==(1<<64)-47 and self.si<len(self.config['trap_results']);e=self.p['SVC_return_contracts'][self.si];self.wrapper_frame(e['before'],a);x=[self.reg(j)for j in range(8)];vector=bool(self.config.get('aux'));status=self.config['trap_results'][self.si];assert e['selector_signed']==-47 and e['original_header_pointer']==hex(self.msg)and e['arguments8']==[hex(v)for v in x]and e['declared_status']==hex(status)and e['memory_before']==self.hashes()
    expected=[None if vector else self.msg,0x500000011 if vector else 0x400000011,(2 if vector else 24)<<32|0x13,0x807,0,0,2 if vector else 0,0]
    if vector:
     rawvec=bytes(u.mem_read(x[0],48));assert e['vector48_hex']==rawvec.hex();a0,r0,n0,c0=struct.unpack_from('<QQII',rawvec,0);a1,r1,n1,c1=struct.unpack_from('<QQII',rawvec,24);assert(a0,r0,n0,c0)==(self.msg,0,24,0)and(r1,n1,c1)==(0,40,128);aux=bytes(u.mem_read(a1,40));const=bytes(u.mem_read(0x185550960,16));assert e['aux40_hex']==aux.hex()==(const+struct.pack('<Q',0x1122334455667788)+bytes(range(1,17))).hex();expected[0]=x[0];self.counts['complete_two_record_vectors_and_original_aux40_bytes_checked']+=1
    else:assert e['vector48_hex']is None and e['aux40_hex']is None
    assert x==expected and x[1]&0x440==0;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['intercepted_original_SVC_visits_checked']+=1;self.si+=1;self.setreg(0,status);u.reg_write(A.UC_ARM64_REG_PC,a+4);self.wrapper_frame(e['after'],a+4);assert e['memory_after']==self.hashes()==e['memory_before'];self.counts['packed_trap_slots_and_X0_only_SVC_contracts_recomputed']+=1;return
   self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['original_libkernel_wrapper_and_aux_visits_checked']+=1;op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   elif op=='mrs':assert i.op_str in('x19, tpidrro_el0','x8, tpidrro_el0')and u.reg_read(A.UC_ARM64_REG_TPIDRRO_EL0)==TLS
   else:assert op not in('svc','hvc','smc','brk','msr')and not op.startswith(('pac','aut','xpac'))
   return
  return super().hook(u,a,n,d)
 def run(self):
  super().run();assert self.xfi==len(self.p['wrapper_frames'])and self.xri==len(self.p['wrapper_returns'])and self.si==len(self.p['SVC_return_contracts'])==len(self.config['trap_results'])and self.p['final_voucher72_hex']==bytes(self.u.mem_read(VOUCHER,72)).hex();return dict(self.counts)
