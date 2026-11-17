#!/usr/bin/env python3
"""Independent CPU/register-bank replay; no new producer executor import.
Linear journals/mapped bytes; inherited fileset rescans may be quadratic.
"""
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import sha
import replay_kernel_main_pointer_signing as B
import recover_kernel_cpu_initialization_execution as R
class Replay(B.Replay):
 def __init__(self,im,row):
  super().__init__(im,row);self.cpu_seen=False;self.cpu_entries=[];self.cpu_returns=[];self.cpu_active=[];self.hardware_reads=[]
 def code(self,u,a,n,d):
  self.finish()
  while self.cpu_active and self.cpu_entries[self.cpu_active[-1]]['return_PC']==hex(a) and self.cpu_entries[self.cpu_active[-1]]['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   j=self.cpu_active.pop();self.cpu_returns.append({'entry_index':j,'before_visit':self.seq,'X0':hex(self.reg(0))})
  if a==R.CALL:self.check_handoff_checkpoint(self.p['CPU_entry_checkpoint']);self.cpu_seen=True
  if a==R.STOP:self.check_handoff_checkpoint(self.p['CPU_return_checkpoint'])
  if self.seq==len(self.p['source_visits']):return super().code(u,a,n,d)
  if a in [R.INIT,*R.ADDITIONS]:self.cpu_active.append(len(self.cpu_entries));self.cpu_entries.append({'PC':hex(a),'before_visit':self.seq,'arguments6':[hex(self.reg(j)) for j in range(6)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_PC':hex(self.reg(30))})
  if a==B.B.B.R.MRS:
   c=self.p['logging_join_checkpoints'][self.join_count];self.check_handoff_checkpoint(c);phase=int.from_bytes(u.mem_read(B.B.B.R.C.PHASE,4),'little');assert phase<19
   for lo,hi in [(B.B.B.R.C.START,B.B.B.R.C.START+16),(B.B.B.R.C.SECOND,B.B.B.R.C.JOIN)]:assert bytes(u.mem_read(lo,hi-lo))==self.image.k.read(lo,hi-lo)
   raw=bytes(u.mem_read(a,4));assert raw.hex()=='28423bd5' and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};event={'PC':hex(a),'kind':'source_proved_early_logging_join','before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'proof_audit_sha256':sha(ROOT/(B.B.B.R.C.P+'_audit.json')),'phase_address':hex(B.B.B.R.C.PHASE),'phase_bytes_hex':phase.to_bytes(4,'little').hex(),'phase_u32':phase,'join_PC':hex(B.B.B.R.JOIN),'contracted_original_words':9,'DAIF_value_supplied':False};assert event==self.p['proved_logging_joins'][self.join_count] and event==self.p['logical_effects'][len(self.logical)];self.logical.append(event);self.seq+=1;self.join_count+=1;self.joined=True;self.counts['source_visits_checked']+=1;self.counts['proved_block_transitions_checked']+=1;self.counts['contracted_original_words_checked']+=9
   for j,value in [(8,0xfffffe0007f34000),(9,phase),(24,1)]:u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),value)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0x80000000);u.reg_write(ar.UC_ARM64_REG_PC,B.B.B.R.JOIN);return
  if self.cpu_seen:
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic in ['mrs','msr','isb','dsb','dmb']:
    assert self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};event={'PC':hex(a),'kind':i.mnemonic,'operands':i.op_str,'before_visit':self.seq,'system_before':dict(self.system)}
    if i.mnemonic=='mrs':
     register,name=i.op_str.split(', ')
     if name=='ccsidr_el1':bank=self.system['csselr_el1'];value=self.p['architectural_input_profile']['CCSIDR_by_CSSELR'][str(bank)];event['bank_selector']=bank
     else:value=self.system[name]
     u.reg_write(getattr(ar,'UC_ARM64_REG_'+register.upper()),value);event['read_value']=hex(value);self.hardware_reads.append({'PC':hex(a),'before_visit':self.seq,'register':name,'value':hex(value),**({'CSSELR':bank} if name=='ccsidr_el1' else {})})
    elif i.mnemonic=='msr':
     name,operand=i.op_str.split(', ')
     if operand.startswith('#'):
      mask=int(operand[1:],0)*64;assert name in ['daifset','daifclr'];self.system['daif']=(self.system['daif']|mask) if name=='daifset' else (self.system['daif']&~mask)
     else:self.system[name]=0 if operand=='xzr' else self.reg(int(operand[1:]))
    event['system_after']=dict(self.system);assert event==self.p['logical_effects'][len(self.logical)];self.logical.append(event);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_effects_checked']+=1;self.counts['CPU_architectural_effects_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  out=super().run();assert self.cpu_seen and not self.cpu_active and not self.p['unfinished_CPU_entry_indices'];assert self.cpu_entries==self.p['original_CPU_entries'] and self.cpu_returns==self.p['original_CPU_returns'] and self.hardware_reads==self.p['architectural_register_reads'];out.update(CPU_checkpoints_checked=2,CPU_entries_checked=len(self.cpu_entries),CPU_returns_checked=len(self.cpu_returns),architectural_register_reads_checked=len(self.hardware_reads));return out
