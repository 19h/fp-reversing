#!/usr/bin/env python3
"""Independent boot-consumer checkpoints and continuous original CPU replay.
Linear source/read/write/RAM work. No new producer import or API result model.
"""
from hashlib import sha256
from unicorn import arm64_const as ar
from probe_rpc502_vm_handoff import decode
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import sha
import replay_kernel_early_logging_execution as B
import recover_kernel_boot_logging_handoff as R
class Replay(B.Replay):
 def __init__(self,image,row):super().__init__(image,row);self.image_entries=[];self.image_returns=[];self.image_active=[];self.consumer_seen=False;self.printf_seen=False;self.join_count=0
 def check_handoff_checkpoint(self,c):
  assert c['before_visit']==self.seq and c['PC']==hex(self.u.reg_read(ar.UC_ARM64_REG_PC));assert c['registers31']==[hex(self.reg(j)) for j in range(31)] and c['SP']==hex(self.u.reg_read(ar.UC_ARM64_REG_SP)) and c['NZCV']==hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));raw=decode(c['private_RAM']);assert bytes(self.u.mem_read(self.lo,len(raw)))==raw
  for key,rows in c.items():
   if key=='image_globals' or key.endswith('_image_globals'):
    for r in rows:raw=bytes.fromhex(r['bytes_hex']);assert bytes(self.u.mem_read(int(r['address'],16),len(raw)))==raw
  for j,v in enumerate(c['vectors']):assert hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))==v
  assert c['system']==self.system
 def code(self,u,a,n,d):
  self.finish()
  if self.seq==len(self.p['source_visits']):return super().code(u,a,n,d)
  if a==B.R.MRS:
   c=self.p['logging_join_checkpoints'][self.join_count];self.check_handoff_checkpoint(c);phase=int.from_bytes(u.mem_read(B.R.C.PHASE,4),'little');assert phase<19 and 'daif' not in self.system
   for lo,hi in [(B.R.C.START,B.R.C.START+16),(B.R.C.SECOND,B.R.C.JOIN)]:assert bytes(u.mem_read(lo,hi-lo))==self.image.k.read(lo,hi-lo)
   raw=bytes(u.mem_read(a,4));assert raw.hex()=='28423bd5' and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};event={'PC':hex(a),'kind':'source_proved_early_logging_join','before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'proof_audit_sha256':sha(ROOT/(B.R.C.P+'_audit.json')),'phase_address':hex(B.R.C.PHASE),'phase_bytes_hex':phase.to_bytes(4,'little').hex(),'phase_u32':phase,'join_PC':hex(B.R.JOIN),'contracted_original_words':9,'DAIF_value_supplied':False};assert self.p['proved_logging_joins'][self.join_count]==event and self.p['logical_effects'][len(self.logical)]==event;self.logical.append(event);self.seq+=1;self.join_count+=1;self.joined=True;self.counts['source_visits_checked']+=1;self.counts['proved_block_transitions_checked']+=1;self.counts['contracted_original_words_checked']+=9
   for j,value in [(8,0xfffffe0007f34000),(9,phase),(24,1)]:u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),value)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0x80000000);u.reg_write(ar.UC_ARM64_REG_PC,B.R.JOIN);return
  while self.image_active and self.image_entries[self.image_active[-1]]['return_PC']==hex(a) and self.image_entries[self.image_active[-1]]['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   index=self.image_active.pop();self.image_returns.append({'entry_index':index,'before_visit':self.seq,'X0':hex(self.reg(0))})
  if a in [R.LOOKUP,R.CONTAINS]:
   self.image_active.append(len(self.image_entries));self.image_entries.append({'PC':hex(a),'before_visit':self.seq,'arguments2':[hex(self.reg(j)) for j in range(2)],'return_PC':hex(self.reg(30)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  if a==R.FRONTIER and not self.consumer_seen:self.check_handoff_checkpoint(self.p['configuration_consumer_checkpoint']);self.consumer_seen=True
  c=self.p['printf_return_checkpoint']
  if c and a==int(c['PC'],16):self.check_handoff_checkpoint(c);self.printf_seen=True
  return super().code(u,a,n,d)
 def run(self):
  result=super().run();assert self.consumer_seen and self.printf_seen and self.join_count==len(self.p['proved_logging_joins']);assert self.image_entries==self.p['original_image_lookup_entries'] and self.image_returns==self.p['original_image_lookup_returns'] and not self.image_active;result.update(boot_consumer_checkpoints_checked=2,image_lookup_entries_checked=len(self.image_entries),image_lookup_returns_checked=len(self.image_returns));return result
