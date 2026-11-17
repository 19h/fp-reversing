#!/usr/bin/env python3
"""Original main walker/signing on one continuous declared private frame.
CPU work includes quadratic child rescans; journal/mapped-byte work linear.
"""
import json
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_vm_mig import Probe as Core
import probe_kernel_boot_logging_handoff as B
import recover_kernel_main_pointer_signing as R
class Probe(B.Probe):
 def __init__(self,im,mutate=None):
  super().__init__(im);self.mutate=mutate;self.signing_e=json.loads(read(ROOT/(R.P+'_checks.json')));self.walk_entry=None;self.walk_return=None;self.signer_entries=[];self.active_walker=False
  tables=self.signing_e['pointer_tables'];self.table_regions=B.B.complement([(int(t['address'],16),t['size_bytes']) for t in tables],self.regions);self.regions=B.B.merge(self.regions+self.table_regions)
  for t in tables:
   a=int(t['address'],16);self.ensure(a,t['size_bytes']);assert bytes(self.u.mem_read(a,t['size_bytes'])).hex()==t['logical_bytes_hex']
  self.allowed += [(R.S.WALK,0xfffffe000c47ce2c),(R.S.SIGN,R.S.SIGN_END)]
  for a in [R.S.WALK,R.S.SIGN]:self.ensure(a,4)
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def full_snapshot(self,a):
  row=super().full_snapshot(a)
  if hasattr(self,'table_regions'):row['module_pointer_image_globals']=[{'address':hex(p),'bytes_hex':bytes(self.u.mem_read(p,n)).hex()} for p,n in self.table_regions]
  return row
 def code(self,u,a,n,d):
  self.flush()
  if self.active_walker and a==R.RETURN:
   self.walk_return=self.full_snapshot(a);self.active_walker=False
   if self.mutate is not None:return self.stop('changed_signer_return_before_main_continuation')
  if a==R.S.WALK:
   assert self.walk_entry is None;self.walk_entry=self.full_snapshot(a);self.active_walker=True
  inside=R.S.WALK<=a<0xfffffe000c47ce2c or R.S.SIGN<=a<R.S.SIGN_END
  if inside:
   if a==R.S.SIGN:self.signer_entries.append({'before_visit':len(self.visits),'PC':hex(a),'argument':hex(self.reg(0)),'return_PC':hex(self.reg(30)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
   raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic in ['xpaci','pacia1716']:
    assert i.op_str==('x16' if i.mnemonic=='xpaci' else '');event={'PC':hex(a),'kind':i.mnemonic,'scope':'original_main_module_pointer_signing','operands':i.op_str,'before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'X16':hex(self.reg(16)),'X17':hex(self.reg(17)),'logical_identity':True};self.logical.append(event);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
   if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
   return Core.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(module_walker_entry_checkpoint=self.walk_entry,module_walker_return_checkpoint=self.walk_return,original_module_signer_entries=self.signer_entries,unfinished_module_walker=self.active_walker);return row
if __name__=='__main__':
 im=R.B.BootImage();row=Probe(im).run();from replay_kernel_early_logging_execution import publication_row
 (ROOT/(R.P+'_probe.json')).write_text(json.dumps(publication_row(row,im),indent=2)+'\n');print({'visits':len(row['source_visits']),'models':len(row['API_models']),'signer_entries':len(row['original_module_signer_entries']),'boundary':row['boundary']['pc']},flush=True)
