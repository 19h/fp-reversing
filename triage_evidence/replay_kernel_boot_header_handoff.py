#!/usr/bin/env python3
"""Independent replay of cold boot, original copies and root consumers.
O(visits + journals + RAM) time/space. No executor imports or native effects.
"""
from unicorn import arm64_const as ar
from replay_kernel_sptm_boot_inputs import Replay as Parent
from replay_kernel_magazine_bootstrap import Replay as Base
import recover_kernel_boot_header_handoff as R
P=0x6500000000;SP=P+0xf0000;STACK0=0xfffffe000cbb4000;BOOTARGS=P+0x3c000
NAMES={R.PREINIT:'declared_self_relocator_no_RAM_effect',**{a:'declared_early_feature_callback_no_RAM_effect' for a in R.CALLBACK_TARGETS},
 0xfffffe000c621194:'declared_vector_registration_no_RAM_effect',0xfffffe000c47cce0:'declared_early_helper_no_RAM_effect'}

class Replay(Parent):
 def __init__(self,image,row,parent=None):
  super().__init__(image,row,parent);self.si=0;self.stackbanks={0:SP,1:P+0xec000};self.spsel=0;self.copies=[];self.callbacks=[]
 def code(self,u,a,n,d):
  self.finish()
  if a==R.COPY:self.copies.append({'PC':hex(a),'arguments3':[hex(self.reg(j)) for j in range(3)],'return_PC':hex(self.reg(30)),'source_visit_index':self.seq})
  if a in R.CALLBACK_TARGETS:self.callbacks.append({'PC':hex(a),'arguments2':[hex(self.reg(j)) for j in range(2)],'modifier_X17':hex(self.reg(17)),'source_visit_index':self.seq})
  if self.si<len(self.p['logical_boot_system_effects']) and self.p['logical_boot_system_effects'][self.si]['PC']==hex(a):
   row=self.p['logical_boot_system_effects'][self.si];raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   assert raw==self.image.k.read(a,4) and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}
   assert row['source_visit_index']==self.seq and (row['mnemonic'],row['operands'])==(i.mnemonic,i.op_str) and row['SP_before']==hex(u.reg_read(ar.UC_ARM64_REG_SP))
   if i.mnemonic=='msr' and i.op_str.startswith('spsel'):
    choice=int(i.op_str.rsplit('#',1)[1],0);self.stackbanks[self.spsel]=u.reg_read(ar.UC_ARM64_REG_SP);self.spsel=choice;u.reg_write(ar.UC_ARM64_REG_SP,self.stackbanks[choice])
   elif i.mnemonic=='msr' and i.op_str=='tpidr_el1, xzr':u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,0)
   else:assert i.mnemonic in ['isb','dsb','ic'] or i.op_str in ['tpidr_el0, xzr','tpidrro_el0, xzr','vbar_el1, x9']
   assert row['SP_after']==hex(u.reg_read(ar.UC_ARM64_REG_SP));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.si+=1;self.counts['source_visits_checked']+=1;self.counts['logical_boot_system_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if self.ei<len(self.envelopes):
   row=self.envelopes[self.ei]
   if row['pc']==hex(a) and row['mnemonic'] in ['paciza','xpaci']:
    raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4) and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}
    assert row['source_visit_index']==self.seq and row['mnemonic']==i.mnemonic and row['registers31']==[hex(self.reg(j)) for j in range(31)]
    self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.ei+=1;self.counts['source_visits_checked']+=1;self.counts['logical_envelopes_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16) and a in NAMES:
   m=self.models[self.mi];assert m['symbol']==NAMES[a] and int(m['return_value'],16)==0
   for j in range(18):
    expected=0 if j==0 else (((j+1)*0x123456789abcdef)^(self.mi+1)*0x8b3dc651)&((1<<64)-1)
    assert int(m['after_registers31'][j],16)==expected
   assert int(m['after_NZCV'],16)==(0xf0000000 if (self.mi+1)&1 else 0)
   self.counts['declared_boot_leaf_contracts_checked']+=1;return Base.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.si==len(self.p['logical_boot_system_effects']) and self.copies==self.p['original_copy_entries'] and self.callbacks==self.p['early_callback_entries']
  self.counts['original_copy_entries_reconstructed']+=len(self.copies);self.counts['early_callback_entries_reconstructed']+=len(self.callbacks);return dict(self.counts)
