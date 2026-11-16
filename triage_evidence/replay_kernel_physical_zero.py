#!/usr/bin/env python3
"""Independent CPU/journal replay with explicit logical64 B DC ZVA effects.
O(visits + journals + private RAM) time/space. No producer/audit imports or
native physical mapping, cache operation, preemption, PAC or IPC effects.
"""
from unicorn import arm64_const as ar
from replay_kernel_magazine_bootstrap import Replay as Parent
from replay_kernel_vm_mig import Replay as CPU
import recover_kernel_physical_zero as R
WINDOW_ALIAS=0xfffffecfffd20000;EXTENT=65536;ALIAS=0x6500040000

class Replay(Parent):
 def __init__(self,image,row):
  super().__init__(image,row);self.dcs=row['logical_DC_ZVA_effects'];self.di=0;self.windows=0;self.clear_entries=[]
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if WINDOW_ALIAS<=pg<WINDOW_ALIAS+EXTENT:
    if pg not in self.pages:self.u.mem_map(pg,4096);self.u.mem_write(pg,bytes(4096));self.pages.add(pg)
   else:CPU.ensure(self,pg,4096)
 def code(self,u,a,n,d):
  self.finish()
  if a in [R.BZERO,R.MEMSET]:self.clear_entries.append({'pc':hex(a),'source_visit_index':self.seq,'arguments3':[hex(self.reg(j)) for j in range(3)]})
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16):
   m=self.models[self.mi];c=self.p['configuration'];expected=0
   if a==R.ATTR:assert m['symbol']=='declared_cache_attributes';expected=c['attribute']
   elif a==R.DIRECT:
    assert m['symbol']=='declared_contiguous_direct_alias' and self.reg(1)==u.reg_read(ar.UC_ARM64_REG_SP)+0x28
    expected=ALIAS+self.reg(0)-0x100000
   elif a==R.WINDOW:
    assert m['symbol']=='declared_window_index' and self.reg(1)==3 and self.reg(2)==c['attribute']
    expected=4 if c.get('invalid_window') else self.windows;self.windows+=1
   elif a==R.UNMAP:assert m['symbol']=='declared_window_unmap'
   else:assert a==R.DEFER and m['symbol']=='declared_deferred_preemption'
   assert int(m['return_value'],16)==expected;self.counts['declared_model_semantic_contracts_checked']+=1
  if self.seq<len(self.p['source_visits']):
   raw=bytes(u.mem_read(a,4));ins=next(self.image.k.cs.disasm(raw,a))
   if ins.mnemonic=='dc':
    e=self.dcs[self.di];self.di+=1;original=self.p['source_visits'][self.seq]
    assert self.image.k.read(a,4)==raw and original=={'pc':hex(a),'bytes_hex':raw.hex()}
    assert ins.op_str.startswith('zva, x');j=int(ins.op_str[6:]);address=(self.reg(j)//64)*64
    assert e['source_visit_index']==self.seq and e['pc']==hex(a) and e['operand_register']==j and e['operand_value']==hex(self.reg(j))
    assert e['address']==hex(address) and e['size_bytes']==self.p['logical_DC_granule_bytes']==64
    assert bytes(u.mem_read(address,64)).hex()==e['before_hex'] and e['after_hex']==bytes(64).hex()
    self.current=self.seq;self.seq+=1;self.rc=self.wc=0;u.mem_write(address,bytes(64));u.reg_write(ar.UC_ARM64_REG_PC,a+4)
    self.counts['source_visits_checked']+=1;self.counts['logical_DC_ZVA_steps_checked']+=1;self.counts['logical_DC_bytes_checked']+=64;return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.di==len(self.dcs) and self.clear_entries==self.p['original_clear_entries']
  self.counts['original_clear_entries_reconstructed']+=len(self.clear_entries);return dict(self.counts)
