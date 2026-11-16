#!/usr/bin/env python3
"""Independent fresh replay of original refill publication calls and storage.
O(visits + journals + mapped RAM) time/space. No producer/audit imports,
native pmap/page allocation, lock effects or complete refill execution.
"""
from unicorn import arm64_const as ar
from replay_kernel_magazine_bootstrap import Replay as Parent
import recover_kernel_refill_publication as R
import recover_kernel_physical_zero as Z
PAGE=0xfffffe0007d00000;PHYSICAL=0x400000;OBJECTS=0x6500060000

class Replay(Parent):
 def __init__(self,image,row):super().__init__(image,row);self.events=[];self.clears=[];self.acquired=0;self.pmap_calls=0
 def code(self,u,a,n,d):
  self.finish()
  if a in [Z.ZERO,R.CONSUME,R.MAP,R.INSERT,R.ACCOUNT]:self.events.append({'pc':hex(a),'source_visit_index':self.seq,'arguments8':[hex(self.reg(j)) for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  if a in [Z.BZERO,Z.MEMSET]:self.clears.append({'pc':hex(a),'source_visit_index':self.seq,'arguments3':[hex(self.reg(j)) for j in range(3)]})
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16):
   c=self.p['configuration'];m=self.models[self.mi];expected=0
   if a==0xfffffe000be100ec:
    assert m['symbol']=='declared_page_object_acquisition' and self.reg(0)==2;expected=OBJECTS+64*self.acquired;self.acquired+=1
   elif a==Z.ATTR:assert m['symbol']=='declared_cache_attributes' and c['attribute']==0
   elif a==Z.DIRECT:
    assert m['symbol']=='declared_physical_clear_alias' and self.reg(1)==u.reg_read(ar.UC_ARM64_REG_SP)+0x28;expected=PAGE+self.reg(0)-PHYSICAL
   elif a==R.PMAP:
    assert m['symbol']=='declared_lower_pmap_result_no_RAM_effect' and bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),1))[0]==m['argument9_byte']
    expected=6 if c.get('retry') and self.pmap_calls==0 else c['pmap_return'];self.pmap_calls+=1
   else:
    assert a in [0xfffffe000be0d098,0xfffffe000be0f308,0xfffffe000be2f16c,0xfffffe000bde9b90,0xfffffe000bd0a630,0xfffffe000bd0aab4]
    assert m['symbol']=='declared_page_list_or_lock_no_RAM_effect'
   assert int(m['return_value'],16)==expected;self.counts['declared_model_semantic_contracts_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.events==self.p['original_publication_entries'] and self.clears==self.p['original_clear_entries']
  assert self.acquired==self.p['configuration']['pages'] and not self.p['logical_DC_ZVA_effects']
  self.counts['original_publication_entries_reconstructed']+=len(self.events);self.counts['original_clear_entries_reconstructed']+=len(self.clears)
  return dict(self.counts)
