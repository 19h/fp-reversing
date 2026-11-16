#!/usr/bin/env python3
"""Independent fresh CPU replay of permanent storage and consumer events.
O(visits + journals + mapped state) time/space; no producer import, native
refill, ownership, zero initialization, hardware PAC or locks executed.
"""
from unicorn import arm64_const as ar
from replay_kernel_magazine_bootstrap import Replay as Parent
import recover_kernel_permanent_storage as R
import recover_kernel_magazine_bootstrap as M
MAGAZINES=0x6500070000

class Replay(Parent):
 def __init__(self,image,row,parent=None):super().__init__(image,row,parent);self.events=[];self.pending_calls=[];self.magazines=0
 def word(self,a,n):return int.from_bytes(bytes(self.u.mem_read(a,n)),'little')
 def code(self,u,a,n,d):
  self.finish()
  if self.pending_calls and a==self.pending_calls[-1]['return_pc']:
   call=self.pending_calls.pop();self.events.append({'kind':'permanent_return','source_visit_index':self.seq,'pc':hex(a),'entry_event_index':call['event_index'],'result':hex(self.reg(0))})
  if a==R.ALLOC:
   self.pending_calls.append({'return_pc':self.reg(30),'event_index':len(self.events)})
   self.events.append({'kind':'permanent_entry','source_visit_index':self.seq,'pc':hex(a),'arguments3':[hex(self.reg(j)) for j in range(3)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16):
   m=self.models[self.mi]
   if a in [0xfffffe000bd0bfa4,0xfffffe000bd0c2cc,0xfffffe000bd0aab4,0xfffffe000bd0ab18]:assert m['symbol']=='declared_lock_no_RAM_effect' and int(m['return_value'],16)==0
   else:
    assert a==0xfffffe000bd75c64 and m['symbol']=='declared_zero_typed_magazine_storage'
    view=self.word(M.VIEW,8);statistics=self.word(view+8,8);extent=self.word(view+0x34,2);ptr=MAGAZINES+self.magazines*extent
    assert [self.reg(j) for j in range(3)]==[view,statistics,0x8004] and int(m['return_value'],16)==ptr
    assert bytes(u.mem_read(ptr,extent))==bytes(extent);self.magazines+=1
   self.counts['declared_model_semantic_contracts_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.events==self.p['permanent_events'] and self.magazines==len(self.p['raw_magazine_returns'])
  self.counts['permanent_events_reconstructed_and_checked']+=len(self.events)
  return dict(self.counts)
