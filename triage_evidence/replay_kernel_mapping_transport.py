#!/usr/bin/env python3
"""Independent private CPU replay; no producer or audit implementation reuse.
O(visits + journals + RAM) time/space; opaque transport never executes.
"""
from unicorn import arm64_const as ar
from replay_kernel_magazine_bootstrap import Replay as Parent
import recover_kernel_mapping_transport as R
THREAD=0x6500010000

class Replay(Parent):
 def __init__(self,image,row):super().__init__(image,row);self.si=0;self.events=[]
 def code(self,u,a,n,d):
  self.finish();c=self.p['configuration']
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16):
   m=self.models[self.mi]
   if a==R.CHECK:assert c['kind']=='gate' and m['symbol']=='declared_validation_no_RAM_effect';value=0
   else:
    assert c['kind']=='implementation' and a==R.WRAPPERS[1] and m['symbol']=='declared_opaque_mapping_transport_no_RAM_effect';value=c['result']
    block=R.CPU_BASE+c['cpu']*16384
    self.events.append({'pc':hex(a),'source_visit_index':self.seq,'arguments8':[hex(self.reg(j)) for j in range(8)],
     'preemption_depth':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little'),
     'epoch_and_active_hex':bytes(u.mem_read(block+0x1270,16)).hex()})
   assert int(m['return_value'],16)==value
   for j in range(18):
    expected=value if j==0 else ((j+1)*0x123456789abcdef)^(self.mi+1)*0x8b3dc651
    assert int(m['after_registers31'][j],16)==expected&((1<<64)-1)
   self.counts['declared_model_semantic_contracts_checked']+=1
  reads=self.p['logical_system_reads']
  if self.si<len(reads) and a==int(reads[self.si]['pc'],16):
   e=reads[self.si];raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4)
   assert e['source_visit_index']==self.seq and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}
   assert i.mnemonic=='mrs' and i.op_str==f"x{e['destination']}, {e['register']}"
   value=0 if e['register']=='s3_6_c15_c8_0' else 0x80;assert int(e['value'],16)==value
   self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.si+=1;self.counts['source_visits_checked']+=1;self.counts['logical_system_reads_checked']+=1
   u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(e['destination'])),value);u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.si==len(self.p['logical_system_reads']) and self.events==self.p['transport_request_entries']
  self.counts['transport_request_entries_reconstructed']+=len(self.events)
  return dict(self.counts)
