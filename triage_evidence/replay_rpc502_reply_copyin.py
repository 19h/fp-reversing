#!/usr/bin/env python3
"""Independent original CPU replay and argument-derived private effect checks.
O(visits+effect bytes) time, O(private RAM+journals) space. No probe import.
"""
from unicorn import arm64_const as ar
from replay_kernel_reply_send import Replay as Parent
P=0x6500000000;SOURCES=[P+0x50000,P+0x60000];COPIES=[P+0x68000,P+0x69000];BACKS=[P+0x70000,P+0x78000]
class Replay(Parent):
 def __init__(self,image,p):
  super().__init__(image,p);self.effects=p['declared_effects'];self.ei=0;self.sign=p['logical_data_signing'];self.si=0;self.cuts=p['VM_copyin_entries'];self.ci=0;self.active=None
  for e in p['private_system_register_fixtures']:assert e['register']=='TPIDR_EL1';self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(e['value'],16))
 def code(self,u,a,n,d):
  if a==0xfffffe000bdd15a4:
   e=self.cuts[self.ci];self.ci+=1;self.active=SOURCES.index(self.reg(1));flags=1|((int.from_bytes(u.mem_read(P+0x2a0b0,4),'little')>>16)&0x200);assert e['descriptor_index']==self.active and e['source_visit_index']==self.seq and e['arguments5']==[hex(self.reg(j))for j in range(5)];assert self.reg(0)==P+0x2a000 and self.reg(2)==self.p['configuration']['lengths'][self.active]and self.reg(3)==flags;self.counts['VM_entry_arguments_checked']+=1
  if self.mi<len(self.models)and a==int(self.models[self.mi]['pc'],16)and a==0xfffffe000bdc3c2c:
   idx=self.active;size=self.p['configuration']['lengths'][idx];start=SOURCES[idx]&~16383;end=(SOURCES[idx]+size+16383)&~16383;assert [self.reg(j)for j in range(5)]==[P+0x2a000,start,end,2,0]and self.reg(6)==0;self.counts['source_removal_ABIs_checked']+=1
  if self.ei<len(self.effects)and self.effects[self.ei]['pc']==hex(a)and self.effects[self.ei]['before_source_visit_index']==self.seq:
   self.finish();e=self.effects[self.ei];self.ei+=1;c=self.p['configuration'];idx=self.active;fail=idx==c['failure_descriptor'];want=[];result=0
   if a==0xfffffe000bcfe5b8:
    assert self.reg(0)==0xfffffe0007f8bfb0 and self.reg(1)==c['lengths'][idx]and self.reg(2)==self.reg(3)==0;result=0 if fail and c['failure']=='allocation'else BACKS[idx]
   elif a==0xfffffe000bd75c64:assert [self.reg(j)for j in range(3)]==[P+0x86000,P+0x88000,4];result=COPIES[idx]
   elif a==0xfffffe000bdc2fc0:
    assert [self.reg(j)for j in range(5)]==[P+0x2a000,SOURCES[idx],BACKS[idx],c['lengths'][idx],1];result=5 if fail and c['failure']=='copy'else 0
    if result==0:want=[(self.reg(2),bytes(u.mem_read(self.reg(1),self.reg(3))))]
   elif a==0xfffffe000c6480c0:assert self.reg(0)in COPIES and self.reg(1)==48;want=[(self.reg(0),bytes(48))]
   else:raise AssertionError(hex(a))
   assert int(self.models[self.mi]['return_value'],16)==result and e['descriptor_index']==idx and len(e['patches'])==len(want)
   for (ptr,b),saved in zip(want,e['patches'],strict=True):
    assert saved['address']==hex(ptr)and saved['before_hex']==bytes(u.mem_read(ptr,len(b))).hex()and saved['after_hex']==b.hex();u.mem_write(ptr,b);self.counts['private_effect_patches_checked']+=1;self.counts['private_effect_bytes_checked']+=len(b)
   self.counts['private_effect_calls_checked']+=1
  if self.si<len(self.sign)and self.sign[self.si]['pc']==hex(a)and self.seq<len(self.p['source_visits'])and self.p['source_visits'][self.seq]['pc']==hex(a):
   self.finish();e=self.sign[self.si];self.si+=1;v=self.p['source_visits'][self.seq];raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic=='pacda'and raw==self.image.k.read(a,4)and raw.hex()==v['bytes_hex']and self.reg(17)==int(e['pointer'],16)and self.reg(16)==int(e['modifier'],16);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_data_sign_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();assert self.ei==len(self.effects)and self.si==len(self.sign)and self.ci==len(self.cuts);return r
