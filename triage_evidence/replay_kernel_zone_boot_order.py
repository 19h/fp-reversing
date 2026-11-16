#!/usr/bin/env python3
"""Fresh CPU journal replay with independently reconstructed startup events.
O(visits + journals + RAM) time/space. No producer executor import, native
callback execution, hardware PAC, synchronization, allocation or Mach IPC.
"""
import struct
from unicorn import arm64_const as ar
from replay_kernel_magazine_bootstrap import Replay as Parent
import recover_kernel_zone_boot_order as R
import recover_kernel_magazine_bootstrap as M
P=0x6500000000;INDIRECT=P+0xd0000

class Replay(Parent):
 def __init__(self,image,row):
  super().__init__(image,row);self.events=[];self.entropy=0;self.descriptors=0
 def word(self,a,n):return int.from_bytes(bytes(self.u.mem_read(a,n)),'little')
 def event(self,kind,**extra):
  self.events.append({'kind':kind,'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq,
   'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'capacity_u16':self.word(M.CAP,2),'count_u32':self.word(M.COUNT,4),
   'phase_u32':self.word(R.PHASE,4),'cursor_u64':hex(self.word(R.CURSOR,8)),**extra})
 def code(self,u,a,n,d):
  self.finish()
  if a==M.POLICY:self.event('policy_entry')
  if a==0xfffffe000c634f20:self.event('policy_return')
  if a==R.DISPATCH:self.event('dispatch_entry',threshold_u32=self.reg(0)&0xffffffff)
  if a in [0xfffffe000c634fd4,0xfffffe000c635058]:self.event('dispatch_return')
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16):
   m=self.models[self.mi];c=self.p['configuration'];count=(c['last_cpu']+1)&0xffffffff
   if m['symbol']=='registered_callback_ordinary_return_no_RAM_effect':
    cursor=self.word(R.CURSOR,8);phase,rank,target,arg=struct.unpack('<IIQQ',bytes(u.mem_read(cursor,24)))
    assert a==target and self.reg(0)==arg and self.reg(30)==0xfffffe000c630374 and int(m['return_value'],16)==0
    self.event('registered_callback',target=hex(a),argument=hex(arg),rank_u32=rank,record_phase_u32=phase)
   elif a==0xfffffe000be577f0:
    self.entropy+=1
    expected={'zero':0,'ones':0xffffffff,'cycle':0xa5b6c700|((self.entropy-1)%8)}[c['rng']]
    assert m['symbol']=='declared_metadata_word_source' and int(m['return_value'],16)==expected
   elif a in [0xfffffe000be57bec,INDIRECT]:
    ptr=R.DESCRIPTORS+48*self.descriptors;self.descriptors+=1
    assert m['symbol']=='declared_descriptor_helper_no_RAM_effect' and int(m['return_value'],16)==0
    assert ([self.reg(j) for j in range(2)]==[ptr,16] if a!=INDIRECT else [self.reg(j) for j in range(4)]==[P+0x11000,max(count-1,0),16,ptr])
   elif a in R.HELPERS:assert m['symbol']=='declared_'+R.HELPERS[a]+'_no_RAM_effect' and int(m['return_value'],16)==0
   else:assert m['symbol'] in ['declared_strncmp','declared_strlen']
   self.counts['declared_model_semantic_contracts_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.events==self.p['sequence_events']
  assert self.entropy==689 and self.descriptors==((self.p['configuration']['last_cpu']+1)&0xffffffff)
  self.counts['startup_events_reconstructed_and_checked']+=len(self.events)
  return dict(self.counts)
