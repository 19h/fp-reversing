#!/usr/bin/env python3
"""Independent waitq CPU replay, membership/scratch frames and DAIF restoration.
O(image+visits+RAM+effects), O(image+RAM+journals). No probe executor import.
"""
from unicorn import arm64_const as ar
from replay_kernel_kmsg_queue import Replay as Parent,THREAD
INNER=0x65000b5000;SCRATCH=0xfffffe000cac74e0
class Replay(Parent):
 def __init__(self,im,p):
  super().__init__(im,p);self.wf=p['waitq_frames'];self.wi=0
  self.u.reg_write(ar.UC_ARM64_REG_PSTATE,(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&~0x3c0)|int(p['entry_DAIF_mask'],16))
 def code(self,u,a,n,d):
  self.finish()
  if self.wi<len(self.wf):
   e=self.wf[self.wi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['thread_nesting']==int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little')and e['DAIF_mask']==hex(u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0)
    assert e['inner24_hex']==bytes(u.mem_read(INNER,24)).hex()and e['scratch48_hex']==bytes(u.mem_read(SCRATCH,48)).hex()
    r=int(e['receiver_address'],16);assert e['receiver1536_hex']==(bytes(u.mem_read(r,0x600)).hex()if r else None)
    self.wi+=1;self.counts['original_waitq_membership_scratch_receiver_DAIF_frames_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.wi==len(self.wf)and self.p['final_DAIF_mask']==hex(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0)
  assert self.p['final_inner24_hex']==bytes(self.u.mem_read(INNER,24)).hex()and self.p['final_scratch48_hex']==bytes(self.u.mem_read(SCRATCH,48)).hex();self.counts['final_waitq_scratch_and_DAIF_states_checked']+=1
  return dict(self.counts)
