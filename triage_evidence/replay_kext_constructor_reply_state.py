#!/usr/bin/env python3
"""Independent constructor reply/startup replay with explicit entry ABI models.
O(visits+effects), O(private RAM+journals); no probe executor reuse.
"""
from unicorn import arm64_const as ar
from replay_kext_constructor_request import Replay as Request
class Replay(Request):
 def __init__(self,im,p):super().__init__(im,p);self.state_snapshots=p['state_snapshots'];self.state_si=0
 def code(self,u,a,n,d):
  if self.state_si<len(self.state_snapshots):
   s=self.state_snapshots[self.state_si]
   if s['pc']==hex(a)and s['before_source_visit_index']==self.seq:
    self.finish();self.state_si+=1;assert s['registers31']==[hex(self.reg(j))for j in range(31)]and s['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP));self.counts['reply_state_snapshots_checked']+=1
  if self.mi<len(self.models):
   m=self.models[self.mi]
   if m['pc']==hex(a)and m['before_source_visit_index']==self.seq:
    self.finish();self.mi+=1;assert m['arguments8']==[hex(self.reg(j))for j in range(8)]and self.reg(30)==int(m['return_pc'],16)
    for e in m['memory_effects']:
     address=int(e['address'],16);b=bytes.fromhex(e['after_hex']);assert bytes(u.mem_read(address,len(b))).hex()==e['before_hex'];u.mem_write(address,b);self.counts['declared_model_memory_effects_checked']+=1;self.counts['declared_model_write_bytes_checked']+=len(b)
    for j,value in enumerate(m['after_registers31']):
     if j<18:u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(value,16))
     else:assert self.reg(j)==int(value,16)
    u.reg_write(ar.UC_ARM64_REG_NZCV,int(m['after_NZCV'],16));u.reg_write(ar.UC_ARM64_REG_PC,int(m['return_pc'],16));self.counts['declared_API_models_checked']+=1;self.counts['entry_ABI_models_checked']+=1;return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.state_si==len(self.state_snapshots)
  for a,key in [(0x6500020000,'final_scratch160_hex'),(0x6500024000,'final_owner1088_hex'),(0x6500022000,'final_child152_hex'),(0x6500023000,'final_shared704_hex'),(0xfffffe000cccb088,'final_MT2496_hex'),(0xfffffe000cccca58,'final_head_hex')]:
   b=bytes.fromhex(self.p[key]);self.ensure(a,len(b));assert bytes(self.u.mem_read(a,len(b)))==b
  for a,h in self.p['final_missing_globals_hex'].items():self.ensure(int(a,16),len(h)//2);assert bytes(self.u.mem_read(int(a,16),len(h)//2)).hex()==h
  return dict(self.counts)
