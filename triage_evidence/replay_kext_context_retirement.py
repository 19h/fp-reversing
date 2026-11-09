#!/usr/bin/env python3
"""Independent close replay with logical calls and declared caller transitions.
O(visits+effects), O(private RAM+journals). No probe executor reuse.
"""
from unicorn import arm64_const as ar
from replay_kext_page_context import Replay as Calls
from replay_kernel_vm_mig import Replay as CPU
class Replay(Calls):
 def __init__(self,im,p):super().__init__(im,p);self.transitions=p['declared_call_transitions'];self.ti=0
 def code(self,u,a,n,d):
  if self.ti<len(self.transitions):
   e=self.transitions[self.ti]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:
    self.finish();self.ti+=1;assert[hex(self.reg(j))for j in range(31)]==e['before_registers31']and hex(u.reg_read(ar.UC_ARM64_REG_SP))==e['SP']and hex(u.reg_read(ar.UC_ARM64_REG_NZCV))==e['before_NZCV']
    for address,b in e['nodes_hex'].items():assert bytes(u.mem_read(int(address,16),1088)).hex()==b
    assert bytes(u.mem_read(0x6500024000,152)).hex()==e['record152_hex']and bytes(u.mem_read(0xfffffe000cccca58,8)).hex()==e['head_hex']
    for j,v in enumerate(e['after_registers31']):u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(v,16))
    u.reg_write(ar.UC_ARM64_REG_NZCV,int(e['after_NZCV'],16));u.reg_write(ar.UC_ARM64_REG_PC,int(e['entry_PC'],16));self.counts['declared_call_transitions_checked']+=1;return
  return super().code(u,a,n,d)
 def run(self):
  r=CPU.run(self);assert self.ei==len(self.edges)and self.ti==len(self.transitions)
  for a,b in self.p['final_nodes_hex'].items():assert bytes(self.u.mem_read(int(a,16),1088)).hex()==b
  import hashlib
  assert bytes(self.u.mem_read(0xfffffe000cccca58,8)).hex()==self.p['final_head_hex']and bytes(self.u.mem_read(0x6500024000,152)).hex()==self.p['final_record152_hex']and hashlib.sha256(bytes(self.u.mem_read(0x6500064000,4096))).hexdigest()==self.p['destination4096_sha256'];return r
