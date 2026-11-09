#!/usr/bin/env python3
"""Fresh original cursor/packed-candidate/callback CPU and memory replay.
O(visits+RAM+effects), O(RAM+journals); no probe executor or native operation.
"""
from unicorn import arm64_const as ar
from replay_rpc502_vm_handoff import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):
  self.regions=[(int(e['address'],16),e['size_bytes'])for e in p['private_auxiliary_regions']];q=dict(p);q['configuration']={**p['configuration'],'stage':'copyin'if p['configuration']['stage']=='type2'else p['configuration']['stage']};super().__init__(im,q);self.xi={k:0 for k in ['cursor_frames','position_frames','range_lock_frames','callback_frames','cursor_return_frames']};self.bi=0
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if any(lo<=pg<lo+size for lo,size in self.regions):
    if pg not in self.pages:self.u.mem_map(pg,4096);self.u.mem_write(pg,bytes(4096));self.pages.add(pg)
   else:super().ensure(pg,1)
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.xi.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.xi[key]+=1;assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))]
   if 'cursor128_hex'in e:
    ptr=self.reg(0)if key=='cursor_frames'else int(self.p['cursor_address'],16);assert e['cursor128_hex']==bytes(u.mem_read(ptr,128)).hex()
   if 'thread_active_cursor'in e:assert e['thread_active_cursor']==hex(int.from_bytes(bytes(u.mem_read(0x650002c238,8)),'little'))
   self.counts[key+'_checked']+=1
  if self.bi<len(self.p['logical_indirect_edges']):
   e=self.p['logical_indirect_edges'][self.bi]
   if a==int(e['pc'],16)and self.seq==e['source_visit_index']:
    self.bi+=1;raw=bytes(u.mem_read(a,4));ins=next(self.image.k.cs.disasm(raw,a));x,y=[int(v.strip()[1:])for v in ins.op_str.split(',')];assert ins.mnemonic=='blraa'and raw==self.image.k.read(a,4)and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}and e['target']==hex(self.reg(x))and e['modifier']==hex(self.reg(y));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_callback_edges_checked']+=1;u.reg_write(ar.UC_ARM64_REG_X30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,int(e['target'],16));return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert all(j==len(self.p[k])for k,j in self.xi.items())and self.bi==len(self.p['logical_indirect_edges'])
  for e in self.p['final_auxiliary_regions']:assert bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()==e['bytes_hex'];self.counts['final_auxiliary_regions_checked']+=1
  return dict(self.counts)
