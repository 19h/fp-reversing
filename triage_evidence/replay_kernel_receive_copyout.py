#!/usr/bin/env python3
"""Independent namespace/high-array, frontend, ordinary completion and copyout replay.
O(image+visits+RAM+effects), O(image+RAM+journals). No probe executor import.
"""
from replay_kernel_receive_continuation import Replay as Parent,SenderReplay as SenderParent
TABLE=0x400000100000;PORT=0x65000c0000;INNER=0x65000b5000;RECV=0x6500060000;USER=0x6500090000;SMR=0x650009c000
class Aux:
 def ensure(self,a,n=1):
  if TABLE<=a<a+n<=TABLE+4096:
   if TABLE not in self.pages:self.u.mem_map(TABLE,4096);self.u.mem_write(TABLE,bytes(4096));self.pages.add(TABLE)
   return
  return super().ensure(a,n)
class SenderReplay(Aux,SenderParent):pass
class Replay(Aux,Parent):
 def __init__(self,im,p):super().__init__(im,p);self.ff=p.get('frontend_frames',[]);self.ffi=0;self.rf=p.get('receive_results_frames',[]);self.rfi=0;self.copies=p.get('user_copyout_effects',[]);self.ci2=0;self.hashes2=p.get('opaque_copyout_hash_inputs',[]);self.hi2=0
 def code(self,u,a,n,d):
  self.finish()
  for name,index in[('ff','ffi'),('rf','rfi')]:
   rows=getattr(self,name);j=getattr(self,index)
   if j<len(rows):
    e=rows[j]
    if e['pc']==hex(a)and e['source_visit_index']==self.seq:
     assert e['arguments8']==[hex(self.reg(k))for k in range(8)]and e['port144_hex']==bytes(u.mem_read(PORT,144)).hex()and e['receiver1536_hex']==bytes(u.mem_read(RECV,1536)).hex()
     if name=='ff':assert e['SMR_slot16_hex']==bytes(u.mem_read(SMR,16)).hex()
     else:
      assert e['inner96_hex']==bytes(u.mem_read(INNER,96)).hex()and e['user8192_hex']==bytes(u.mem_read(USER,8192)).hex()
      if e['result_record40_hex']is not None:assert e['result_record40_hex']==bytes(u.mem_read(self.reg(2),40)).hex()
     setattr(self,index,j+1);self.counts['original_frontend_lifetime_header_pack_and_return_frames_checked']+=1
  if self.hi2<len(self.hashes2):
   e=self.hashes2[self.hi2]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:assert e['arguments4']==[hex(self.reg(j))for j in range(4)]and e['bytes_hex']==bytes(u.mem_read(self.reg(0),self.reg(1))).hex();self.hi2+=1;self.counts['opaque_copyout_signature_hash_inputs_checked']+=1
  if self.ci2<len(self.copies):
   e=self.copies[self.ci2]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    src,dst,count=self.reg(0),self.reg(1),self.reg(2);assert e['source']==hex(src)and e['destination']==hex(dst)and e['size_bytes']==count and e['source_hex']==bytes(u.mem_read(src,count)).hex()and e['before_hex']==bytes(u.mem_read(dst,count)).hex()and self.models[self.mi]['return_value']==e['result']
    if int(e['result'],16)==0:u.mem_write(dst,bytes(u.mem_read(src,count)));self.counts['independent_user_copyout_bytes_copied']+=count
    assert e['after_hex']==bytes(u.mem_read(dst,count)).hex();self.ci2+=1;self.counts['independent_user_copyout_contracts_checked']+=1;self.counts['independent_user_copyout_bytes_requested']+=count
  return super().code(u,a,n,d)
 def run(self):super().run();assert self.ffi==len(self.ff)and self.rfi==len(self.rf)and self.ci2==len(self.copies)and self.hi2==len(self.hashes2)and bytes(self.u.mem_read(USER,8192)).hex()==self.p['final_user8192_hex'];return dict(self.counts)
