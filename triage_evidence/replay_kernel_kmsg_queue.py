#!/usr/bin/env python3
"""Independent original queue CPU/effect replay with explicit queue-entry variants.
O(image+visits+RAM+effects), O(image+RAM+journals). No probe executor import.
"""
from replay_kernel_kmsg_allocation import Replay as Parent
from unicorn import arm64_const as ar
P=0x6500000000;PORT=P+0xc0000;KMSG=P+0xd0000;QSTATS=P+0xb9000;THREAD=P+0x2c000
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.qf=p['queue_frames'];self.qi=0;self.qv=p['queue_entry_variant'];self.qdone=False
 def code(self,u,a,n,d):
  self.finish()
  if not self.qdone and self.qv is not None and a==int(self.qv['pc'],16)and self.seq==self.qv['before_source_visit_index']:
   e=self.qv;assert e['before_arguments4']==[hex(self.reg(j))for j in range(4)]
   for r in e['registers']:j=int(r['register'][1:]);assert hex(self.reg(j))==r['before'];u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(r['after'],16));self.counts['explicit_queue_ABI_register_variants_checked']+=1
   for r in e['patches']:ptr=int(r['address'],16);b=bytes.fromhex(r['after_hex']);assert bytes(u.mem_read(ptr,len(b))).hex()==r['before_hex'];u.mem_write(ptr,b);self.counts['explicit_queue_header_metadata_variants_checked']+=1
   assert e['after_arguments4']==[hex(self.reg(j))for j in range(4)];self.qdone=True;self.counts['queue_entry_variant_boundaries_checked']+=1
  if self.qi<len(self.qf):
   e=self.qf[self.qi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['port144_hex']==bytes(u.mem_read(PORT,144)).hex()and e['kmsg64_hex']==bytes(u.mem_read(KMSG,64)).hex()and e['task_send_counter']==int.from_bytes(bytes(u.mem_read(QSTATS,8)),'little')and e['thread_nesting']==int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little');self.qi+=1;self.counts['original_queue_port_size_list_and_return_frames_checked']+=1
  return super().code(u,a,n,d)
 def run(self):super().run();assert self.qi==len(self.qf)and self.qdone==(self.qv is not None);return dict(self.counts)
