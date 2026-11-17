#!/usr/bin/env python3
"""Continue original early node allocation through a declared register return.
No model RAM writes or CPU/phase repairs. Initial input/source provenance kept.
O(C*(B+V+E)) time/retained space; 30000 visits per case; logical PAC only.
"""
from probe_userclient_early_header import Entry as Base,cases as previous_cases
from probe_legacy_stack import P,kernel
CALL=0xfffffe000a661664
NODE=P+0xe100
NODE_PROFILES={'blob_tag_one','blob_payload','u32_payload','u64_payload','u64_payload_high32_size'}
class Entry(Base):
 def code(self,u,a,n,d):
  if a==CALL:
   self.flush();assert self.reg(10)==0xfffffe000c4ba154 and self.reg(0)==0xfffffe000847b4a0;raw=kernel().read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visit(a,raw);return self.model(a,self.reg(10),'earlier_FPTTLVNode32_register_return',self.case['node_result_fixture'])
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['earlier_node']=self.snapshot(NODE,32);return r
def cases():
 for j,c in enumerate(previous_cases()):
  if c['profile']not in NODE_PROFILES:continue
  for v in [0,NODE]:yield {**c,'node_parent_case_index':j,'node_result_fixture':v}
