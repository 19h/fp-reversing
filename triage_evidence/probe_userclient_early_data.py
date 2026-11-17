#!/usr/bin/env python3
"""Continue early node data allocation through a fifth register-only return.
No model RAM writes, phase repairs or native allocator execution.
O(C*(B+V+E)) time/retained space; 30000 visits per case; logical PAC.
"""
from probe_userclient_early_node import Entry as Base,cases as previous_cases
from probe_legacy_stack import P,kernel
CALL=0xfffffe000a661848
DATA=P+0xe200
WRITER_INPUTS=[(0xfffffe000a654ae4,'C',0x768,8),(0xfffffe000a654af0,'S',0xd30,4),(0xfffffe000a654b04,'C',0x458,8),(0xfffffe000a654b0c,'C',0x140,8),(0xfffffe000a654b14,'C',0x6b8,8),(0xfffffe000a654b20,'S',0xe28,4),(0xfffffe000a654b2c,'S',0xdf8,4),(0xfffffe000a654b38,'C',0x58,8),(0xfffffe000a654b40,'S',0x94,4),(0xfffffe000a654b48,'S',0x110,4),(0xfffffe000a654b54,'S',0xb90,2),(0xfffffe000a654b68,'S',0x1b2,2)]
class Entry(Base):
 def code(self,u,a,n,d):
  if a==CALL:
   self.flush();assert self.reg(8)==0xfffffe000c4ba60c and self.reg(0)==10+self.case['wire_length32'];raw=kernel().read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visit(a,raw);return self.model(a,self.reg(8),'earlier_TLV_data_register_return',self.case['data_result_fixture'])
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['earlier_data']=self.snapshot(DATA,64);r['writer_input_cells']=[{'source_PC':hex(pc),'root':root,'offset':hex(off),**self.snapshot(P+(0xc000 if root=='C'else 0x8000)+off,n)}for pc,root,off,n in WRITER_INPUTS];return r
def cases():
 for j,c in enumerate(previous_cases()):
  if not c['node_result_fixture']:continue
  for value in [0,DATA]:yield {**c,'data_parent_case_index':j,'data_result_fixture':value}
