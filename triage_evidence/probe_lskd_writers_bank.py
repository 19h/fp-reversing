#!/usr/bin/env python3
"""Conditional source table-pointer fragment over all byte inputs and two frames.

Initial bank pointers are explicit saved-frame premises established separately
by the real entry prefix. This does not establish control-flow reachability or
a table-entry write. No accepted tag/vector/object is supplied or mutated.
O(C*(B+I)) time, O(C*I+B) retained space. No API/model/native target executes.
"""
import hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from probe_legacy_stack import Bridge,P,kernel
from kext_port_tools import ROOT,SOURCE,CS
A=0xfffffe000a589908;Z=0xfffffe000a58993c;L=0xfffffe0007920c10;R=0xfffffe00079170c0;TABLE=0xfffffe000ccc7b08
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Candidate(Bridge):
 def __init__(self,c):
  super().__init__(c);self.F=P+0x10000+c['placement'];self.u.reg_write(ar.UC_ARM64_REG_SP,self.F);self.setreg(26,R);self.setreg(16,c['input32']);self.setreg(17,c['input32']&255);raw=struct.pack('<Q',L);a=self.F+0xc28;self.u.mem_write(a,raw);self.known[a-P:a-P+8]=b'\1'*8;self.provenance[a-P:a-P+8]=b'\3'*8;self.fixture={'address':hex(a),'bytes_hex':raw.hex()}
 def code(self,u,a,n,d):
  self.flush()
  if a==Z:self.reason='local_table_pointer_fragment_end';return u.emu_stop()
  assert A<=a<a+4<=Z;raw=kernel().read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1
 def run(self):
  self.u.emu_start(A,Z,count=100);self.flush();assert self.reason in[None,'local_table_pointer_fragment_end']and self.u.reg_read(ar.UC_ARM64_REG_PC)==Z and self.visits==[{'pc':hex(a),'bytes_hex':kernel().read(a,4).hex(),'source_visit_index':j}for j,a in enumerate(range(A,Z,4))]
  s=self.snapshot(self.F+0xd28,8);assert s['bytes_hex']==struct.pack('<Q',TABLE).hex()and s['known_mask_hex']=='01'*8 and s['provenance_hex']=='01'*8
  return {'input':self.case,'frame_SP':hex(self.F),'initial_bank_fixture':self.fixture,'initial_X26':hex(R),'initial_X16':hex(self.case['input32']),'initial_X17':hex(self.case['input32']&255),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'saved_table_pointer':s,'end_PC':hex(Z),'original_parent_path_executed':False,'tag_table_modified':False,'native_target_executed':False,'model_memory_writes':0}
def cases():
 for placement in[0,0x100]:
  for high in[0,0xa5f0c300]:
   for byte in range(256):yield {'family':'writer_bank','inputs8':[0]*8,'global_fixture':'original','placement':placement,'delta_units32':0,'input32':high|byte}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Candidate(c);rows.append(f.run());del f
  if j%256==255:print(json.dumps({'local_cases':j+1}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_legacy_stack.py','legacy_stack_contracts.json','kernel_native_reader.py','kext_port_tools.py']},'kernel_collection_sha256':kernel().sha256,'source_sha256':sha(SOURCE),'cases':rows,'model_memory_writes':0,'native_target_executed':False,'original_parent_path_executed':False,'full_goal_complete':False};(ROOT/'lskd_writers_bank_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
