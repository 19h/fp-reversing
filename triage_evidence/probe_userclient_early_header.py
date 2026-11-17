#!/usr/bin/env python3
"""Original entry plus explicitly declared pre-entry input bytes.
No CPU/phase repairs, RAM API writes or further allocation-return cuts.
Initial-input provenance=2, source stores=1, unknown=0. PAC logical only.
O(C*(B+V+E)) time/retained space; 30000 visits per case.
"""
from probe_userclient_fpttlv_entry import Entry as Base,cases as parent_cases
from probe_legacy_stack import P
class Entry(Base):
 def __init__(self,c,mutation=None):
  super().__init__(c,mutation);b=bytes.fromhex(c['input_fixture_hex']);a=c['inputs8'][0];assert a==P+0x2000 and len(b)<=64
  self.u.mem_write(a,b);self.known[a-P:a-P+len(b)]=b'\1'*len(b);self.provenance[a-P:a-P+len(b)]=b'\2'*len(b)
 def run(self):
  r=super().run();r['declared_input']=self.snapshot(self.case['inputs8'][0],len(bytes.fromhex(self.case['input_fixture_hex'])));r['initial_input_bytes_declared']=len(bytes.fromhex(self.case['input_fixture_hex']));return r
def profiles():
 # Raw wire type values are fixtures, with meaning checked from original words.
 for name,d,u,l,n,body in [
  ('unknown_type',0,0,0,10,b''),('body_too_long',1,0x50db,1,10,b''),
  ('blob_zero_tag',0,0x50db,0,10,b''),('blob_tag_one',1,0x50db,0,10,b''),
  ('u32_short_length',1,0x9777,0,10,b''),('u64_short_length',1,0x8485,0,10,b''),
  ('blob_unconsumed_suffix',0,0x50db,0,16,b'\x11'*6),
  ('short_header',1,0x50db,0,9,b''),
  ('blob_payload',1,0x50db,8,18,bytes.fromhex('0123456789abcdef')),
  ('u32_payload',1,0x9777,4,14,bytes.fromhex('01234567')),
  ('u64_payload',1,0x8485,8,18,bytes.fromhex('0123456789abcdef')),
  ('u64_payload_high32_size',1,0x8485,8,0x1234567800000012,bytes.fromhex('fedcba9876543210'))]:
  yield {'profile':name,'wire_tag32':d,'wire_type16':u,'wire_length32':l,'declared_size64':n,'input_fixture_hex':(d.to_bytes(4,'big')+u.to_bytes(2,'big')+l.to_bytes(4,'big')+body).hex()}
def cases():
 parents=list(parent_cases())
 for g in ['original','zero','declared_noise']:
  for placement in [0,0x100]:
   for p in profiles():
    n=p['declared_size64'];match=next(((j,c)for j,c in enumerate(parents)if c['global_fixture']==g and c['placement']==placement and c['inputs8'][:2]==[P+0x2000,n]and c['FPTTLV_result_fixture']),None)
    j,c=match if match is not None else next((j,c)for j,c in enumerate(parents)if c['global_fixture']==g and c['placement']==placement and c['inputs8'][:2]==[P+0x2000,10]and c['FPTTLV_result_fixture'])
    yield {**c,**p,'inputs8':[P+0x2000,n,*c['inputs8'][2:]],'header_parent_case_index':j if match is not None else None,'header_template_case_index':j}
