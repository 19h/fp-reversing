#!/usr/bin/env python3
"""Continue original core entry through the earlier FPTTLV allocation return.

Three register-only allocation cuts, no RAM model writes. The third result
is declared before entry; original source determines all later branches and
stores. Stop before every other unmodeled call/undefined read. PAC logical.
O(C*(B+V+E)) time/retained space, 30000 source visits per case.
"""
from kext_port_tools import ROOT,IMAGE
from probe_legacy_stack import P,kernel
from probe_userclient_entry_execution import Entry as Base,cases as previous_cases
ENTRY_CALL=0xfffffe000a636404
OBJECT=P+0xe000
class Entry(Base):
 def code(self,u,a,n,d):
  if any(x<=a<a+4<=z for x,z in self.ranges):
   i=next(self.decoder.disasm(bytes(u.mem_read(a,4)),a))
   if i.mnemonic in ['ldr','ldp','ldur','ldrb','ldrh','ldurb','ldurh']:
    at,width,dest=self.effective_load(i)
    if not(P<=at<at+width<=P+0x20000 or at==self.guard or any(va<=at<at+width<=va+size for va,off,size in IMAGE.segments)):
     self.unknown_read={'pc':hex(a),'operands':i.op_str,'address':hex(at),'size_bytes':width,'kind':'unbacked_private_or_source_value'};return self.stop(a,'before_unbacked_value_load')
  if a==ENTRY_CALL:
   self.flush();assert self.reg(11)==0xfffffe000c4ba154 and self.reg(0)==0xfffffe000847bb60;raw=kernel().read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visit(a,raw)
   return self.model(a,self.reg(11),'earlier_FPTTLV16_register_return',self.case['FPTTLV_result_fixture'])
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['earlier_FPTTLV_object']=self.snapshot(OBJECT,16);return r
def cases():
 for j,c in enumerate(previous_cases()):
  if not c['inputs8'][0]:continue
  for value in [0,OBJECT]:yield {**c,'parent_case_index':j,'FPTTLV_result_fixture':value}
 for j,c in enumerate(previous_cases()):
  if c['inputs8'][:2]!=[P+0x2000,0]:continue
  for n in [9,10]:yield {**c,'inputs8':[P+0x2000,n,*c['inputs8'][2:]],'parent_case_index':None,'template_case_index':j,'FPTTLV_result_fixture':OBJECT}
if __name__=='__main__':
 import json
 rows=[]
 for c in cases():
  f=Entry(c);r=f.run();rows.append(r);del f;print(json.dumps({'case':len(rows),'result':c['FPTTLV_result_fixture'],'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'pc':r['boundary']['pc'],'call':r['unexecuted_call']}),flush=True)
 (ROOT/'userclient_fpttlv_entry_profiles.json').write_text(json.dumps(rows,indent=2)+'\n')
