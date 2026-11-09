#!/usr/bin/env python3
"""Declared ASCII-conversion bytes and strtol returns/end pointers, using
separately captured host-libc reference vectors. Execute only original daemon
instructions in a private CPU. No native daemon/framework/IPC API calls.
Stop at unmodeled APIs/owners/undefined reads. O(cases*visits) time,
O(one private CPU map/journals) space; no fixture PC transitions.
"""
import json
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from capture_daemon_record720 import sha
from probe_daemon_secondary_types import Run as BeforeString
from probe_daemon_descriptor_producers import P,IMPORTS
class Run(BeforeString):
 def __init__(self,index,stage,first,case,reference):
  self.string_case=case;self.reference=reference;self.convert_event=None;self.parse_event=None;super().__init__(index,stage,first,'string_frontier');self.c['string_case']=case
 def apply(self,u,a,symbol,result,effects=(),extra=None):
  self.flush()
  for e in effects:
   at=int(e['address'],16);before=self.snapshot(at,e['size_bytes']);assert before['bytes_hex']==e['before_hex']and before['known_mask_hex']==e['before_known_mask_hex'];u.mem_write(at,bytes.fromhex(e['after_hex']));self.known[at-P:at-P+e['size_bytes']]=bytes([1])*e['size_bytes']
  self.model(u,a,symbol,result)
  if effects:self.api_models[-1]['memory_models']=list(effects)
  if extra:self.api_models[-1].update(extra)
  return self.api_models[-1]
 def code(self,u,a,n,d):
  if self.after_secondary_query and a==0x10014c658:
   assert self.convert_event is None;assert self.reg(0)==P+0x13000 and self.reg(1)==self.reg(29)-0x80 and self.reg(2)==32 and self.reg(3)==0x600;effects=[];result=0 if self.string_case=='conversion_fail'else 1
   if result:
    raw=bytes.fromhex(self.reference['NUL_inclusive_hex']);at=self.reg(1);before=self.snapshot(at,len(raw));effects=[{'address':hex(at),'size_bytes':len(raw),'before_hex':before['bytes_hex'],'before_known_mask_hex':before['known_mask_hex'],'after_hex':raw.hex(),'provenance':'declared CFString ASCII result bytes; not native CFString data'}]
   self.convert_event=self.apply(u,a,'CoreFoundation/_CFStringGetCString',result,effects,{'declared_string_case':self.string_case,'reference_name':self.reference['name']});return
  if self.after_secondary_query and a==0x10000a2e8 and self.string_case!='parser_frontier':
   assert self.parse_event is None;start=self.reg(0);out=self.reg(1);assert start==self.reg(29)-0x80 and out==self.reg(29)-0x90 and self.reg(2)==10;raw=bytes.fromhex(self.reference['NUL_inclusive_hex']);assert self.snapshot(start,len(raw))['bytes_hex']==raw.hex();before=self.snapshot(out,8);end=0 if self.string_case=='end_null'else start+self.reference['end_offset_bytes'];effect={'address':hex(out),'size_bytes':8,'before_hex':before['bytes_hex'],'before_known_mask_hex':before['known_mask_hex'],'after_hex':end.to_bytes(8,'little').hex(),'provenance':'declared strtol end-pointer output; native runtime equivalence unestablished'};value=int(self.reference['return_bits64'],16);self.parse_event=self.apply(u,a,'libSystem/_strtol',value,[effect],{'reference_name':self.reference['name'],'reference_errno_not_applied_to_target':self.reference['errno'],'counterfactual_end_null':self.string_case=='end_null'});return
  return super().code(u,a,n,d)
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');ref=json.loads((ROOT/'daemon_secondary_string_reference.json').read_text());references={e['name']:e for e in ref['cases']};rows=[]
 for first in ['boolean_false','boolean_true']:
  tests=[(case,j,references['positive'])for case in ['conversion_fail','parser_frontier']for j in [0,3]]+[(e['name'],j%4,e)for j,e in enumerate(ref['cases'])]+[('end_null',0,references['positive'])]
  for case,j,reference in tests:
   r=Run(j,stage,first,case,reference).run();rows.append(r);print(json.dumps({'first':first,'case':case,'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_secondary_types.py','daemon_secondary_string_reference.json','daemon_mig_handover_symbolic.json']},'cases':rows,'host_libc_reference_is_separate':True,'native_target_executed':False,'host_framework_API_executed':False,'full_goal_complete':False};(ROOT/'daemon_secondary_string_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
