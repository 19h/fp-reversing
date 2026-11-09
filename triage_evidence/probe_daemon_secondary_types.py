#!/usr/bin/env python3
"""Declared CFNumber/CFString type IDs and signed32 conversion outputs after
fairplay-client query. Native type IDs, values and API feasibility remain
unknown. Stop before unmodeled APIs or unavailable data/owners.
O(cases*source visits) time, O(one CPU map + journals) space; no native calls.
"""
import json
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from capture_daemon_record720 import sha
from probe_daemon_secondary_result import Run as BeforeType
from probe_daemon_descriptor_producers import P,IMPORTS
class Run(BeforeType):
 def __init__(self,index,stage,first,kind):
  self.type_model=kind;super().__init__(index,stage,first,'value_untyped');self.c['secondary_type_model']=kind
 def code(self,u,a,n,d):
  if self.after_secondary_query:
   ins=next(self.cs.disasm(IMAGE.read(a,4),a))
   if ins.mnemonic=='blraa':
    symbol=next((s for s,t in IMPORTS.items()if t==self.reg(8)),None);number=[0xb0a1,0x10000b0a1,0x800000000000b0a1,0xffffffffffffffff][self.source_index];string=number^0x100000000;wrong=number^0x200000000
    if symbol=='CoreFoundation/_CFNumberGetTypeID':return self.model(u,a,symbol,number)
    if symbol=='CoreFoundation/_CFStringGetTypeID':return self.model(u,a,symbol,string)
    if symbol=='CoreFoundation/_CFGetTypeID':
     assert self.reg(0)==P+0x13000;value=wrong if self.type_model=='wrong_type'else string if self.type_model=='string_frontier'else number;return self.model(u,a,symbol,value)
    if symbol=='CoreFoundation/_CFNumberGetValue'and self.type_model in ['number_fail','number_success']:
     self.flush();assert self.reg(0)==P+0x13000 and self.reg(1)==3 and self.reg(2)==0x68000504b0;at=self.reg(2);before=self.snapshot(at,4);value=[0,1,0x80000000,0xffffffff][self.source_index];effect={'address':hex(at),'size_bytes':4,'before_hex':before['bytes_hex'],'before_known_mask_hex':before['known_mask_hex'],'after_hex':value.to_bytes(4,'little').hex(),'provenance':'declared CFNumber signed32 output; not observed native conversion'};u.mem_write(at,value.to_bytes(4,'little'));self.known[at-P:at-P+4]=bytes([1])*4;self.model(u,a,symbol,int(self.type_model=='number_success'));self.api_models[-1]['memory_models']=[effect];return
  return super().code(u,a,n,d)
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for first in ['boolean_false','boolean_true']:
  for kind in ['number_frontier','wrong_type','string_frontier','number_fail','number_success']:
   for j in ([0,3]if kind in ['number_frontier','wrong_type','string_frontier']else range(4)):
    r=Run(j,stage,first,kind).run();rows.append(r);print(json.dumps({'first':first,'type':kind,'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_secondary_result.py','probe_daemon_secondary_identity.py','daemon_mig_handover_symbolic.json']},'cases':rows,'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False};(ROOT/'daemon_secondary_result_type_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
