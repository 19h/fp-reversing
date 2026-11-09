#!/usr/bin/env python3
"""Follow original post-fairplay-client Boolean-adapter invocations, preserving
distinct record/object epochs and explicit constructor/query/Boolean models.
Stop before every other unmodeled API/unknown owner/read. No native target,
framework or IPC execution. O(cases*visits) time, O(one CPU map/journals) space.
"""
import json
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from capture_daemon_record720 import sha
from probe_daemon_secondary_types import Run as BeforeChain
from probe_daemon_descriptor_producers import P,SIZE,IMPORTS,Run as Original
class Run(BeforeChain):
 def __init__(self,index,stage,first,mode):
  self.chain_mode=mode;self.adapters=[];self.active=None;super().__init__(index,stage,first,'number_success');self.c['Boolean_chain_model']=mode
 def state(self):return self.snapshot(0x6800055d0c,4)
 def key_string(self,at):
  raw=bytearray()
  for j in range(512):
   if P<=at+j<P+SIZE:
    row=self.snapshot(at+j,1)
    if row['known_mask_hex']!='01':self.stop('before_unknown_key_byte',{'address':hex(at+j)});return None
    b=bytes.fromhex(row['bytes_hex'])[0]
   elif 0x100000000<=at+j<0x102000000:b=IMAGE.read(at+j,1)[0]
   else:self.stop('before_unavailable_key_owner',{'address':hex(at+j)});return None
   raw.append(b)
   if b==0:return {'address':hex(at),'NUL_inclusive_bytes':len(raw),'bytes_hex':raw.hex(),'ASCII':raw[:-1].decode('ascii')}
  self.stop('before_unbounded_key_scan',{'address':hex(at)});return None
 def code(self,u,a,n,d):
  if self.after_secondary_query and a==0x10046ef4c:
   self.flush();assert self.active is None and len(self.adapters)<24;R=self.reg(0);record=self.snapshot(R,40);index=len(self.adapters);self.active={'index':index,'entry_PC':hex(a),'entry_source_visit_index':self.seq,'record_address':hex(R),'record_before':record,'caller_return_PC':hex(self.reg(30)),'SP':hex(self.register('sp')),'state_before':self.state(),'API_event_indices':[]};self.adapters.append(self.active)
  if self.active and a==int(self.active['caller_return_PC'],16):
   self.flush();R=int(self.active['record_address'],16);ptr=int.from_bytes(bytes.fromhex(self.active['record_before']['bytes_hex'])[16:24],'little');self.active.update({'return_source_visit_index':self.seq,'record_after':self.snapshot(R,40),'marker':self.snapshot(R+8,1),'flag':self.snapshot(ptr,1),'state_at_return':self.state()});self.active=None
  if self.active:
   e=self.active;base=P+0x20000+e['index']*0x1000;name,task,value=base+0x100,base+0x200,base+0x300;symbol=None;result=None;extra={};memory=[]
   if a==0x10033376c:
    assert self.reg(28)==0x8bb2;key=self.key_string(self.reg(1))
    if key is None:return
    e['key']=key;symbol='CoreFoundation/_CFStringCreateWithCStringNoCopy';result=0 if self.chain_mode=='string_null'else name;extra={'Boolean_adapter_index':e['index'],'key':key}
   elif a==0x10047d9ac:
    symbol='Security/_SecTaskCreateWithAuditToken';result=0 if self.chain_mode=='task_null'else task;token=self.snapshot(self.reg(1),32);assert token['known_mask_hex']=='01'*32;original=next(x['original_token']for x in self.api_models if'original_token'in x);assert token['bytes_hex']==original['bytes_hex'];extra={'Boolean_adapter_index':e['index'],'audit_argument':token,'original_token':original}
   elif a==0x1002b7728 and self.chain_mode!='query_frontier':
    symbol='Security/_SecTaskCopyValueForEntitlement';result=0 if self.chain_mode=='query_null'else value;at=self.reg(2);assert at==self.reg(29)-0x60;memory=[{'address':hex(at),'size_bytes':8,'before_hex':'00'*8,'after_hex':'00'*8,'provenance':'declared Boolean-adapter query error output; not native'}];extra={'Boolean_adapter_index':e['index']}
   elif a==0x10030acb0 and self.chain_mode in ['boolean_false','boolean_true']:symbol='CoreFoundation/_CFBooleanGetTypeID';result=[0xb001,0x10000b001,0x800000000000b001,0xffffffffffffffff][self.source_index];extra={'Boolean_adapter_index':e['index']}
   elif a==0x10030ad04 and self.chain_mode in ['boolean_false','boolean_true']:
    assert self.reg(0)==value;symbol='CoreFoundation/_CFGetTypeID';result=[0xb001,0x10000b001,0x800000000000b001,0xffffffffffffffff][self.source_index];extra={'Boolean_adapter_index':e['index']}
   elif a==0x10052bcc4 and self.chain_mode in ['boolean_false','boolean_true']:
    assert self.reg(0)==value;symbol='CoreFoundation/_CFBooleanGetValue';result=int(self.chain_mode=='boolean_true');extra={'Boolean_adapter_index':e['index']}
   if symbol:
    self.model(u,a,symbol,result,memory);self.api_models[-1].update(extra);e['API_event_indices'].append(len(self.api_models)-1);return
  if self.adapters:
   ins=next(self.cs.disasm(IMAGE.read(a,4),a))
   if ins.mnemonic=='blraa'and self.reg(8)==IMPORTS['CoreFoundation/_CFRelease']:
    if self.reg(0)==0:self.flush();return self.stop('before_CFRelease_null_model_argument')
    self.model(u,a,'CoreFoundation/_CFRelease',0)
    if self.active:self.api_models[-1]['Boolean_adapter_index']=self.active['index'];self.active['API_event_indices'].append(len(self.api_models)-1)
    return
   return Original.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['Boolean_adapters']=self.adapters;return r
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for first in ['boolean_false','boolean_true']:
  for mode in ['string_null','task_null','query_frontier','query_null','boolean_false','boolean_true']:
   for j in [0,3]:
    r=Run(j,stage,first,mode).run();rows.append(r);print(json.dumps({'first':first,'mode':mode,'environment':j,'visits':len(r['source_visits']),'keys':[e.get('key',{}).get('ASCII')for e in r['Boolean_adapters']],'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_secondary_types.py','probe_daemon_secondary_result.py','daemon_mig_handover_symbolic.json']},'cases':rows,'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False};(ROOT/'daemon_boolean_chain_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
