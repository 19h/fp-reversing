#!/usr/bin/env python3
"""Declare the second adapter's CFString result and, in one stage, SecTask
constructor result, retaining the preceding PID-output model. Stop before all
other later APIs/unknown reads. O(cases*visits) time, O(one CPU map/journals) space. No native calls.
"""
import json
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from probe_daemon_entitlement_audit import Run as BeforeString
from probe_daemon_descriptor_producers import P,IMPORTS
class Run(BeforeString):
 def __init__(self,index,stage,mode):
  self.secondary_string_mode=mode;self.secondary_string_event=None;self.secondary_task_event=None;super().__init__(index,stage,'boolean_true');self.c['secondary_string_model']=mode
 def code(self,u,a,n,d):
  if self.after_query_return and a==0x1000622e8 and self.secondary_string_mode=='nonnull_task':
   self.flush();assert self.secondary_task_event is None;symbol='Security/_SecTaskCreateWithAuditToken';slot=0x1010a0330;word=int.from_bytes(IMAGE.read(slot,8),'little');assert self.reg(8)==IMPORTS[symbol]and self.reg(17)==0x2a84 and FIXUPS[slot]['target']==symbol and word>>63==1 and(word>>32)&65535==0x2a84 and(word>>48)&7==0;token=self.snapshot(self.reg(1),32);assert all(bytes.fromhex(token['known_mask_hex']));original=next(e['original_token']for e in self.api_models if 'original_token'in e);assert token['bytes_hex']==original['bytes_hex'];result=P+0x12000
   event={'pc':hex(a),'source_visit_index':self.seq,'symbol':symbol,'target':hex(IMPORTS[symbol]),'slot':hex(slot),'modifier':'0x2a84','arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_value':hex(result),'native_effects_executed':False,'audit_argument':token,'original_token':original};self.visits.append({'pc':hex(a),'source_visit_index':self.seq,'bytes_hex':IMAGE.read(a,4).hex(),'image':'daemon'});self.seq+=1
   for j in range(18):self.set(j,((0x123456789abcdef*(j+1))^(self.source_index*0x8b3dc651))&((1<<64)-1))
   self.set(0,result);self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_NZCV,[0,0xa0000000,0x50000000,0xf0000000][self.source_index]);event['after_registers31']=[hex(self.reg(j))for j in range(31)];event['after_NZCV']=hex(u.reg_read(ar.UC_ARM64_REG_NZCV));self.api_models.append(event);self.secondary_task_event=event;return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if self.after_query_return and a==0x1000141c4:
   self.flush();assert self.secondary_string_event is None;symbol='CoreFoundation/_CFStringCreateWithCStringNoCopy';slot=0x1010a0598;word=int.from_bytes(IMAGE.read(slot,8),'little');assert self.reg(8)==IMPORTS[symbol]and self.reg(17)==0xd471 and FIXUPS[slot]['target']==symbol and word>>63==1 and(word>>32)&65535==0xd471 and(word>>48)&7==0;cstring=self.snapshot(self.reg(1),16);assert all(bytes.fromhex(cstring['known_mask_hex']))and bytes.fromhex(cstring['bytes_hex'])==b'fairplay-client\0';result=0 if self.secondary_string_mode=='null'else P+0x11000
   event={'pc':hex(a),'source_visit_index':self.seq,'symbol':symbol,'target':hex(IMPORTS[symbol]),'slot':hex(slot),'modifier':'0xd471','arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_value':hex(result),'native_effects_executed':False,'cstring':cstring};self.visits.append({'pc':hex(a),'source_visit_index':self.seq,'bytes_hex':IMAGE.read(a,4).hex(),'image':'daemon'});self.seq+=1
   for j in range(18):self.set(j,((0x123456789abcdef*(j+1))^(self.source_index*0x8b3dc651))&((1<<64)-1))
   self.set(0,result);self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_NZCV,[0,0xa0000000,0x50000000,0xf0000000][self.source_index]);event['after_registers31']=[hex(self.reg(j))for j in range(31)];event['after_NZCV']=hex(u.reg_read(ar.UC_ARM64_REG_NZCV));self.api_models.append(event);self.secondary_string_event=event;return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  return super().code(u,a,n,d)
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for mode in ['null','nonnull','nonnull_task']:
  for j in range(4):
   r=Run(j,stage,mode).run();rows.append(r);print(json.dumps({'secondary_string':mode,'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_entitlement_audit.py','probe_daemon_entitlement_flow.py','daemon_mig_handover_symbolic.json']},'cases':rows,'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False};(ROOT/'daemon_entitlement_flow_string_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
