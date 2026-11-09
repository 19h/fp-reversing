#!/usr/bin/env python3
"""Declared entitlement-result/error models after the source-established key
and token constructor path. Native frameworks/entitlement values are never
queried. Stop before any unmodeled API or unavailable owner/data access.
O(cases*source visits) time, O(one private CPU map/journal) space.
"""
import json
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from probe_daemon_record40_consumer import Run as BeforeQuery
from probe_daemon_descriptor_producers import P,IMPORTS
SCENARIOS={'null_no_error':(0,0),'null_with_error':(0,P+0xd000),'value_with_error':(P+0xb000,P+0xd000),'value_untyped':(P+0xb000,0),'value_wrong_type':(P+0xb000,0),'boolean_false':(P+0xb000,0),'boolean_true':(P+0xb000,0)}
class Run(BeforeQuery):
 def __init__(self,index,stage,scenario):
  self.query_scenario=scenario;super().__init__(index,stage,'task_nonnull');self.c['query_result_model']=scenario
 def code(self,u,a,n,d):
  ins=next(self.cs.disasm(IMAGE.read(a,4),a))
  if ins.mnemonic=='blraa'and self.query_scenario in ['value_wrong_type','boolean_false','boolean_true']:
   target=self.register(ins.op_str.split(',')[0].strip());symbol=next((name for name,value in IMPORTS.items()if value==target),None);type_id=[0xb001,0x10000b001,0x800000000000b001,0xffffffffffffffff][self.source_index];result=None
   if symbol=='CoreFoundation/_CFBooleanGetTypeID':result=type_id
   elif symbol=='CoreFoundation/_CFGetTypeID':
    assert self.reg(0)==P+0xb000;result=type_id^0x100000000 if self.query_scenario=='value_wrong_type'else type_id
   elif symbol=='CoreFoundation/_CFBooleanGetValue':
    assert self.query_scenario in ['boolean_false','boolean_true']and self.reg(0)==P+0xb000;result=int(self.query_scenario=='boolean_true')
   if result is not None:
    self.flush();last=next(e for e in reversed(self.reads)if e['size_bytes']==8 and int(e['address'],16)in FIXUPS and FIXUPS[int(e['address'],16)]['target']==symbol);slot=int(last['address'],16);word=int.from_bytes(IMAGE.read(slot,8),'little');modifier=self.reg(17);assert word>>63==1 and(word>>32)&65535==modifier and(word>>48)&7==0
    event={'pc':hex(a),'source_visit_index':self.seq,'symbol':symbol,'target':hex(target),'slot':hex(slot),'modifier':hex(modifier),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_value':hex(result),'native_effects_executed':False,'abstract_CFBoolean_type_ID':hex(type_id)};self.visits.append({'pc':hex(a),'source_visit_index':self.seq,'bytes_hex':IMAGE.read(a,4).hex(),'image':'daemon'});self.seq+=1
    for j in range(18):self.set(j,((0x123456789abcdef*(j+1))^(self.source_index*0x8b3dc651))&((1<<64)-1))
    self.set(0,result);self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_NZCV,[0,0xa0000000,0x50000000,0xf0000000][self.source_index]);event['after_registers31']=[hex(self.reg(j))for j in range(31)];event['after_NZCV']=hex(u.reg_read(ar.UC_ARM64_REG_NZCV));self.api_models.append(event);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if ins.mnemonic=='blraa'and self.register(ins.op_str.split(',')[0].strip())==IMPORTS['Security/_SecTaskCopyValueForEntitlement']:
   self.flush();result,error=SCENARIOS[self.query_scenario];address=self.reg(2);assert address==self.reg(29)-0x60 and self.snapshot(address,8)['known_mask_hex']=='01'*8;before=bytes(u.mem_read(address,8));assert before==bytes(8);slot=0x10109ffa0;word=int.from_bytes(IMAGE.read(slot,8),'little');assert FIXUPS[slot]['target']=='Security/_SecTaskCopyValueForEntitlement'and word>>63==1 and(word>>32)&65535==self.reg(17)==0xfe9e
   event={'pc':hex(a),'source_visit_index':self.seq,'symbol':'Security/_SecTaskCopyValueForEntitlement','target':hex(IMPORTS['Security/_SecTaskCopyValueForEntitlement']),'slot':hex(slot),'modifier':'0xfe9e','arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_value':hex(result),'native_effects_executed':False,'memory_models':[{'address':hex(address),'size_bytes':8,'before_hex':before.hex(),'after_hex':error.to_bytes(8,'little').hex(),'provenance':'declared CFErrorRef output model; not a native error'}]};u.mem_write(address,error.to_bytes(8,'little'));self.known[address-P:address-P+8]=bytes([1])*8;self.visits.append({'pc':hex(a),'source_visit_index':self.seq,'bytes_hex':IMAGE.read(a,4).hex(),'image':'daemon'});self.seq+=1
   for j in range(18):self.set(j,((0x123456789abcdef*(j+1))^(self.source_index*0x8b3dc651))&((1<<64)-1))
   self.set(0,result);self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_NZCV,[0,0xa0000000,0x50000000,0xf0000000][self.source_index]);event['after_registers31']=[hex(self.reg(j))for j in range(31)];event['after_NZCV']=hex(u.reg_read(ar.UC_ARM64_REG_NZCV));self.api_models.append(event);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  return super().code(u,a,n,d)
def main():
 parent=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in parent['cases']if c['path_class']=='allnonnull');rows=[]
 for scenario in SCENARIOS:
  for j in range(4):
   r=Run(j,stage,scenario).run();rows.append(r);print(json.dumps({'scenario':scenario,'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_mig_handover_symbolic.json','probe_daemon_record40_consumer.py','probe_daemon_descriptor_producers.py']},'scenarios':{n:{'value_ref':hex(v),'error_ref':hex(e),'native_feasibility_established':False}for n,(v,e)in SCENARIOS.items()},'cases':rows,'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False};(ROOT/'daemon_entitlement_result_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
