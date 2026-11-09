#!/usr/bin/env python3
"""Declared fairplay-client query value/error outputs, preserving the source
chain through both Security tasks. Release requests receive explicit void
clobber models; stop before all other unmodeled APIs/owners/undefined reads.
O(cases*source visits) time, O(one private CPU map/journals) space.
No native target/framework/IPC execution or fixture PC transitions.
"""
import json
from unicorn import arm64_const as ar
from capstone.arm64_const import ARM64_OP_MEM,ARM64_EXT_SXTW,ARM64_EXT_SXTX
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from probe_daemon_secondary_identity import Run as BeforeQuery
from probe_daemon_descriptor_producers import P,SIZE,IMPORTS
SCENARIOS={'null_no_error':(0,0),'null_with_error':(0,P+0x14000),'value_with_error':(P+0x13000,P+0x14000),'value_untyped':(P+0x13000,0)}
class Run(BeforeQuery):
 def __init__(self,index,stage,first,second):
  self.after_secondary_query=False;self.second_result_scenario=second;super().__init__(index,stage,'nonnull_task');self.query_scenario=first;self.c['query_result_model']=first;self.c['secondary_result_model']=second
 def model(self,u,a,symbol,result,memory=()):
  self.flush();slotrow=next(e for e in reversed(self.reads)if e['size_bytes']==8 and int(e['address'],16)in FIXUPS and FIXUPS[int(e['address'],16)]['target']==symbol);slot=int(slotrow['address'],16);word=int.from_bytes(IMAGE.read(slot,8),'little');assert self.reg(8)==IMPORTS[symbol]and word>>63==1 and(word>>32)&65535==self.reg(17)and(word>>48)&7==0
  event={'pc':hex(a),'source_visit_index':self.seq,'symbol':symbol,'target':hex(IMPORTS[symbol]),'slot':hex(slot),'modifier':hex(self.reg(17)),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_value':hex(result),'native_effects_executed':False}
  if memory:event['memory_models']=list(memory)
  for e in memory:
   at=int(e['address'],16);before=self.snapshot(at,e['size_bytes']);assert all(bytes.fromhex(before['known_mask_hex']))and before['bytes_hex']==e['before_hex'];u.mem_write(at,bytes.fromhex(e['after_hex']));self.known[at-P:at-P+e['size_bytes']]=bytes([1])*e['size_bytes']
  self.visits.append({'pc':hex(a),'source_visit_index':self.seq,'bytes_hex':IMAGE.read(a,4).hex(),'image':'daemon'});self.seq+=1
  for j in range(18):self.set(j,((0x123456789abcdef*(j+1))^(self.source_index*0x8b3dc651))&((1<<64)-1))
  self.set(0,result);self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_NZCV,[0,0xa0000000,0x50000000,0xf0000000][self.source_index]);event['after_registers31']=[hex(self.reg(j))for j in range(31)];event['after_NZCV']=hex(u.reg_read(ar.UC_ARM64_REG_NZCV));self.api_models.append(event);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def preflight(self,ins):
  if self.after_secondary_query and ins.mnemonic.startswith(('str','stur','stp','stnp','stlr','stlx')):
   op=next((o for o in ins.operands if o.type==ARM64_OP_MEM),None)
   if op:
    a=self.register(ins.reg_name(op.mem.base))+op.mem.disp
    if op.mem.index:
     idx=self.register(ins.reg_name(op.mem.index))
     if op.ext in [ARM64_EXT_SXTW,ARM64_EXT_SXTX]:bits=32 if op.ext==ARM64_EXT_SXTW else 64;idx&=(1<<bits)-1;idx-=1<<bits if idx>>(bits-1)else 0
     a+=idx<<op.shift.value
    a&=(1<<64)-1
    if not(P<=a<P+SIZE or 0x101000000<=a<0x102000000):self.stop('before_unmapped_owner_write',{'address':hex(a),'instruction':ins.mnemonic+' '+ins.op_str});return False
  return super().preflight(ins)
 def code(self,u,a,n,d):
  if a==0x1002382e8:
   assert not self.after_secondary_query;value,error=SCENARIOS[self.second_result_scenario];at=self.reg(2);assert at==self.register('sp')+0x98;self.after_secondary_query=True;return self.model(u,a,'Security/_SecTaskCopyValueForEntitlement',value,[{'address':hex(at),'size_bytes':8,'before_hex':'00'*8,'after_hex':error.to_bytes(8,'little').hex(),'provenance':'declared second CFErrorRef output; not a native error'}])
  if self.after_secondary_query:
   ins=next(self.cs.disasm(IMAGE.read(a,4),a))
   if ins.mnemonic=='blraa'and self.reg(8)==IMPORTS['CoreFoundation/_CFRelease']:
    if self.reg(0)==0:self.flush();return self.stop('before_CFRelease_null_model_argument')
    return self.model(u,a,'CoreFoundation/_CFRelease',0)
  return super().code(u,a,n,d)
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for first in ['boolean_false','boolean_true']:
  for second in SCENARIOS:
   for j in range(4):
    r=Run(j,stage,first,second).run();rows.append(r);print(json.dumps({'first':first,'second':second,'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_secondary_identity.py','probe_daemon_entitlement_audit.py','daemon_mig_handover_symbolic.json']},'scenarios':{k:{'value_ref':hex(v),'error_ref':hex(e),'native_feasibility_established':False}for k,(v,e)in SCENARIOS.items()},'cases':rows,'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False};(ROOT/'daemon_secondary_result_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
