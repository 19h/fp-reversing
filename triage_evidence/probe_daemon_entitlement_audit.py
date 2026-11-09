#!/usr/bin/env python3
"""Declared PID-output word after the source-established post-entitlement
audit call. The model does not parse a native token or assume libbsm internals.
Continue original source with no further API models. O(cases*visits) time,
O(one private CPU map + journals) space; no native target/framework/IPC.
"""
import json
from unicorn import arm64_const as ar
from capstone.arm64_const import ARM64_OP_MEM,ARM64_EXT_SXTW,ARM64_EXT_SXTX
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from probe_daemon_entitlement_flow import Run as BeforeAudit
from probe_daemon_descriptor_producers import P,SIZE,IMPORTS
class Run(BeforeAudit):
 def __init__(self,index,stage,scenario):
  self.pid_word=[0,1,0x80000000,0xffffffff][index];self.audit_event=None;super().__init__(index,stage,scenario);self.c['PID_output_model_word']=hex(self.pid_word)
 def preflight(self,ins):
  if self.after_query_return and ins.mnemonic.startswith(('ldr','ldur','ldp','ldnp','ldar','ldax')):
   op=next((o for o in ins.operands if o.type==ARM64_OP_MEM),None)
   if op:
    a=self.register(ins.reg_name(op.mem.base))+op.mem.disp
    if op.mem.index:
     idx=self.register(ins.reg_name(op.mem.index))
     if op.ext in [ARM64_EXT_SXTW,ARM64_EXT_SXTX]:bits=32 if op.ext==ARM64_EXT_SXTW else 64;idx&=(1<<bits)-1;idx-=1<<bits if idx>>(bits-1)else 0
     a+=idx<<op.shift.value
    a&=(1<<64)-1
    if not(P<=a<P+SIZE or 0x100000000<=a<0x102000000 or a in self.import_word_models):
     symbol=next((s for s,v in IMPORTS.items()if v==a),None);self.stop('before_unavailable_imported_data'if symbol else'before_unmapped_owner_access',{'address':hex(a),'symbol':symbol,'instruction':ins.mnemonic+' '+ins.op_str});return False
  return super().preflight(ins)
 def code(self,u,a,n,d):
  if self.after_query_return and a==0x1004b503c:
   self.flush();assert self.audit_event is None;slot=0x1010a0500;symbol='libbsm/_audit_token_to_au32';word=int.from_bytes(IMAGE.read(slot,8),'little');assert FIXUPS[slot]['target']==symbol and self.reg(8)==IMPORTS[symbol]and self.reg(17)==0xdc55 and word>>63==1 and(word>>32)&65535==0xdc55 and(word>>48)&7==0;at=self.reg(6);assert at==self.C+0x5d5c;before=self.snapshot(at,4);token=self.snapshot(self.reg(0),32);assert all(bytes.fromhex(token['known_mask_hex']));sp=u.reg_read(ar.UC_ARM64_REG_SP);stack=self.snapshot(sp,8);assert all(bytes.fromhex(stack['known_mask_hex']))and stack['bytes_hex']=='00'*8
   event={'pc':hex(a),'source_visit_index':self.seq,'symbol':symbol,'target':hex(IMPORTS[symbol]),'slot':hex(slot),'modifier':'0xdc55','arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(sp),'return_value':'0x0','void_return_X0_is_only_clobber_model':True,'native_effects_executed':False,'token_argument':token,'stack_final_argument':stack,'memory_models':[{'address':hex(at),'size_bytes':4,'before_hex':before['bytes_hex'],'before_known_mask_hex':before['known_mask_hex'],'after_hex':self.pid_word.to_bytes(4,'little').hex(),'provenance':'declared PID-output word, not observed native extraction'}]};u.mem_write(at,self.pid_word.to_bytes(4,'little'));self.known[at-P:at-P+4]=bytes([1])*4;self.visits.append({'pc':hex(a),'source_visit_index':self.seq,'bytes_hex':IMAGE.read(a,4).hex(),'image':'daemon'});self.seq+=1
   for j in range(18):self.set(j,((0x123456789abcdef*(j+1))^(self.source_index*0x8b3dc651))&((1<<64)-1))
   self.set(0,0);self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_NZCV,[0,0xa0000000,0x50000000,0xf0000000][self.source_index]);event['after_registers31']=[hex(self.reg(j))for j in range(31)];event['after_NZCV']=hex(u.reg_read(ar.UC_ARM64_REG_NZCV));self.api_models.append(event);self.audit_event=event;return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  return super().code(u,a,n,d)
def main():
 p=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in p['cases']if c['path_class']=='allnonnull');rows=[]
 for mode in ['null_no_error','boolean_false','boolean_true']:
  for j in range(4):
   r=Run(j,stage,mode).run();rows.append(r);print(json.dumps({'scenario':mode,'environment':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_entitlement_flow.py','probe_daemon_entitlement_result.py','daemon_mig_handover_symbolic.json']},'cases':rows,'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False};(ROOT/'daemon_entitlement_flow_audit_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
