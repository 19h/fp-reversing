#!/usr/bin/env python3
"""Original value decoding, caller handoffs and conditional query publication.

Only inherited allocator/free register effects; no model writes memory.
Original known append/copy/return paths execute privately. Stop at unknown
processing/accessor calls, unchanged random/stop boundaries or execution return.
O(C*(B+V+E)) time/space, abstract PAC, 30000 visits/case. No native target,
heap/API, crypto/provider, random/stop-helper or IPC operation executes.
"""
import gc,hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,CS
from probe_lskd_handlers import Handlers,cases as handler_cases
from probe_lskd_response import Response,RESPONSE
from probe_lskd_request import kernel,OBJECT
from probe_legacy_stack import P
from lskd_values_spec import HANDOFFS,VALUE_RETURNS
C=None
PURE_CALLS={0xfffffe000a525d74:0xfffffe000a54daf8,0xfffffe000a54df54:0xfffffe000a55e8b0,0xfffffe000a51a600:0xfffffe000a508cf4}
MODEL_SITES={0xfffffe000a50c8f8,0xfffffe000a50c950,0xfffffe000a5356d8}
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'lskd_values_contracts.json').read_text())
 return C
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Values(Handlers):
 def __init__(self,c):
  super().__init__(c);self.following=False;self.prior_boundary=None;self.value_returns=[];self.handoff=None;self.publication=None;self.handoffs={int(h['pc'],16):h for h in HANDOFFS};self.value_sites={int(a,16)for a in VALUE_RETURNS}
  for s in contracts()['spans']:self.ranges.append((int(s['start'],16),int(s['end'],16)))
 def boundary_snapshot(self,a,kind):return {'kind':kind,'pc':hex(a),'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]}
 def code(self,u,a,n,d):
  self.flush()
  if self.in_handler and a in [0xfffffe000a52f26c,0xfffffe000a549e08,0xfffffe000a51c02c]:
   self.following=True;sp=u.reg_read(ar.UC_ARM64_REG_SP)
   if a in [0xfffffe000a52f26c,0xfffffe000a549e08]:
    G=sp+(0x20 if a==0xfffffe000a52f26c else 0x10);row=self.snapshot(G,40);raw=bytes.fromhex(row['bytes_hex']);lp,dp=struct.unpack_from('<QQ',raw,8);self.search_return={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'record':row,'length_output':self.snapshot(lp,2),'pointer_output':self.snapshot(dp,8)};self.prior_boundary=self.boundary_snapshot(a,'field_search_return')
   else:
    self.init_return={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'registers31':[hex(self.reg(j))for j in range(31)],'record':self.snapshot(P+0x80a8,28),'response':self.snapshot(RESPONSE,160)};self.prior_boundary=self.boundary_snapshot(a,'response_initializer_return')
  if self.following:
   if a==P+0x1f000:return self.stop(a,'execution_wrapper_return')
   if a==self.execute_return_pc:return Response.code(self,u,a,n,d)
   if a in self.value_sites:
    call=next(x for x in self.calls if x['kind']in ['scalar_record','span_record']);R=int(call['record']['address'],16);raw=bytes.fromhex(call['record']['bytes_hex']);row={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)],'record':self.snapshot(R,32 if call['kind']=='scalar_record'else 40)}
    if call['kind']=='scalar_record':row['value_output']=self.snapshot(struct.unpack_from('<Q',raw,24)[0],8)
    else:row.update(pointer_output=self.snapshot(struct.unpack_from('<Q',raw,0)[0],8),length_output=self.snapshot(struct.unpack_from('<Q',raw,24)[0],2))
    self.value_returns.append(row)
   if a in self.handoffs:
    h=self.handoffs[a];assert self.reg(8)==int(h['target'],16)and self.reg(17)==int(h['modifier16'],16);self.handoff={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'target':hex(self.reg(8)),'registers31':[hex(self.reg(j))for j in range(31)],'kind':h.get('kind','record')}
    if P<=self.reg(0)<P+0x20000-48:self.handoff['record']=self.snapshot(self.reg(0),48)
    else:
     assert a==0xfffffe000a5296e4 and self.reg(0)==0xfffffe000ccc2ce0 and self.reg(1)==41;self.handoff['external_destination']={'address':hex(self.reg(0)),'size_bytes':41,'bytes_hex':bytes(u.mem_read(self.reg(0),41)).hex()}
    return self.stop(a,'before_span_random_call'if h.get('kind')=='random_41_call'else'before_next_record_helper')
   if a==0xfffffe000a522e44:
    sp=u.reg_read(ar.UC_ARM64_REG_SP);self.publication={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'registers31':[hex(self.reg(j))for j in range(31)],'out_reference_before':self.snapshot(self.reg(8),8),'candidate':self.snapshot(RESPONSE,160),'frame_out_reference':self.snapshot(sp+8,8),'frame_candidate':self.snapshot(sp+0x28,8)}
   if a in MODEL_SITES:return Response.code(self,u,a,n,d)
   i=next(CS.disasm(kernel().read(a,4),a));m=i.mnemonic
   if m in ['bl','blraa']:
    target=int(i.op_str[1:],16)if m=='bl'else self.reg(int(i.op_str.split(',',1)[0][1:]));assert PURE_CALLS.get(a)==target,('unmodeled continuation call',hex(a),hex(target));before=len(self.calls);result=Response.code(self,u,a,n,d)
    if a==0xfffffe000a525d74:
     assert len(self.calls)==before+1;self.calls[-1].update(kind='query_u32_append_record',record=self.snapshot(self.reg(0),24),candidate_before=self.snapshot(RESPONSE,160))
    return result
   if m=='braa':
    self.visit(a);target=self.reg(int(i.op_str.split(',',1)[0][1:]));assert any(x<=target<z for x,z in self.ranges),('continuation branch escape',hex(a),hex(target));self.dispatches.append({'pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers31':[hex(self.reg(j))for j in range(31)]});return u.reg_write(ar.UC_ARM64_REG_PC,target)
   return Response.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.pop('complete_business_handler_executed');returned=r['boundary']['kind']in ['execution_wrapper_return','wrapper_returned_to_provider'];r.update(prior_boundary=self.prior_boundary,value_bridge_returns=self.value_returns,next_record_handoff=self.handoff,response_publication=self.publication,positive_publication_executed=self.publication is not None,source_execution_wrapper_returned=returned,source_query_success_executed=self.original_case['operation32']==0x1b5b and self.publication is not None and returned,complete_native_business_operation_executed=False);return r
def cases():
 for c in handler_cases():yield json.loads(json.dumps(c))
 for length in [1,4,7,9,16]:
  for glob in ['original','zero','declared_noise']:
   for placement in [0,0x100]:
    for location in ['adjacent','separated']:
     c=next(c for c in handler_cases()if c['kind']=='execute'and c['operation32']==0x1b69);yield {**c,'global_fixture':glob,'placement':placement,'auxiliary_location':location,'stream_fields':[[0x72,bytes((11+37*n)&255 for n in range(length)).hex()]],'stream_fixture_label':'scalar_length_'+str(length)}
 for glob in ['original','zero','declared_noise']:
  for placement in [0,0x100]:
   for location in ['adjacent','separated']:
    c=next(c for c in handler_cases()if c['kind']=='caller'and c['caller']=='span');args=list(c['inputs8']);args[2]=37;yield {**c,'inputs8':args,'global_fixture':glob,'placement':placement,'auxiliary_location':location,'span_shape_fixture':'length37'}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Values(c);r=f.run();del f;rows.append(r)
  if j%16==0:gc.collect();print(json.dumps({'cases_completed':j+1}),flush=True)
 deps=['lskd_values_contracts.json','lskd_values_spec.py','probe_lskd_handlers.py','lskd_handlers_contracts.json','probe_lskd_consumer.py','lskd_consumer_contracts.json','probe_lskd_response.py','lskd_response_contracts.json','probe_lskd_execute.py','lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'native_request_execution_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_values_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
