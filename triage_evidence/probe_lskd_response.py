#!/usr/bin/env python3
"""Source response staging, request metadata reads and original error cleanup.

Only allocation/free register effects are modeled. Original zeroing, record
codecs, stack probes, metadata getters and error stores execute privately;
stop before business-request state and never execute positive publication.
O(C*(B+V+E)) time/space, 30000 visits/case, abstract PAC. No native heap/free,
crypto/provider request processing, Mach, synchronization or target-file API.
"""
import gc,hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,CS
from probe_legacy_stack import P,M64
from probe_lskd_request import kernel,OBJECT,PARAM,OUT
from probe_lskd_fields import cases as field_cases
from probe_lskd_execute import Execute,WORK,AUX
RESPONSE=P+0x6000;SEPARATED_AUX=P+0xd000
C=None
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'lskd_response_contracts.json').read_text())
 return C
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Response(Execute):
 def __init__(self,c):
  super().__init__(c);self.response_pointer=None;self.aux_target=AUX if c['auxiliary_location']=='adjacent'else SEPARATED_AUX
  for s in contracts()['spans']:
   if not s['label'].endswith('_symbolic')and s['label']not in['conditional_publish','business_entry_static']:self.ranges.append((int(s['start'],16),int(s['end'],16)))
  for f in contracts()['stack_helpers']:self.ranges.append((int(f['start'],16),int(f['end'],16)))
  for j,d in enumerate(contracts()['additional_mutable_globals'],15):
   a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M64;self.u.mem_write(a,struct.pack('<Q',v));self.allowed.append((a,a+8))
  self.fp_initial={f'd{j}':hex(0x1122334455660000+j)for j in range(8,12)}
  for j in range(8,12):self.u.reg_write(getattr(ar,'UC_ARM64_REG_D'+str(j)),int(self.fp_initial['d'+str(j)],16))
  if c['kind']!='provider':
   b=struct.pack('<II',c['request_header32'],c['operation32']);self.seed(OBJECT,b);self.fixture_additions.append({'address':hex(OBJECT),'bytes_hex':b.hex()})
 def code(self,u,a,n,d):
  c=self.original_case
  if a==0xfffffe000a51bee0 and self.reg(8)==0x5e561849:return self.stop(a,'before_business_request_state')
  if a==0xfffffe000a50c74c:
   assert self.reg(0)==0xfffffe000847ae20;self.auxiliary_pointer=self.aux_target;return self.register_model(a,0xfffffe000c4ba154,'auxiliary_typed_register_return',self.aux_target)
  if a==0xfffffe000a524868:
   assert self.reg(0)==0xfffffe000847ae60;self.response_pointer=RESPONSE if c['response_nonnull']else 0;return self.register_model(a,0xfffffe000c4ba154,'response_typed_register_return',self.response_pointer)
  if a==0xfffffe000a5356d8:
   assert self.reg(0)==0xfffffe000847b020 and self.reg(1)==RESPONSE;return self.register_model(a,0xfffffe000c4ba368,'response_free_register_clobbers',0xd00d0000feed0000)
  if a in[0xfffffe000a50c8f8,0xfffffe000a50c950]:return self.register_model(a,0xfffffe000c4ba368 if a==0xfffffe000a50c8f8 else 0xfffffe000c4b9a24,'typed_free_register_clobbers'if a==0xfffffe000a50c8f8 else'aligned_free_register_clobbers',0xd00d0000feed0000)
  before=len(self.calls);result=super().code(u,a,n,d)
  if len(self.calls)>before:
   row=self.calls[-1]
   if a==0xfffffe000a5617b4:row.update(kind='original_response_clear',response_before=self.snapshot(RESPONSE,160))
   elif a==0xfffffe000a5618c0:row.update(kind='workspace_record_bridge',record=self.snapshot(self.reg(0),64),delta_cell=self.snapshot(self.reg(1),8))
   elif a==0xfffffe000a58a314:row.update(kind='original_stack_probe',probe_size_X8=hex(self.reg(8)))
   elif a==0xfffffe000a58a3b8:row.update(kind='inner_workspace_record',record=self.snapshot(self.reg(0),64),delta_cell=self.snapshot(self.reg(1),8))
   elif a==0xfffffe000a51beb8:row.update(kind='request_metadata_getter',record=self.snapshot(self.reg(0),24))
  return result
 def run(self):
  r=super().run();r.pop('protected_operation_executed');r.update(response_pointer=None if self.response_pointer is None else hex(self.response_pointer),response=self.snapshot(RESPONSE,160),actual_auxiliary=self.snapshot(self.aux_target,4096),initial_fp_callee_saved64=self.fp_initial,final_fp_callee_saved64={f'd{j}':hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_D'+str(j))))for j in range(8,12)},probe_only_reads=self.probe_reads,first_nonnull_output_state_executed=any(v['pc']=='0xfffffe000a5247ac'for v in self.visits),request_metadata_getter_executed_in_private_guest=any(v['kind']=='request_metadata_getter'for v in self.calls),business_request_operation_executed=False,positive_publication_executed=False)
  out=int(self.execution_input['response_reference']['address'],16)if self.execution_input is not None else OUT;r['execution_response_reference_final']=self.snapshot(out,8);return r
def cases():
 for c in field_cases():
  if c['kind']=='provider':
   for location in['adjacent','separated']:
    for nonnull in[False,True]:yield {**c,'mode':'response','workspace_nonnull':True,'auxiliary_nonnull':True,'auxiliary_location':location,'response_nonnull':nonnull}
 for g in['original','zero','declared_noise']:
  for placement in[0,0x100]:
   for location in['adjacent','separated']:
    for header,op,request in[(0,0x1b69,OBJECT),(2,0x1b69,OBJECT),(0xffffffff,0x1b69,OBJECT),(1,0x1b69,0)]+[(1,op,OBJECT)for op in[0,1,0xffffffff,0x1b69]]:yield {'kind':'execute','mode':'response','inputs8':[request,OUT,0,0,0,0,0,0],'request_header32':header,'operation32':op,'workspace_nonnull':True,'auxiliary_nonnull':True,'auxiliary_location':location,'response_nonnull':True,'global_fixture':g,'placement':placement,'heap_nonnull':True,'out_initial64':0xabcdef0112345678}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Response(c);r=f.run();del f;rows.append(r)
  if j%16==0:gc.collect();print(json.dumps({'cases_completed':j+1}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_response_contracts.json','probe_lskd_execute.py','lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'native_heap_executed':False,'business_request_operation_executed':False,'positive_publication_executed':False,'full_goal_complete':False};(ROOT/'lskd_response_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
