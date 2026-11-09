#!/usr/bin/env python3
"""Full original caller preparation through operation selection, private only.

Allocation/free register models are inherited; no model writes memory.
Stop before the selected leaf's first instruction. No operation callee,
native heap/API, crypto/provider, IPC, synchronization or target-file action.
O(C*(B+V+E)) time/space, abstract PAC, 30000 visits per case.
"""
import gc,hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,CS
from probe_lskd_response import Response,kernel,OBJECT,OUT
from probe_lskd_request import OTHER_OUT
from probe_lskd_fields import DATA,cases as field_cases
from probe_lskd_execute import WORK
C=None
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'lskd_consumer_contracts.json').read_text())
 return C
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Consumer(Response):
 def __init__(self,c):
  super().__init__(c);self.selection=False;self.entries=[];self.loads=[];self.prepare=None;self.leaves={int(v,16)for v in contracts()['leaf_map'].values()}|{int(contracts()['default_leaf'],16)};self.nodes={int(n['start'],16):n for n in contracts()['nodes']};self.load_nodes={int(n['table_load_pc'],16):n for n in contracts()['nodes']};self.branch_nodes={int(n['branch_pc'],16):n for n in contracts()['nodes']}
  for s in contracts()['spans']:
   if s['label']=='shared_frame_prepare'or s['label'].startswith('node_'):self.ranges.append((int(s['start'],16),int(s['end'],16)))
  self.caller=None
  if c['kind']=='caller':
   self.caller=next(p for p in contracts()['additional_callers']if p['label']==c['caller']);self.start=int(self.caller['start'],16);f=self.caller['function'];self.ranges.append((int(f['start'],16),int(f['end'],16)))
 def code(self,u,a,n,d):
  if self.selection and a in self.leaves:return self.stop(a,'selected_operation_leaf')
  c=self.original_case;caller=self.caller if c['kind']=='caller'else self.provider if c['kind']=='provider'else None
  if caller is not None and a==int(caller['execution_call'],16):
   self.visit(a);assert next(CS.disasm(kernel().read(a,4),a)).op_str=='#0xfffffe000a50c508';self.execution_input={'pc':hex(a),'source_visit_index':self.seq-1,'request_pointer':hex(self.reg(0)),'response_reference':self.snapshot(self.reg(1),8),'request':self.snapshot(OBJECT,160)};self.execute_return_pc=a+4;self.calls.append({'kind':'source_caller_execute_wrapper','pc':hex(a),'target':'0xfffffe000a50c508','source_visit_index':self.seq-1,'registers8':[hex(self.reg(j))for j in range(8)],'target_executed_in_private_guest':True});self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,0xfffffe000a50c508)
  if a==0xfffffe000a51bee0:
   assert self.reg(8)==0x5e561849 and self.reg(9)==0xfffffe000a59bf78;self.visit(a);self.dispatches.append({'pc':hex(a),'target':hex(self.reg(9)),'source_visit_index':self.seq-1,'registers31':[hex(self.reg(j))for j in range(31)]});self.selection=True;return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(9))
  if self.selection:
   self.flush();sp=u.reg_read(ar.UC_ARM64_REG_SP)
   if a==0xfffffe000a59bf78:self.prepare={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'registers31':[hex(self.reg(j))for j in range(31)],'operation_scratch':self.snapshot(WORK+0x118,4),'auxiliary_frame_cell':self.snapshot(sp+0x160,8)}
   if a in self.nodes:self.entries.append({'node':self.nodes[a]['label'],'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'registers31':[hex(self.reg(j))for j in range(31)]})
   if a in self.load_nodes:
    node=self.load_nodes[a];ix=self.reg(int(node['index_register'][1:]))&0xffffffff;table=self.reg(int(node['table_register'][1:]));assert table==int(contracts()['table_address'],16)and ix<0xb00;slot=table+ix*8;self.loads.append({'node':node['label'],'pc':hex(a),'source_visit_index':self.seq,'index32':ix,'slot':hex(slot),'target_from_memory':hex(int.from_bytes(bytes(u.mem_read(slot,8)),'little'))})
   if a in self.branch_nodes:
    node=self.branch_nodes[a];self.visit(a);target=self.reg(int(node['destination_register'][1:]));assert target in self.nodes or target in self.leaves;assert self.reg(17)==int(node['modifier16'],16);self.dispatches.append({'pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers31':[hex(self.reg(j))for j in range(31)]});return u.reg_write(ar.UC_ARM64_REG_PC,target)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.pop('business_request_operation_executed');r.update(shared_prepare_entry=self.prepare,classifier_entries=self.entries,classifier_table_loads=self.loads,operation_selection_executed_in_private_guest=True,selected_operation_callee_executed=False,native_business_operation_executed=False);return r
def cases():
 for c in field_cases():
  if c['kind']=='provider':
   p=next(v for v in contracts()['prior_provider_callers']if v['label']==c['provider'])
   for location in['adjacent','separated']:yield {**c,'mode':'consumer','workspace_nonnull':True,'auxiliary_nonnull':True,'auxiliary_location':location,'response_nonnull':True,'operation32':p['operation32']}
 for g in['original','zero','declared_noise']:
  for placement in[0,0x100]:
   for location in['adjacent','separated']:
    for p in contracts()['additional_callers']:
     args=[0]*8 if p['label']!='span'else[0,DATA,8,OTHER_OUT,8,0,0,0]
     yield {'kind':'caller','caller':p['label'],'mode':'consumer','inputs8':args,'request_header32':1,'operation32':p['operation32'],'workspace_nonnull':True,'auxiliary_nonnull':True,'auxiliary_location':location,'response_nonnull':True,'global_fixture':g,'placement':placement,'heap_nonnull':True,'out_initial64':0}
 for operation in sorted({0,1,0x7fffffff,0x80000000,0x80000001,0xfffffffe,0xffffffff,*range(0x1b58,0x1b70)}):yield {'kind':'execute','mode':'consumer','inputs8':[OBJECT,OUT,0,0,0,0,0,0],'request_header32':1,'operation32':operation,'workspace_nonnull':True,'auxiliary_nonnull':True,'auxiliary_location':'separated','response_nonnull':True,'global_fixture':'original','placement':0,'heap_nonnull':True,'out_initial64':0xabcdef0112345678}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Consumer(c);r=f.run();del f;rows.append(r)
  if j%16==0:gc.collect();print(json.dumps({'cases_completed':j+1}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_consumer_contracts.json','lskd_consumer_spec.py','probe_lskd_response.py','lskd_response_contracts.json','probe_lskd_execute.py','lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'selected_operation_callee_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_consumer_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
