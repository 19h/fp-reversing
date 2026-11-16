#!/usr/bin/env python3
"""Pin original kernel allocation, conditional returns and retirement ABI.
O(B+I+S) extraction time/space; no target execution or database mutation.
"""
import json
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha

P='kernel_allocator_boundary'
SCOPE='Original-kernel selected small-size zone selection, conditional null allocation-result propagation, typed fallback allocation/free heap-size congruence, null retirement guards and small-size zone-query ABI. Native backend outcomes, full allocator recovery, allocation identity/ownership, PAC, locking, whole-command reachability and daemon transaction correlation remain unknown.'
FUNCTIONS=[0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4ba60c,0xfffffe000c4ba84c,
 0xfffffe000bcfeb8c,0xfffffe000bcfe5b8,0xfffffe000bcff010,0xfffffe000bcfec48]
SPANS={
 'typed_prologue':(0xfffffe000bcfeb90,0xfffffe000bcfeb98),
 'typed_heap_request':(0xfffffe000bcfebe8,0xfffffe000bcfec24),
 'typed_zone_return':(0xfffffe000bcfebe0,0xfffffe000bcfebe4),
 'typed_heap_return':(0xfffffe000bcfec24,0xfffffe000bcfec28),
 'data_allocate_enter':(0xfffffe000c4ba610,0xfffffe000c4ba63c),
 'data_allocate_gate':(0xfffffe000c4ba63c,0xfffffe000c4ba640),
 'data_allocate_null_return':(0xfffffe000c4ba690,0xfffffe000c4ba698),
 'size_allocate_prologue':(0xfffffe000bcfe5bc,0xfffffe000bcfe5d0),
 'size_select':(0xfffffe000bcfe660,0xfffffe000bcfe678),
 'size_zone_class':(0xfffffe000bcfe678,0xfffffe000bcfe6c0),
 'size_zone_request':(0xfffffe000bcfe6cc,0xfffffe000bcfe6dc),
 'size_zone_result_gate':(0xfffffe000bcfe6dc,0xfffffe000bcfe6e4),
 'size_null_bridge':(0xfffffe000bcfe79c,0xfffffe000bcfe7a4),
 'size_return_value':(0xfffffe000bcfe770,0xfffffe000bcfe778),
 'size_return_frame':(0xfffffe000bcfe778,0xfffffe000bcfe784),
 'typed_free_adapter':(0xfffffe000c4ba368,0xfffffe000c4ba370),
 'typed_free_gate':(0xfffffe000bcff010,0xfffffe000bcff01c),
 'typed_free_zone_tail':(0xfffffe000bcff01c,0xfffffe000bcff020),
 'typed_free_heap_tail':(0xfffffe000bcff020,0xfffffe000bcff054),
 'data_free_enter':(0xfffffe000c4ba850,0xfffffe000c4ba860),
 'data_free_request':(0xfffffe000c4ba860,0xfffffe000c4ba878),
 'data_free_null_return':(0xfffffe000c4ba8c8,0xfffffe000c4ba8d0),
 'size_free_enter':(0xfffffe000bcfec4c,0xfffffe000bcfec64),
 'size_free_limit':(0xfffffe000bcfec64,0xfffffe000bcfec78),
 'size_free_small_gate':(0xfffffe000bcfec78,0xfffffe000bcfec80),
 'size_free_query':(0xfffffe000bcfec80,0xfffffe000bcfeca0),
 'size_free_null_return':(0xfffffe000bcfed58,0xfffffe000bcfed68)}
RETURNS={name:z for name,(a,z) in SPANS.items() if name in ['typed_zone_return','typed_heap_return',
 'data_allocate_null_return','size_return_frame','data_free_null_return','size_free_null_return']}
DEPS=['kernel_native_reader.py','lskd_values_symbolic.py','userclient_query_failure_checks.json',
 'userclient_query_failure_audit.json','userclient_query_records_checks.json','userclient_query_records_audit.json']
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_allocator_outcome_established',
 'full_allocator_semantics_established','native_allocation_identity_established','native_ownership_established',
 'native_locking_established','whole_command_reachability_established','daemon_kext_transaction_correlated',
 'new_Mach_port_endpoint_established','full_goal_complete']

def build():
 k=Kernel();functions=[k.function(a) for a in FUNCTIONS];spans=[]
 for name,(a,z) in SPANS.items():
  f=next(f for f in functions if int(f['start'],16)<=a<z<=int(f['end'],16));b=k.read(a,z-a)
  ii=list(k.cs.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'container_start':f['start'],'container_sha256':f['sha256'],
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 returns=[]
 for name,a in RETURNS.items():
  b=k.read(a,4);i=next(k.cs.disasm(b,a));assert i.mnemonic=='retab'
  returns.append({'label':name,'ea':hex(a),'bytes_hex':b.hex(),'mnemonic':i.mnemonic})
 symbols=k.symbols(FUNCTIONS+[0xfffffe000bd75c64,0xfffffe000bd792dc,0xfffffe000bd7a4b8])
 for a,n in [(0xfffffe000c4ba154,'_IOMallocTypeImpl'),(0xfffffe000c4ba368,'_IOFreeTypeImpl'),
  (0xfffffe000c4ba60c,'_IOMallocData'),(0xfffffe000c4ba84c,'_IOFreeData')]:assert any(r['name']==n for r in symbols[hex(a)])
 prior=json.loads(read(ROOT/'userclient_query_failure_checks.json'))
 assert prior['kernel_collection_sha256']==k.sha256
 for f in prior['kernel_function_containers']:
  new=next(n for n in functions if n['start']==f['start']);assert f==new
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'dependencies':{n:sha(ROOT/n) for n in DEPS},'functions':functions,'exact_symbols':symbols,
  'spans':spans,'authenticated_return_envelopes':returns,
  'verified_counts':{'kernel_functions':len(functions),'captured_function_instructions':sum(len(f['instructions']) for f in functions),
   'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'authenticated_return_envelopes':len(returns),'small_query_data_bytes':14,'typed_query_node_bytes':32},
  'conditional_kernel_allocator_boundary_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
