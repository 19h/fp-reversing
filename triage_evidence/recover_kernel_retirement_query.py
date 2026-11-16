#!/usr/bin/env python3
"""Pin complete retirement metadata query and selected caller continuation.
O(B+I+S) extraction time/space; no target execution or database mutation.
"""
import json
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_allocator_boundary as Parent

P='kernel_retirement_query'
SCOPE='Complete original 68-word metadata-query source, conditional range rejection, zone/extent outputs, all offset-layout blocks and destructive offset reads; selected 14/32-byte retirement caller extent gate and regular recovered-base request. Runtime metadata validity/coherence, allocator identity/ownership, subsequent deallocation/PAC/locking and daemon transaction correlation remain unknown.'
SPANS={
 'query_entry':(0xfffffe000bd792dc,0xfffffe000bd792e8),
 'query_range':(0xfffffe000bd792e8,0xfffffe000bd79308),
 'query_reject':(0xfffffe000bd79308,0xfffffe000bd79310),
 'query_reject_write':(0xfffffe000bd79310,0xfffffe000bd79314),
 'query_plain_return':(0xfffffe000bd79314,0xfffffe000bd79318),
 'query_metadata':(0xfffffe000bd79318,0xfffffe000bd7934c),
 'query_offset_enabled':(0xfffffe000bd7934c,0xfffffe000bd79350),
 'query_crossing':(0xfffffe000bd79350,0xfffffe000bd79360),
 'query_special':(0xfffffe000bd79360,0xfffffe000bd79370),
 'query_special_read':(0xfffffe000bd79370,0xfffffe000bd79378),
 'query_special_clear':(0xfffffe000bd79378,0xfffffe000bd7937c),
 'query_offset_return':(0xfffffe000bd7937c,0xfffffe000bd79384),
 'query_zero_gate':(0xfffffe000bd79384,0xfffffe000bd79388),
 'query_zero_value':(0xfffffe000bd79388,0xfffffe000bd79390),
 'query_large':(0xfffffe000bd79390,0xfffffe000bd79398),
 'query_large_mode':(0xfffffe000bd79398,0xfffffe000bd793a4),
 'query_large_byte':(0xfffffe000bd793a4,0xfffffe000bd793ac),
 'query_large_half':(0xfffffe000bd793ac,0xfffffe000bd793b0),
 'query_large_address':(0xfffffe000bd793b0,0xfffffe000bd793c8),
 'query_large_zero':(0xfffffe000bd793c8,0xfffffe000bd793cc),
 'query_offset_store':(0xfffffe000bd793cc,0xfffffe000bd793d0),
 'query_zone_gate':(0xfffffe000bd793d0,0xfffffe000bd793d4),
 'query_zone_store_return':(0xfffffe000bd793d4,0xfffffe000bd793dc),
 'query_large_read':(0xfffffe000bd793dc,0xfffffe000bd793e4),
 'query_large_clear':(0xfffffe000bd793e4,0xfffffe000bd793ec),
 'caller_query_return':(0xfffffe000bcfeca0,0xfffffe000bcfecb0),
 'caller_extent':(0xfffffe000bcfecb0,0xfffffe000bcfecbc),
 'caller_adjust_request':(0xfffffe000bcfecbc,0xfffffe000bcfece0)}
DEPS=['kernel_native_reader.py','lskd_values_symbolic.py','recover_kernel_allocator_boundary.py',
 'audit_kernel_allocator_boundary.py','kernel_allocator_boundary_checks.json','kernel_allocator_boundary_audit.json',
 'mixed_data_retirement_source.json','mixed_data_retirement_checks.json']
FALSE=['native_target_executed','IDB_modified','native_metadata_epoch_established','native_allocation_identity_established',
 'native_ownership_established','native_deallocation_established','native_PAC_authenticated','native_locking_established',
 'whole_command_reachability_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']

def build():
 k=Kernel();query=k.function(0xfffffe000bd792dc);caller=k.function(0xfffffe000bcfec48);lower=k.function(0xfffffe000bcfed8c)
 old=json.loads(read(ROOT/'mixed_data_retirement_source.json'))
 assert [query,caller,lower]==[old['functions'][n] for n in ['lookup','retire','retire_small']]
 parent=json.loads(read(ROOT/'kernel_allocator_boundary_checks.json'))
 assert caller==next(f for f in parent['functions'] if f['start']==caller['start'])
 spans=[]
 for name,(a,z) in SPANS.items():
  b=k.read(a,z-a);ii=list(k.cs.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 assert sum(len(s['instructions']) for s in spans if s['label'].startswith('query_'))==68
 reused=[s for s in parent['spans'] if s['label'] in ['size_free_enter','size_free_limit','size_free_small_gate','size_free_query']]
 assert len(reused)==4
 dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True;writes=set();stores=[]
 for i in dec.disasm(bytes.fromhex(query['bytes']),int(query['start'],16)):
  writes.update(i.reg_name(r) for r in i.regs_access()[1])
  if i.mnemonic.startswith('st'):stores.append({'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
 assert not writes&{'sp','fp','lr',*[f'x{j}' for j in range(19,31)],*[f'w{j}' for j in range(19,31)]}
 assert len(stores)==5
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'dependencies':{n:sha(ROOT/n) for n in DEPS},'query':query,'caller':caller,'lower':lower,
  'spans':spans,'reused_caller_spans':reused,
  'complete_query_effect_inventory':{'written_registers':sorted(writes),'stores':stores,
   'no_SP_or_callee_saved_GPR_write':True},
  'runtime_globals':{'range':{'address':'0xfffffe0007e66e50','original_bytes_hex':k.read(0xfffffe0007e66e50,16).hex()},
   'metadata_root':{'address':'0xfffffe0007e66f00','original_bytes_hex':k.read(0xfffffe0007e66f00,8).hex()}},
  'exact_symbols':k.symbols([0xfffffe000bd792dc,0xfffffe000bcfec48,0xfffffe000bcfed8c]),
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'complete_query_instructions':68,'reused_caller_spans':4,'reused_caller_instructions':sum(len(s['instructions']) for s in reused),
   'original_function_matches':4,'captured_function_instructions':sum(len(f['instructions']) for f in [query,caller,lower])},
  'conditional_kernel_retirement_query_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
