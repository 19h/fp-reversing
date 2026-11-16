#!/usr/bin/env python3
"""Capture complete small-retirement dispatch and original boundary symbols.
O(B+I+S) time/space; no target execution or IDB mutation.
"""
import json
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha

P='kernel_retirement_dispatch'
SCOPE='Complete 73-word small-retirement dispatch: raw zone interval, query-derived zone-index gate and flag-table index, normal/tagged heap and accounting selection, strict/ordinary heap-class predicates, bzero request and conditional post-clear zone-tail ABI. Runtime metadata/heap coherence, allocation identity/ownership, native clear/retirement, PAC validity, synchronization and daemon transaction correlation remain unknown.'
BASE=0xfffffe000caeb480
FLAGS=0xfffffe0007e6a7a0
DATA=0xfffffe0007f8bfb0
TYPED=0xfffffe0007f36938
VARIABLE=0xfffffe0007e6a780
SPECIAL=0xfffffe0007f411b8
SPANS={
 'geometry':(0xfffffe000bcfed8c,0xfffffe000bcfedbc),
 'index':(0xfffffe000bcfedbc,0xfffffe000bcfedf0),
 'tagged':(0xfffffe000bcfedf0,0xfffffe000bcfee20),
 'heap_stats':(0xfffffe000bcfee20,0xfffffe000bcfee24),
 'class_data':(0xfffffe000bcfee24,0xfffffe000bcfee34),
 'class_second':(0xfffffe000bcfee34,0xfffffe000bcfee44),
 'class_ordinary':(0xfffffe000bcfee44,0xfffffe000bcfee50),
 'mismatch':(0xfffffe000bcfee50,0xfffffe000bcfee5c),
 'class_strict':(0xfffffe000bcfee5c,0xfffffe000bcfee64),
 'clear':(0xfffffe000bcfee64,0xfffffe000bcfee7c),
 'postclear':(0xfffffe000bcfee7c,0xfffffe000bcfee80),
 'zone_stats':(0xfffffe000bcfee80,0xfffffe000bcfee84),
 'handoff':(0xfffffe000bcfee84,0xfffffe000bcfeea8),
 'geometry_error':(0xfffffe000bcfeea8,0xfffffe000bcfeeb0)}
FALSE=['native_target_executed','IDB_modified','native_metadata_epoch_established','native_heap_class_values_established',
 'native_allocation_identity_established','native_ownership_established','native_clear_established','native_deallocation_established',
 'native_PAC_authenticated','native_locking_established','whole_command_reachability_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']
DEPS=['kernel_native_reader.py','lskd_values_symbolic.py','audit_kernel_allocator_boundary.py',
 'audit_kernel_retirement_query.py','kernel_retirement_query_checks.json','kernel_retirement_query_audit.json',
 'mixed_data_retirement_source.json','mixed_data_retirement_checks.json']

def build():
 k=Kernel();f=k.function(0xfffffe000bcfed8c)
 old=json.loads(read(ROOT/'mixed_data_retirement_source.json'));query=json.loads(read(ROOT/'kernel_retirement_query_checks.json'))
 assert f==old['functions']['retire_small']==query['lower']
 spans=[]
 for name,(a,z) in SPANS.items():
  b=k.read(a,z-a);ii=list(k.cs.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 assert b''.join(bytes.fromhex(s['bytes_hex']) for s in spans)==bytes.fromhex(f['bytes'])
 targets=[0xfffffe000c62d430,0xfffffe000c6480c0,0xfffffe000bd74fcc,0xfffffe000c6336f8]
 symbols=k.symbols([int(f['start'],16),*targets,BASE,FLAGS,DATA,TYPED,VARIABLE,SPECIAL])
 assert {s['name'] for s in symbols['0xfffffe000c6480c0']}=={'_bzero','___bzero'}
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'dependencies':{n:sha(ROOT/n) for n in DEPS},'function':f,'spans':spans,'exact_symbols':symbols,
  'original_data_snapshots':[{'address':hex(a),'bytes_hex':k.read(a,n).hex(),'runtime_value_established':False}
   for a,n in [(DATA,32),(TYPED,32),(VARIABLE,32),(SPECIAL,32),(FLAGS,4)]],
  'contexts':[{'request_bytes':14,'heap':hex(DATA),'class_policy':'strict'},
   {'request_bytes':32,'heap':hex(TYPED),'class_policy':'zone_class_one_or_equality'}],
  'verified_counts':{'source_spans':len(spans),'selected_instructions':73,'captured_function_bytes':292,
   'original_function_matches':2,'direct_transfer_sites':4,'named_clear_aliases':2},
  'conditional_kernel_retirement_dispatch_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
