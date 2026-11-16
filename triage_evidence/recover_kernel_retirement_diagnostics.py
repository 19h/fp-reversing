#!/usr/bin/env python3
"""Capture complete retirement diagnostic callees and original literal/fixup ABI.
O(B+I+S+selected chain work) time/space; no target execution or IDB mutation.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_retirement_dispatch as Parent

P='kernel_retirement_diagnostics'
SCOPE='Complete original class/zone diagnostic callees, original _panic target, literal formats and variadic stack operands, query-derived flag/name indexing, coherent flag-reload branch partition, typed diagnostic global stores, and selected dispatch-to-diagnostic joins. Native panic/termination, concurrent flag epochs, initialized class/name values, allocator ownership and daemon transaction identity remain unknown.'
BASE=Parent.BASE
FLAGS=Parent.FLAGS
NAMES=0xfffffe0007e66f08
PANIC=0xfffffe000c62a2b0
DIAG_FLAG=0xfffffe000cadd714
DIAG_ZONE=0xfffffe000cadd718
SPANS={
 'class_entry':(0xfffffe000c62d430,0xfffffe000c62d458),
 'class_bad_zone':(0xfffffe000c62d458,0xfffffe000c62d460),
 'class_index':(0xfffffe000c62d460,0xfffffe000c62d490),
 'class_regular_gate':(0xfffffe000c62d490,0xfffffe000c62d4a4),
 'class_named_gate':(0xfffffe000c62d4a4,0xfffffe000c62d4ac),
 'class_regular':(0xfffffe000c62d4ac,0xfffffe000c62d4d4),
 'class_typed':(0xfffffe000c62d4d4,0xfffffe000c62d510),
 'class_invalid_name':(0xfffffe000c62d510,0xfffffe000c62d51c),
 'class_heap':(0xfffffe000c62d51c,0xfffffe000c62d540),
 'zone_diagnostic':(0xfffffe000c6336f8,0xfffffe000c633728)}
LITERALS={
 'source_kalloc':(0xfffffe000704c2bc,'kalloc.c'),
 'regular':(0xfffffe000704c70f,"kfree: addr %p, size %zd found in regular zone '%s%s' @%s:%d"),
 'typed':(0xfffffe000704c6c0,"kfree: addr %p found in kalloc type zone '%s'but being freed to %s heap @%s:%d"),
 'heap':(0xfffffe000704c74c,'kfree: addr %p, size %zd found in heap %s* instead of %s* @%s:%d'),
 'invalid_name':(0xfffffe0007053178,'invalid'),
 'source_zalloc':(0xfffffe000705316f,'zalloc.c'),
 'zone':(0xfffffe0007053148,"zone %p isn't in the zone_array @%s:%d")}
DEPS=['kernel_native_reader.py','recover_kext_cold_init.py','resolve_kernel_collection_interfaces.py',
 'lskd_values_symbolic.py','audit_kernel_allocator_boundary.py','audit_kernel_retirement_query.py',
 'audit_kernel_retirement_dispatch.py','kernel_retirement_dispatch_checks.json','kernel_retirement_dispatch_audit.json']
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_panic_executed',
 'native_termination_established','native_metadata_epoch_established','concurrent_flag_epoch_established',
 'native_class_name_values_established','native_allocation_identity_established','native_ownership_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']

def build():
 k=Kernel();functions=[k.function(a) for a in [0xfffffe000c62d430,0xfffffe000c6336f8]];spans=[]
 for name,(a,z) in SPANS.items():
  raw=k.read(a,z-a);ii=list(k.cs.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 for f in functions:
  assert b''.join(bytes.fromhex(s['bytes_hex']) for s in spans if int(f['start'],16)<=int(s['start'],16)<int(f['end'],16))==bytes.fromhex(f['bytes'])
 parent=json.loads(read(ROOT/'kernel_retirement_dispatch_checks.json'))
 reused=[s for s in parent['spans'] if s['label'] in ['mismatch','geometry_error']];assert len(reused)==2
 for s in reused:assert k.read(int(s['start'],16),len(bytes.fromhex(s['bytes_hex']))).hex()==s['bytes_hex']
 strings={}
 for name,(a,text) in LITERALS.items():
  raw=k.read(a,len(text)+1);assert raw==text.encode()+b'\0'
  strings[name]={'address':hex(a),'text':text,'bytes_hex':raw.hex(),'sha256':sha256(raw).hexdigest()}
 table=[]
 for j,expected in enumerate(['','early.','data.','data_shared.','']):
  p=pointer(k,NAMES+8*j);a=int(p['target'],16);raw=k.read(a,len(expected)+1);assert raw==expected.encode()+b'\0'
  table.append({'index':j,'fixup':p,'literal_address':hex(a),'literal_bytes_hex':raw.hex(),'text':expected,'runtime_value_established':False})
 symbols=k.symbols([PANIC,*[int(f['start'],16) for f in functions],DIAG_FLAG,DIAG_ZONE,NAMES])
 assert any(r['name']=='_panic' for r in symbols[hex(PANIC)])
 assert all(not i['mnemonic'].startswith('ret') for f in functions for i in f['instructions'])
 calls=[i for f in functions for i in f['instructions'] if i['mnemonic']=='bl'];assert len(calls)==5
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'dependencies':{n:sha(ROOT/n) for n in DEPS},'functions':functions,'spans':spans,
  'reused_caller_spans':reused,'exact_symbols':symbols,'literals':strings,'original_name_table':table,
  'diagnostic_global_file_bytes_hex':k.read(DIAG_FLAG,1).hex()+k.read(DIAG_ZONE,8).hex(),
  'complete_effect_inventory':{'direct_calls':calls,'return_instructions':0,'native_nonreturn_established':False},
  'verified_counts':{'kernel_functions':2,'source_spans':10,'selected_instructions':80,'captured_function_bytes':320,
   'reused_caller_spans':2,'reused_caller_instructions':5,'literal_records':7,'name_table_fixups':5,'direct_call_sites':5},
  'conditional_kernel_retirement_diagnostics_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
