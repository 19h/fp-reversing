#!/usr/bin/env python3
"""Capture complete zone-retirement tail and selected multiplier producer.
O(B+I+S) extraction time/space; no target execution or database mutation.
"""
import json
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha

P='kernel_zone_retirement'
BASE=0xfffffe000caeb480
SCOPE='Complete original 109-word zone-retirement tail plus seven-word zone multiplier producer: range/reclassification/displacement gates, per-thread and CPU accounting, authenticated-cache pointer boundary, current/spare magazine publication, helper-return custody, nesting/pending continuations and deeper release requests. Native ownership, authentication, concurrency, helper effects, reclamation/reuse and daemon transaction identity remain unknown.'
SPANS={
 'entry':(0xfffffe000bd74fcc,0xfffffe000bd75004),
 'classify':(0xfffffe000bd75004,0xfffffe000bd75034),
 'displacement':(0xfffffe000bd75034,0xfffffe000bd7504c),
 'extended_displacement':(0xfffffe000bd7504c,0xfffffe000bd75054),
 'alignment':(0xfffffe000bd75054,0xfffffe000bd75064),
 'accounting':(0xfffffe000bd75064,0xfffffe000bd7508c),
 'cache_raw':(0xfffffe000bd7508c,0xfffffe000bd75098),
 'cache_auth':(0xfffffe000bd75098,0xfffffe000bd750a4),
 'cache_gate':(0xfffffe000bd750a4,0xfffffe000bd750bc),
 'push':(0xfffffe000bd750bc,0xfffffe000bd750cc),
 'nest_gate':(0xfffffe000bd750cc,0xfffffe000bd750d4),
 'nest_drop':(0xfffffe000bd750d4,0xfffffe000bd750e0),
 'pending':(0xfffffe000bd750e0,0xfffffe000bd750ec),
 'return':(0xfffffe000bd750ec,0xfffffe000bd750f8),
 'spare_gate':(0xfffffe000bd750f8,0xfffffe000bd75104),
 'swap':(0xfffffe000bd75104,0xfffffe000bd75120),
 'nest_error':(0xfffffe000bd75120,0xfffffe000bd75124),
 'pending_tail':(0xfffffe000bd75124,0xfffffe000bd75134),
 'validation_error':(0xfffffe000bd75134,0xfffffe000bd75140),
 'helper_request':(0xfffffe000bd75140,0xfffffe000bd75150),
 'helper_return':(0xfffffe000bd75150,0xfffffe000bd7515c),
 'release_tail':(0xfffffe000bd7515c,0xfffffe000bd75174),
 'helper_cache':(0xfffffe000bd75174,0xfffffe000bd75180),
 'multiplier_producer':(0xfffffe000bd7759c,0xfffffe000bd775b8)}
DEPS=['kernel_native_reader.py','lskd_values_symbolic.py','audit_kernel_allocator_boundary.py',
 'audit_kernel_retirement_query.py','audit_kernel_retirement_dispatch.py','kernel_retirement_dispatch_checks.json',
 'kernel_retirement_dispatch_audit.json','mixed_data_retirement_source.json','mixed_data_retirement_checks.json',
 'mixed_data_zone_geometry_source.json']
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_thread_context_established',
 'native_metadata_epoch_established','native_allocation_identity_established','native_ownership_established',
 'native_locking_established','native_helper_effects_established','native_reclamation_established',
 'native_cache_reuse_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']

def build():
 k=Kernel();f=k.function(0xfffffe000bd74fcc);creator=k.function(0xfffffe000bd772b4)
 old=json.loads(read(ROOT/'mixed_data_retirement_source.json'));geometry=json.loads(read(ROOT/'mixed_data_zone_geometry_source.json'))
 assert f==old['functions']['zone_retire']
 assert creator==geometry['functions']['zone_create']
 spans=[]
 for name,(a,z) in SPANS.items():
  raw=k.read(a,z-a);ii=list(k.cs.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 assert b''.join(bytes.fromhex(s['bytes_hex']) for s in spans if s['label']!='multiplier_producer')==bytes.fromhex(f['bytes'])
 parent=json.loads(read(ROOT/'kernel_retirement_dispatch_checks.json'))
 reused=[s for s in parent['spans'] if s['label']=='handoff'];assert len(reused)==1
 symbols=k.symbols([0xfffffe000bd74fcc,0xfffffe000bd75180,0xfffffe000bd756f8,0xfffffe000be8663c,
  0xfffffe000c633aa0,0xfffffe000c63aec8,0xfffffe000bd772b4])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'dependencies':{n:sha(ROOT/n) for n in DEPS},'function':f,'creator':creator,'spans':spans,
  'reused_caller_spans':reused,'exact_symbols':symbols,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':116,'complete_tail_instructions':109,
   'multiplier_producer_instructions':7,'reused_caller_spans':1,'reused_caller_instructions':9,'original_function_matches':2},
  'conditional_kernel_zone_retirement_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
