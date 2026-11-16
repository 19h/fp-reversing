#!/usr/bin/env python3
"""Capture original deeper zone-release and lock/nesting tail bytes.
O(image bytes + instructions + symbols) time/space; no target or IDB effects.
"""
import json
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
P='kernel_zone_bitmap_release';ENTRY=0xfffffe000bd756f8;END=0xfffffe000bd75b54
UNLOCK=0xfffffe000bd0ab18;UNLOCK_END=0xfffffe000bd0ab80
SCOPE='Complete original deeper-release and unlock/nesting-tail capture; exact bitmap/count arithmetic obligations and independent private CPU queue/state components. Native exclusion, authenticated pointers, external callee RAM effects, physical page reclamation/reuse and a matched daemon transaction remain unknown.'
SPANS={
 'extended_lead':(0xfffffe000bd7579c,0xfffffe000bd757b8),
 'extended_tag':(0xfffffe000bd757b8,0xfffffe000bd757bc),
 'extended_join':(0xfffffe000bd757bc,0xfffffe000bd757c0),
 'quotient':(0xfffffe000bd757c0,0xfffffe000bd757d8),
 'layout':(0xfffffe000bd757d8,0xfffffe000bd757e0),
 'external_gate':(0xfffffe000bd757e0,0xfffffe000bd7580c),
 'external_set':(0xfffffe000bd7580c,0xfffffe000bd75818),
 'inline_gate':(0xfffffe000bd75818,0xfffffe000bd75834),
 'inline_set':(0xfffffe000bd75834,0xfffffe000bd7583c),
 'count':(0xfffffe000bd7583c,0xfffffe000bd75850),
 'count_zero':(0xfffffe000bd75850,0xfffffe000bd75858),
 'threshold':(0xfffffe000bd75858,0xfffffe000bd75874),
 'unlock_byte':(0xfffffe000bd0ab24,0xfffffe000bd0ab30),
 'nest_gate':(0xfffffe000bd0ab3c,0xfffffe000bd0ab48),
 'nest_decrement':(0xfffffe000bd0ab48,0xfffffe000bd0ab54),
 'pending_gate':(0xfffffe000bd0ab54,0xfffffe000bd0ab60)}
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_synchronization_established',
 'native_external_callee_effects_established','physical_page_reclamation_established','native_allocation_identity_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']
DEPS=['kernel_native_reader.py','kernel_vm_mig_tools.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py',
 'audit_kernel_retirement_magazines.py','kernel_retirement_magazines_checks.json','kernel_retirement_magazines_audit.json',
 'kernel_zone_retirement_checks.json','kernel_zone_startup_profiles.json']

def build():
 k=Kernel();functions=[k.function(ENTRY),k.function(UNLOCK)];caller=k.function(0xfffffe000bd74fcc)
 assert caller==json.loads(read(ROOT/'kernel_zone_retirement_checks.json'))['function']
 assert k.function(0xfffffe000bd75180)==json.loads(read(ROOT/'kernel_retirement_magazines_checks.json'))['function']
 spans=[]
 for name,(a,z) in SPANS.items():
  b=k.read(a,z-a);ii=list(k.cs.disasm(b,a));assert sum(i.size for i in ii)==len(b)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 calls=[i for f in functions for i in f['instructions'] if i['mnemonic']=='bl']
 tails=[i for f in functions for i in f['instructions'] if i['mnemonic']=='b' and not any(int(g['start'],16)<=int(i['operands'][1:],16)<int(g['end'],16) for g in functions)]
 targets=sorted({int(i['operands'][1:],16) for i in calls+tails})
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'dependencies':{n:sha(ROOT/n) for n in DEPS},'functions':functions,'caller':caller,
  'spans':spans,'reused_caller_spans':[],'calls':calls,'external_tails':tails,'exact_symbols':k.symbols([ENTRY,UNLOCK,*targets]),
  'verified_counts':{'complete_release_instructions':len(functions[0]['instructions']),
   'complete_release_bytes':len(bytes.fromhex(functions[0]['bytes'])),
   'complete_unlock_instructions':len(functions[1]['instructions']),
   'complete_unlock_bytes':len(bytes.fromhex(functions[1]['bytes'])),
   'source_blocks':len(spans),'block_instructions':sum(len(s['instructions']) for s in spans),
   'call_sites':len(calls),'external_tail_sites':len(tails),'distinct_external_targets':len(targets),'original_function_matches':2},
  'conditional_kernel_zone_bitmap_release_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
