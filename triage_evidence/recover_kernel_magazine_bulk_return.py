#!/usr/bin/env python3
"""Pinned bulk-return, prefill, followup and slot-production bodies.
O(image bytes + instructions + symbols) time/space; no native/IDB effects.
"""
import json
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
P='kernel_magazine_bulk_return';BULK=0xfffffe000bd74bec;END=0xfffffe000bd74fcc
FOLLOW=0xfffffe000bd75b54;PREFILL=0xfffffe000bd730f8
FUNCTIONS=[BULK,FOLLOW,PREFILL,0xfffffe000bd75e20,0xfffffe000bd76db4,0xfffffe000bd76ad0]
SPANS={
 'slot':(0xfffffe000bd74c5c,0xfffffe000bd74c64),
 'range':(0xfffffe000bd74c64,0xfffffe000bd74c74),
 'owner':(0xfffffe000bd74c74,0xfffffe000bd74c9c),
 'extended':(0xfffffe000bd74cb8,0xfffffe000bd74cd4),
 'extended_tag':(0xfffffe000bd74cd4,0xfffffe000bd74cd8),
 'extended_join':(0xfffffe000bd74cd8,0xfffffe000bd74cdc),
 'quotient':(0xfffffe000bd74cdc,0xfffffe000bd74cf4),
 'layout':(0xfffffe000bd74cf4,0xfffffe000bd74cfc),
 'external_gate':(0xfffffe000bd74cfc,0xfffffe000bd74d20),
 'external_set':(0xfffffe000bd74d20,0xfffffe000bd74d2c),
 'inline_gate':(0xfffffe000bd74d2c,0xfffffe000bd74d44),
 'inline_set':(0xfffffe000bd74d44,0xfffffe000bd74d4c),
 'count':(0xfffffe000bd74d4c,0xfffffe000bd74d60),
 'zero':(0xfffffe000bd74d60,0xfffffe000bd74d68),
 'threshold':(0xfffffe000bd74d68,0xfffffe000bd74d84),
 'follow_gate':(0xfffffe000bd74ec8,0xfffffe000bd74ed0),
 'loop':(0xfffffe000bd74ed0,0xfffffe000bd74edc),
 'loop_exit':(0xfffffe000bd74edc,0xfffffe000bd74ee0),
 'follow_save':(0xfffffe000bd74f54,0xfffffe000bd74f64),
 'follow_restore':(0xfffffe000bd74f64,0xfffffe000bd74f78),
 'available':(0xfffffe000bd74f78,0xfffffe000bd74f84)}
SCOPE='Original bulk slot clear, object metadata/free-bit/count/list transitions, followup reload and completion accounting; coherent private arrays and original-fill-produced slot roundtrips, with explicit ownership handoff/new-call epochs. Native storage production, authentication/exclusion, reclamation, scheduler effects and daemon transaction identity remain unknown.'
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_synchronization_established',
 'native_allocation_identity_established','native_ownership_handoff_established','physical_page_reclamation_established',
 'native_wake_delivery_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']

def build():
 k=Kernel();functions=[k.function(a) for a in FUNCTIONS];drain=json.loads(read(ROOT/'kernel_magazine_depot_drain_checks.json'))
 for f in [functions[0],functions[2],functions[3]]:assert any(f==old for old in drain['functions'])
 event=json.loads(read(ROOT/'kernel_zone_observer_event_checks.json'));assert functions[1]==event['functions'][1]
 refill=json.loads(read(ROOT/'kernel_zone_refill_source.json'))
 for f in functions[4:]:assert any(all(old.get(key)==f[key] for key in f) for old in refill['functions'])
 spans=[]
 for label,(a,b) in SPANS.items():
  raw=k.read(a,b-a);ii=list(k.cs.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 calls=[i for i in functions[0]['instructions'] if i['mnemonic']=='bl']
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_magazine_depot_drain_checks.json','kernel_zone_observer_event_checks.json',
   'kernel_zone_refill_source.json','kernel_zone_startup_profiles.json','probe_kernel_zone_bitmap_release.py','probe_kernel_zone_refill.py',
   'audit_kernel_zone_bitmap_release.py','kernel_zone_bitmap_release_audit.json','replay_kernel_zone_refill.py',
   'probe_kernel_vm_mig.py']},'functions':functions,'spans':spans,'reused_caller_spans':[],
  'bulk_calls':calls,'exact_symbols':k.symbols(FUNCTIONS),
  'verified_counts':{'captured_functions':len(functions),'captured_instructions':sum(len(f['instructions']) for f in functions),
   'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'bulk_instructions':len(functions[0]['instructions']),
   'matched_prior_functions':6,'source_blocks':len(spans),'block_instructions':sum(len(s['instructions']) for s in spans),'bulk_call_sites':len(calls)},
  'conditional_kernel_magazine_bulk_return_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
