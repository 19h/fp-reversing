#!/usr/bin/env python3
"""Original per-CPU magazine drain and source consumer interfaces.
O(collection bytes + instructions + symbols) time/space. Read-only bytes;
direct aligned branch inventory does not establish indirect reachability.
"""
import json,struct
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
P='kernel_magazine_depot_drain';DRAIN=0xfffffe000bd7497c;END=0xfffffe000bd74bec
COUNT=0xfffffe0007e66f38;PREFILL=0xfffffe000bd730f8;ARM=0xfffffe000bd7332c
ACQUIRE=0xfffffe000bd0aab4;UNLOCK=0xfffffe000bd0ab18;REFILL=0xfffffe000bd75e20
FUNCTIONS=[DRAIN,PREFILL,ARM,ACQUIRE,UNLOCK,REFILL,0xfffffe000bd78004,0xfffffe000bd74bec]
SPANS={'bound_sum':(0xfffffe000bd749f4,0xfffffe000bd74a00),
 'retention':(0xfffffe000bd74a18,0xfffffe000bd74a24),
 'full_gate':(0xfffffe000bd74a9c,0xfffffe000bd74aa8),
 'empty_gate':(0xfffffe000bd74b18,0xfffffe000bd74b24),
 'full_add':(0xfffffe000bd74afc,0xfffffe000bd74b08),
 'empty_add':(0xfffffe000bd74b5c,0xfffffe000bd74b68),
 'full_boundary_gate':(0xfffffe000bd74adc,0xfffffe000bd74ae0),
 'full_boundary_reset':(0xfffffe000bd74ae0,0xfffffe000bd74ae4),
 'end_compare':(0xfffffe000bd74a64,0xfffffe000bd74a6c),
 'advance':(0xfffffe000bd74bb0,0xfffffe000bd74bb8),
 'maintenance_flag_gate':(0xfffffe000bd78328,0xfffffe000bd78330),
 'maintenance_flag_clear':(0xfffffe000bd78330,0xfffffe000bd78338),
 'maintenance_request':(0xfffffe000bd78338,0xfffffe000bd78348),
 'bulk_zero_gate':(0xfffffe000bd74c10,0xfffffe000bd74c14),
 'bulk_slot_clear':(0xfffffe000bd74c5c,0xfffffe000bd74c64),
 'bulk_available_add':(0xfffffe000bd74f78,0xfffffe000bd74f84)}
SCOPE='Original per-CPU full/empty magazine drain, retention arithmetic, partition ordering, raw pointer/count admission and continuous drain-to-prefill-to-arm source join. Existing uncontended acquire/unlock bodies execute on private thread/cache state. Authentication, native exclusion, cache initialization/lifetimes, scheduler admission, reclamation and daemon transaction identity remain unknown.'
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_synchronization_established',
 'native_cache_production_established','native_blocking_established','all_indirect_callers_established',
 'physical_page_reclamation_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']

def build():
 k=Kernel();functions=[k.function(a) for a in FUNCTIONS];prior=json.loads(read(ROOT/'kernel_zone_prefill_callers_checks.json'))
 for f in functions[1:4]:assert any(old==f for old in prior['functions'])
 old=json.loads(read(ROOT/'kernel_zone_observer_event_checks.json'));assert functions[4]==old['functions'][4]
 old=json.loads(read(ROOT/'kernel_zone_refill_source.json'));f=functions[5]
 assert any(all(old.get(key)==f[key] for key in ['start','end','bytes','sha256','instructions']) for old in old['functions'])
 spans=[]
 for name,(a,b) in SPANS.items():
  raw=k.read(a,b-a);ii=list(k.cs.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 calls=[];words=0
 for sec in prior['direct_branch_scan']['sections']:
  start=int(sec['address'],16);raw=k.read(start,sec['bytes_scanned']);assert sha256(raw).hexdigest()==sec['sha256'];words+=len(raw)//4
  for j,(w,) in enumerate(struct.iter_unpack('<I',raw)):
   if w&0x7c000000!=0x14000000:continue
   pc=start+j*4;d=w&0x3ffffff;d-=((d>>25)&1)<<26
   if (pc+4*d)&((1<<64)-1)!=DRAIN:continue
   i=next(k.cs.disasm(raw[j*4:j*4+4],pc));assert int(i.op_str[1:],16)==DRAIN
   calls.append({'entry':sec['entry'],'pc':hex(pc),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,
    'compiler_function':k.function(pc,exact=False)['start'] if sec['entry']=='com.apple.kernel' else None})
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_native_reader.py','kernel_vm_mig_tools.py','probe_kernel_zone_prefill_callers.py',
   'kernel_zone_prefill_callers_checks.json','kernel_zone_observer_event_checks.json','kernel_zone_refill_source.json','audit_kernel_zone_bitmap_release.py']},
  'functions':functions,'spans':spans,'reused_caller_spans':[],
  'exact_symbols':k.symbols([*FUNCTIONS,COUNT]),'cache_count_global':{'address':hex(COUNT),'file_bytes_hex':k.read(COUNT,4).hex()},
  'direct_branch_scan':{'section_inventory_artifact':'kernel_zone_prefill_callers_checks.json','section_inventory_sha256':sha(ROOT/'kernel_zone_prefill_callers_checks.json'),
   'sections_rehashed':len(prior['direct_branch_scan']['sections']),'aligned_words':words,'direct_branch_candidates':calls,
   'native_reachability_established':False,'indirect_reference_completeness_established':False},
  'verified_counts':{'captured_functions':len(functions),'captured_instructions':sum(len(f['instructions']) for f in functions),
   'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'new_drain_instructions':len(functions[0]['instructions']),
   'matched_prior_functions':5,'source_blocks':len(spans),'block_instructions':sum(len(s['instructions']) for s in spans),
   'sections_rehashed':len(prior['direct_branch_scan']['sections']),'scan_aligned_words':words,'direct_branch_candidates':len(calls)},
  'conditional_kernel_magazine_depot_drain_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
