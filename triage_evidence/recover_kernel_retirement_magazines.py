#!/usr/bin/env python3
"""Capture the complete retirement magazine helper and source interface blocks.
O(input bytes+instructions+symbol records) time/space; no target/IDB effects.
"""
import json
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
P='kernel_retirement_magazines';HELPER=0xfffffe000bd75180;END=0xfffffe000bd756f8
SCOPE='Complete 350-word both-full retirement magazine helper: source CFG return/reset provenance, quota/depot arithmetic, source lock-word operations, local/shared magazine exchange and linked caller publication under declared storage/call/authentication epochs. Native synchronization, ownership, allocator/drain effects, reclamation and daemon transaction identity remain unknown.'
SPANS={
 'quota':(0xfffffe000bd751a4,0xfffffe000bd751ac),
 'ticket':(0xfffffe000bd751c4,0xfffffe000bd751dc),
 'retain':(0xfffffe000bd751f4,0xfffffe000bd75204),
 'marker':(0xfffffe000bd75294,0xfffffe000bd752a8),
 'empty_bound':(0xfffffe000bd75314,0xfffffe000bd7532c),
 'shared_unlock':(0xfffffe000bd75398,0xfffffe000bd753a4),
 'local_pop':(0xfffffe000bd753b8,0xfffffe000bd753d4),
 'local_install':(0xfffffe000bd753d4,0xfffffe000bd753e8),
 'local_queue_prefix':(0xfffffe000bd753e8,0xfffffe000bd753fc),
 'local_queue_links':(0xfffffe000bd753fc,0xfffffe000bd75410),
 'cache_unlock':(0xfffffe000bd75410,0xfffffe000bd7541c),
 'shared_install':(0xfffffe000bd754bc,0xfffffe000bd754d4),
 'marker_cas':(0xfffffe000bd754d8,0xfffffe000bd754e8),
 'return':(0xfffffe000bd75580,0xfffffe000bd7559c),
 'caller_push':(0xfffffe000bd750bc,0xfffffe000bd750cc),
 'allocation_pop':(0xfffffe000bd75ccc,0xfffffe000bd75ce8)}
DEPS=['kernel_native_reader.py','kernel_vm_mig_tools.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py',
 'audit_kernel_zone_retirement.py','kernel_zone_retirement_checks.json','kernel_zone_retirement_audit.json',
 'kernel_zone_startup_source.json','kernel_zone_startup_profiles.json','kernel_zone_refill_source.json',
 'kernel_retirement_diagnostics_checks.json']
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_synchronization_established',
 'native_magazine_ownership_established','native_allocator_effects_established','native_drain_effects_established',
 'native_reclamation_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']

def build():
 k=Kernel();f=k.function(HELPER);tail=k.function(0xfffffe000bd74fcc);alloc=k.function(0xfffffe000bd75c64)
 previous=json.loads(read(ROOT/'kernel_zone_retirement_checks.json'));assert tail==previous['function']
 refill=json.loads(read(ROOT/'kernel_zone_refill_source.json'))
 assert alloc=={n:v for n,v in next(x for x in refill['functions'] if int(x['start'],16)==0xfffffe000bd75c64).items() if n!='exact_symbols'}
 spans=[]
 for label,(a,z) in SPANS.items():
  raw=k.read(a,z-a);ii=list(k.cs.disasm(raw,a));assert sum(i.size for i in ii)==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 calls=[i for i in f['instructions'] if i['mnemonic']=='bl'];targets=sorted({int(i['operands'][1:],16) for i in calls})
 addresses=[(0xfffffe0007e6a248,2),(0xfffffe000cb0bc50,4),(0xfffffe000cb115b0,4),
  (0xfffffe000ca92380,1),(0xfffffe0007e66f58,8),(0xfffffe0007e63658,16)]
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'dependencies':{n:sha(ROOT/n) for n in DEPS},'function':f,'caller':tail,'allocation':alloc,
  'spans':spans,'reused_caller_spans':[],'calls':calls,'exact_symbols':k.symbols([HELPER,*targets]),
  'original_globals':[{'address':hex(a),'bytes_hex':k.read(a,n).hex()} for a,n in addresses],
  'verified_counts':{'complete_helper_instructions':len(f['instructions']),'complete_helper_bytes':len(bytes.fromhex(f['bytes'])),
   'source_blocks':len(spans),'block_instructions':sum(len(s['instructions']) for s in spans),
   'call_sites':len(calls),'call_targets':len(targets),'original_function_matches':2},
  'conditional_kernel_retirement_magazines_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
