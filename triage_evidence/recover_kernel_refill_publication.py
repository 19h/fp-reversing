#!/usr/bin/env python3
"""Original refill page-list consumption, lower mapping ABI and metadata publication.
O(collection + captured bytes + fixups) construction/space; no native mappings.
"""
import json
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_physical_zero as Z
import recover_kernel_permanent_storage as PS
import recover_kernel_magazine_bootstrap as M
P='kernel_refill_publication';CONSUME=0xfffffe000bdc12cc;MAP=0xfffffe000bdc15a8
INSERT=0xfffffe000bd73b5c;ACCOUNT=0xfffffe000bd01454;PMAP=0xfffffe000be5b2e8
ENTRY=0xfffffe000bd72b40;END=0xfffffe000bd72ae0
FUNCTIONS=[PS.REFILL,Z.ZERO,Z.MEMSET,CONSUME,MAP,INSERT,PS.ALLOC,ACCOUNT,M.CREATE,M.CACHEINIT,M.BOOT]
SPANS={'refill_mapping_request':(0xfffffe000bd72a68,0xfffffe000bd72a90),
 'refill_insert_request':(0xfffffe000bd72ac4,0xfffffe000bd72ae0),
 'list_pop':(0xfffffe000bdc13cc,0xfffffe000bdc13d8),
 'map_PFN_in_interval':(0xfffffe000bdc1644,0xfffffe000bdc1658),
 'map_lower_request':(0xfffffe000bdc1658,0xfffffe000bdc1694),
 'permanent_no_bitmap':(0xfffffe000bd73d40,0xfffffe000bd73d48),
 'ready_gate':(0xfffffe000bd74410,0xfffffe000bd74420),
 'queue_head_code':(0xfffffe000bd74420,0xfffffe000bd74438),
 'queue_publish':(0xfffffe000bd7445c,0xfffffe000bd74470),
 'ready_accounting':(0xfffffe000bd744e0,0xfffffe000bd744f4),
 'ledger_direct':(0xfffffe000bd0147c,0xfffffe000bd01490),
 'creator_percpu_flag':(0xfffffe000bd775e4,0xfffffe000bd775f4),
 'creator_percpu_span':(0xfffffe000bd77568,0xfffffe000bd77578),
 'insert_logical_span':(0xfffffe000bd73c64,0xfffffe000bd73c8c),
 'insert_logical_bytes':(0xfffffe000bd73c8c,0xfffffe000bd73ca4),
 'insert_capacity':(0xfffffe000bd73d10,0xfffffe000bd73d14)}
SCOPE='One continuous original refill source cut allocates declared page objects, zeros declared aliases, consumes their list through original mapping adapters and publishes permanent metadata. Lower page acquisition/pmap/list/lock leaves are explicit models. Exact predecessor outputs feed original creator/cache components in declared new-call epochs. Native physical alias ownership, lower mapping effects, complete refill/boot, concurrency and daemon transaction identity remain unknown.'
FALSE=[n for n in Z.FALSE if n not in ['permanent_refill_executed','allocation_to_zero_identity_established']]+['original_refill_entry_executed','native_allocation_to_zero_identity_established','complete_refill_publication_native_executed','native_lower_mapping_effects_established']

def build():
 im=Image();k=im.k;k.cs.detail=True;functions=[k.function(a) for a in FUNCTIONS]
 prior=json.loads(read(ROOT/(Z.P+'_checks.json')));other=json.loads(read(ROOT/(PS.P+'_checks.json')));matched=0
 for f in functions:
  old=next((x for x in prior['functions']+other['functions'] if x['start']==f['start']),None)
  if old is not None:assert f==old;matched+=1
 spans=[]
 for label,(a,b) in SPANS.items():
  raw=k.read(a,b-a);ii=list(k.cs.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 counts={'captured_functions':len(functions),'captured_instructions':sum(len(f['instructions']) for f in functions),
  'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'matched_prior_functions':matched,
  'source_blocks':len(spans),'block_instructions':sum(len(s['instructions']) for s in spans)}
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_native_reader.py','kernel_vm_mig_tools.py',Z.P+'_checks.json',PS.P+'_checks.json',
   'audit_kernel_physical_zero.py','probe_kernel_physical_zero.py','probe_kernel_permanent_storage.py','replay_kernel_permanent_storage.py']},
  'functions':functions,'spans':spans,'exact_symbols':k.symbols([*FUNCTIONS,PMAP,0xfffffe000be2f16c,0xfffffe000be0d098,0xfffffe000be0f308]),
  'verified_counts':counts,'conditional_kernel_refill_publication_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
