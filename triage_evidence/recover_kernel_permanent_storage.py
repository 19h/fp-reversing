#!/usr/bin/env python3
"""Original ready-page permanent storage and fixed setup-record custody.
O(collection + scanned words + source + fixups) time/space; direct BL/B
inventory is encoding-bounded. No native initialization or allocation.
"""
import json,struct
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_magazine_bootstrap as M
P='kernel_permanent_storage';ALLOC=0xfffffe000bd71a20;REFILL=0xfffffe000bd71c10
SETUP1=0xfffffe000bd77ce4;SETUP2=0xfffffe000bd77b94
RECORDS=[0xfffffe0007e66fc0,0xfffffe0007e67000]
ZONE=M.ARRAY+2*192;METABASE=0xfffffe0007e66f00;HEADBASE=0xfffffe000ca8c000
FUNCTIONS=[ALLOC,SETUP1,SETUP2,M.CREATE,M.CACHEINIT,M.BOOT]
SPANS={'round_request':(0xfffffe000bd71a38,0xfffffe000bd71a4c),
 'scan_page':(0xfffffe000bd71a68,0xfffffe000bd71a94),'debit_page':(0xfffffe000bd71a94,0xfffffe000bd71adc),
 'full_gate':(0xfffffe000bd71adc,0xfffffe000bd71aec),'return_pointer':(0xfffffe000bd71be0,0xfffffe000bd71bf4),
 'setup1':(SETUP1,SETUP1+28),'setup2':(SETUP2,SETUP2+28),
 'creator_statistics_request':(0xfffffe000bd7745c,0xfffffe000bd77470),
 'cache_storage_request':(0xfffffe000bd77bfc,0xfffffe000bd77c10),
 'fixed1_request':(0xfffffe000c63259c,0xfffffe000c6325c4),
 'fixed2_request':(0xfffffe000c6325c4,0xfffffe000c6325ec),
 'cache_control_stores':(0xfffffe000bd77c78,0xfffffe000bd77c84)}
SCOPE='Original ready-page permanent allocator, fixed setup records/callbacks, and source creator/cache-initializer consumers. Independent private ready-page, queue and new-call publication/cache components qualify former opaque 32/64-byte storage returns. Refill, native backing/zero initialization, ownership, boot completion, authentication/exclusion and daemon transaction identity remain unknown.'
FALSE=M.FALSE+['native_backing_zero_initialization_established','permanent_refill_executed','complete_magazine_bootstrap_executed']

def build():
 im=Image();k=im.k;k.cs.detail=True;functions=[k.function(a) for a in FUNCTIONS]
 prior=json.loads(read(ROOT/'kernel_magazine_bootstrap_checks.json'))
 for f in functions[3:]:assert f==next(x for x in prior['functions'] if x['start']==f['start'])
 spans=[]
 for label,(a,b) in SPANS.items():
  raw=k.read(a,b-a);ii=list(k.cs.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 records=[]
 for a,target in zip(RECORDS,[SETUP1,SETUP2]):
  raw=k.read(a,32);logical=bytes(im.logical_page(a&~4095))[(a&4095):(a&4095)+32]
  pointers=[im.pointer(a+j) for j in [0,16,24]]
  assert pointers[1]['target']==hex(target)
  records.append({'address':hex(a),'raw_bytes_hex':raw.hex(),'logical_bytes_hex':logical.hex(),'pointers':pointers})
 sections=json.loads(read(ROOT/'kernel_zone_prefill_callers_checks.json'))['direct_branch_scan']['sections'];calls=[];words=0
 for sec in sections:
  a=int(sec['address'],16);raw=k.read(a,sec['bytes_scanned']);assert sha256(raw).hexdigest()==sec['sha256'];words+=len(raw)//4
  for j,(w,) in enumerate(struct.iter_unpack('<I',raw)):
   if w&0x7c000000!=0x14000000:continue
   d=w&0x3ffffff;d-=((d>>25)&1)<<26;pc=a+4*j
   if (pc+4*d)&((1<<64)-1)==ALLOC:calls.append({'entry':sec['entry'],'pc':hex(pc),'mnemonic':'bl' if w>>31 else 'b','bytes_hex':raw[4*j:4*j+4].hex()})
 counts={'captured_functions':len(functions),'captured_instructions':sum(len(f['instructions']) for f in functions),
  'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'matched_prior_functions':3,
  'source_blocks':len(spans),'block_instructions':sum(len(s['instructions']) for s in spans),
  'setup_records':len(records),'setup_pointer_fixups':sum(len(r['pointers']) for r in records),
  'sections_rehashed':len(sections),'aligned_words_scanned':words,'direct_branch_sites':len(calls)}
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_native_reader.py','kernel_vm_mig_tools.py','kernel_magazine_bootstrap_checks.json',
   'kernel_zone_prefill_callers_checks.json','audit_kernel_zone_boot_inputs.py','replay_kernel_magazine_bootstrap.py']},
  'functions':functions,'spans':spans,'setup_records':records,'direct_branch_scan':{'sections':sections,'sites':calls,'scope':'All aligned immediate B/BL encodings in the pinned rehashed spans; indirect and data references are outside this scan.'},
  'strings':[{'address':hex(a),'text':k.read(a,96).split(bytes(1))[0].decode('ascii')} for a in [0xfffffe000705352d,0xfffffe000705353a,0xfffffe000705354e]],
  'exact_symbols':k.symbols([*FUNCTIONS,ZONE,METABASE,HEADBASE,*RECORDS]),'verified_counts':counts,
  'conditional_kernel_permanent_storage_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
