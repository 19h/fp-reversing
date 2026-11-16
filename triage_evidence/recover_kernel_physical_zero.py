#!/usr/bin/env python3
"""Original refill-to-zero edge and physical-range zero wrapper custody.
O(collection + scanned words + captured bytes) time/space. Immediate branch
inventory is encoding-bounded; no native page or mapping is acquired.
"""
import json,struct
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_permanent_storage as PS
P='kernel_physical_zero'
ZERO=0xfffffe000be7b5b8;BZERO=0xfffffe000c6480c0;MEMSET=0xfffffe000c648170
META=0xfffffe000bd73598;ATTR=0xfffffe000be67808
DIRECT=0xfffffe000be76154;WINDOW=0xfffffe000be69d4c;UNMAP=0xfffffe000be6a0e0
DEFER=0xfffffe000be8663c;LOWER=0xfffffe0007ef81e0;UPPER=LOWER+8
WINDOW_BASE=0xfffffecfffd00000
FUNCTIONS=[PS.ALLOC,PS.REFILL,META,ZERO,BZERO,MEMSET]
SPANS={'refill_zero_request':(0xfffffe000bd72c20,0xfffffe000bd72c44),
 'range_gate':(0xfffffe000be7b618,0xfffffe000be7b638),
 'window_alias':(0xfffffe000be7b680,0xfffffe000be7b69c),
 'chunk_minimum':(0xfffffe000be7b6b0,0xfffffe000be7b6c0),
 'attribute_limit':(0xfffffe000be7b6c0,0xfffffe000be7b6cc),
 'attribute_mask':(0xfffffe000be7b6cc,0xfffffe000be7b6dc),
 'full_page_gate':(0xfffffe000be7b6dc,0xfffffe000be7b6e4),
 'partial_bzero':(0xfffffe000be7b918,0xfffffe000be7b920),
 'fallback_memset':(0xfffffe000be7b958,0xfffffe000be7b960)}
SCOPE='Original refill contains a PFN-to-16384-byte physical-zero request; complete zero wrapper and original bzero/memset execute in private declared aliases, with mapping/cache/preemption helpers modeled and DC ZVA an explicit 64-byte logical effect. Native alias ownership, complete refill, allocation-to-zero identity, hardware cache behavior and daemon IPC remain unknown.'
FALSE=PS.FALSE+['native_physical_alias_established','native_DC_ZVA_executed','complete_refill_executed','allocation_to_zero_identity_established']

def build():
 im=Image();k=im.k;k.cs.detail=True;functions=[k.function(a) for a in FUNCTIONS]
 old=json.loads(read(ROOT/(PS.P+'_checks.json')))
 assert functions[0]==next(f for f in old['functions'] if f['start']==hex(PS.ALLOC))
 spans=[]
 for label,(a,b) in SPANS.items():
  raw=k.read(a,b-a);ii=list(k.cs.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 sections=old['direct_branch_scan']['sections'];calls=[];words=0
 for sec in sections:
  a=int(sec['address'],16);raw=k.read(a,sec['bytes_scanned']);assert sha256(raw).hexdigest()==sec['sha256'];words+=len(raw)//4
  for j,(w,) in enumerate(struct.iter_unpack('<I',raw)):
   if w&0x7c000000!=0x14000000:continue
   d=w&0x3ffffff;d-=((d>>25)&1)<<26;pc=a+4*j
   if (pc+4*d)&((1<<64)-1)==ZERO:calls.append({'entry':sec['entry'],'pc':hex(pc),'mnemonic':'bl' if w>>31 else 'b','bytes_hex':raw[4*j:4*j+4].hex()})
 exact=k.symbols([*FUNCTIONS,ATTR,DIRECT,WINDOW,UNMAP,DEFER,LOWER,UPPER])
 counts={'captured_functions':len(functions),'captured_instructions':sum(len(f['instructions']) for f in functions),
  'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'matched_prior_functions':1,
  'source_blocks':len(spans),'block_instructions':sum(len(s['instructions']) for s in spans),
  'sections_rehashed':len(sections),'aligned_words_scanned':words,'direct_zero_branch_sites':len(calls)}
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_native_reader.py','kernel_vm_mig_tools.py',PS.P+'_checks.json',
   'audit_kernel_permanent_storage.py','probe_kernel_vm_mig.py','replay_kernel_magazine_bootstrap.py']},
  'functions':functions,'spans':spans,'exact_symbols':exact,
  'direct_branch_scan':{'sections':sections,'sites':calls,'scope':'Immediate aligned B/BL encodings only; indirect/data references and caller feasibility outside scope.'},
  'verified_counts':counts,'conditional_kernel_physical_zero_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
