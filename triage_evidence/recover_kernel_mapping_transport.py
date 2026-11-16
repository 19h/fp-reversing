#!/usr/bin/env python3
"""Pinned mapping admission, descriptor and SPTM transport source custody.
O(collection bytes + captured words + symbols) time/space; no native effects.
Unknown words are retained individually, never silently skipped.
"""
import bisect,json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import sha
P='kernel_mapping_transport'
GATE=0xfffffe000be5b2e8;DESC=0xfffffe000be5ca04;IMPL=0xfffffe000be5ce90;CLASSIFY=0xfffffe000be5de8c
EXPAND=0xfffffe000be5c0bc;PRE=0xfffffe000bc9c090;POST=0xfffffe000bc9c0fc
WRAPPERS=[0xfffffe000c620b7c,0xfffffe000c620bb8,0xfffffe000c620bf4]
CHECK=0xfffffe000c6456f8;CTX=0xfffffe000cb0bf18;CPU_BASE=0xfffffe000cac8000
TRANSPORT_FLAG=0xfffffe0007f8c7c8;TAG_FLAG=0xfffffe0007e6dc18
FUNCTIONS=[GATE,DESC,IMPL,CLASSIFY,EXPAND,PRE,POST,*WRAPPERS,CHECK]
STRINGS=[0xfffffe000705f810,0xfffffe000706125b,0xfffffe000706166a,0xfffffe0007064363,
 0xfffffe000705ffcd,0xfffffe000706006b,0xfffffe000705fffa,0xfffffe0007060099]
SCOPE='Original mapping admission/descriptor construction, selected implementation arguments and per-CPU request/result protocol, and three SPTM wrappers. Private source components and explicit no-RAM helper models establish conditional contracts. The two opaque transport words are never executed or assigned unverified instruction names. Native translation effects, live context, SPTM payload/return ABI, full gateway execution, ownership, exclusion and daemon transaction pairing remain unknown.'
FALSE=['native_target_executed','native_translation_effects_established','opaque_transport_words_executed',
 'complete_mapping_gateway_executed','hardware_PAC_executed','native_SPTM_return_ABI_established','full_goal_complete']

def build():
 k=Kernel();functions=[];unknown=[]
 for address in FUNCTIONS:
  j=bisect.bisect_right(k.starts,address)-1;start,end=k.starts[j:j+2];assert start==address
  raw=k.read(start,end-start);words=[]
  for at in range(start,end,4):
   b=k.read(at,4);ii=list(k.cs.disasm(b,at));assert len(ii)<=1
   row={'ea':hex(at),'mnemonic':ii[0].mnemonic if ii else '.word','operands':ii[0].op_str if ii else hex(int.from_bytes(b,'little'))}
   if not ii:unknown.append({'pc':hex(at),'bytes_hex':b.hex(),'word_u32':hex(int.from_bytes(b,'little'))})
   words.append(row)
  functions.append({'start':hex(start),'end':hex(end),'bytes':raw.hex(),'sha256':sha256(raw).hexdigest(),'instructions':words})
 assert len(unknown)==6 and {r['word_u32'] for r in unknown}=={'0x201420','0xd4e00000'}
 calls=[{'caller':f['start'],'pc':i['ea'],'target':i['operands'][1:]} for f in functions for i in f['instructions'] if i['mnemonic']=='bl']
 strings=[{'address':hex(a),'bytes_hex':k.read(a,512).split(bytes(1))[0].hex(),'text':k.read(a,512).split(bytes(1))[0].decode('ascii')} for a in STRINGS]
 counts={'captured_functions':len(functions),'captured_words':sum(len(f['instructions']) for f in functions),
  'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'undecoded_words_preserved':len(unknown),'direct_call_sites':len(calls),'original_diagnostics':len(strings)}
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_native_reader.py','kernel_vm_mig_tools.py','kernel_refill_publication_checks.json']},
  'functions':functions,'undecoded_words':unknown,'direct_calls':calls,'diagnostics':strings,
  'exact_symbols':k.symbols([*FUNCTIONS,*[int(c['target'],16) for c in calls]]),
  'context_file_bytes_hex':k.read(CTX,128).hex(),'verified_counts':counts,
  'conditional_kernel_mapping_transport_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
