#!/usr/bin/env python3
"""Pinned CPU enumeration, bootstrap-thread producer and register/caller ABI.
O(collection + fixups + captured bytes) time/space. No native execution.
"""
import json,bisect
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_kernel_boot_header_handoff import logical
P='kernel_boot_cpu_identity'
ENUM=0xfffffe000be83068;SCALAR=0xfffffe000be83f8c;SETTER=0xfffffe000bc9c7f0
CALLER=0xfffffe000be780f8;MAIN=0xfffffe000c639a40;COPY=0xfffffe000c647f10
SPTM=0xfffffe000be734f0;CACHE=0xfffffe000be79c6c;CONFIG=0xfffffe000be95490
THREAD=0xfffffe000cbc9d08;CPU=0xfffffe000cac7520;TEMPLATE=0xfffffe0007e66610
RECORD_PTR=0xfffffe0007ef8c18;ARRAY=0xfffffe0007ef8260;CLUSTERS=0xfffffe0007ef8ae0
GLOBALS=0xfffffe0007ef8bec;CPU_MAP=0xfffffe000cb0c760;SLOT_PTR=0xfffffe000ca908b0
SLOT=0xfffffe000cb62fe0;ARGS=0xfffffe0007e6d1e0
PROPERTY=0xfffffe000c662110;PANIC=0xfffffe000c62a2b0;TAIL=0xfffffe000be487e8
FUNCTIONS=[ENUM,SCALAR,SETTER,CALLER,MAIN,COPY,SPTM,CACHE,CONFIG,0xfffffe000c620ec4]
STRINGS=[0xfffffe0007064132,0xfffffe0007064139,0xfffffe0007064144,0xfffffe0007064152,
 0xfffffe000706415e,0xfffffe000706416c,0xfffffe0007064178,0xfffffe0007064187,
 0xfffffe0007064194,0xfffffe00070641a2,0xfffffe00070641af,0xfffffe00070641c2,
 0xfffffe00070641cf,0xfffffe00070641dc,0xfffffe00070641eb,0xfffffe000706432b,
 0xfffffe0007064339,0xfffffe0007064346,0xfffffe0007064355,
 0xfffffe00070ea8e4,0xfffffe00070eb1ff,0xfffffe00070de859,
 0xfffffe000706412a,0xfffffe00070ea8de,0xfffffe00070ea8ea]
BLOCKS=[(TEMPLATE,0x5c0),(CPU,0xa40),(THREAD,0x5c0),(GLOBALS,0xa4),
 (CPU_MAP,16*16),(SLOT,8),(ARGS,0x480),(0xfffffe00070135c8,12),
 (0xfffffe000700dc58,8),(0xfffffe000700df20,8)]
FALSE=['native_target_executed','native_topology_enumerator_executed','native_system_registers_attested',
 'native_PAC_attested','native_SPTM_receiver_executed','native_boot_continuity_established',
 'matched_daemon_kext_kernel_transaction_observed','full_goal_complete']
SCOPE='Original CPU topology/boot-record publication and bootstrap thread/CPU identity contracts; selected original bootstrap-copy, register-setter, scalar-property and CPU-initializer paths under explicit private inputs/API/system/PAC envelopes. Complete enumerator, startup continuity, SecureDT parsing, hardware/cache/context helpers and opaque receiver remain unexecuted.'

def build():
 im=Image();k=im.k;functions=[];opaque=[]
 for a in FUNCTIONS:
  j=bisect.bisect_left(k.starts,a);assert k.starts[j]==a;b=k.starts[j+1];raw=k.read(a,b-a);instructions=[]
  for at in range(a,b,4):
   word=k.read(at,4);decoded=list(k.cs.disasm(word,at));assert len(decoded)<=1
   instructions.append({'ea':hex(at),'mnemonic':decoded[0].mnemonic if decoded else '.word','operands':decoded[0].op_str if decoded else hex(int.from_bytes(word,'little'))})
   if not decoded:opaque.append({'PC':hex(at),'bytes_hex':word.hex()})
  functions.append({'start':hex(a),'end':hex(b),'bytes':raw.hex(),'sha256':sha256(raw).hexdigest(),'instructions':instructions})
 previous=json.loads(read(ROOT/'kernel_boot_header_handoff_checks.json'));matches=[]
 for f in functions:
  old=next((r for r in previous['functions'] if r['start']==f['start']),None)
  if old is not None:assert old==f;matches.append(f['start'])
 blocks=[{'address':hex(a),'size_bytes':n,'raw_hex':k.read(a,n).hex(),'logical_hex':logical(im,a,n).hex()} for a,n in BLOCKS]
 pointers=[im.pointer(a) for a in [GLOBALS+0x1c,GLOBALS+0x24,SLOT_PTR]]
 assert [int(p['target'],16) for p in pointers]==[ARRAY,CLUSTERS,SLOT]
 assert k.read(RECORD_PTR,16)==bytes(16) and im.offset(RECORD_PTR) not in im.meta and im.offset(RECORD_PTR+8) not in im.meta
 strings=[]
 for a in STRINGS:
  raw=k.read(a,100).split(bytes(1))[0];strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw.decode('ascii')})
 calls=[]
 for f in functions:
  for i in f['instructions']:
   if i['mnemonic']=='bl':calls.append({'owner':f['start'],'PC':i['ea'],'target':i['operands'].removeprefix('#')})
 counts={'captured_functions':len(functions),'captured_words':sum(len(f['instructions']) for f in functions),
  'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'matched_prior_functions':len(matches),
  'captured_strings':len(strings),'direct_calls':len(calls),'logical_data_blocks':len(blocks),'original_pointer_fixups':len(pointers),'opaque_words_preserved':len(opaque)}
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_boot_header_handoff_checks.json','kernel_native_reader.py','kernel_vm_mig_tools.py','recover_kernel_boot_header_handoff.py']},
  'functions':functions,'opaque_words':opaque,'matched_prior_functions':matches,'data_blocks':blocks,'pointer_fixups':pointers,
  'runtime_boot_pointer_original_zero_and_not_fixup':True,'strings':strings,'direct_calls':calls,
  'exact_symbols':k.symbols([*FUNCTIONS,THREAD,CPU,TEMPLATE,RECORD_PTR]),'verified_counts':counts,
  'conditional_kernel_boot_cpu_identity_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
