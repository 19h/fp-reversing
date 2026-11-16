#!/usr/bin/env python3
"""Pinned original topology enumerator, comparison and environmental APIs.
O(collection + fixups + source + data + symbols) time/space. No native boot.
"""
import bisect,json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_boot_cpu_identity as B
from recover_kernel_boot_header_handoff import logical
P='kernel_cpu_topology_handoff';COMPARE=0xfffffe000bc9dbf0;PARSE=0xfffffe000c5e48a4
LOOKUP=0xfffffe000c662324;ITERATE=0xfffffe000c5e4550;FIND=0xfffffe000c5e40f0
PROPERTY=B.PROPERTY;WRAPPER=0xfffffe000c620ec4;STACKFAIL=0xfffffe000c629694
POST=0xfffffe000be85a48;CONTROL=0xfffffe0007ef8e98;OPTION=0xfffffe000706443b
FUNCTIONS=[*B.FUNCTIONS,COMPARE,PARSE,LOOKUP,ITERATE,FIND,PROPERTY,POST]
EXTRA_BLOCKS=[(B.ARRAY-4,16*136+4),(B.CLUSTERS,3*88),(0xfffffe0007f8b508,32),
 (0xfffffe0007f8b6e8,8),(0xfffffe000cacb000,8),(0xfffffe000cba40e8,8),(COMPARE-16,16),(CONTROL,4)]
SCOPE='Complete original topology enumerator and bounded comparison execute for selected private node/property/parser/iterator outputs. Original main calls enumeration, executes its34-word post-enumeration boot-option/system-register helper and continues into original bootstrap-copy/thread-setter code without a new call epoch at that handoff. Source boot-record checkpoints and a later complete-RAM explicit CPU-caller epoch replace the prior boot-record fixture. Actual SecureDT parsing/iterator internal effects, selector0e receiver, intervening later main callbacks, native hardware/PAC/cache/context effects and daemon pairing remain unknown.'
FALSE=B.FALSE+['native_device_tree_admission_established','native_iterator_internal_effects_established']

def build():
 prior=json.loads(read(ROOT/(B.P+'_checks.json')));assert prior==B.build();im=Image();k=im.k;functions=[];opaque=[]
 for a in FUNCTIONS:
  j=bisect.bisect_left(k.starts,a);assert k.starts[j]==a;b=k.starts[j+1];raw=k.read(a,b-a);instructions=[]
  for at in range(a,b,4):
   word=k.read(at,4);decoded=list(k.cs.disasm(word,at));assert len(decoded)<=1
   instructions.append({'ea':hex(at),'mnemonic':decoded[0].mnemonic if decoded else '.word','operands':decoded[0].op_str if decoded else hex(int.from_bytes(word,'little'))})
   if not decoded:opaque.append({'PC':hex(at),'bytes_hex':word.hex()})
  f={'start':hex(a),'end':hex(b),'bytes':raw.hex(),'sha256':sha256(raw).hexdigest(),'instructions':instructions}
  old=next((r for r in prior['functions'] if r['start']==f['start']),None)
  if old is not None:assert old==f
  functions.append(f)
 blocks=prior['data_blocks']+[{'address':hex(a),'size_bytes':n,'raw_hex':k.read(a,n).hex(),'logical_hex':logical(im,a,n).hex()} for a,n in EXTRA_BLOCKS]
 strings=prior['strings']
 for a in [0xfffffe00070eaf3a,0xfffffe00070ea959,OPTION]:
  raw=k.read(a,100).split(bytes(1))[0];strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw.decode('ascii')})
 counts={'captured_functions':len(functions),'captured_words':sum(len(f['instructions']) for f in functions),
  'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'matched_prior_functions':len(B.FUNCTIONS),
  'captured_strings':len(strings),'logical_data_blocks':len(blocks),'opaque_words_preserved':len(opaque),
  'original_pointer_fixups':len(prior['pointer_fixups'])}
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in [B.P+'_checks.json','recover_kernel_boot_cpu_identity.py','kernel_native_reader.py','kernel_vm_mig_tools.py']},
  'functions':functions,'opaque_words':opaque,'data_blocks':blocks,'strings':strings,'pointer_fixups':prior['pointer_fixups'],
  'exact_symbols':k.symbols([*FUNCTIONS,B.RECORD_PTR,B.THREAD,B.CPU]),'verified_counts':counts,
  'conditional_kernel_cpu_topology_handoff_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
