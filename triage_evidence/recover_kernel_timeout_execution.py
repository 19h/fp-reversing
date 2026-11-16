#!/usr/bin/env python3
"""Original phase-two timeout descriptors and shared source closure.
Linear collection/source/symbol/registry construction; no IDB mutation.
"""
import json,struct
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_uuid_formatter_execution as B
P='kernel_timeout_execution';COMMON=0xfffffe000bd10994;ORDINARY=0xfffffe000bd10980;SPECIAL=0xfffffe000bd12f7c;LOCK=0xfffffe000c63ab68
STACK_STUB=0xfffffe000c61e5e8;STACK_BODY=0xfffffe000c61e5f0;ZERO=0xfffffe000c6480c0;CONCAT=0xfffffe000be3e1c4;DISPATCH=B.PHASE2_CALL
ADDITIONS=[COMMON,ZERO,CONCAT,STACK_STUB,STACK_BODY];APIS=[*ADDITIONS,ORDINARY,SPECIAL,LOCK]
GLOBAL_REGIONS=[(0xfffffe000cb62710,1),(0xfffffe000cb62718,8),(0xfffffe0007ef8240,24),(0xfffffe000cb0c4f8,24)]
SCOPE='Original phase-two timeout descriptor, tree/boot-option precedence, cached scaling, saturation and lock-timeout preparation. Continuous private startup stops before the first phase-three callback. Native startup, authentic PAC, phase-three/phase-fourteen callback execution and matched FairPlay transactions remain unknown.'
TRUE=[*B.TRUE,'phase_two_callbacks_executed']
FALSE=[n for n in B.FALSE if n not in TRUE]+['native_phase_two_completed','phase_three_callbacks_executed','general_timeout_units_contract_established']

def build():
 im=Image();prior=json.loads(read(ROOT/(B.P+'_checks.json')));fs=list(prior['functions'])
 for a in ADDITIONS:
  assert hex(a) not in {f['start'] for f in fs};fs.append(B.B.B.B.B.E.capture(im.k,a))
 registry=json.loads(read(ROOT/(B.B.B.P+'_checks.json')))['registry']['entries'];registrations=[r for r in registry if r['phase_u32']==2];descriptors=[]
 for r in registrations:
  if r['argument_pointer'] is None:assert int(r['callback_pointer']['target'],16)==LOCK;continue
  a=int(r['argument_pointer']['target'],16);raw=im.k.read(a,64);descriptors.append({'registry_index':r['index'],'address':hex(a),'bytes_hex':raw.hex(),'destination_pointer':im.pointer(a),'default_u64':int.from_bytes(raw[8:16],'little'),'divisor_u64':int.from_bytes(raw[16:24],'little'),'name':raw[24:56].split(b'\0')[0].decode('ascii'),'filter_pointer':im.pointer(a+56) if raw[56:64]!=bytes(8) else None,'special_W2_bit0':int(int(r['callback_pointer']['target'],16)==SPECIAL)})
 strings=[]
 for a in [0xfffffe00070eb2c9,0xfffffe000704e355,0xfffffe000704e35c,0xfffffe000704e368,0xfffffe000704e37a,0xfffffe000704e4fe,0xfffffe000704e5be,0xfffffe000706407a,0xfffffe0007064082,0xfffffe000706408a,0xfffffe0007064092]:
  raw=im.k.read(a,200).split(b'\0')[0]+b'\0';strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw[:-1].decode('ascii')})
 assert len(registrations)==10 and len(descriptors)==9 and all(d['filter_pointer'] is None and d['divisor_u64']==0 for d in descriptors)
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':im.k.sha256,'prior_checks_sha256':sha(ROOT/(B.P+'_checks.json')),'functions':fs,'matched_prior_functions':[f['start'] for f in prior['functions']],'added_functions':list(map(hex,ADDITIONS)),'timeout_registrations':registrations,'timeout_descriptors':descriptors,'strings':strings,'stack_probe_pointer':im.pointer(0xfffffe0007f95e28),'exact_symbols':im.k.symbols([*APIS,0xfffffe000be3e3c4,0xfffffe000c662324,0xfffffe000c662110]),'verified_counts':{'captured_functions':len(fs),'captured_words':sum(len(f['instructions']) for f in fs),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'matched_prior_functions':len(prior['functions']),'added_functions':len(ADDITIONS),'timeout_registrations':len(registrations),'timeout_descriptors':len(descriptors),'strings':len(strings),'shared_timeout_words':495,'opaque_words_preserved':sum(i['mnemonic']=='opaque' for f in fs for i in f['instructions'])},'conditional_kernel_timeout_execution_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
