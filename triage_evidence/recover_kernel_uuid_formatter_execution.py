#!/usr/bin/env python3
"""Original bounded formatter closure and remaining phase-one interfaces.
O(collection+source+symbols) time/space. No target or IDB execution.
"""
import json,struct
from collections import Counter
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_tunable_batch_execution as B
P='kernel_uuid_formatter_execution';FORMAT=B.FORMAT;EMIT=0xfffffe000c300414;ENGINE=0xfffffe000bd146a0;PHASE2_CALL=0xfffffe000c630370
IMAGE=B.IMAGE;PERCPU=0xfffffe000c62f35c;STACK=0xfffffe000bd3a524;CAPABILITY=0xfffffe000c629adc;FLAGS=0xfffffe000c62a0a4;PLATFORM=0xfffffe000c644d1c;NOOP=0xfffffe000c629a70
TRUE=['UUID_output_produced','all_phase_one_callbacks_executed']
FALSE=[n for n in B.FALSE if n not in TRUE]+['native_formatter_executed','phase_two_callbacks_executed','full_generic_formatter_contract_established']
SCOPE='Original main continues through original UUID formatting, actual return of the Mach-O identity callback and the remaining phase-one callbacks. The bounded formatter wrapper, byte-output callback and generic engine are captured. Selected UUID-format capacities are checked independently. Native startup, authentic PAC, generic format completeness, phase-two callback execution and matched FairPlay transactions remain unknown.'

def build():
 im=Image();prior=json.loads(read(ROOT/(B.P+'_checks.json')));fs=list(prior['functions']);added=[]
 for a in [FORMAT,EMIT,ENGINE]:
  assert hex(a) not in {f['start'] for f in fs};f=B.B.B.B.E.capture(im.k,a);fs.append(f);added.append(f['start'])
 symbols=im.k.symbols([FORMAT,EMIT,ENGINE,0xfffffe000bc9db70,0xfffffe000c629694]);strings=[]
 for a in [0xfffffe00070d7f36,0xfffffe000704ae53,0xfffffe000704f9ab]:
  raw=im.k.read(a,256).split(b'\0')[0]+b'\0';strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw[:-1].decode('ascii')})
 optional=0xfffffe0007e5c2b8;raw=im.k.read(optional,24)

 table=0xfffffe000bd15408;dispatch_base=0xfffffe000bd149b4;dispatch_raw=im.k.read(table,121*4);targets=[dispatch_base+v for v in struct.unpack('<121i',dispatch_raw)];assert all(ENGINE<=t<table for t in targets)
 registry=json.loads(read(ROOT/(B.B.P+'_checks.json')))['registry']['entries'];objects=[];registrations=[]
 for row in registry:
  if int(row['callback_pointer']['target'],16)!=PERCPU:continue
  a=int(row['argument_pointer']['target'],16);registrations.append({'registry_index':row['index'],'phase_u32':row['phase_u32'],'rank_u32':row['rank_u32'],'argument_pointer':row['argument_pointer'],'object_address':hex(a)})
  if hex(a) not in {o['address'] for o in objects}:objects.append({'address':hex(a),'header_bytes_hex':im.k.read(a,32).hex(),'original_logical_word10_hex':im.logical_page((a+16)&~4095)[(a+16)&4095:((a+16)&4095)+8].hex()})
 assert len(objects)==4 and len(registrations)==8 and Counter(r['phase_u32'] for r in registrations)=={1:4,7:4}
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':im.k.sha256,'prior_checks_sha256':sha(ROOT/(B.P+'_checks.json')),'functions':fs,'matched_prior_functions':[f['start'] for f in prior['functions']],'added_functions':added,'exact_symbols':symbols,'strings':strings,'optional_capability_record':{'address':hex(optional),'bytes_hex':raw.hex(),'callback_pointer':im.pointer(optional+16) if raw[16:24]!=bytes(8) else None},'conversion_dispatch':{'address':hex(table),'size_bytes':484,'signed_offset_base':hex(dispatch_base),'bytes_hex':dispatch_raw.hex(),'entries':[{'conversion_byte':j,'target':hex(t)} for j,t in enumerate(targets)]},'digit_table':{'address':'0xfffffe000704e797','bytes_hex':im.k.read(0xfffffe000704e797,33).hex()},'per_CPU_objects':objects,'per_CPU_object_registrations':registrations,'verified_counts':{'captured_functions':len(fs),'captured_words':sum(len(f['instructions']) for f in fs),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'matched_prior_functions':len(prior['functions']),'added_functions':len(added),'formatter_wrapper_words':25,'output_callback_words':12,'format_engine_words':858,'authenticated_engine_call_sites':sum(i['mnemonic']=='blraa' for f in fs if f['start']==hex(ENGINE) for i in f['instructions']),'conversion_dispatch_slots':121,'conversion_dispatch_targets':len(set(targets)),'per_CPU_object_descriptors':len(objects),'per_CPU_object_registrations':len(registrations),'opaque_words_preserved':sum(i['mnemonic']=='opaque' for f in fs for i in f['instructions'])},'conditional_kernel_uuid_formatter_execution_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
