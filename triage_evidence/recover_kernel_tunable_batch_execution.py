#!/usr/bin/env python3
"""Pinned phase-one descriptors, pointer adjustments and UUID caller source.
O(collection+source+records*owner-segments+symbols) time; linear retained space.
No native target or IDB access.
"""
import json,struct
from collections import Counter
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_startup_registry_abi as B
P='kernel_tunable_batch_execution';OPTION=0xfffffe000c6306e0;ADJUST=0xfffffe000c62a018;INDEXED=0xfffffe000c62f2a4;UUID=0xfffffe000c48ef18;FORMAT=0xfffffe000c3003b0;STOP=0xfffffe000c48ef98
TIMER=0xfffffe000c62f458;CHOSEN=0xfffffe000c63ad8c;POLICY=0xfffffe000c63bb08;TRACE_CONFIG=0xfffffe000c26498c;WATCHDOG=0xfffffe000c6334fc;IMAGE=0xfffffe000c62a0cc
PHASE1=[0xfffffe000bd3a524,TRACE_CONFIG,0xfffffe000c629a70,0xfffffe000c629adc,ADJUST,0xfffffe000c62a0a4,IMAGE,INDEXED,0xfffffe000c62f35c,TIMER,B.TUNABLE,OPTION,WATCHDOG,CHOSEN,POLICY,0xfffffe000c644d1c]
GLOBAL_REGIONS=[(0xfffffe000cb62e78,4),(0xfffffe000cb62e80,8),(0xfffffe0007f12c60,4),(0xfffffe000cadce28,18*96),(0xfffffe0007f19d90,4),(0xfffffe000cb29c18,8),(0xfffffe000cb2a71c,4),(0xfffffe000cb29df0,259),(0xfffffe000cb29ef4,259),(0xfffffe000cb29ff8,259),(0xfffffe000ca92374,4),(0xfffffe0007e66e28,4),(0xfffffe000cb51120,8),(0xfffffe000cb2a1a0,37),(0xfffffe000caceea8,4),(0xfffffe0007e5ca28,4),(0xfffffe0007f30770,8),(0xfffffe0007e64500,16),(0xfffffe0007e62bc8,2),(0xfffffe0007f18be0,4)]
FALSE=B.FALSE+['native_phase_one_completed','all_phase_one_callbacks_executed','UUID_output_produced','native_SFI_handlers_executed']
SCOPE='Original main continues through repeated original phase-one callbacks from the preserved first-callback boundary. All 237 compact option descriptors, 101 per-CPU pointer arguments and 17 indexed SFI initializer descriptors are retained. Seventeen registered SFI thunks and two shared bodies are captured but not invoked. Original parsers and initialization callback bodies execute with no new callback-result model; execution stops before the original UUID formatter call. Native startup, formatter output, completion of phase one and matched FairPlay transactions remain unknown.'

def build():
 im=Image();k=im.k;prior=json.loads(read(ROOT/(B.P+'_checks.json')));options=[];adjustments=[];indexed=[]
 def pointer(a):return im.pointer(a) if k.read(a,8)!=bytes(8) else None
 for r in prior['registry']['entries']:
  t=int(r['callback_pointer']['target'],16)
  if r['phase_u32']!=1 or t not in [OPTION,ADJUST,INDEXED]:continue
  a=int(r['argument_pointer']['target'],16)
  if t==OPTION:
   raw=k.read(a,24);key=pointer(a);dest=pointer(a+8);text=k.read(int(key['target'],16),256).split(b'\0')[0]+b'\0';n=int.from_bytes(raw[16:20],'little');assert 0<n<=256
   options.append({'registry_index':r['index'],'descriptor':hex(a),'raw_hex':raw.hex(),'key_pointer':key,'destination_pointer':dest,'name':text[:-1].decode('ascii'),'name_bytes_hex':text.hex(),'size_bytes':n,'normalize_byte14':raw[20],'string_byte15':raw[21],'reserved_hex':raw[22:].hex()})
  elif t==ADJUST:
   adjustments.append({'registry_index':r['index'],'slot':hex(a),'raw_hex':k.read(a,8).hex(),'pointer':pointer(a)})
  else:
   raw=k.read(a,32);pointers=[pointer(a+j) for j in [8,16,24]];labels=[]
   for p in pointers[1:]:
    label=k.read(int(p['target'],16),256).split(b'\0')[0]+b'\0';labels.append({'address':p['target'],'bytes_hex':label.hex(),'text':label[:-1].decode('ascii')})
   indexed.append({'registry_index':r['index'],'descriptor':hex(a),'raw_hex':raw.hex(),'selector_u32':int.from_bytes(raw[:4],'little'),'pointers':pointers,'labels':labels})
 handlers=sorted({int(o['pointers'][0]['target'],16) for o in indexed});additional=[UUID,*handlers,0xfffffe000bd35c34,0xfffffe000be7c70c];functions=list(prior['functions'])
 for a in additional:
  if hex(a) not in {f['start'] for f in functions}:functions.append(B.B.B.E.capture(k,a))
 symbols=k.symbols([*PHASE1,*additional,FORMAT]);strings=[]
 for a in [0xfffffe00070ab799,0xfffffe00070ab7a6,0xfffffe00070ab7f5,0xfffffe00070ab80c,0xfffffe00070ab828,0xfffffe00070ab82d,0xfffffe00070ab838,0xfffffe00070ab849,0xfffffe00070ab7ae,0xfffffe00070eabb9,0xfffffe00070b485b,0xfffffe00070a92c2,0xfffffe00070a92c5,0xfffffe00070a92ca,0xfffffe00070a92de,0xfffffe00070a92f1,0xfffffe00070e3950,0xfffffe00070e3953,0xfffffe0007053333,0xfffffe0007064277,0xfffffe00070d7f36,0xfffffe000704f86e,0xfffffe000704f88c,0xfffffe000704f892,0xfffffe0007063f6c,0xfffffe0007063f86,0xfffffe0007063fb9]:
  raw=k.read(a,256).split(b'\0')[0]+b'\0';strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw[:-1].decode('ascii')})
 header=0xfffffe000700c000;count=int.from_bytes(k.read(header+16,4),'little');at=header+32;commands=[]
 for j in range(count):
  cmd,n=struct.unpack('<II',k.read(at,8));assert n>=8;commands.append({'index':j,'address':hex(at),'command':cmd,'size_bytes':n,'bytes_hex':k.read(at,n).hex()});at+=n
 uuid=next(c for c in commands if c['command']==27);assert uuid['size_bytes']==24
 assert len(options)==237 and len(adjustments)==101 and len(indexed)==17 and len({t for t in PHASE1})==16
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'prior_checks_sha256':sha(ROOT/(B.P+'_checks.json')),'functions':functions,'matched_prior_functions':[f['start'] for f in prior['functions']],'exact_symbols':symbols,'option_descriptors':options,'per_CPU_pointer_arguments':adjustments,'indexed_descriptors':indexed,'SFI_handler_targets':list(map(hex,handlers)),'SFI_shared_targets':list(map(hex,[0xfffffe000bd35c34,0xfffffe000be7c70c])),'strings':strings,'kernel_MachO_header':{'address':hex(header),'bytes_hex':k.read(header,32).hex(),'load_commands':commands,'first_UUID_command':uuid},'declared_global_regions':[{'address':hex(a),'size_bytes':n} for a,n in GLOBAL_REGIONS],'verified_counts':{'captured_functions':len(functions),'captured_words':sum(len(f['instructions']) for f in functions),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'matched_prior_functions':len(prior['functions']),'phase_one_callback_targets':len(PHASE1),'option_descriptors':len(options),'per_CPU_pointer_arguments':len(adjustments),'indexed_descriptors':len(indexed),'SFI_handler_bodies':len(handlers),'option_shapes':{','.join(map(str,key)):n for key,n in Counter((o['size_bytes'],o['normalize_byte14'],o['string_byte15']) for o in options).items()},'strings':len(strings),'MachO_load_commands':len(commands),'opaque_words_preserved':sum(i['mnemonic']=='opaque' for f in functions for i in f['instructions'])},'conditional_kernel_tunable_batch_execution_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
