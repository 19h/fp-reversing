#!/usr/bin/env python3
"""Pinned platform/tree/clock/diagnostic and original pre-enumeration closure.
O(collection+source+data+symbols) time/space. Static extraction only.
"""
import json
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_boot_environment_publication as E
import recover_kernel_boot_option_execution as O

P='kernel_platform_environment_execution';CLOCK=0xfffffe000c5e5894;ANCHOR=0xfffffe000c5e5c70;FLAGS=0xfffffe000c5e507c;TIMER=0xfffffe000be854e0;ACTLR=0xfffffe000be864d8;ACTLR_WRITE=0xfffffe000bc9cea8
FUNCTIONS=[*E.FUNCTIONS,O.PARSE,O.NUMBER,O.FLAG,O.SPACE,O.B.STRCMP,O.B.B.COMPARE,O.B.B.LOOKUP,O.B.B.ITERATE,O.B.B.FIND,O.B.B.PROPERTY,O.B.SKIP,CLOCK,ANCHOR,FLAGS,TIMER,ACTLR,ACTLR_WRITE]
STRINGS=[0xfffffe00070ea000+x for x in [0x806,0x811,0x81c,0x82b,0x836,0x838,0x8de,0x8e4,0x8ea,0x8f2,0x905,0x913,0x924,0x939,0x949,0x959,0x960,0xc3d,0xc56,0xc62,0xc6e,0xc76,0xc83,0xc94,0xca2,0xcba,0xccb,0xcda,0xf3a]]+[0xfffffe00070eb1df,0xfffffe00070eb248,O.ONE,0xfffffe00070641fb,0xfffffe00070644e0,0xfffffe0007062148,0xfffffe0007062154,0xfffffe0007062167]
FALSE=E.FALSE+['native_clock_state_established','uninterrupted_native_boot_established']
SCOPE='Original main input copies, guarded publisher, range-anchor cache, CPU-derived clock fields, identity/firmware copies, diagnostic option tail, timer-event calculation and four later main parser calls execute continuously on bounded private serialized trees. No generic-initializer/main epoch and no tree/parser/helper output model. Two earlier registration returns and logical PAC/system instructions remain conditional; native boot, later enumeration and matched daemon/kernel effects remain unknown.'

def build():
 k=Kernel();assert len(FUNCTIONS)==len(set(FUNCTIONS));fs=[E.capture(k,a) for a in FUNCTIONS];priors=[json.loads(read(ROOT/(q+'_checks.json'))) for q in [E.P,O.P]];matches=[]
 for f in fs:
  found=[]
  for q in priors:
   r=next((x for x in q['functions'] if x['start']==f['start']),None)
   if r:assert r['bytes']==f['bytes'] and r['end']==f['end'];found.append(q['generator_sha256'])
  if found:matches.append({'start':f['start'],'prior_generator_sha256':found})
 strings=[]
 for a in STRINGS:
  raw=k.read(a,256).split(b'\0')[0]+b'\0';strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw[:-1].decode('ascii')})
 data=[{'address':hex(a),'bytes_hex':k.read(a,n).hex()} for a,n in [(E.LITERAL,16),(O.LITERAL,32),(0xfffffe0007010930,16),(0xfffffe0007010940,16)]]
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in [E.P+'_checks.json',O.P+'_checks.json','kernel_native_reader.py','kernel_vm_mig_tools.py']},'functions':fs,'matched_prior_functions':matches,'strings':strings,'literal_data':data,'exact_symbols':k.symbols(FUNCTIONS),
  'verified_counts':{'captured_functions':len(fs),'captured_words':sum(len(f['instructions']) for f in fs),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'matched_prior_functions':len(matches),'captured_strings':len(strings),'literal_blocks':len(data),'opaque_words_preserved':sum(i['mnemonic']=='opaque' for f in fs for i in f['instructions'])},
  'conditional_kernel_platform_environment_execution_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']))
