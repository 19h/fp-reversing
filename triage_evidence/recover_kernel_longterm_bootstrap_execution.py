#!/usr/bin/env python3
"""Original post-lock timer initialization and its first logging closure.
Linear source bytes and initialized records; no native target operations.
"""
import json
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_lock_bootstrap_execution as B
P='kernel_longterm_bootstrap_execution';INIT=B.FRONTIER;CALL=B.STOP;STOP=CALL+4
PRINTF=0xfffffe000bd1573c;VPRINTF=0xfffffe000bd15774;LOG=0xfffffe000c490108;LOG_BODY=0xfffffe000c48f880;LOCK=0xfffffe000bd0af50
CPU=0xfffffe000be780f8;CALLBACK=0xfffffe000bd65380
ADDITIONS=[PRINTF,VPRINTF,LOG,LOG_BODY,LOCK,CPU,CALLBACK]
REGIONS=[(0xfffffe000ca920a8,0x110),(0xfffffe000cb7d0b8,8),(0xfffffe000cadd708,8),(0xfffffe000cb2a4b4,0xac),(0xfffffe000cadd6e8,8),(0xfffffe000cb7d0c8,8),(0xfffffe000cbe9e58,8),(0xfffffe000cad0108,16),(0xfffffe000caab10c,4)]
SCOPE='Original post-lock timer initializer, longterm boot-option control, converted timeout record, authenticated callback publication and source-backed logging frontier. Private continuous startup; native timing, later CPU setup and matched FairPlay transactions remain unknown.'

def build():
 im=Image();prior=json.loads(read(ROOT/(B.P+'_checks.json')));fs=list(prior['functions'])
 for a in ADDITIONS:
  assert hex(a) not in {f['start'] for f in fs};fs.append(B.B.B.B.B.B.B.E.capture(im.k,a))
 records=[]
 for a,n in [(0xfffffe000ca92088,16),(0xfffffe000ca93e08,0xa8),(0xfffffe000700eb10,16),(0xfffffe000700dc58,8)]:records.append({'address':hex(a),'bytes_hex':im.k.read(a,n).hex()})
 strings=[]
 for a in [0xfffffe00070b0587,0xfffffe0007052b8b]:
  raw=im.k.read(a,128).split(b'\0')[0]+b'\0';strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw[:-1].decode('ascii')})
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':im.k.sha256,'prior_checks_sha256':sha(ROOT/(B.P+'_checks.json')),'functions':fs,'added_functions':list(map(hex,ADDITIONS)),'records':records,'strings':strings,'log_counter_bank_pointer':im.pointer(0xfffffe000caab078),'exact_symbols':im.k.symbols([INIT,*ADDITIONS]),'verified_counts':{'captured_functions':len(fs),'captured_words':sum(len(f['instructions']) for f in fs),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'matched_prior_functions':len(prior['functions']),'added_functions':len(ADDITIONS),'timer_initializer_words':311,'records':len(records),'strings':len(strings)}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
