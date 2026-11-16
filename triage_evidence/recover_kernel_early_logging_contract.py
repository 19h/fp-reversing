#!/usr/bin/env python3
"""Pinned logging source and initialized records; O(source bytes) work/space."""
import json
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_longterm_bootstrap_execution as B
from recover_kernel_boot_environment_publication import capture
P='kernel_early_logging_contract'
JOIN=0xfffffe000c48f934;PHASE=0xfffffe0007f8b5f0
START=0xfffffe000c48faf8;SECOND=0xfffffe000c48f920
UNLOCK=0xfffffe000bd0b348;FORMAT=0xfffffe000c3002f4;PUTC=0xfffffe000c2ffae0;CORE=0xfffffe000bd146a0;WAKE=0xfffffe000c2fdda8
SCOPE='Original early logging full-state join, ticket-lock names, formatter/callback ABI and conditional storage interfaces. Source cuts only; continuous bootstrap remains at unknown DAIF. Native emission and matched FairPlay IPC remain unknown.'
def build():
 im=Image();old=json.loads(read(ROOT/(B.P+'_checks.json')));wanted=[B.LOG_BODY,B.LOCK,UNLOCK,FORMAT,PUTC,CORE,WAKE]
 fs=[capture(im.k,a) for a in wanted]
 for f in fs:
  prior=[x for x in old['functions'] if x['start']==f['start']]
  if prior:assert prior==[f]
 addresses=[(0xfffffe000caab10c,4),(0xfffffe000caab110,1),(0xfffffe0007f8b5f0,4),(0xfffffe000caac260,1),(0xfffffe0007f8b643,1),(0xfffffe000cb9bf61,1),(0xfffffe000cb0bc50,4),(0xfffffe000cb115b0,4)]
 records=[{'address':hex(a),'bytes_hex':im.k.read(a,n).hex()} for a,n in addresses]
 pointers=[im.pointer(a) for a in [0xfffffe000caab078,0xfffffe000caab0d0,0xfffffe000caab0e0,0xfffffe000caab118]]
 target=int(pointers[-1]['target'],16);records.append({'address':hex(target),'bytes_hex':im.k.read(target,24).hex()})
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'kernel_collection_sha256':im.k.sha256,'source_sha256':sha(SOURCE),'prior_checks_sha256':sha(ROOT/(B.P+'_checks.json')),'functions':fs,'records':records,'pointers':pointers,'exact_symbols':im.k.symbols(wanted),'verified_counts':{'functions':len(fs),'words':sum(len(f['instructions']) for f in fs),'bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'prior_bodies_preserved':2,'records':len(records),'pointer_slots':len(pointers)}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
