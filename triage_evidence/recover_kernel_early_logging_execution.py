#!/usr/bin/env python3
"""Original logging execution closure; O(source and record bytes) work/space."""
import json
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_kernel_boot_environment_publication import capture
import recover_kernel_longterm_bootstrap_execution as B
import recover_kernel_early_logging_contract as C
P='kernel_early_logging_execution';MRS=0xfffffe000c48faf4;JOIN=C.JOIN;TIMESTAMP=0xfffffe000c300220
REGIONS=[(0xfffffe000caab110,1),(0xfffffe000caa3070,24),(0xfffffe000cb2fe28,131072),(0xfffffe000cbe9eb0,8),(0xfffffe000cbe9ec0,8)]
SCOPE='Continuous original startup with one universally proved early-phase state join across unknown DAIF, original ticket lock, timestamp and diagnostic formatting. Logical PAC custody only; native scheduling, console effects and matched FairPlay IPC remain unknown.'
def build():
 im=Image();prior=json.loads(read(ROOT/(B.P+'_checks.json')));contract=json.loads(read(ROOT/(C.P+'_checks.json')));fs=list(prior['functions']);added=[]
 for a in [*[int(f['start'],16) for f in contract['functions']],TIMESTAMP]:
  if hex(a) not in {f['start'] for f in fs}:fs.append(capture(im.k,a));added.append(hex(a))
 raw=im.k.read(0xfffffe00070d803f,128).split(b'\0')[0]+b'\0'
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'kernel_collection_sha256':im.k.sha256,'prior_checks_sha256':sha(ROOT/(B.P+'_checks.json')),'join_contract_checks_sha256':sha(ROOT/(C.P+'_checks.json')),'join_contract_audit_sha256':sha(ROOT/(C.P+'_audit.json')),'functions':fs,'added_functions':added,'timestamp_format':{'address':'0xfffffe00070d803f','bytes_hex':raw.hex(),'text':raw[:-1].decode('ascii')},'ring_data_pointer':im.pointer(0xfffffe000caa3080),'new_mutable_regions':[{'address':hex(a),'size_bytes':n} for a,n in REGIONS],'verified_counts':{'functions':len(fs),'words':sum(len(f['instructions']) for f in fs),'bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'prior_bodies_preserved':len(prior['functions']),'added_functions':len(added),'new_mutable_regions':len(REGIONS),'new_mutable_bytes':sum(n for a,n in REGIONS)}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
