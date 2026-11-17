#!/usr/bin/env python3
"""Pinned scheduler/group/processor bootstrap bodies and original records.
Linear source/record capture; no native scheduler or hardware execution.
"""
import json
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_kernel_boot_environment_publication import capture
import recover_kernel_cpu_initialization_execution as B
P='kernel_scheduler_bootstrap_execution';CALL=B.STOP;STOP=CALL+4
INIT=0xfffffe000bd17314;CLASSIFY=0xfffffe000bd16d94;GROUP=0xfffffe000bd170dc;PROCESSOR_INIT=0xfffffe000bd174a4;PROCESSOR=0xfffffe000cac6e18;GROUP_BASE=0xfffffe000cad0800
PANIC=0xfffffe000c62a2b0
ADDITIONS=[INIT,CLASSIFY,GROUP,PROCESSOR_INIT,0xfffffe000bd212b0,0xfffffe000bd2d3cc,0xfffffe000bd2507c,0xfffffe000bd2173c,0xfffffe000bd67f08,0xfffffe000bd0bfa4,0xfffffe000bd0c2cc,0xfffffe000bd33474,0xfffffe000be7c458]
REGIONS=[(GROUP_BASE,3*0x4200),(0xfffffe000cad0118,3*64),(0xfffffe000cad05a0,3*32),(PROCESSOR,0x708),(0xfffffe0007e66d8c,1),(0xfffffe0007e66d98,3),(0xfffffe0007e66da0,3*8),(0xfffffe000cbc9618,8),(0xfffffe000cb62948,32),(0xfffffe0007e644b8,32),(0xfffffe0007e64008,8),(0xfffffe000cad01e8,16),(0xfffffe0007e6a414,4),(0xfffffe0007ef8f20,8),(0xfffffe000cadce10,16),(0xfffffe000cad01d8,16),(0xfffffe000ca90790,8),(0xfffffe000cb0bca0,16),(0xfffffe000cadd5a8,16),(0xfffffe000cb0c6c8,16),(0xfffffe000cadd658,16),(0xfffffe000cadd768,16)]
SCOPE='Original main scheduler bootstrap, CPU-class admission, group and processor setup under inherited architectural inputs. The unchanged missing-property case and an explicitly declared pre-main E-type tree are distinct cases. No native topology, scheduler scheduling, port emission or matched FairPlay IPC attested.'
def build():
 im=B.B.B.BootImage();old=json.loads(read(ROOT/(B.P+'_checks.json')));known={f['start'] for f in old['functions']};added=[capture(im.k,a) for a in ADDITIONS if hex(a) not in known];functions=old['functions']+added
 records=[{'address':hex(a),'bytes_hex':B.B.S.logical(im,a,n).hex()} for a,n in REGIONS]
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'kernel_collection_sha256':im.k.sha256,'dependencies':{n:sha(ROOT/n) for n in [B.P+'_checks.json',B.P+'_audit.json','kernel_cpu_topology_handoff_checks.json','recover_kernel_boot_logging_handoff.py']},'functions':functions,'added_function_starts':[f['start'] for f in added],'original_records':records,'inherited_architectural_input_profile':B.PROFILE,'exact_symbols':im.k.symbols(ADDITIONS),'verified_counts':{'functions':len(functions),'source_words':sum(len(f['instructions']) for f in functions),'added_functions':len(added),'added_words':sum(len(f['instructions']) for f in added),'declared_input_cases':2},'native_target_executed':False}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
