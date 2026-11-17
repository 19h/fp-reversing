#!/usr/bin/env python3
"""Original CPU/cache/context bodies and declared architectural input profile.
Linear source/collection/record work; no native register attestation.
"""
import json
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_kernel_boot_environment_publication import capture
import recover_kernel_main_pointer_signing as B
P='kernel_cpu_initialization_execution';CALL=0xfffffe000c639e40;STOP=CALL+4
CPU=0xfffffe000cac7520;INIT=0xfffffe000be780f8;CACHE=0xfffffe000be79c6c;CONFIG=0xfffffe000be95490;TAIL=0xfffffe000be487e8;LOCK=0xfffffe000bd0c1cc;RESTORE=0xfffffe000be81fa8;INSTALL=0xfffffe000be94f4c
ADDITIONS=[CACHE,CONFIG,TAIL,LOCK,RESTORE,INSTALL]
PROFILE={'label':'declared_boot_CPU_unified_L1','registers':{'midr_el1':0x410fd0c1,'mpidr_el1':0x100,'id_aa64dfr0_el1':0,'clidr_el1':4,'daif':0x3c0},'CCSIDR_by_CSSELR':{'0':(3<<28)|(63<<13)|(3<<3)|2},'native_values_attested':False}
REGIONS=[(CPU,0xa40),(0xfffffe000cb8a808,1),(0xfffffe000cb8a810,3*168),(0xfffffe0007ef81c8,16),(0xfffffe000cb8ab68,20),(0xfffffe000cab3210,12),(0xfffffe000cb0bce0,16),(0xfffffe000cb0c318,4)]
SCOPE='Original main CPU initialization, cache discovery, context record setup and register-install tail under a declared architectural-register/cache-bank profile. Prior main fixtures and models retained; no native register values, cache sizes, PAC or matched FairPlay IPC attested.'
def build():
 im=B.B.BootImage();old=json.loads(read(ROOT/(B.P+'_checks.json')));known={f['start'] for f in old['functions']};added=[capture(im.k,a) for a in ADDITIONS if hex(a) not in known];functions=[*old['functions'],*added]
 records=[{'address':hex(a),'bytes_hex':B.S.logical(im,a,n).hex()} for a,n in [*REGIONS,(0xfffffe00070135c8,12),(0xfffffe00070139fc,32),(0xfffffe0007013bf8,216),(0xfffffe000cb87968,8),(0xfffffe000cb87998,4),(0xfffffe000cb11544,12)]]
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'kernel_collection_sha256':im.k.sha256,'dependencies':{n:sha(ROOT/n) for n in [B.P+'_checks.json',B.P+'_audit.json','kernel_boot_cpu_identity_checks.json','recover_kernel_boot_logging_handoff.py']},'functions':functions,'added_function_starts':[f['start'] for f in added],'original_records':records,'architectural_input_profile':PROFILE,'exact_symbols':im.k.symbols([INIT,*ADDITIONS]),'verified_counts':{'functions':len(functions),'source_words':sum(len(f['instructions']) for f in functions),'added_functions':len(added),'added_words':sum(len(f['instructions']) for f in added),'architectural_initial_registers':len(PROFILE['registers']),'CCSIDR_banks':len(PROFILE['CCSIDR_by_CSSELR'])},'native_target_executed':False}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
