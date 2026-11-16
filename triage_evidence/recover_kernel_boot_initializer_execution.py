#!/usr/bin/env python3
"""Pinned boot initializer, child relocation and range publication closure.
Linear collection/source/header work; no target execution.
"""
import json,struct
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import commands
from recover_kernel_boot_environment_publication import capture
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import sha
P='kernel_boot_initializer_execution';BOOT=0xfffffe000c66058c;SET=0xfffffe000c6626e4;RANGES=0xfffffe000c660e6c;CHILD=0xfffffe000c660bf8;HEADER=0xfffffe0007004000
GLOBALS=[0xfffffe0007f8b528,0xfffffe0007f8b548,0xfffffe0007f8b568,0xfffffe0007f8b5a8,*range(0xfffffe0007e6d160,0xfffffe0007e6d180,8)]
SCOPE='Full original boot initializer in raw-image private CPU execution with logical PAC, streamed source/memory receipts, independent replay and complete final mapped-page projection. Native boot, hardware signatures, cold-entry admission and later main/FairPlay IPC remain unknown.'
def build():
 k=Kernel();functions=[capture(k,a) for a in [BOOT,SET,RANGES,CHILD]];segments=[]
 for at,c,n in commands(k.data,0):
  if c==0x19:
   vm,size=struct.unpack_from('<QQ',k.data,at+24);maximum,initial=struct.unpack_from('<II',k.data,at+56);segments.append({'command':hex(HEADER+at),'name':k.data[at+8:at+24].split(b'\0')[0].decode(),'VM_address':hex(vm),'VM_size_bytes':size,'maximum_protection':maximum,'initial_protection':initial})
 nonempty=[s for s in segments if s['VM_size_bytes']];readonly=[s for s in nonempty if not s['maximum_protection']&2 and s['name']!='__LINKEDIT'];minimum=min(int(s['VM_address'],16) for s in nonempty);maximum=max(int(s['VM_address'],16)+s['VM_size_bytes'] for s in nonempty);ro_min=min(int(s['VM_address'],16) for s in readonly);ro_max=max(int(s['VM_address'],16)+s['VM_size_bytes'] for s in readonly)
 values=[HEADER,0,minimum,0,minimum,maximum,ro_min,ro_max];expected=[{'address':hex(a),'value':hex(v),'initial_raw_bytes_hex':k.read(a,8).hex()} for a,v in zip(GLOBALS,values)]
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'kernel_collection_sha256':k.sha256,'functions':functions,'root_segments':segments,'expected_global_words':expected,'exact_symbols':k.symbols([BOOT,SET,RANGES,CHILD]),'dependencies':{n:sha(ROOT/n) for n in ['kernel_boot_fixup_projection_checks.json','kernel_boot_fixup_projection_audit.json','recover_kernel_boot_fixup_projection.py','kernel_vm_mig_tools.py']},'verified_counts':{'functions':len(functions),'source_words':sum(len(f['instructions']) for f in functions),'source_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'root_segments':len(segments),'published_global_words':len(expected),'published_global_bytes':8*len(expected)},'native_target_executed':False}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
