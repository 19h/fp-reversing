#!/usr/bin/env python3
"""Static async request/reference/default-lookup/completion interface capture.
No target execution/emulation, message generation, IPC or IDB mutation.
O(collection+fixups+symbols+selected cache files) time, O(collection+capture) space.
"""
import hashlib,json,struct
from pathlib import Path
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache,Dylib,CACHE
ROOT=Path(__file__).resolve().parent;P='iokit_async_contract'
FLAGS=['native_target_executed','target_instructions_emulated','native_IPC_executed','hardware_PAC_executed','idb_mutated','native_async_completion_observed','FairPlay_async_method_implemented_proven','complete_FairPlay_round_trip_established','full_goal_complete']
FUNCTIONS=[0xfffffe000be383bc,0xfffffe000c570cc0,0xfffffe000c5707ec,0xfffffe000c562bc8,0xfffffe000c562848,0xfffffe000c5628f0,0xfffffe000c56946c,0xfffffe000c569858,0xfffffe000c569864,0xfffffe000c5695cc,0xfffffe000c567a08,0xfffffe000c567a24,0xfffffe000bcf55dc]
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def build():
 im=Image();k=im.k;syms=k.symbols(FUNCTIONS+[0xfffffe000bcd0448]);fs=[]
 for a in FUNCTIONS:f=k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 b=0xfffffe000846a868;bindings=[im.pointer(b+off)for off in(0x880,0x968,0x978,0x970)];bs=k.symbols([int(p['target'],16)for p in bindings])
 for p in bindings:p['exact_symbols']=bs[p['target']]
 sub=next(s for s in im.subsystems()if s['start']<=2866<s['end']);routine=next(r for r in sub['routines']if r['id']==2866)
 c=Cache();io=Dylib(c,'/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit');cf=[]
 for a in(0x184e9d01c,0x184e807e0,0x184e79d1c):f=io.function(a);f['exact_nlist']=io.symbols_at(a);cf.append(f)
 return {'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in('kernel_native_reader.py','kernel_vm_mig_tools.py','bootpolicy_cache_reader.py','resolve_kernel_collection_interfaces.py','iokit_filter_policy_source.json','iokit_structure_arguments_source.json','iokit_connection_lifecycle_source.json','kernel_notification_send_source.json','zut_xnu_reference.json','zut_trace_decoded.json')},'kernel_sha256':k.sha256,'kernel_UUID':k.kernel['uuid'],'kernel_functions':fs,'FairPlay_vtable_bindings':bindings,'release_send_symbols':syms['0xfffffe000bcd0448'],'MIG_routine2866':routine,'cache_UUID':c.uuid,'IOKit_UUID':io.uuid,'cache_functions':cf,'cache_files':[{'path':p,'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],**{f:False for f in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'kernel_functions':len(s['kernel_functions']),'cache_functions':len(s['cache_functions']),'instructions':sum(len(f['instructions'])for f in s['kernel_functions']+s['cache_functions'])}),flush=True)
