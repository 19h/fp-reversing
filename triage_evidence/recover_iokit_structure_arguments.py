#!/usr/bin/env python3
"""Static structure-method argument/size/copy/task provenance capture.
No target execution/emulation, IPC, payload generation or IDB mutation.
O(image+fixups+symbols+selected cache files) time, O(image+capture) space.
"""
import hashlib,json
from pathlib import Path
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
ROOT=Path(__file__).resolve().parent;P='iokit_structure_arguments'
FLAGS=['native_target_executed','target_instructions_emulated','native_IPC_executed','hardware_PAC_executed','idb_mutated','native_structure_tail_value_established','complete_FairPlay_round_trip_established','full_goal_complete']
FUNCTIONS=[0xfffffe000c5708f4,0xfffffe000c562bc8,0xfffffe000c565154,0xfffffe000c53a934,0xfffffe000be386b4,0xfffffe000c5707ec,0xfffffe000bd7e9c4,0xfffffe000c6480c0,0xfffffe000bcf4154]
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def build():
 from resolve_kernel_collection_interfaces import KEXT,macho
 im=Image();syms=im.k.symbols(FUNCTIONS);fs=[]
 for a in FUNCTIONS:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 data=KEXT.read_bytes();own=macho(data,0,'extracted');ks=[]
 for a,end in[(0xfffffe000a504034,0xfffffe000a5040d4),(0xfffffe000a5040d4,0xfffffe000a504320),(0xfffffe000a505198,0xfffffe000a5053f4)]:
  raw=im.k.read(a,end-a);sec=next(s for s in own['sections']if s['address']<=a<s['address']+s['size']);o=sec['file_offset']+a-sec['address'];assert data[o:o+len(raw)]==raw;ks.append({'start':hex(a),'end':hex(end),'bound_source':'supplied adjacent declarations; extracted/collection byte equality','bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]})
 record=0xfffffe000846b710;method={'address':hex(record),'bytes48_hex':im.k.read(record,48).hex(),'function_pointer':im.pointer(record+8),'router_slot':im.pointer(0xfffffe000846b838)}
 a=0xfffffe000a69f1e4;raw=im.k.read(a,16);ins=list(im.k.cs.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=im.pointer(cell);ptr['exact_symbols']=im.k.symbols([int(ptr['target'],16)])[ptr['target']];stub={'address':hex(a),'bytes16_hex':raw.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins],'pointer':ptr}
 c=Cache();io=Dylib(c,'/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit');platform=Dylib(c,'/usr/lib/system/libsystem_platform.dylib');cf=[]
 for a in(0x184e78db0,0x184e77d74,0x184e77e8c):f=io.function(a);f['exact_nlist']=io.symbols_at(a);cf.append(f)
 a=0x18806c550;raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(cell);ptr['exact_nlist']=platform.symbols_at(int(ptr['target'],16));copy_stub={'address':hex(a),'bytes16_hex':raw.hex(),'pointer':ptr}
 sub=next(s for s in im.subsystems()if s['start']<=2865<s['end']);routine=next(r for r in sub['routines']if r['id']==2865)
 return {'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in('kernel_native_reader.py','kernel_vm_mig_tools.py','bootpolicy_cache_reader.py','resolve_kernel_collection_interfaces.py','iokit_connection_lifecycle_source.json','iokit_connection_lifecycle_checks.json','kernel_iokit_open_source.json','selector26_lifecycle_contract.json','selector26_core_rpc_native.json','zut_trace_decoded.json')},'kernel_sha256':im.k.sha256,'kernel_UUID':im.k.kernel['uuid'],'kext_sha256':sha(KEXT),'kext_UUID':own['uuid'],'kernel_functions':fs,'kext_functions':ks,'method26':method,'provider_memory_factory_stub':stub,'MIG_routine2865':routine,'cache_UUID':c.uuid,'IOKit_UUID':io.uuid,'cache_functions':cf,'copy_stub':copy_stub,'cache_files':[{'path':p,'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'kernel_functions':len(s['kernel_functions']),'kext_functions':len(s['kext_functions']),'cache_functions':len(s['cache_functions']),'instructions':sum(len(f['instructions'])for f in s['kernel_functions']+s['kext_functions']+s['cache_functions'])}),flush=True)
