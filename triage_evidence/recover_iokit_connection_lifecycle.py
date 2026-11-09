#!/usr/bin/env python3
"""Original static connection export/import, method routing and close capture.
No target execution/emulation, IPC or IDB mutation. O(image+fixups+symbols+
selected cache file bytes) time; O(image+capture) space.
"""
import hashlib,json
from pathlib import Path
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
ROOT=Path(__file__).resolve().parent;P='iokit_connection_lifecycle'
FLAGS=['native_target_executed','target_instructions_emulated','native_IPC_executed','hardware_PAC_executed','idb_mutated','native_connection_lifetime_established','complete_FairPlay_round_trip_established','full_goal_complete']
FUNCTIONS=[0xfffffe000be3599c,0xfffffe000be35448,0xfffffe000be35314,0xfffffe000c56114c,0xfffffe000c561300,0xfffffe000be35a54,0xfffffe000bcf4a5c,0xfffffe000bcf4fa0,0xfffffe000bccfc94,0xfffffe000be3c6ac,0xfffffe000be386b4,0xfffffe000c56f10c,0xfffffe000c5708f4,0xfffffe000c5707ec,0xfffffe000c562bc8,0xfffffe000be38c4c,0xfffffe000c56e604]
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def build():
 from resolve_kernel_collection_interfaces import KEXT,macho
 im=Image();syms=im.k.symbols(FUNCTIONS);fs=[]
 for a in FUNCTIONS:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 extracted=KEXT.read_bytes();own=macho(extracted,0,'extracted');ks=[]
 for a,end in[(0xfffffe000a503cd0,0xfffffe000a503d28),(0xfffffe000a50445c,0xfffffe000a5044a0),(0xfffffe000a5044c8,0xfffffe000a504520)]:
  raw=im.k.read(a,end-a);sec=next(s for s in own['sections']if s['address']<=a< s['address']+s['size']);off=sec['file_offset']+a-sec['address'];assert extracted[off:off+len(raw)]==raw
  ks.append({'start':hex(a),'end':hex(end),'bound_source':'supplied adjacent function declarations; original extracted-kext byte comparison','bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]})
 b=0xfffffe000846a868;slots=[b+o for o in(0x20,0x28,0x630,0x880,0x920,0x970,0x978,0x990)]+[0xfffffe0007f502d8+o for o in(0x20,0x28)];ptr=[im.pointer(a)for a in slots];syms=im.k.symbols([int(p['target'],16)for p in ptr]+[0xfffffe000cb5bbc0,0xfffffe000bd07048,0xfffffe000bd0655c,0xfffffe000bcd0448])
 for p in ptr:p['exact_symbols']=syms[p['target']]
 sub=next(s for s in im.subsystems()if s['start']<=2862<s['end']);routines=[r for r in sub['routines']if r['id']in(2816,2862,2865)];sub={k:v for k,v in sub.items()if k!='routines'}
 c=Cache();io=Dylib(c,'/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit');lk=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib');cf=[]
 for a in(0x184e7b99c,0x184e7b9dc):f=io.function(a);f['exact_nlist']=io.symbols_at(a);cf.append(f)
 stubs=[]
 for a in(0x18806c480,0x188088a80):
  raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);p=c.pointer(cell);p['exact_nlist']=lk.symbols_at(int(p['target'],16));stubs.append({'address':hex(a),'bytes16_hex':raw.hex(),'pointer':p,'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 constants=[{'address':hex(a),'bytes8_hex':c.read(a,8).hex()}for a in(0x184f528c0,0x184f52948)];task=c.pointer(0x1e01c8b30);task['exact_nlist']=lk.symbols_at(int(task['target'],16))
 selector_table=[]
 for j in range(40):
  a=0xfffffe000846b770+8*j;raw=im.k.read(a,8);entry_pointer=im.pointer(a)if raw!=bytes(8)else None;selector_table.append({'selector':j+1,'slot':hex(a),'bytes8_hex':raw.hex(),'pointer':entry_pointer})
 return {'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in('kernel_native_reader.py','kernel_vm_mig_tools.py','bootpolicy_cache_reader.py','resolve_kernel_collection_interfaces.py','kernel_iokit_open_source.json','kernel_iokit_open_checks.json','iorpc_object_conversion_source.json','iorpc_object_conversion_checks.json','userclient_provider_routes.json','zut_trace_decoded.json','selector26_lifecycle_contract.json')},'kernel_sha256':im.k.sha256,'kernel_UUID':im.k.kernel['uuid'],'kext_sha256':sha(KEXT),'kext_UUID':own['uuid'],'kernel_functions':fs,'kext_functions':ks,'chained_bindings':ptr,'boundary_symbols':syms,'MIG_subsystem':sub,'MIG_routines':routines,'selector_table':selector_table,'cache_UUID':c.uuid,'IOKit_UUID':io.uuid,'cache_functions':cf,'cache_stubs':stubs,'cache_constants':constants,'task_self_binding':task,'cache_files':[{'path':p,'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'kernel_functions':len(s['kernel_functions']),'kext_functions':len(s['kext_functions']),'cache_functions':len(s['cache_functions']),'instructions':sum(len(f['instructions'])for f in s['kernel_functions']+s['kext_functions']+s['cache_functions'])}),flush=True)
