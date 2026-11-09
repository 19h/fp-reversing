#!/usr/bin/env python3
"""Pin original CF descriptor/source factory, callbacks and readiness helpers.
No native CF/dispatch/POSIX/IPC/PAC execution. O(inputs+captured code) readback.
"""
import json,struct
from pathlib import Path
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_cf_receive import CF_PATH
from recover_cf_wake_send_wrapper import FLAGS,sha
P='cf_descriptor_source_factory';CREATE=0x1847b566c;SOURCE=0x1847b5cd0;ENABLE=0x1847b607c;VALID=0x1847b5e38;SCHEDULE=0x1847b6074;PERFORM=0x1847b7ca0;SOURCECREATE=0x18472d31c;DAEMON=0x10044f23c
FUNCS={CREATE,SOURCE,ENABLE,VALID,SCHEDULE,PERFORM,SOURCECREATE,0x1847b58a4,0x1847b58fc,0x1847b5f10,0x1847b6190,0x1847b7954,0x18480fa1c,0x1847b7ef4,0x1847b62cc,0x18480fb04,0x1847c9690,0x1847c968c,0x1847b5bd4,0x1847791b4,0x1847b802c}
# Stubs remain explicit lower contracts; raw stub/pointer/name provenance retained.
STUBS=[0x18806c3e0,0x1880767f0,0x1880766c0,0x18806c310,0x18806c020,0x188076590,0x1880765d0,0x188076640,0x188076680,0x188076670,0x1880766b0,0x1880765e0,0x18806c4f0,0x18806c2f0,0x188086880,0x188086d70,0x18806c3d0,0x18806c120,0x1880773f0,0x188077400,0x1880773b0,0x18807b8a0]
def build():
 old=json.loads((ROOT/'cf_source_wake_callers_source.json').read_text());cs=old['CF_source'];c=Cache();cf=Dylib(c,CF_PATH);fs=list(cs['CF_functions']);known={int(f['start'],16)for f in fs}
 for a in sorted(FUNCS-known):f=cf.function(a);f['exact_nlist']=cf.symbols_at(a);fs.append(f)
 libs=[Dylib(c,e['path'])for e in c.images if e['path'].rsplit('/',1)[-1]in('libdispatch.dylib','libsystem_kernel.dylib','libsystem_c.dylib','libsystem_blocks.dylib','libsystem_malloc.dylib','libsystem_pthread.dylib','libsystem_platform.dylib')]
 stubs=[]
 for a in STUBS:
  raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];at=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(at);target=int(ptr['target'],16);owner=next(d for d in libs if any(seg['address']<=target<seg['address']+seg['size']for seg in d.segments if seg['name']in('__TEXT','__TEXT_EXEC')));exports=[n for n,e in owner.exports.items()if e.get('address')==target];assert exports;stubs.append({'address':hex(a),'bytes16_hex':raw.hex(),'pointer':ptr,'target':hex(target),'dylib':owner.path,'exact_exports':exports,'exact_nlist':owner.symbols_at(target)})
 extra=list(cs['extra_pointer_fixups']);addrs={int(e['address'],16)for e in extra}
 for a in(0x1e01c8750,0x1e01c8788):
  if a not in addrs:
   ptr=c.pointer(a);ld=next(d for d in libs if d.path.endswith('/libdispatch.dylib'));ptr['exact_exports']=[n for n,e in ld.exports.items()if e.get('address')==int(ptr['target'],16)];assert ptr['exact_exports'];extra.append(ptr)
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in cs['original_cache_pages']};ranges=[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in fs]+[(a,16)for a in STUBS]+[(int(e['pointer']['address'],16),8)for e in stubs]+[(int(e['address'],16),8)for e in extra]+[(0x18494ecc0,64),(0x184aa3c17,64),(0x1eb159d50,112),(0x1e232e8d0,256),(0x1e05d5228,256)]
 for a,n in ranges:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 files=sorted(c.used|{e['path']for e in cs['cache_files']}|{str(CACHE)});cfsource={**cs,'CF_functions':fs,'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'extra_pointer_fixups':extra,'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files]}
 return{'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['cf_source_wake_callers_source.json','daemon_descriptor_source_source.json','daemon_descriptor_source_profiles.json','daemon_descriptor_source_checks.json','probe_cf_wake_send_wrapper.py','replay_cf_wake_send_wrapper.py','probe_cf_source_wake_callers.py','replay_cf_source_wake_callers.py','cf_runloop_wake_port_profiles.json']},'CF_source':cfsource,'root_caller_options':old['root_caller_options'],'factory_functions':[hex(a)for a in sorted(FUNCS)],'lower_stubs':stubs,'named_exports':{n:cf.exports[n]for n in('_CFFileDescriptorCreate','_CFFileDescriptorCreateRunLoopSource','_CFFileDescriptorEnableCallBacks','_CFFileDescriptorGetNativeDescriptor','_CFRunLoopSourceCreate')},'original_queue_label_hex':c.read(0x184aa3c17,64).hex(),'original_type_once_predicate8_hex':c.read(0x1eb159db0,8).hex(),**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'CF_functions':len(s['CF_source']['CF_functions']),'CF_instructions':sum(len(f['instructions'])for f in s['CF_source']['CF_functions'])+4*len(s['CF_source']['import_stubs']),'cache_files':len(s['CF_source']['cache_files']),'lower_stubs':len(s['lower_stubs'])}),flush=True)
