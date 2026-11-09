#!/usr/bin/env python3
"""Original daemon initializer/setup/callback bound to captured CF exports.
Static source/chain/export and new close/cancel/removal dependency provenance.
No native daemon, CF, dispatch, IPC or PAC. O(source+captured ranges) time/space.
"""
import json
from pathlib import Path
from daemon_receive_tools import ROOT,IMAGE,SOURCE,FIXUPS
from daemon_import_bindings import binding
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_cf_receive import CF_PATH
from recover_cf_public_runloop import FLAGS,sha
P='daemon_cf_descriptor_bridge';INIT=0x100437c18;SETUP=0x10009689c;CALLBACK=0x10044f23c;HEADER=0x1010c4cd8;SETUP_END=0x100093518
INVALID=0x1847c9690;INVBLOCK=0x1847c9870;SOURCEINV=0x184779a30;REMOVE_CALLBACK=0x184794f2c;REMOVE=0x18477921c;SETREMOVE=0x184717024;READCANCEL=0x1847c999c;WRITECANCEL=0x1847c9b68;GETMAIN=0x18471bb78
FUNCS={INVALID,INVBLOCK,SOURCEINV,REMOVE_CALLBACK,REMOVE,SETREMOVE,READCANCEL,WRITECANCEL,GETMAIN};STUBS=[0x188076630,0x188084be0,0x18806c5c0,0x188085b10]
CF_NAMES=['CFFileDescriptorCreate','CFFileDescriptorCreateRunLoopSource','CFFileDescriptorEnableCallBacks','CFFileDescriptorGetNativeDescriptor','CFFileDescriptorInvalidate','CFRunLoopGetMain','CFRunLoopStop','CFRunLoopAddSource','CFRelease']
BOUNDARIES={0x184757e4c:'declared_registered_mode_array',0x1846f5978:'declared_mode_array_count',0x1846f7424:'declared_mode_array_value',0x1847170cc:'declared_hash_remove',0x1846dc364:'declared_bag_type4'}
def build():
 old=json.loads((ROOT/'cf_public_runloop_source.json').read_text());cs=old['CF_source'];c=Cache();cf=Dylib(c,CF_PATH);fs=list(cs['CF_functions']);known={int(f['start'],16)for f in fs}
 for a in sorted(FUNCS-known):f=cf.function(a);f['exact_nlist']=cf.symbols_at(a);fs.append(f)
 libs=[Dylib(c,e['path'])for e in c.images if e['path'].rsplit('/',1)[-1]in('libdispatch.dylib','libsystem_kernel.dylib')];stubs=[]
 for a in STUBS:
  raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];at=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(at);target=int(ptr['target'],16);lib=next(d for d in libs if any(e['address']<=target<e['address']+e['size']for e in d.segments if e['name']in('__TEXT','__TEXT_EXEC')));names=[n for n,e in lib.exports.items()if e.get('address')==target];assert names;stubs.append({'address':hex(a),'bytes16_hex':raw.hex(),'pointer':ptr,'target':hex(target),'dylib':lib.path,'exact_exports':names})
 binds=[]
 for name in CF_NAMES:
  slot=next(a for a,e in FIXUPS.items()if e['target']=='CoreFoundation/_'+name);binds.append({'binding':binding(slot),'captured_CF_export':cf.exports['_'+name]})
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in cs['original_cache_pages']};ranges=[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in fs]+[(a,16)for a in STUBS]+[(int(e['pointer']['address'],16),8)for e in stubs]+[(a,16)for a in BOUNDARIES]+[(0x184aa3b86,64),(0x1ed8912b8,8),(0x1ed8913f0,8)]
 for a,n in ranges:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 files=sorted(c.used|{e['path']for e in cs['cache_files']}|{str(CACHE)});cfsource={**cs,'CF_functions':fs,'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files]};daemon=json.loads((ROOT/'daemon_descriptor_source_source.json').read_text())
 return{'scope':__doc__,'generator_sha256':sha(__file__),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['cf_public_runloop_source.json','cf_public_runloop_profiles.json','cf_public_runloop_checks.json','daemon_descriptor_source_source.json','daemon_descriptor_source_profiles.json','daemon_descriptor_source_checks.json','probe_cf_public_runloop.py','replay_cf_public_runloop.py','cf_runloop_wake_port_profiles.json']},'CF_source':cfsource,'root_caller_options':old['root_caller_options'],'bridge_functions':[hex(a)for a in sorted(FUNCS)],'original_daemon_ranges':daemon['original_ranges'],'daemon_to_CF_bindings':binds,'default_mode_original_addend':daemon['default_mode_binding'],'new_lower_stubs':stubs,'new_lower_boundaries':[{'address':hex(a),'role':role,'original_prefix16_hex':c.read(a,16).hex(),'exact_nlist':cf.symbols_at(a)}for a,role in BOUNDARIES.items()],'original_null_device64_hex':c.read(0x184aa3b86,64).hex(),**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'CF_functions':len(s['CF_source']['CF_functions']),'CF_instructions':sum(len(f['instructions'])for f in s['CF_source']['CF_functions'])+4*len(s['CF_source']['import_stubs']),'cache_files':len(s['CF_source']['cache_files']),'CF_bound_slots':len(s['daemon_to_CF_bindings']),'new_lower_stubs':len(s['new_lower_stubs'])}),flush=True)
