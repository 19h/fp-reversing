#!/usr/bin/env python3
"""Capture original CF Mach-port construction, invalidation and right cleanup.
Read-only cache/daemon provenance. O(source bytes+instructions), O(capture bytes).
"""
import json,struct
from pathlib import Path
from bootpolicy_cache_reader import Cache,Dylib,CS,CACHE
from recover_cf_receive import CF_PATH
from recover_cf_public_runloop import FLAGS,sha
from daemon_import_bindings import binding
from daemon_receive_tools import FIXUPS,IMAGE,SOURCE
P='cf_mach_port_retirement';ROOT=Path(__file__).resolve().parent
CREATE=0x184752484;WITH=0x18472cfe8;INVALID=0x184779fe8;DESTROY=0x18477a54c
INTENT=0x184751868;CANCEL=0x184812c64;DEAD=0x184810424;RECORD=0x18477a700;CLEAN=0x18477a854
NS_INTEREST=0x18476d9ac;NS_RECORD=0x18477a2d0;RETAIN_RECORD=0x184751a00;RELEASE_RECORD=0x18477a6ac
FUNCS=[CREATE,WITH,0x184812774,0x1848121b0,INVALID,DESTROY,INTENT,CANCEL,DEAD,RECORD,CLEAN,NS_INTEREST,NS_RECORD,RETAIN_RECORD,RELEASE_RECORD,0x18477a448,0x18472cff0]
BOUNDARIES={0x1846da4dc:'runtime_create',0x1846db030:'CF_retain',0x1846e1278:'CF_release',0x184833260:'ObjC_type_check',0x1846f5978:'array_count',0x1846f7424:'array_value',0x1846f5c74:'array_append',0x18472ef50:'array_remove',0x184718000:'set_value',0x184716e68:'set_add',0x184717024:'set_remove',0x184751868:'intent_original',0x184779a30:'source_invalidate_request',0x18800e750:'ObjC_invalidate_dispatch',0x18476f510:'log_object'}
DATA=[(0x1ed890000,4096),(0x1ed891000,4096),(0x1e01c8000,4096),(0x1848fc000,4096),(0x1e232e000,4096),(0x1e05d9000,4096)]
def build():
 c=Cache();d=Dylib(c,CF_PATH);assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a'and d.uuid=='7fe5392e-ff16-31e1-8552-3a45c6b68224'
 fs=[];stub_addresses=set()
 for a in FUNCS:
  f=d.function(a);f['nlist']=d.symbols_at(a);fs.append(f)
  for i in f['instructions']:
   if i['mnemonic']in('bl','b')and i['operands'].startswith('#0x188'):stub_addresses.add(int(i['operands'][1:],16)) if int(i['operands'][1:],16)>=0x188060000 else None
 libs={};stubs=[]
 for a in sorted(stub_addresses):
  raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(cell);target=int(ptr['target'],16);path=max((x for x in c.images if x['address']<=target),key=lambda x:x['address'])['path']
  if path not in libs:libs[path]=Dylib(c,path)
  names=[n for n,e in libs[path].exports.items()if e.get('address')==target];assert names
  stubs.append({'address':hex(a),'bytes16_hex':raw.hex(),'pointer':ptr,'target':hex(target),'dylib':path,'uuid':libs[path].uuid,'exact_exports':names})
 pages={}
 for a,n in DATA+[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in fs]+[(a,16)for a in stub_addresses]+[(a,16)for a in BOUNDARIES]:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 # Original daemon binds/windows retain the caller provenance without IDB edits.
 names=['CFMachPortCreate','CFMachPortCreateWithPort','CFMachPortInvalidate'];binds=[binding(next(a for a,e in FIXUPS.items()if e['target']=='CoreFoundation/_'+n))for n in names]
 windows=[{'address':hex(a),'bytes_hex':IMAGE.read(a,n).hex()}for a,n in[(0x100001f50,144),(0x1001f4cd0,96),(0x1004ace50,64)]]
 kernel=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib');retirement=[]
 for a in(0x18054906c,0x180548320,0x180547ac8,0x180547ad4,0x18056c8a4,0x18056c9c0):
  f=kernel.function(a);f['nlist']=kernel.symbols_at(a);retirement.append(f)
 constants=[{'address':hex(a),'bytes_hex':c.read(a,8).hex()}for a in(0x18057d3e0,0x18057d608,0x18057d618,0x18057d620,0x1eb065de0)]
 files=sorted(c.used|{str(CACHE)})
 return{'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['bootpolicy_cache_reader.py','recover_cf_receive.py','daemon_import_bindings.py','daemon_receive_tools.py','daemon_cf_descriptor_bridge_checks.json','cf_receive_contracts.json']},'cache_uuid':c.uuid,'CF_uuid':d.uuid,'daemon_sha256':sha(SOURCE),'functions':fs,'stubs':stubs,'boundaries':[{'address':hex(a),'role':n,'prefix16_hex':c.read(a,16).hex(),'nlist':d.symbols_at(a)}for a,n in BOUNDARIES.items()],'pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files],'daemon_bindings':binds,'daemon_windows':windows,'retirement_library_functions_static_only':retirement,'retirement_RPC_constants':constants,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'functions':len(s['functions']),'instructions':sum(len(f['instructions'])for f in s['functions']),'stubs':len(s['stubs']),'cache_files':len(s['cache_files'])}),flush=True)
