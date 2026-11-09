#!/usr/bin/env python3
"""Original CF mode construction, dispatch root queue, timer callback and ports.
O(source+symbols+cache hashes), O(source+symbols+hash block). Original bodies
are captured; raw CF/dispatch objects and lower APIs remain explicit premises.
"""
import json,struct
from pathlib import Path
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_cf_runloop_handoff import CacheView
from recover_daemon_request_consumption import FLAGS,sha
from recover_cf_receive import CF_PATH,CF_UUID
P='cf_mode_construction';COPYMODE=0x1848316fc;SETGET=0x184718000;ROOTCREATE=0x18554a160;ROOTINIT=0x1855221f4;ROOTGET=0x18552296c;CALLBACK=0x1848329a8;FORK=0x185522f20;ALLOC_TRAP=0x180547abc;CONSTRUCT_TRAP=0x180547b10;MK=0x180547cfc
BOUNDARIES={0x1846dc364:'runtime_key_type44_contract',0x1846da4dc:'runtime_mode_storage_contract',0x1846df2ec:'immutable_name_copy_contract',0x180588798:'mutexattr_init_contract',0x1805887c8:'mutexattr_type2_contract',0x1805884cc:'mode_mutex_init_contract',0x18058891c:'mutexattr_destroy_contract',0x1855140c8:'dispatch_object_storage_contract',ALLOC_TRAP:'original_kernel_pset_allocate_return',CONSTRUCT_TRAP:'root_port_construct_contract',MK:'kernel_timer_create_contract',0x18552896c:'dispatch_timer_source_create_contract',0x18552955c:'dispatch_timer_event_handler_contract',0x185528b10:'dispatch_runloop_timer_parameters_contract',0x185514684:'dispatch_resume_contract',0x18550ebf8:'block_byref_dispose_contract',0x184716d78:'mutable_source_set_create_contract',0x1846dbcac:'mutable_source_dictionary_create_contract'}
STUBS=[0x1880773f0,0x188077400,0x1880773b0,0x18807b8a0,0x188076b80,0x1880868d0,0x1880868e0,0x188076640,0x188076680,0x1880766a0,0x1880765e0,0x188080dc0,0x18806c020,0x18806cf30]
FAILURES=[0x1848d3ee4,0x1848d4020,0x1848d3fd0,0x1848d400c,0x1848d3fe4,0x1848d3ff8]
def build():
 old=json.loads((ROOT/'kernel_portset_delivery_source.json').read_text())['CF_source'];c=Cache();cf=Dylib(c,CF_PATH);ld=Dylib(c,'/usr/lib/system/libdispatch.dylib');lk=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib');assert c.uuid==old['cache_uuid']and cf.uuid==CF_UUID;funcs=list(old['CF_functions'])
 for lib,a in[(cf,COPYMODE),(cf,SETGET),(cf,CALLBACK),(ld,ROOTCREATE),(ld,ROOTINIT),(ld,ROOTGET),(ld,0x185549410),(ld,FORK),(lk,0x180549ee0),(lk,0x180548e9c),(lk,MK)]:f=lib.function(a);f['exact_nlist']=lib.symbols_at(a);funcs.append(f)
 stubs=list(old['import_stubs']);libs={CF_PATH:cf,ld.path:ld,lk.path:lk}
 for a in STUBS:
  raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(cell);target=int(ptr['target'],16);path=max((e for e in c.images if e['address']<=target),key=lambda e:e['address'])['path']
  if path not in libs:libs[path]=Dylib(c,path)
  names=libs[path].symbols_at(target);stubs.append({'start':hex(a),'end':hex(a+16),'bytes':raw.hex(),'pointer':ptr,'target':hex(target),'exact_nlist':names,'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 extras=list(old['extra_pointer_fixups'])+[c.pointer(a)for a in(0x1e01c8768,0x1e01c8888)];helpers=[]
 for a,role in BOUNDARIES.items():helpers.append({'address':hex(a),'role':role,'original_bytes16_hex':c.read(a,16).hex()})
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in old['original_cache_pages']};ranges=[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in funcs+stubs]+[(int(f['pointer']['address'],16),8)for f in stubs]+[(a,16)for a in list(BOUNDARIES)+FAILURES]+[(a,n)for a,n in[(0x1ed897df0,128),(0x1ed8991c0,8),(0x1ed8999d0,1),(0x1ed899b90,1),(0x185550590,32),(0x18494e130,8),(0x1848fc7e8,8),(0x1e2330700,16)]]
 for a,n in ranges:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 descriptor=c.read(0x1e2330700,16);byref=c.read(0x18494e130,8);assert struct.unpack('<2Q',descriptor)==(0,40)and struct.unpack('<2I',byref)[1]==32
 files=sorted(c.used|{r['path']for r in old['cache_files']}|{str(CACHE)})
 return{**old,'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['kernel_portset_delivery_source.json','kernel_portset_delivery_profiles.json','kernel_portset_delivery_checks.json','probe_kernel_portset_delivery.py','replay_kernel_portset_delivery.py','bootpolicy_cache_reader.py']},'CF_functions':funcs,'import_stubs':stubs,'extra_pointer_fixups':extras,'mode_boundary_models':helpers,'timer_block_layout':{'descriptor_address':'0x1e2330700','descriptor16_hex':descriptor.hex(),'block_size_bytes':40,'byref_template_address':'0x18494e130','byref_template8_hex':byref.hex(),'byref_size_bytes':32},'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files]}
if __name__=='__main__':
 out=build();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(out['CF_functions']),'instructions':sum(len(f['instructions'])for f in out['CF_functions'])+4*len(out['import_stubs']),'stubs':len(out['import_stubs']),'cache_files':len(out['cache_files'])}),flush=True)
