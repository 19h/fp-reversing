#!/usr/bin/env python3
"""Original control-name dispatch, empty root drain and empty timer handling.
Pinned cache bodies; synthetic control receive contracts are explicitly distinct
from paired original-kernel service returns. No native IPC or scheduler effects.
"""
import json
from pathlib import Path
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_cf_receive import CF_PATH,CF_UUID
from recover_daemon_request_consumption import FLAGS,sha
P='cf_control_port_dispatch';ROOTPERFORM=0x185522410;TIMERS=0x184771f9c;ARM=0x18471cd5c;EMPTY=0x184756d34
BOUNDARIES={0x1855140d8:'declared_dispatch_root_retain',0x185514128:'declared_dispatch_root_release',0x18472907c:'declared_collection_cardinality'}
def build():
 old=json.loads((ROOT/'cf_mode_construction_source.json').read_text());c=Cache();cf=Dylib(c,CF_PATH);ld=Dylib(c,'/usr/lib/system/libdispatch.dylib');assert c.uuid==old['cache_uuid']and cf.uuid==CF_UUID;funcs=list(old['CF_functions'])
 for lib,a in[(ld,ROOTPERFORM),(cf,TIMERS),(cf,ARM),(cf,EMPTY)]:f=lib.function(a);f['exact_nlist']=lib.symbols_at(a);funcs.append(f)
 stubs=list(old['import_stubs']);a=0x1880868f0;raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(cell);assert int(ptr['target'],16)==ROOTPERFORM;stubs.append({'start':hex(a),'end':hex(a+16),'bytes':raw.hex(),'pointer':ptr,'target':hex(ROOTPERFORM),'exact_nlist':ld.symbols_at(ROOTPERFORM),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in old['original_cache_pages']}
 for a,n in[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in funcs+stubs]+[(cell,8)]+[(a,16)for a in BOUNDARIES]:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 files=sorted(c.used|{r['path']for r in old['cache_files']}|{str(CACHE)})
 return{**old,'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['cf_mode_construction_source.json','cf_mode_construction_profiles.json','cf_mode_construction_checks.json','probe_cf_mode_construction.py','replay_cf_mode_construction.py','bootpolicy_cache_reader.py']},'CF_functions':funcs,'import_stubs':stubs,'control_runtime_boundaries':[{'address':hex(a),'role':role,'original_bytes16_hex':c.read(a,16).hex(),'exact_nlist':(cf if a==0x18472907c else ld).symbols_at(a)}for a,role in BOUNDARIES.items()],'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files]}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'functions':len(s['CF_functions']),'instructions':sum(len(f['instructions'])for f in s['CF_functions'])+4*len(s['import_stubs']),'stubs':len(s['import_stubs'])}),flush=True)
