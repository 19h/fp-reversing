#!/usr/bin/env python3
"""Pin original source registration, collection wrappers and Mach port wrappers.
O(source+symbols+full cache hashes), O(source+symbols+hash block). No native
CoreFoundation, Mach, TSD or hardware PAC; runtime objects remain premises.
"""
import json,struct
from pathlib import Path
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_cf_runloop_handoff import CacheView,initial_max_engine
from recover_daemon_request_consumption import FLAGS,sha
from recover_cf_receive import CF_PATH,CF_UUID
P='cf_source_scheduling';ADD=0x18472d934;GETPORT=0x1847e8924;DSET=0x1846dcc44;DGET=0x1846ddc8c;FIND=0x1846ddd5c;SETADD=0x184716e68;CONTAINS=0x184718234;BAGADD=0x18472dd48
TYPE_TRAP=0x180547cc0;INSERT_TRAP=0x180547af8;TASK_CELL=0x1ed83e960
HELPERS={0x184833380:'CF_info_PAC_contract',0x184833694:'CF_type43_contract',0x184833260:'non_ObjC_contract',0x1848316fc:'existing_mode_contract',0x1846dcd84:'BasicHash_set_contract',0x1846fb710:'BasicHash_count_contract',0x1846fb960:'BasicHash_add_contract',0x18489b724:'BasicHash_find_bucket_contract',TYPE_TRAP:'mach_port_type_trap_contract',INSERT_TRAP:'mach_port_insert_member_trap_contract'}
def build():
 old=json.loads((ROOT/'cf_runloop_handoff_source.json').read_text());c=Cache();cf=Dylib(c,CF_PATH);lk=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib');assert c.uuid==old['cache_uuid']and cf.uuid==CF_UUID;funcs=list(old['CF_functions'])
 for lib,a in[(cf,a)for a in(ADD,GETPORT,DSET,DGET,FIND,SETADD,CONTAINS,BAGADD)]+[(lk,0x18054a938),(lk,0x180549f50)]:f=lib.function(a);f['exact_nlist']=lib.symbols_at(a);funcs.append(f)
 stubs=list(old['import_stubs'])
 for a,target,label in((0x188076bc0,0x18054a938,'_mach_port_type'),(0x188085b80,0x180549f50,'_mach_port_insert_member')):
  raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];slot=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(slot);assert int(ptr['target'],16)==target and lk.exports[label]['address']==target;stubs.append({'start':hex(a),'end':hex(a+16),'bytes':raw.hex(),'pointer':ptr,'exact_export':label,'target':hex(target),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 extra=list(old['extra_pointer_fixups'])+[c.pointer(0x1e01c8b30)];assert extra[-1]['target']==hex(TASK_CELL);extra[-1]['exact_nlist']=lk.symbols_at(TASK_CELL);assert any(e['name']=='_mach_task_self_'for e in extra[-1]['exact_nlist']);helpers=[]
 for a,name in HELPERS.items():lib=lk if a in(TYPE_TRAP,INSERT_TRAP)else cf;helpers.append({'address':hex(a),'role':name,'original_bytes16_hex':c.read(a,16).hex(),'exact_nlist':lib.symbols_at(a)})
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in old['original_cache_pages']};ranges=[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in funcs+stubs]+[(int(f['pointer']['address'],16),8)for f in stubs]+[(int(e['address'],16),16)for e in helpers]+[(0x1ed891720,1),(TASK_CELL,8)]
 for a,n in ranges:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 out={**old,'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['cf_runloop_handoff_source.json','cf_runloop_handoff_profiles.json','cf_runloop_handoff_checks.json','probe_cf_runloop_handoff.py','replay_cf_runloop_handoff.py','bootpolicy_cache_reader.py']},'CF_functions':funcs,'import_stubs':stubs,'extra_pointer_fixups':extra,'scheduling_helper_boundaries':helpers,'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())]};files=sorted(c.used|{r['path']for r in old['cache_files']}|{str(CACHE)});out['cache_files']=[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files];return out
if __name__=='__main__':
 out=build();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(out['CF_functions']),'instructions':sum(len(f['instructions'])for f in out['CF_functions'])+4*len(out['import_stubs']),'cache_files':len(out['cache_files'])}),flush=True)
