#!/usr/bin/env python3
"""Original public run-loop wrappers, indexed context, cleanup and TSD access.
Static cache/daemon-bind provenance only; no native CF/IPC/threads/PAC.
O(source bytes+captured ranges) time/space.
"""
import json,struct
from pathlib import Path
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache,Dylib,CACHE
from recover_cf_receive import CF_PATH
from recover_cf_source0_scheduler import FLAGS,sha
from daemon_import_bindings import binding
P='cf_public_runloop';SPEC=0x1847568e8;INMODE=0x184756870;PUBLICRUN=0x1847cf374;WITH=0x1848319f8;CLEAN=0x184832a04;CURRENT=0x184717c88;GET=0x1846dbbb8;GETCREATE=0x1846dbbc0;TABLE=0x1846dbc30;SET=0x1846ddde4;EMPTY=0x184756d34;STOP=0x184784250;COPYMODE=0x1848316fc
FUNCS={SPEC,INMODE,PUBLICRUN,WITH,CLEAN,CURRENT,GET,GETCREATE,TABLE,SET,EMPTY,STOP,COPYMODE};FATALS={0x1848d407c:'depth_limit',0x1848d460c:'type_mismatch',0x1848d4034:'fork_diagnostic'}
def build():
 old=json.loads((ROOT/'cf_source0_scheduler_source.json').read_text());cs=old['CF_source'];c=Cache();cf=Dylib(c,CF_PATH);fs=list(cs['CF_functions']);known={int(f['start'],16)for f in fs}
 for a in sorted(FUNCS-known):f=cf.function(a);f['exact_nlist']=cf.symbols_at(a);fs.append(f)
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in cs['original_cache_pages']};bounds=[{'address':hex(a),'role':role,'original_prefix16_hex':c.read(a,16).hex(),'exact_nlist':cf.symbols_at(a)}for a,role in[(0x1846df588,'declared_mode_name_CFEqual')]+list(FATALS.items())]
 ranges=[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in fs]+[(int(e['address'],16),16)for e in bounds]+[(0x1eb15a448,8),(0x1e233b370,64),(0x184951c40,40),(0x1e05d4e70,64)]
 for a,n in ranges:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 files=sorted(c.used|{e['path']for e in cs['cache_files']}|{str(CACHE)});out={**cs,'CF_functions':fs,'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files]}
 return{'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['cf_source0_scheduler_source.json','cf_source0_scheduler_profiles.json','cf_source0_scheduler_checks.json','probe_cf_source0_scheduler.py','replay_cf_source0_scheduler.py','daemon_descriptor_source_source.json','cf_runloop_wake_port_profiles.json']},'CF_source':out,'root_caller_options':old['root_caller_options'],'public_functions':[hex(a)for a in sorted(FUNCS)],'named_exports':{n:cf.exports[n]for n in('_CFRunLoopRun','_CFRunLoopRunInMode','_CFRunLoopRunSpecific','_CFRunLoopGetCurrent','_CFRunLoopGetMain','_CFRunLoopStop')},'selected_daemon_bindings':[binding(a)for a in(0x1010a0270,0x1010a0690,0x1010a08f8)],'new_boundaries':bounds,'public_RUN_duration':{'address':'0x184951c40','bytes8_hex':c.read(0x184951c40,8).hex(),'seconds':struct.unpack('<d',c.read(0x184951c40,8))[0]},'internal_deadline_threshold':{'address':'0x184951c58','bytes8_hex':c.read(0x184951c58,8).hex(),'seconds':struct.unpack('<d',c.read(0x184951c58,8))[0]},'original_warning_once8_hex':c.read(0x1eb15a448,8).hex(),**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'CF_functions':len(s['CF_source']['CF_functions']),'captured_instructions':sum(len(f['instructions'])for f in s['CF_source']['CF_functions'])+4*len(s['CF_source']['import_stubs']),'cache_files':len(s['CF_source']['cache_files']),'duration_s':s['public_RUN_duration']['seconds'],'threshold_s':s['internal_deadline_threshold']['seconds']}),flush=True)
