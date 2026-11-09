#!/usr/bin/env python3
"""Original source0 collection/dispatch/callout and CF autorelease wrappers.
Read-only cache identities and complete bodies. No native runtime/IPC/PAC.
O(source bytes+captured ranges) time/space.
"""
import json
from pathlib import Path
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_cf_receive import CF_PATH
from recover_cf_descriptor_source_factory import FLAGS,sha
P='cf_source0_scheduler';DO=0x184758504;COLLECT=0x1847586e4;ONE=0x1847587d4;CALLOUT=0x184758904;SETAPPLY=0x18471c38c;SETBLOCK=0x18471c6e0;SETCOUNT=0x18472907c;HASHCOUNT=0x1847290e4;TYPE=0x1846f7d14;PUSH=0x1846e13d0;END=0x184832a70;POP=0x18471445c;COMPARE=0x184794e44
FUNCS={DO,COLLECT,ONE,CALLOUT,SETAPPLY,SETBLOCK,SETCOUNT,HASHCOUNT,TYPE,PUSH,END,POP,COMPARE};STUBS=[0x188076e60,0x188076e50,0x188076ab0,0x1880773c0,0x1880773e0]
def build():
 old=json.loads((ROOT/'cf_descriptor_source_factory_source.json').read_text());cs=old['CF_source'];c=Cache();d=Dylib(c,CF_PATH);fs=list(cs['CF_functions']);known={int(f['start'],16)for f in fs}
 for a in sorted(FUNCS-known):f=d.function(a);f['exact_nlist']=d.symbols_at(a);fs.append(f)
 libs=[Dylib(c,e['path'])for e in c.images if e['path'].rsplit('/',1)[-1]in('libobjc.A.dylib','libsystem_kernel.dylib','libsystem_pthread.dylib')];stubs=[]
 for a in STUBS:
  raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];at=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(at);target=int(ptr['target'],16);owner=next(d for d in libs if any(e['address']<=target<e['address']+e['size']for e in d.segments if e['name']in('__TEXT','__TEXT_EXEC')));names=[n for n,e in owner.exports.items()if e.get('address')==target];assert names;stubs.append({'address':hex(a),'bytes16_hex':raw.hex(),'pointer':ptr,'target':hex(target),'dylib':owner.path,'exact_exports':names})
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in cs['original_cache_pages']};ranges=[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in fs]+[(a,16)for a in STUBS]+[(int(e['pointer']['address'],16),8)for e in stubs]+[(0x1e0261e80,64),(0x1e232d5b0,64)]
 for a,n in ranges:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 files=sorted(c.used|{e['path']for e in cs['cache_files']}|{str(CACHE)});out={**cs,'CF_functions':fs,'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files]}
 run=next(f for f in fs if f['start']=='0x184756e7c');site=next(i for i in run['instructions']if i['mnemonic']=='bl'and i['operands']=='#'+hex(DO));assert site['ea']=='0x1847571b8'
 return{'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['cf_descriptor_source_factory_source.json','cf_descriptor_source_factory_profiles.json','cf_descriptor_source_factory_checks.json','probe_cf_descriptor_source_factory.py','replay_cf_descriptor_source_factory.py','cf_runloop_wake_port_profiles.json']},'CF_source':out,'root_caller_options':old['root_caller_options'],'scheduler_functions':[hex(a)for a in sorted(FUNCS)],'new_lower_stubs':stubs,'original_RUN_callsite':site,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'CF_functions':len(s['CF_source']['CF_functions']),'CF_instructions':sum(len(f['instructions'])for f in s['CF_source']['CF_functions'])+4*len(s['CF_source']['import_stubs']),'cache_files':len(s['CF_source']['cache_files']),'new_lower_stubs':len(s['new_lower_stubs'])}),flush=True)
