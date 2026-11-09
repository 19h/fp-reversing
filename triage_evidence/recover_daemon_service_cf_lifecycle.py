#!/usr/bin/env python3
"""Pin original daemon service check-in and CF source1 lifecycle in one epoch.
Static cache/daemon provenance; no native target effects. O(source+capture bytes).
"""
import json,struct
from pathlib import Path
from bootpolicy_cache_reader import Cache,Dylib,CS,CACHE
from recover_cf_receive import CF_PATH
from recover_cf_public_runloop import FLAGS,sha
from daemon_receive_tools import IMAGE,FIXUPS,ROOT
from daemon_import_bindings import binding
from probe_daemon_registration import RANGES
P='daemon_service_cf_lifecycle';CHECKIN=0x10044011c
FUNCS={0x18472cfe8,0x1848121b0,0x18472cff0,0x184779fe8,0x18472d178,0x18473094c,0x184779130,0x18054b360}
TYPE_TRAP=0x180547cc0;EXTRACT_TRAP=0x180547b04
BOUNDARIES={0x1846f5978:'service_registry_count',0x1846f7424:'service_registry_value',0x1846f5c74:'service_registry_append',0x18472ef50:'service_registry_remove',0x18476f510:'disabled_log_object',0x1880770a0:'disabled_log_type',EXTRACT_TRAP:'declared_service_extract_member'}
def build():
 old=json.loads((ROOT/'daemon_cf_descriptor_bridge_source.json').read_text());life=json.loads((ROOT/'cf_mach_port_retirement_source.json').read_text());src=old['CF_source'];c=Cache();cf=Dylib(c,CF_PATH);lk=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib');fs=list(src['CF_functions']);known={int(f['start'],16)for f in fs}
 for a in sorted(FUNCS-known):
  lib=lk if a<0x184000000 else cf;f=lib.function(a);f['exact_nlist']=lib.symbols_at(a);fs.append(f)
 a=0x188085b70;raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(cell);assert int(ptr['target'],16)==lk.exports['_mach_port_extract_member']['address']==0x18054b360
 stub={'start':hex(a),'end':hex(a+16),'bytes':raw.hex(),'pointer':ptr,'exact_export':'_mach_port_extract_member','target':'0x18054b360','instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]};stubs=list(src['import_stubs'])+[stub]
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in src['original_cache_pages']}
 for e in life['pages']:
  a=int(e['address'],16);raw=bytes.fromhex(e['bytes_hex'])
  if a in pages:assert pages[a]==raw
  pages[a]=raw
 for a,n in[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in fs]+[(0x188085b70,16),(cell,8)]+[(a,16)for a in BOUNDARIES]:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 files=sorted(c.used|{e['path']for e in src['cache_files']}|{e['path']for e in life['cache_files']}|{str(CACHE)})
 binds=list(old['daemon_to_CF_bindings'])
 for name in('CFMachPortCreateWithPort','CFMachPortCreateRunLoopSource','CFMachPortInvalidate'):
  slot=next(a for a,e in FIXUPS.items()if e['target']=='CoreFoundation/_'+name);binds.append({'binding':binding(slot),'captured_CF_export':cf.exports['_'+name]})
 cfsource={**src,'CF_functions':fs,'import_stubs':stubs,'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files]}
 return{'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['daemon_cf_descriptor_bridge_source.json','daemon_cf_descriptor_bridge_profiles.json','daemon_cf_descriptor_bridge_checks.json','cf_mach_port_retirement_source.json','cf_mach_port_retirement_checks.json','probe_daemon_cf_descriptor_bridge.py','probe_daemon_registration.py','daemon_registration_contracts.json']},'CF_source':cfsource,'root_caller_options':old['root_caller_options'],'daemon_to_CF_bindings':binds,'new_service_functions':[hex(a)for a in sorted(FUNCS)],'new_extract_stub':stub,'new_boundaries':[{'address':hex(a),'role':n,'prefix16_hex':c.read(a,16).hex(),'nlist':(lk if a==EXTRACT_TRAP else cf).symbols_at(a)}for a,n in BOUNDARIES.items()],'original_checkin_ranges':[{'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex()}for a,b in RANGES],'bootstrap_port_binding':binding(next(a for a,e in FIXUPS.items()if e['target']=='libSystem/_bootstrap_port')),**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'functions':len(s['CF_source']['CF_functions']),'instructions':sum(len(f['instructions'])for f in s['CF_source']['CF_functions'])+4*len(s['CF_source']['import_stubs']),'CF_bindings':len(s['daemon_to_CF_bindings']),'cache_files':len(s['CF_source']['cache_files'])}),flush=True)
