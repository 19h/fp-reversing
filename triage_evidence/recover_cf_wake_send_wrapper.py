#!/usr/bin/env python3
"""Original CF wake -> libkernel packing/retry -> intercepted Mach -47 boundary.
No native Mach send, kernel entry, scheduler, ownership or hardware PAC effects.
"""
import json
from pathlib import Path
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache,Dylib,CACHE
from recover_cf_runloop_wake_port import FLAGS,sha
from kernel_vm_mig_tools import Image
import struct
P='cf_wake_send_wrapper';MACH=0x180547f94;OVERWRITE=0x180550848;INTERNAL=0x18055a894;TRAP=0x180547c18;SVC=TRAP+4;AUX=0x18553c2a8

def build():
 old=json.loads((ROOT/'cf_runloop_wake_port_source.json').read_text());cs=old['CF_source'];c=Cache();lk=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib');fs=list(cs['CF_functions'])
 for a in(OVERWRITE,INTERNAL,TRAP):
  assert a not in{int(f['start'],16)for f in fs};f=lk.function(a);f['exact_nlist']=lk.symbols_at(a);fs.append(f)
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in cs['original_cache_pages']}
 for a,n in[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in fs]+[(0x185550960,16)]:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 header=ROOT/'xnu_osfmk_mach_message.h';ref=next(e for e in json.loads((ROOT/'daemon_receive_public_sources.json').read_text())if e['path']==header.name);assert sha(header)==ref['sha256'];files=sorted(c.used|{e['path']for e in cs['cache_files']}|{str(CACHE)})
 im=Image();prior=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text());row=next(e for e in prior['mach_entries']if e['index']==47);record=0xfffffe0007efb010+24*47;assert im.k.sha256==old['kernel_sha256']
 assert(row['signed_selector'],row['name'],row['argument_count'],row['u32_words'],row['returns_port'])==(-47,'mach_msg2_trap',8,16,False)and struct.unpack('<4B',im.k.read(record,4))==(8,16,0,0)and im.pointer(record+8)==row['handler_pointer']and im.pointer(0xfffffe0007efbc10+8*47)==row['name_pointer']and im.k.read(int(row['name_pointer']['target'],16),len(b'mach_msg2_trap\0'))==b'mach_msg2_trap\0'
 handler=im.k.function(int(row['handler_pointer']['target'],16));handler['exact_symbols']=im.k.symbols([int(handler['start'],16)])[handler['start']];kernel_fs=old['functions']+[handler]
 return{**old,'functions':kernel_fs,'kernel_trap_binding':{**row,'record_address':hex(record),'record24_hex':im.k.read(record,24).hex(),'handler_executed':False},'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['cf_runloop_wake_port_source.json','cf_runloop_wake_port_profiles.json','cf_runloop_wake_port_checks.json','probe_cf_runloop_wake_port.py','replay_cf_runloop_wake_port.py','bootpolicy_cache_reader.py','kernel_dispatch_contracts.json']},'CF_source':{**cs,'CF_functions':fs,'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files]},'original_aux_constant16_hex':c.read(0x185550960,16).hex(),'pinned_public_header':{**ref,'exact_target_revision':False},'raw_send_trap':{'entry':hex(TRAP),'svc':hex(SVC),'selector':-47,'bytes12_hex':c.read(TRAP,12).hex(),'native_executed':False}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'CF_functions':len(s['CF_source']['CF_functions']),'CF_instructions':sum(len(f['instructions'])for f in s['CF_source']['CF_functions'])+4*len(s['CF_source']['import_stubs']),'cache_files':len(s['CF_source']['cache_files'])}),flush=True)
