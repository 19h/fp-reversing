#!/usr/bin/env python3
"""Original run-loop creation/wakeup and kernel wake-port construct/member ABI.
Wake send results, runtime storage/backends and inherited lower contracts remain
explicit; no native daemon/kernel/Mach IPC/scheduling or hardware PAC effects.
"""
import json,struct
from pathlib import Path
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_cf_receive import CF_PATH
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='cf_runloop_wake_port';CREATE=0x184717e70;WAKE=0x18473ae10;CHECK=0x184758964;MACH=0x180547f94;DEFAULT=0x1e233b370;QLIMIT=0xfffffe000bcc8c60

def build():
 im=Image();old=json.loads((ROOT/'kernel_timer_port_create_source.json').read_text());fs=list(old['functions'])
 if QLIMIT not in{int(f['start'],16)for f in fs}:f=im.k.function(QLIMIT);f['exact_symbols']=im.k.symbols([QLIMIT])[hex(QLIMIT)];fs.append(f)
 cs=old['CF_source'];c=Cache();cf=Dylib(c,CF_PATH);lk=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib');funcs=list(cs['CF_functions'])
 for lib,a in[(cf,CREATE),(cf,WAKE),(cf,CHECK),(lk,MACH)]:
  if a not in{int(f['start'],16)for f in funcs}:f=lib.function(a);f['exact_nlist']=lib.symbols_at(a);funcs.append(f)
 stubs=list(cs['import_stubs']);a=0x188076b90;raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(cell);assert ptr['target']=='0x180548e9c';stubs.append({'start':hex(a),'end':hex(a+16),'bytes':raw.hex(),'pointer':ptr,'target':ptr['target'],'exact_nlist':lk.symbols_at(0x180548e9c),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in cs['original_cache_pages']};ranges=[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in funcs+stubs]+[(cell,8),(0x184951c48,8),(0x184951c70,24),(DEFAULT,64),(0x1e2330990,64),(0x1848d4168,16),(0x1848d3f28,16)]
 for a,n in ranges:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 files=sorted(c.used|{e['path']for e in cs['cache_files']}|{str(CACHE)});options=c.read(0x184951c70,24);assert options==struct.pack('<IIQQ',0x33,1,0,0)and c.read(0x184951c48,8)==struct.pack('<2I',0x13,24)
 cfsource={**cs,'CF_functions':funcs,'import_stubs':stubs,'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files]}
 sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach');headers=[sdk/'port.h',sdk/'message.h'];constants={'MPO_CONTEXT_AS_GUARD':1,'MPO_QLIMIT':2,'MPO_INSERT_SEND_RIGHT':16,'MPO_STRICT':32,'MACH_SEND_TIMED_OUT':0x10000004,'MACH_SEND_INTERRUPTED':0x10000007};import re
 for name,value in constants.items():assert any(re.search(r'^#define\s+'+name+r'\s+(0x[0-9a-fA-F]+)',h.read_text(),re.M)and int(re.search(r'^#define\s+'+name+r'\s+(0x[0-9a-fA-F]+)',h.read_text(),re.M).group(1),16)==value for h in headers)
 return{**old,'SDK_wake_constants':constants,'SDK_wake_headers':[{'path':str(h),'sha256':sha(h),'size_bytes':h.stat().st_size}for h in headers],'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['kernel_timer_port_create_source.json','kernel_timer_port_create_profiles.json','kernel_timer_port_create_checks.json','probe_kernel_timer_port_create.py','replay_kernel_timer_port_create.py','bootpolicy_cache_reader.py']},'functions':fs,'CF_source':cfsource,'wake_original_options24_hex':options.hex(),'wake_original_message_constant8_hex':c.read(0x184951c48,8).hex(),'default_mode_constant_address':hex(DEFAULT)}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'kernel_functions':len(s['functions']),'kernel_instructions':sum(len(f['instructions'])for f in s['functions']),'CF_functions':len(s['CF_source']['CF_functions']),'CF_instructions':sum(len(f['instructions'])for f in s['CF_source']['CF_functions'])+4*len(s['CF_source']['import_stubs']),'cache_files':len(s['CF_source']['cache_files'])}),flush=True)
