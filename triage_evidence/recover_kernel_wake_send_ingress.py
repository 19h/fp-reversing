#!/usr/bin/env python3
"""Original -47 wake send ingress using source-produced CF trap packets.
No native exception crossing, Mach IPC, allocator, scheduling or hardware PAC.
"""
import json
from pathlib import Path
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_cf_receive import CF_PATH
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from recover_cf_wake_send_wrapper import FLAGS,sha
from replay_cf_runloop_handoff import unpack,LOW,LOW_SIZE
P='kernel_wake_send_ingress';HANDLER=0xfffffe000bcdd73c;SEND=0xfffffe000bcdd350;ROFLAGS=0xfffffe000bd41068
EXTRA=[SEND,ROFLAGS,0xfffffe000be82050,0xfffffe000bcca864,0xfffffe000bcd51c0,0xfffffe000bcd3620,0xfffffe000bccff4c,0xfffffe000bcd9d40,0xfffffe000bcd50d4,0xfffffe000bccabd4]
def build():
 im=Image();old=json.loads((ROOT/'cf_wake_send_wrapper_source.json').read_text());fs=list(old['functions']);known={int(f['start'],16)for f in fs}
 for a in EXTRA:
  if a not in known:f=im.k.function(a);f['exact_symbols']=im.k.symbols([a])[hex(a)];fs.append(f)
 profiles=json.loads((ROOT/'cf_wake_send_wrapper_profiles.json').read_text());packets=[]
 for j in(1,6):
  r=profiles['cases'][j];svc=r['SVC_return_contracts'][0];stack=unpack(r['final_lower_stack'],LOW,LOW_SIZE);a=int(svc['original_header_pointer'],16);header=stack[a-LOW:a-LOW+24];assert header.hex()==svc['before']['original_header24_hex'];regions=[{'address':hex(a),'bytes_hex':header.hex(),'role':'original_CF_header24'}]
  if svc['vector48_hex']:
   a=int(svc['arguments8'][0],16);vec=stack[a-LOW:a-LOW+48];assert vec.hex()==svc['vector48_hex'];regions.append({'address':hex(a),'bytes_hex':vec.hex(),'role':'original_libkernel_vector48'});a=int.from_bytes(vec[24:32],'little');aux=stack[a-LOW:a-LOW+40];assert aux.hex()==svc['aux40_hex'];regions.append({'address':hex(a),'bytes_hex':aux.hex(),'role':'original_dispatch_aux40'})
  packets.append({'CF_case_index':j,'label':r['configuration']['label'],'arguments8':svc['arguments8'],'regions':regions,'lower_stack':r['final_lower_stack'],'native_crossing':False})
 c=Cache();cf=Dylib(c,CF_PATH);objc=Dylib(c,'/usr/lib/libobjc.A.dylib');cs=old['CF_source'];cfs=list(cs['CF_functions']);stubs=list(cs['import_stubs']);pools={}
 for a in(0x1846e13d0,0x18471445c):f=cf.function(a);f['exact_nlist']=cf.symbols_at(a);cfs.append(f)
 for a,role,name in((0x188076e60,'push','_objc_autoreleasePoolPush'),(0x188076e50,'pop','_objc_autoreleasePoolPop')):
  raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(cell);target=int(ptr['target'],16);assert objc.exports[name]['address']==target;pools[role]={'target':hex(target),'name':name,'original_prefix16_hex':c.read(target,16).hex()};stubs.append({'start':hex(a),'end':hex(a+16),'bytes':raw.hex(),'pointer':ptr,'target':hex(target),'exact_nlist':objc.symbols_at(target),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in cs['original_cache_pages']}
 for a,n in[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in cfs+stubs]+[(int(f['pointer']['address'],16),8)for f in stubs]+[(int(e['target'],16),16)for e in pools.values()]:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 files=sorted(c.used|{e['path']for e in cs['cache_files']}|{str(CACHE)});cfsource={**cs,'CF_functions':cfs,'import_stubs':stubs,'pool_runtime_boundaries':pools,'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files]}
 return{**old,'CF_source':cfsource,'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['cf_wake_send_wrapper_source.json','cf_wake_send_wrapper_profiles.json','cf_wake_send_wrapper_checks.json','cf_runloop_wake_port_profiles.json','probe_cf_runloop_wake_port.py','replay_cf_runloop_wake_port.py']},'functions':fs,'CF_original_trap_packets':packets}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'kernel_functions':len(s['functions']),'instructions':sum(len(f['instructions'])for f in s['functions']),'original_CF_packets':len(s['CF_original_trap_packets'])}),flush=True)
