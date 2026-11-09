#!/usr/bin/env python3
"""Static original-byte capture of the IOKit open status boundary.
No target instructions executed/emulated, IPC, IDB changes or native effects.
Time O(image+fixups+symbols+selected cache files); space O(image+capture).
"""
import hashlib,json,re,struct
from pathlib import Path
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache,Dylib,CACHE
ROOT=Path(__file__).resolve().parent;P='kernel_iokit_open'
FLAGS=['native_target_executed','target_instructions_emulated','native_IPC_executed','hardware_PAC_executed','idb_mutated','historical_failure_cause_established','complete_FairPlay_round_trip_established','full_goal_complete']
KERNEL=[0xfffffe000be38c4c,0xfffffe000c56e604,0xfffffe000c4cc010,0xfffffe000c4cc000,0xfffffe000c562b14,0xfffffe000c4df840,0xfffffe000bd7e9c4,0xfffffe000c562a20]
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def trace_messages():
 p=Path('/Users/___/Downloads/zut/annotated-strace-rax-user.txt');assert sha(p)=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e';lines=p.read_text().splitlines();rows=[]
 for n,line in enumerate(lines):
  m=re.search(r' (send|received) bits=.* id=(2862|2962)\b',line)
  if not m:continue
  raw=bytearray();j=n+1
  while j<len(lines):
   h=re.search(r'\]\s+([0-9a-f]{4,})\s+((?:[0-9a-f]{2}\s+)+)\|',lines[j])
   if not h:break
   assert int(h[1],16)==len(raw);raw.extend(bytes.fromhex(h[2]));j+=1
  size=struct.unpack_from('<I',raw,4)[0];rows.append({'line':n+1,'direction':m[1],'id':int(m[2]),'message_hex':raw[:size].hex(),'trailer_hex':raw[size:].hex()})
 assert len(rows)==2
 return {'path':str(p),'sha256':sha(p),'lines':len(lines),'messages':rows,'transport_line1742':lines[1741],'cleanup_lines1743_1748':lines[1742:1748]}
def build():
 im=Image();fs=[im.k.function(a)for a in KERNEL];symbols=im.k.symbols(KERNEL)
 for f in fs:f['exact_symbols']=symbols[f['start']]
 a=0xfffffe000a5040d4;end=0xfffffe000a504320;raw=im.k.read(a,end-a);ks={'start':hex(a),'end':hex(end),'bound_source':'supplied adjacent initWithTask/start function declarations; full bytes compared to extracted kext','bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]}
 from resolve_kernel_collection_interfaces import KEXT,macho
 data=KEXT.read_bytes();own=macho(data,0,'extracted');sec=next(s for s in own['sections']if s['address']<=a< s['address']+s['size']);off=sec['file_offset']+a-sec['address'];assert data[off:off+len(raw)]==raw
 slots=[0xfffffe000846c070,0xfffffe000846c078,0xfffffe000846b178,0xfffffe000846b180,0xfffffe000847c5e0,0xfffffe000847c600];ptrs=[im.pointer(a)for a in slots];super_table=int(ptrs[4]['target'],16);ptrs.append(im.pointer(super_table+0x928));ps=im.k.symbols([int(p['target'],16)for p in ptrs])
 for p in ptrs:p['exact_symbols']=ps[p['target']]
 sub=next(s for s in im.subsystems()if s['start']<=2862<s['end']);r=next(r for r in sub['routines']if r['id']==2862);sub={k:v for k,v in sub.items()if k!='routines'}
 c=Cache();lib=Dylib(c,'/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit');cf=[]
 for a in(0x184e77b74,0x184e77bc0):f=lib.function(a);f['exact_nlist']=lib.symbols_at(a);cf.append(f)
 strings=[]
 for a in(0xfffffe000790af41,0xfffffe000790af72,0xfffffe000790afa3):raw=im.k.read(a,128).split(b'\0')[0]+b'\0';strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw[:-1].decode()})
 return {'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in('kernel_native_reader.py','kernel_vm_mig_tools.py','bootpolicy_cache_reader.py','resolve_kernel_collection_interfaces.py','zut_trace_decoded.json','daemon_iokit_objects_contracts.json','daemon_iokit_errors_contracts.json')},'kernel_sha256':im.k.sha256,'kernel_UUID':im.k.kernel['uuid'],'kext_sha256':sha(KEXT),'kext_UUID':own['uuid'],'kernel_functions':fs,'kext_initializer':ks,'original_chained_bindings':ptrs,'MIG_subsystem':sub,'MIG_routine2862':r,'trace':trace_messages(),'entitlement_strings':strings,'cache_UUID':c.uuid,'IOKit_UUID':lib.uuid,'cache_functions':cf,'cache_files':[{'path':p,'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'kernel_functions':len(s['kernel_functions']),'kext_functions':1,'cache_functions':2,'instruction_count':sum(len(f['instructions'])for f in s['kernel_functions']+s['cache_functions']+[s['kext_initializer']])}),flush=True)
