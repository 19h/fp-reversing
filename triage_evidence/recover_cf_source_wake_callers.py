#!/usr/bin/env python3
"""Pin CF direct WakeUp callers, source-signal/bag callback path and daemon imports.
Only static B/BL census and selected callback materialization are exhaustive.
No native caller attribution, CF/Mach IPC, scheduling or hardware PAC effects.
"""
import bisect,json,struct
from pathlib import Path
from daemon_receive_tools import ROOT,IMAGE,SOURCE,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from resolve_kernel_collection_interfaces import commands
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_cf_receive import CF_PATH
from recover_kernel_wake_send_ingress import FLAGS,sha
P='cf_source_wake_callers';SIGNAL=0x184751bcc;WAKELOOPS=0x1847b79c8;LOOP=0x1847b7c9c;COPY=0x1847b7aa0;APPLY=0x184779b58;HASHAPPLY=0x18471c4a0;INVOKE=0x184794ee0;WAKE=0x18473ae10
BOUNDARIES={0x1847290e4:'declared_bag_count',0x184749a88:'declared_hash_elements',0x18471aab0:'declared_hash_storage',0x1846f3564:'declared_hash_capacity',0x18471c584:'declared_hash_bucket'}
def census(c,d):
 sec=next(e for e in d.sections if e['name']=='__text');raw=c.read(sec['address'],sec['size']);refs=[];material=[];helper_refs=[]
 for off in range(0,len(raw)-3,4):
  w=struct.unpack_from('<I',raw,off)[0];pc=sec['address']+off
  if w&0xfc000000 in(0x14000000,0x94000000):
   imm=w&0x3ffffff;imm-=1<<26 if imm&(1<<25)else 0
   if pc+4*imm==WAKELOOPS:helper_refs.append({'pc':hex(pc),'target':hex(WAKELOOPS),'bytes_hex':raw[off:off+4].hex(),'caller_start':hex(d.functions[bisect.bisect_right(d.functions,pc)-1]),'caller_exact_nlist':d.symbols_at(d.functions[bisect.bisect_right(d.functions,pc)-1])})
   if pc+4*imm==WAKE:
    a=d.functions[bisect.bisect_right(d.functions,pc)-1];refs.append({'pc':hex(pc),'target':hex(WAKE),'kind':'BL'if w&0xfc000000==0x94000000 else'B','bytes_hex':raw[off:off+4].hex(),'caller_start':hex(a),'caller_exact_nlist':d.symbols_at(a)})
  if off+16>len(raw)or w&0x9f000000!=0x90000000:continue
  imm=((w>>5)&0x7ffff)<<2|((w>>29)&3);imm-=1<<21 if imm&(1<<20)else 0;page=(pc&~4095)+(imm<<12);reg=w&31
  for k in(4,8,12):
   v=struct.unpack_from('<I',raw,off+k)[0]
   if v&0xff000000!=0x91000000 or(v>>5)&31!=reg:continue
   add=((v>>10)&4095)<<(12 if(v>>22)&1 else 0)
   if page+add==LOOP:material.append({'adrp':hex(pc),'add':hex(pc+k),'callback':hex(LOOP),'bytes36_hex':c.read(pc,36).hex(),'caller_start':hex(d.functions[bisect.bisect_right(d.functions,pc)-1])})
 return{'section_address':hex(sec['address']),'section_size_bytes':sec['size'],'instruction_words_scanned':len(raw)//4,'section_sha256':__import__('hashlib').sha256(raw).hexdigest(),'direct_B_BL_refs':refs,'direct_source_wake_helper_B_BL_refs':helper_refs,'callback_ADRP_ADD_refs_within3_instructions':material}
def daemon_imports():
 data=IMAGE.data;at=next(a for a,cmd,n in commands(data,0)if cmd==0x80000034);off,n=struct.unpack_from('<II',data,at+8);version,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',data,off);assert(version,fmt,symfmt)==(0,2,0);names=[]
 for j in range(count):
  word,add=struct.unpack_from('<Ii',data,off+imports+8*j);so=off+symbols+(word>>9);name=data[so:data.index(0,so)].decode();names.append({'index':j,'name':name,'library_ordinal_raw':word&255,'weak':bool(word&256),'addend':add})
 terms=['_CFRunLoopWakeUp','_CFRunLoopSourceSignal','_CFRunLoopAddSource','_CFRunLoopRemoveSource','_CFRunLoopSourceInvalidate','__CFRunLoopSourceWakeUpRunLoops','_CFMachPortInvalidate'];slots=[a for a,e in FIXUPS.items()if isinstance(e.get('target'),str)and e['target'].split('/',1)[-1]in terms];assert len(slots)==2
 fdslots=[a for a,e in FIXUPS.items()if isinstance(e.get('target'),str)and'CFFileDescriptor'in e['target']];assert len(fdslots)==5
 return{'daemon_sha256':sha(SOURCE),'import_count':count,'import_format':fmt,'all_import_records':names,'queried_names':{name:[e for e in names if e['name']==name]for name in terms},'selected_bindings':[binding(a)for a in sorted(slots)],'selected_original_fixups':verify_original_fixups(slots),'file_descriptor_named_imports':[e for e in names if'CFFileDescriptor'in e['name']],'file_descriptor_bindings':[binding(a)for a in sorted(fdslots)],'file_descriptor_original_fixups':verify_original_fixups(sorted(fdslots)),'runtime_resolution_and_indirect_targets':'unknown'}
def build():
 old=json.loads((ROOT/'kernel_wake_send_ingress_source.json').read_text());cs=old['CF_source'];c=Cache();cf=Dylib(c,CF_PATH);scan=census(c,cf);fs=list(cs['CF_functions']);known={int(f['start'],16)for f in fs};add={SIGNAL,WAKELOOPS,LOOP,COPY,APPLY,HASHAPPLY,INVOKE}|{int(e['caller_start'],16)for e in scan['direct_B_BL_refs']+scan['direct_source_wake_helper_B_BL_refs']}
 for a in sorted(add-known):f=cf.function(a);f['exact_nlist']=cf.symbols_at(a);fs.append(f)
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in cs['original_cache_pages']};ranges=[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in fs]+[(a,16)for a in BOUNDARIES]+[(0x1e232d698,64),(0x184a8f1a0,32),(0x1848fc7a8,8),(0x1eb15a9e8,1)]
 for a,n in ranges:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 files=sorted(c.used|{e['path']for e in cs['cache_files']}|{str(CACHE)});imports=daemon_imports()
 return{**old,'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['kernel_wake_send_ingress_source.json','kernel_wake_send_ingress_profiles.json','kernel_wake_send_ingress_checks.json','cf_wake_send_wrapper_profiles.json','probe_cf_wake_send_wrapper.py','replay_cf_wake_send_wrapper.py','daemon_import_bindings.py','daemon_receive_fixups.txt','daemon_registration_contracts.json']},'CF_source':{**cs,'CF_functions':fs,'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files]},'caller_census':scan,'daemon_named_import_inventory':imports,'source_wake_helper_linkage':{'exact_nlist':cf.symbols_at(WAKELOOPS),'queried_exports':{name:cf.exports.get(name)for name in('__CFRunLoopSourceWakeUpRunLoops','_CFRunLoopSourceWakeUpRunLoops')},'native_caller':'unknown'},'source_runtime_boundaries':[{'address':hex(a),'role':role,'original_prefix16_hex':c.read(a,16).hex(),'exact_nlist':cf.symbols_at(a)}for a,role in BOUNDARIES.items()]}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');cs=s['CF_source'];print(json.dumps({'direct_wake_sites':len(s['caller_census']['direct_B_BL_refs']),'scan_words':s['caller_census']['instruction_words_scanned'],'CF_functions':len(cs['CF_functions']),'CF_instructions':sum(len(f['instructions'])for f in cs['CF_functions'])+4*len(cs['import_stubs']),'daemon_imports':s['daemon_named_import_inventory']['import_count']}),flush=True)
