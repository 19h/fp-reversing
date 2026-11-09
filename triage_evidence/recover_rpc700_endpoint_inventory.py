#!/usr/bin/env python3
"""Read-only cache reference/caller inventory, linked to frozen launchd data.
O(cache bytes + chain entries + selected branch words + image headers) time.
No target execution, target messages, registration or IDB changes.
"""
import bisect,json,mmap,struct
from pathlib import Path
from bootpolicy_cache_reader import Cache,Dylib,file_read,CS,CACHE
from recover_registered_port_consumers import stub
from recover_launchd_variant_binding import ROOT,SDK,sha,h
P='rpc700_endpoint_inventory'
FLAGS=['target_executed','target_emulated','FairPlay_requests_sent','registration_modified','kernel_port_object_identity_proved','RPC700_receiver_identified','hardware_PAC_checked','IDB_mutated','full_goal_complete']
KP='/usr/lib/system/libsystem_kernel.dylib'
APIS=['_host_get_special_port','_host_set_special_port','_mach_ports_lookup','_mach_ports_register']

def image_headers(c):
 rows=[]
 for img in c.images:
  head=c.read(img['address'],32);magic,cpu,sub,kind,n,sz,flags,res=struct.unpack('<8I',head);assert magic==0xfeedfacf
  data=head+c.read(img['address']+32,sz);at=32;sections=[];segments=[];uid=None
  for _ in range(n):
   cmd,z=struct.unpack_from('<II',data,at);raw=data[at:at+z];assert len(raw)==z
   if cmd==0x1b:uid=raw[8:24].hex()
   if cmd==0x19:
    name=raw[8:24].split(b'\0')[0].decode();a,size=struct.unpack_from('<QQ',raw,24);segments.append({'name':name,'address':a,'size':size})
    ns=struct.unpack_from('<I',raw,64)[0]
    for k in range(ns):
     q=raw[72+k*80:152+k*80];a,size=struct.unpack_from('<QQ',q,32)
     sections.append({'name':q[:16].split(b'\0')[0].decode(),'segment':q[16:32].split(b'\0')[0].decode(),'address':a,'size':size})
   at+=z
  assert at==len(data)and uid
  rows.append({'path':img['path'],'address':hex(img['address']),'UUID_bytes':uid,'header_bytes':data.hex(),'header_sha256':h(data),'segments':segments,'sections':sections})
 return rows

def scan_chains(c,targets):
 maps=[];matches=[];members={};count=0
 for m in c.maps:
  if not m['slide_off']:continue
  with open(m['path'],'rb')as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)as mm:
   ver,ps,np,pad,add=struct.unpack_from('<4IQ',mm,m['slide_off']);assert ver==5 and ps in[4096,16384]
   starts=struct.unpack_from('<'+'H'*np,mm,m['slide_off']+24);pages=local=0
   for pg,first in enumerate(starts):
    if first==0xffff:continue
    pages+=1;off=first;prev=-1
    while True:
     assert off>prev and off+8<=ps and pg*ps+off+8<=m['size'];prev=off
     w=struct.unpack_from('<Q',mm,m['off']+pg*ps+off)[0];local+=1
     target=add+(w&0x3ffffffff)
     if not w>>63:target|=((w>>34)&255)<<56
     if target in targets:
      a=m['va']+pg*ps+off;ptr=c.pointer(a);assert int(ptr['target'],16)==target
      matches.append({'API':targets[target],'pointer':ptr})
     delta=((w>>52)&0x7ff)*8
     if not delta:break
     off+=delta
   sl=mm[m['slide_off']:m['slide_off']+m['slide_size']]
   maps.append({'mapping':m,'slide_version':ver,'page_size':ps,'page_count':np,'value_add':hex(add),'slide_info_sha256':h(sl),'chain_pages_visited':pages,'chain_entries_visited':local});count+=local;c.used.add(m['path'])
 return maps,matches,count

def scan_stubs(c,slots):
 maps=[];hits=[];sites=0
 for m in c.maps:
  if not(m['initprot']&4 and m['flags']&8):continue
  bb=c.read(m['va'],m['size']);assert len(bb)%4==0;sites+=(len(bb)-12)//4
  maps.append({'mapping':m,'bytes_sha256':h(bb),'candidate_start_sites':(len(bb)-12)//4})
  for j,(w,)in enumerate(struct.iter_unpack('<I',bb[:-12])):
   if w&0x9f000000!=0x90000000:continue
   n=struct.unpack_from('<I',bb,4*j+4)[0]
   if n&0xffc00000!=0x91000000 or n&31!=w&31 or(n>>5)&31!=w&31:continue
   im=((w>>29)&3)|(((w>>5)&0x7ffff)<<2);im=im-(1<<21)if im&(1<<20)else im
   a=m['va']+4*j;slot=(a&~4095)+(im<<12)+((n>>10)&4095)
   if slot in slots:
    r=stub(c,a);assert int(r['pointer']['address'],16)==slot;hits.append(r)
 return maps,hits,sites

def scan_branches(c,targets):
 # A negative imm26 can reach -2^27 B, including a caller exactly target+2^27.
 lo=min(targets)-(1<<27);hi=max(targets)+(1<<27)+4;maps=[];hits=[];words=0
 for m in c.maps:
  if not m['initprot']&4:continue
  a=(max(lo,m['va'])+3)&~3;z=min(hi,m['va']+m['size'])&~3
  if a>=z:continue
  digest=__import__('hashlib').sha256()
  with open(m['path'],'rb')as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)as mm:
   offset=m['off']+a-m['va'];view=memoryview(mm)[offset:offset+z-a];digest.update(view)
   for j,(w,)in enumerate(struct.iter_unpack('<I',view)):
    if w&0x7c000000!=0x14000000:continue
    im=w&0x3ffffff;im=im-(1<<26)if im&(1<<25)else im;pc=a+4*j;dst=pc+4*im
    if dst in targets:hits.append({'address':hex(pc),'bytes':struct.pack('<I',w).hex(),'target':hex(dst),'kind':targets[dst]})
   view.release()
  n=(z-a)//4;words+=n;maps.append({'mapping':m,'start':hex(a),'end':hex(z),'aligned_words_scanned':n,'bytes_sha256':digest.hexdigest()});c.used.add(m['path'])
 return maps,hits,words

def build():
 c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a';lib=Dylib(c,KP);targets={lib.exports[n]['address']:n for n in APIS}
 root_header=file_read(CACHE,0,0x200);table_offset,table_count=struct.unpack_from('<II',root_header,0x1c0);table=file_read(CACHE,table_offset,32*table_count);assert table_count==len(c.images)
 api_functions={n:{**lib.function(a),'original_nlist':lib.symbols_at(a)}for a,n in targets.items()}
 headers=image_headers(c);got_words=0
 for row in headers:
  got=[]
  for s in row['sections']:
   if s['name']not in['__got','__auth_got']:continue
   bb=c.read(s['address'],s['size']);assert len(bb)%8==0;got_words+=len(bb)//8
   got.append({**s,'bytes_sha256':h(bb),'words':len(bb)//8})
  row['declared_GOT_sections']=got
 maps,matches,entries=scan_chains(c,targets)
 for hit in matches:
  a=int(hit['pointer']['address'],16);hit['declared_section_owners']=[{'image':r['path'],**s}for r in headers for s in r['sections']if s['address']<=a<s['address']+s['size']]
  hit['within_declared_GOT']=any(q['name']in['__got','__auth_got']for q in hit['declared_section_owners'])
 getter_slots={int(q['pointer']['address'],16)for q in matches if q['API']=='_host_get_special_port'}
 stubmaps,stubs,sites=scan_stubs(c,getter_slots)
 bt={lib.exports['_host_get_special_port']['address']:'getter_direct',lib.exports['_host_set_special_port']['address']:'setter_direct',**{int(q['address'],16):'getter_stub'for q in stubs}}
 branchmaps,branches,words=scan_branches(c,bt);callers={};caller_libraries={}
 for hit in branches:
  pc=int(hit['address'],16);owners=[{'image':r['path'],**s}for r in headers for s in r['sections']if s['address']<=pc<s['address']+s['size']];hit['owners']=owners;assert len(owners)==1 and owners[0]['name']=='__text'
  path=owners[0]['image']
  if path not in caller_libraries:caller_libraries[path]=Dylib(c,path)
  d=caller_libraries[path];ix=bisect.bisect_right(d.functions,pc)-1;assert ix>=0;start=d.functions[ix]
  key=hex(start)
  if key not in callers:
   f=d.function(start);assert len(f['instructions'])*4==len(bytes.fromhex(f['bytes']))
   callers[key]={**f,'image':path,'uuid':d.uuid,'original_nlist':d.symbols_at(start)}
  assert pc<int(callers[key]['end'],16);hit['function']=key
 controls=[c.pointer(a)for a in[0x1e2103b60,0x1e2103b68]]
 observation=ROOT/(P+'_observations.json');o=json.loads(observation.read_text());assert o['native_inspection_executed']and o['native_launchd_interrogation_executed']
 headers_used=[SDK/'usr/include/mach/host_special_ports.h',SDK/'usr/include/mach/host_priv.h',SDK/'usr/include/mach/mach_types.h',SDK/'usr/include/mach/port.h']
 functions=list(api_functions.values())+list(callers.values());deps=['bootpolicy_cache_reader.py','recover_registered_port_consumers.py','recover_launchd_variant_binding.py','recover_rpc700_publication.py','rpc700_publication_observations.json','host_special_registration_source.json']
 return{'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cache_uuid':c.uuid,'cache_mappings':c.maps,'image_table':{'root_header_bytes':root_header.hex(),'file_offset':table_offset,'count':table_count,'bytes':table.hex(),'sha256':h(table)},'API_library':{'path':KP,'uuid':lib.uuid},'API_functions':api_functions,'image_headers':headers,'chain_maps':maps,'chain_matches':matches,'known_pointer_controls':controls,'stub_maps':stubmaps,'getter_stubs':stubs,'branch_targets':{hex(a):n for a,n in bt.items()},'branch_maps':branchmaps,'branch_matches':branches,'caller_functions':callers,
  'observation_sha256':sha(observation),'observation_counts':{'domain_queries':len(o['domain_observations']),'selected_Apple_job_queries':len(o['queries']),'successful_job_queries':sum(q['exit_code']==0 for q in o['queries']),'endpoints':sum(len(q['endpoints'])for q in o['queries']),'host_associations':len(o['host_associations'])},
  'cache_files':[{'path':p,'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],
  'SDK_headers':[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in headers_used],
  'inspection_tools':[{'path':p,'sha256':sha(p)}for p in['/bin/launchctl','/usr/bin/clang']],
  'verified_source_counts':{'cache_images':len(headers),'declared_GOT_words':got_words,'slide_maps':len(maps),'slide_chain_entries':entries,'API_chain_matches':len(matches),'host_getter_chain_matches':sum(q['API']=='_host_get_special_port'for q in matches),'host_setter_chain_matches':sum(q['API']=='_host_set_special_port'for q in matches),'raw_flag8_executable_maps':len(stubmaps),'stub_candidate_start_sites':sites,'getter_stubs':len(stubs),'branch_words_scanned':words,'branch_matches':len(branches),'complete_functions':len(functions),'instructions':sum(len(f['instructions'])for f in functions),'function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in functions)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
