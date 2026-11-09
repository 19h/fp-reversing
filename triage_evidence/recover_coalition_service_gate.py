#!/usr/bin/env python3
"""Original coalition producer/membership/service-consumer static correspondence.
O(B+F+I) time/space. Optional pinned primary-source metadata capture; no target IPC.
"""
import bisect,json,re,struct,sys,types,urllib.request
from pathlib import Path
from kernel_vm_mig_tools import Image
from kernel_native_reader import Kernel
from recover_launchd_variant_binding import SDK,CS,sha,h,branches
from resolve_kernel_collection_interfaces import CACHE as KC
ROOT=Path(__file__).resolve().parent;P='coalition_service_gate';COMMIT='f6217f891ac0bb64f3d375211650a4c1ff8ca1ea';REPO='https://github.com/apple-oss-distributions/xnu'
FLAGS=['target_executed','target_emulated','native_IPC_emitted','native_coalition_modified','native_membership_proved','native_service_admission_proved','native_guard_state_proved','hardware_PAC_checked','full_goal_complete']
PRIMARY={'osfmk/kern/coalition.c':{'sha256':'244a162e8d29296b766c4dae07f7c8072bf67a742d8be5f233c71dae8e247976','anchors':['coalition_create_internal','task_is_in_privileged_coalition','privileged :']},'osfmk/mach/coalition.h':{'sha256':'d0bf59956b735fb239b26f4a9aabc2640951259564dba9b0dd0eb0d329bca754','anchors':['COALITION_TYPE_JETSAM','COALITION_CREATE_FLAGS_PRIVILEGED','COALITION_CREATE_FLAGS_GET_ROLE']},'bsd/kern/sys_coalition.c':{'sha256':'1f252b9329751286f670a8d6824117c2712b4bf20bbf82376fe12c3d39835545','anchors':['COALITION_CREATE_FLAGS_GET_ROLE','COALITION_CREATE_FLAGS_PRIVILEGED','task_is_in_privileged_coalition']}}
ROLES={'current_task':0xfffffe000bd41ac4,'thread_task':0xfffffe000bd7e9c4,'get_bsdtask_info':0xfffffe000bd7deec,'jetsam_set_taskrole':0xfffffe000bce7758,'coalition_adopt':0xfffffe000bce8fa0,'coalition_create':0xfffffe000bce7304,'coalitions_init':0xfffffe000bce9d14,'coalition_syscall':0xfffffe000c309a4c,'service_construct':0xfffffe000bce00b8,'receive_publish':0xfffffe000bcd5e24,'task_create':0xfffffe000bd41e68,'task_coalition_release':0xfffffe000bce955c}
def capture_primary():
 out=[]
 for path,expected in PRIMARY.items():
  url='https://raw.githubusercontent.com/apple-oss-distributions/xnu/'+COMMIT+'/'+path;b=urllib.request.urlopen(url,timeout=30).read();assert h(b)==expected['sha256'];lines=b.decode().splitlines();out.append({'path':path,'url':url,'browser_url':REPO+'/blob/'+COMMIT+'/'+path,'sha256':h(b),'size_bytes':len(b),'identifier_locations':{name:[j for j,line in enumerate(lines,1)if name in line]for name in expected['anchors']}});assert all(out[-1]['identifier_locations'].values())
 header=next(r for r in out if r['path']=='osfmk/mach/coalition.h');url=header['url'];b=urllib.request.urlopen(url,timeout=30).read();assert h(b)==header['sha256'];text=b.decode();values={}
 for name in ['COALITION_CREATE_FLAGS_MASK','COALITION_CREATE_FLAGS_PRIVILEGED','COALITION_CREATE_FLAGS_EFFICIENT','COALITION_CREATE_FLAGS_TYPE_MASK','COALITION_CREATE_FLAGS_TYPE_SHIFT','COALITION_CREATE_FLAGS_ROLE_MASK','COALITION_CREATE_FLAGS_ROLE_SHIFT','COALITION_ROLE_SYSTEM','COALITION_TYPE_RESOURCE','COALITION_TYPE_JETSAM']:
  line=re.search(r'^#define\s+'+name+r'\s+(.+)$',text,re.M).group(1);values[name]=int(re.findall(r'\b(?:0x[0-9a-fA-F]+|[0-9]+)\b',line)[-1],0)
 header['numeric_constants']=values
 obj={'repository':REPO,'commit':COMMIT,'files':out,'scope':'Pinned public primary-source naming/correspondence only. Exact source/build equivalence to inspected xnu-13432.41.4 is unknown. Full source text is not copied. No target or IPC executes.','exact_target_source_equivalence':'unknown'};(ROOT/(P+'_primary_context.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps({'pinned_primary_files':len(out),'commit':COMMIT}),flush=True)
def locators(k):
 sec=next(s for s in k.kernel['sections']if s['segment']=='__TEXT_EXEC'and s['section']=='__text');raw=k.read(sec['address'],sec['size']);rows=[]
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
  if w&0xffc00000 not in[0xf9400000,0xf9000000]or(w>>10&4095)*8!=0x608:continue
  pc=sec['address']+4*j;rows.append({'site':hex(pc),'bytes':k.read(pc,4).hex(),'mnemonic':'ldr'if w&0xffc00000==0xf9400000 else'str','containing_start':hex(k.starts[bisect.bisect_right(k.starts,pc)-1])})
 return{'section':sec,'section_sha256':h(raw),'aligned_words_scanned':len(raw)//4,'offset_bytes':0x608,'rows':rows,'scope':'64-bit unsigned-immediate LDR/STR with encoded displacement0x608 in kernel __TEXT_EXEC,__text only. Includes unrelated objects/globals. Excludes indexed, paired/vector/unscaled/aliased stores, __KLD, other images and runtime writers.'}
def build():
 im=Image();k=im.k;n=types.SimpleNamespace(meta=k.kernel,read=k.read,starts=k.starts);roles=dict(ROLES);ops=[]
 for typ in[0,1]:
  a=0xfffffe0007e5c8e0+64*typ;ps={name:im.pointer(a+off)for name,off in[('init',8),('adopt',24)]};ops.append({'type_index':typ,'address':hex(a),'bytes':k.read(a,64).hex(),'pointers':ps})
  for name,p in ps.items():roles['type'+str(typ)+'_'+name]=int(p['target'],16)
 syms=k.symbols(list(roles.values()));fs={name:{**k.function(a),'original_nlist':syms[hex(a)]}for name,a in roles.items()};rr=branches(n,ROLES['coalition_create']);loc=locators(k);ss=[]
 for a in[0xfffffe000704aacd,0xfffffe000704ad2a,0xfffffe000704acd0,0xfffffe000704ab4c,0xfffffe000704fbdb,0xfffffe000704ab91,0xfffffe000704abc6,0xfffffe000704aad9,0xfffffe000704ab13,0xfffffe0007051123]:
  b=k.read(a,4096).split(b'\0')[0];ss.append({'address':hex(a),'bytes':b.hex(),'text':b.decode(),'sha256':h(b)})
 at=k.data.find(b'Darwin Kernel Version');v=k.data[at:at+384].split(b'\0')[0];primary=json.loads((ROOT/(P+'_primary_context.json')).read_text());assert primary['commit']==COMMIT and{r['path']:r['sha256']for r in primary['files']}=={p:r['sha256']for p,r in PRIMARY.items()};deps=['kernel_vm_mig_tools.py','kernel_native_reader.py','recover_launchd_variant_binding.py','recover_managed_fairplay_bridge.py','recover_rpc700_namespace.py','recover_host_special_registration.py','bootpolicy_cache_reader.py','resolve_kernel_collection_interfaces.py','receive_name_guard_source.json',P+'_primary_context.json'];counts={'complete_kernel_functions':len(fs),'instructions':sum(len(r['instructions'])for r in fs.values()),'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in fs.values()),'type_operation_bindings':4,'constructor_direct_call_sites':len(rr),'immediate608_locator_hits':len(loc['rows']),'immediate608_store_hits':sum(r['mnemonic']=='str'for r in loc['rows']),'text_words_scanned':loc['aligned_words_scanned'],'original_strings':len(ss),'pinned_primary_files':len(primary['files'])}
 return{'generator_sha256':sha(__file__),'dependencies':{name:sha(ROOT/name)for name in deps},'kernel_source_path':str(KC),'kernel_source_sha256':sha(KC),'kernel_version':{'file_offset':hex(at),'bytes':v.hex(),'text':v.decode()},'functions':fs,'type_operations':ops,'constructor_direct_callers':rr,'immediate608_locators':loc,'original_strings':ss,'primary_context':primary,'inspection_tools':[{'path':'/Users/___/Downloads/zut/.venv/bin/python','sha256':sha('/Users/___/Downloads/zut/.venv/bin/python')}],'SDK_headers':[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in[SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers/kern/coalition.h',SDK/'usr/include/mach/mach_types.h']],'verified_source_counts':counts,**{f:False for f in FLAGS}}
if __name__=='__main__':
 if sys.argv[1:]==['--capture-primary']:capture_primary()
 else:
  assert not sys.argv[1:];s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
