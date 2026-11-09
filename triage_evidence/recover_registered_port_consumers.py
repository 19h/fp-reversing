#!/usr/bin/env python3
"""Original cache/kernel/daemon initialization and registered-port contracts.
Read-only source recovery; O(bytes+fixups+instructions+imports) time/space.
No target execution, loader calls, native Mach operations, fork or IDB mutation.
"""
import json,struct,re,subprocess,hashlib,plistlib
from pathlib import Path
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from kernel_vm_mig_tools import Image as KernelImage
from verify_interface_contracts import Image as UserImage
from resolve_kernel_collection_interfaces import commands,macho,CACHE as KC
from recover_launchd_variant_binding import SDK,sha,h
ROOT=Path(__file__).resolve().parent;P='registered_port_consumers';DAEMON=Path('/Users/___/Downloads/zut/fairplayd.arm64e')
FLAGS=['target_executed','target_emulated','native_IPC_emitted','native_fork_executed','native_initializer_executed',
 'native_port_identity_proved','native_right_balance_proved','native_bootstrap_value_proved','hardware_PAC_checked','full_goal_complete']
KP='/usr/lib/system/libsystem_kernel.dylib';XP='/usr/lib/system/libxpc.dylib';BP='/usr/lib/libSystem.B.dylib'
MP='/usr/lib/system/libmacho.dylib';CP='/usr/lib/system/libsystem_c.dylib'
KERNEL={'registered_store':0xfffffe000bcfa5fc,'registered_lookup':0xfffffe000bcfa80c,'copy_send':0xfffffe000bccffa4,
 'task_conversion':0xfffffe000bcfa000,'special_front':0xfffffe000bcf9eec,'special_core':0xfffffe000bcf9750}

def stub(c,a):
 bb=c.read(a,16);ii=list(CS.disasm(bb,a));assert len(ii)==4 and[q.mnemonic for q in ii]==['adrp','add','ldr','braa']
 slot=int(ii[0].op_str.split('#')[1],0)+int(ii[1].op_str.split('#')[1],0)
 return{'address':hex(a),'bytes':bb.hex(),'pointer':c.pointer(slot),
  'instructions':[{'ea':hex(q.address),'mnemonic':q.mnemonic,'operands':q.op_str}for q in ii]}

def daemon_record():
 u=UserImage(DAEMON);assert sha(DAEMON)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 m=macho(u.data,0,'fairplayd');loads=[]
 for at,cmd,size in commands(u.data,0):
  if cmd in [0xc,0x80000018,0x8000001f,0x80000023,0x20]:
   off=struct.unpack_from('<I',u.data,at+8)[0];a=at+off;loads.append({'command':hex(cmd),'path':u.data[a:u.data.index(0,a)].decode()})
 at=next(at for at,cmd,size in commands(u.data,0)if cmd==0x80000034);off,sz=struct.unpack_from('<II',u.data,at+8)
 v,st,im,sy,n,fmt,sf=struct.unpack_from('<7I',u.data,off);assert(v,fmt,sf)==(0,2,0);imports=[]
 for j in range(n):
  w,ad=struct.unpack_from('<Ii',u.data,off+im+8*j);lib=w&255;lib=lib-256 if lib&128 else lib;a=off+sy+(w>>9)
  imports.append({'ordinal':j,'symbol':u.data[a:u.data.index(0,a)].decode(),'addend':ad,'library_ordinal':lib,
   'library':loads[lib-1]['path']if 0<lib<=len(loads)else 'special ordinal','weak':bool(w&256)})
 cmd=['/usr/bin/dyld_info','-imports',str(DAEMON)];rr=subprocess.run(cmd,capture_output=True,text=True);assert rr.returncode==0 and not rr.stderr
 ref={}
 for line in rr.stdout.splitlines():
  q=re.match(r'\s+0x([0-9a-fA-F]+)\s+([^\s+]+)(?:\+0x([0-9a-fA-F]+))?\s',line)
  if q:ref[int(q[1],16)]=(q[2],int(q[3],16)if q[3]else 0)
 assert len(ref)==len(imports)and all(ref[q['ordinal']]==(q['symbol'],q['addend']&0xffffffff)for q in imports)
 section_cmd=['/usr/bin/otool','-l',str(DAEMON)];sr=subprocess.run(section_cmd,capture_output=True,text=True);assert sr.returncode==0 and not sr.stderr
 section_ref=re.findall(r'^\s+sectname (\S+)\n\s+segname (\S+)\n',sr.stdout,re.M)
 assert section_ref==[(q['section'],q['segment'])for q in m['sections']]
 slot=0x1010a3278;word=struct.unpack('<Q',u.read(slot,8))[0];assert word>>62==1;ordinal=word&0xffffff
 bank=[]
 for a in [0x100fc4230,0x101031fa0]:bank.append({'address':hex(a),'bytes':u.read(a,256).hex()})
 l,r=[bytes.fromhex(q['bytes'])for q in bank];values=[i^r[l[i]^0x6c]for i in range(256)];assert set(values)=={0x87}
 fragments=[]
 for name,a,z in [('bootstrap_data_forward',0x1004402c0,0x1004402dc),('checkin_call',0x100440380,0x100440390)]:
  raw=u.read(a,z-a);ii=list(CS.disasm(raw,a));assert len(ii)*4==len(raw)
  fragments.append({'role':name,'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':h(raw),
   'instructions':[{'ea':hex(q.address),'mnemonic':q.mnemonic,'operands':q.op_str}for q in ii]})
 return{'path':str(DAEMON),'sha256':sha(DAEMON),'uuid':m['uuid'],'sections':m['sections'],'loads':loads,
  'imports':imports,'sections_reference':{'command':section_cmd,'exit_code':sr.returncode,'stdout_sha256':h(sr.stdout.encode()),'sections_compared':len(section_ref)},'imports_reference':{'command':cmd,'exit_code':rr.returncode,'stdout_sha256':h(rr.stdout.encode()),'entries_compared':len(ref)},
  'bootstrap_binding':{'slot':hex(slot),'bytes':u.read(slot,8).hex(),'word':hex(word),'import':imports[ordinal],'pointer_format':12,'authenticated':False,'pointer_addend':0},
  'bootstrap_bank':{'tables':bank,'key':0x6c,'constant':0x87,'additive':0x29c,'pool':hex(0x1010a1960),'index':0x323,'slot':hex(slot),'inputs_checked':256},
  'fragments':fragments,'native_header_identity_observed':False}

def build():
 c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a';libs={p:Dylib(c,p)for p in [KP,XP,BP,MP,CP]};kf=libs[KP];xp=libs[XP];bp=libs[BP];cf={}
 requests=[(KP,n,None)for n in ['_mach_ports_lookup','__kernelrpc_mach_ports_lookup3','_mach_ports_register','__kernelrpc_mach_ports_register3','_task_get_special_port','___libkernel_init','_mig_deallocate']]
 requests += [(KP,'lookup_legacy',0x18055cec0),(KP,'register_legacy',0x18055cdd4),(BP,'libSystem_initializer',0x2cbbed264),
  (XP,'__libxpc_initializer',None),(XP,'bootstrap_pipe',0x184b6ce64),(XP,'pipe_create',0x184b880b8),(XP,'_xpc_atfork_prepare',None),
  (XP,'_bootstrap_check_in',None),(MP,'_getsectbyname',None),(MP,'_getsectbynamefromheader_64',None),(CP,'__NSGetMachExecuteHeader',None)]
 for path,name,a in requests:
  d=libs[path];a=d.exports[name]['address']if a is None else a;r=d.function(a);assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']))
  cf[name]={**r,'library':path,'original_nlist':d.symbols_at(a),'exact_export':name if name in d.exports else None}
 stubs={hex(a):stub(c,a)for a in [0x188087980,0x188087990,0x1880879b0,0x188087cc0,0x18806cf50,0x1880878d0,0x18806ca00,0x2d00b4d20]}
 export_bindings={0x188087980:(KP,'_mach_ports_lookup'),0x188087990:(KP,'_mach_ports_register'),0x1880879b0:(KP,'_mig_deallocate'),
  0x188087cc0:(KP,'_task_get_special_port'),0x18806cf50:(KP,'_mach_port_mod_refs'),0x1880878d0:(MP,'_getsectbyname'),
  0x18806ca00:(CP,'_getenv'),0x2d00b4d20:(CP,'__NSGetMachExecuteHeader')}
 for a,(path,name)in export_bindings.items():
  d=libs[path];target=d.exports[name]['address'];assert stubs[hex(a)]['pointer']['target']==hex(target)
  stubs[hex(a)]['symbol_binding']={'exact_export':name,'address':hex(target),'library':path,'library_uuid':d.uuid,'original_nlist':d.symbols_at(target)}
 init_edges=[]
 targets={cf[n]['start']:n for n in ['___libkernel_init','__libxpc_initializer']}
 for i in cf['libSystem_initializer']['instructions']:
  if i['mnemonic']!='bl':continue
  a=int(i['operands'][1:],0);bb=c.read(a,16);zz=list(CS.disasm(bb,a))
  if len(zz)!=4 or[q.mnemonic for q in zz]!=['adrp','add','ldr','braa']:continue
  q=stub(c,a)
  if q['pointer']['target']in targets:init_edges.append({'call_site':i['ea'],'role':targets[q['pointer']['target']],**q})
 assert len(init_edges)==2
 sec=next(q for q in bp.sections if q['name']=='__init_offsets');init={'section':sec,'bytes':c.read(sec['address'],sec['size']).hex(),'library_base':hex(bp.base)}
 init['targets']=[hex(bp.base+w[0])for w in struct.iter_unpack('<I',bytes.fromhex(init['bytes']))]
 reexports=[]
 for cmd,raw in bp.commands:
  if cmd==0x8000001f:
   off=struct.unpack_from('<I',raw,8)[0];reexports.append({'path':raw[off:].split(b'\0')[0].decode(),'command_bytes':raw.hex()})
 pointers=[{'pointer':c.pointer(a),'original_nlist':kf.symbols_at(int(c.pointer(a)['target'],16))}for a in [0x1e01c8b30,0x1e01c8ad0,0x1e01c8ac0,0x1e01c8ac8]]
 strings=[{'address':hex(a),'value':c.cstring(a)}for a in [0x184bb7122,0x184bb7130,0x184bb7143,0x184bb715c,0x184bb7163,0x184bb716d,0x184bb7178,0x184bb7184,0x18057de43,0x18057de53]]
 cells=[{'address':hex(a),'bytes':c.read(a,z).hex(),'native_value_observed':False}for a,z in [(0x1eb065e20,1),(0x1ed83e95c,4),(0x1ed84eda0,8)]]
 constants=[{'address':hex(a),'bytes':c.read(a,8).hex()}for a in [0x18057d308,0x18057d310,0x18057d318,0x18057d320,0x18057d3e0,0x18057d458,0x18057d958]]
 im=KernelImage();migs={str(r['id']):r for s in im.subsystems()for r in s['routines']if r['id']in [3403,3404,3409]};kr={**KERNEL,**{'MIG'+mid:int(q['stub']['target'],16)for mid,q in migs.items()}}
 syms=im.k.symbols(kr.values());kernel={name:{**im.k.function(a),'original_nlist':syms[hex(a)]}for name,a in kr.items()}
 constant={'address':'0xfffffe000700dda0','bytes':im.k.read(0xfffffe000700dda0,8).hex()};daemon=daemon_record()
 frozen=json.loads((ROOT/'native_fairplayd_services.json').read_text());jp=Path(frozen['job_path']);assert sha(jp)==frozen['job_sha256']
 kh=SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers'
 headers=[SDK/'usr/include/mach/task.defs',SDK/'usr/include/mach/task.h',SDK/'usr/include/mach/mach_init.h',SDK/'usr/include/mach/message.h',SDK/'usr/include/mach/mig_errors.h',SDK/'usr/include/mach/task_special_ports.h',kh/'mach/message.h']
 deps=['bootpolicy_cache_reader.py','kernel_native_reader.py','kernel_vm_mig_tools.py','resolve_kernel_collection_interfaces.py','verify_interface_contracts.py','recover_launchd_variant_binding.py','spawn_port_actions_source.json','daemon_registration_contracts.json','bootstrap_checkin_handoff_source.json','native_fairplayd_services.json']
 bodies=list(cf.values())+list(kernel.values());counts={'cache_functions':len(cf),'kernel_functions':len(kernel),'complete_functions':len(bodies),'instructions':sum(len(r['instructions'])for r in bodies),'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in bodies),'cache_stub_bindings':len(stubs),'initializer_edges':len(init_edges),'cache_pointer_bindings':len(pointers),'MIG_bindings':len(migs),'daemon_imports_compared':len(daemon['imports']),'daemon_sections_compared':len(daemon['sections']),'daemon_fragments':len(daemon['fragments']),'daemon_fragment_bytes':sum(len(bytes.fromhex(q['bytes']))for q in daemon['fragments']),'daemon_bank_inputs':256,'SDK_headers':len(headers)}
 return{'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cache_uuid':c.uuid,'cache_libraries':{p:d.uuid for p,d in libs.items()},'cache_functions':cf,'cache_stubs':stubs,'initializer_edges':init_edges,'initializer_registration':init,'libSystem_reexports':reexports,'cache_pointer_bindings':pointers,'cache_strings':strings,'file_default_cells':cells,'cache_constants':constants,
  'kernel_source_path':str(KC),'kernel_source_sha256':sha(KC),'kernel_functions':kernel,'MIG_bindings':migs,'kernel_port_descriptor_constant':constant,'daemon':daemon,'job_declaration':{'path':str(jp),'sha256':sha(jp),'relevant_plist':plistlib.loads(jp.read_bytes())},
  'cache_files':[{'path':p,'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],
  'SDK_headers':[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in headers],
  'inspection_tools':[{'path':p,'sha256':sha(p)}for p in ['/usr/bin/dyld_info','/usr/bin/otool']],
  'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
