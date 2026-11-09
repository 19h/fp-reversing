#!/usr/bin/env python3
"""Static dyld/ProgramVars/libSystem/libc initialization interface recovery.
O(original bytes+starts+selected instructions+metadata) time/space.
No target execution/emulation, native constructors/IPC, loader or IDB mutation.
"""
import bisect,hashlib,json,re,struct,subprocess
from pathlib import Path
from bootpolicy_cache_reader import Cache,Dylib,CS,uleb,CACHE
from resolve_kernel_collection_interfaces import macho,commands
from recover_launchd_variant_binding import SDK,LLVM,sha,h
from recover_registered_port_consumers import stub
ROOT=Path(__file__).resolve().parent;P='initializer_programvars';DYLD=Path('/usr/lib/dyld')
FLAGS=['target_executed','target_emulated','native_initializer_executed','native_IPC_emitted',
 'native_header_identity_proved','native_environment_provenance_proved','hardware_PAC_checked','IDB_mutated','full_goal_complete']
BP='/usr/lib/libSystem.B.dylib';CP='/usr/lib/system/libsystem_c.dylib';DP='/usr/lib/system/libdyld.dylib';XP='/usr/lib/system/libxpc.dylib';MP='/usr/lib/system/libmacho.dylib'
NAMES={
 'prepare':'__ZN5dyld4L7prepareERNS_4APIsEPKN6mach_o12UnsafeHeaderE',
 'process_ctor':'__ZN5dyld413ProcessConfig7ProcessC2EPKNS_10KernelArgsERNS_15SyscallDelegateERN3lsl9AllocatorE',
 'runtime_ctor':'__ZN5dyld412RuntimeStateC2ERKNS_13ProcessConfigERNS_12RuntimeLocksERN3lsl9AllocatorE',
 'initializer_walk':'__ZNK5dyld46Loader25findAndRunAllInitializersERNS_12RuntimeStateE',
 'initializer_callback':'____ZZNK5dyld46Loader25findAndRunAllInitializersERNS_12RuntimeStateEENK3$_0clEv_block_invoke',
 'header_value':'__ZNK6mach_o6Header6headerEv',
 'loader_dispatch':'__ZNK5dyld46Loader15runInitializersERNS_12RuntimeStateE',
 'JIT_initializers':'__ZNK5dyld416JustInTimeLoader15runInitializersERNS_12RuntimeStateE',
 'prebuilt_initializers':'__ZNK5dyld414PrebuiltLoader15runInitializersERNS_12RuntimeStateE',
 'initializer_enum':'__ZNK6mach_o5Image18forEachInitializerEU13block_pointerFvjE',
 'initializer_enum_block':'____ZNK6mach_o5Image18forEachInitializerEU13block_pointerFvjE_block_invoke',
 'initializer_enum_block2':'____ZNK6mach_o5Image18forEachInitializerEU13block_pointerFvjE_block_invoke.82'}

class DyldSlice:
 def __init__(self,raw,index,label):
  cpu,sub,off,size,align=struct.unpack_from('>5I',raw,8+20*index);assert cpu==0x100000c
  self.label=label;self.data=raw[off:off+size];self.meta=macho(self.data,0,'dyld');self.slice={'index':index,'offset':off,'size_bytes':size,'cpu_subtype':hex(sub),'sha256':h(self.data),'uuid':self.meta['uuid']}
  self.base=next(q['address']for q in self.meta['segments']if q['name']=='__TEXT');self.starts=[];self.symbols={};self.byname={}
  for at,c,z in commands(self.data,0):
   if c==0x26:
    p,n=struct.unpack_from('<II',self.data,at+8);buf=self.data[p:p+n];cur=0;v=self.base
    while cur<len(buf):
     delta,cur=uleb(buf,cur)
     if not delta:break
     v+=delta;self.starts.append(v)
  so,n,st,ss=self.meta['symtab']
  for j in range(n):
   ix,ty,se,de,v=struct.unpack_from('<IBBHQ',self.data,so+j*16)
   if ix:
    assert ix<ss;name=self.data[st+ix:self.data.index(0,st+ix)].decode();row={'name':name,'address':hex(v),'type':ty,'section':se,'nlist_index':j}
    self.symbols.setdefault(v,[]).append(row);self.byname[name]=v
  self.nlist_count=n
  cmd=[str(LLVM),'--macho','--arch='+label,'--disassemble',str(DYLD)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0
  self.llvm={}
  for line in r.stdout.splitlines():
   m=re.match(r'^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+){4})(\S+)(?:\s+(.*))?$',line)
   if m:self.llvm[int(m[1],16)]={'bytes':bytes.fromhex(m[2]).hex(),'mnemonic':m[3],'operands':(m[4]or'').split(';')[0].strip()}
  self.llvm_record={'command':cmd,'exit_code':r.returncode,'stdout_sha256':h(r.stdout.encode()),'stderr':r.stderr,'global_invalid_encoding_warnings':r.stderr.count('invalid instruction encoding'),'global_full_decode_proved':False}
  cmd=['/usr/bin/dyld_info','-arch',label,'-function_starts',str(DYLD)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
  found=[int(x,16)for x in re.findall(r'^\s+(0x[0-9a-fA-F]+)\s',r.stdout,re.M)];assert found==self.starts
  self.starts_reference={'command':cmd,'exit_code':r.returncode,'stdout_sha256':h(r.stdout.encode()),'starts_compared':len(found),'all_matches':True}
 def read(self,a,n):
  s=next(q for q in self.meta['segments']if q['address']<=a and a+n<=q['address']+q['file_size']);p=s['file_offset']+a-s['address'];return self.data[p:p+n]
 def function(self,a):
  j=self.starts.index(a);z=self.starts[j+1];bb=self.read(a,z-a);out=[];extended=[]
  for pc in range(a,z,4):
   word=self.read(pc,4);ll=self.llvm[pc];assert ll['bytes']==word.hex();cc=list(CS.disasm(word,pc))
   if cc:mn,op=cc[0].mnemonic,cc[0].op_str;decoder='Capstone'
   else:
    assert ll['mnemonic']not in ['.long','.word','<unknown>'];mn,op=ll['mnemonic'],ll['operands'];decoder='LLVM'
   row={'ea':hex(pc),'mnemonic':mn,'operands':op,'bytes':word.hex(),'decoder':decoder,'LLVM':ll};out.append(row)
   if not cc:extended.append(row)
  return{'start':hex(a),'end':hex(z),'bytes':bb.hex(),'sha256':h(bb),'instructions':out,'extended':extended,'original_nlist':self.symbols.get(a,[])}

def build():
 raw=DYLD.read_bytes();assert raw[:4]==bytes.fromhex('cafebabe');variants=[]
 for j,label in [(1,'arm64e'),(2,'arm64e.x1')]:
  n=DyldSlice(raw,j,label);roles={role:n.function(n.byname[name])for role,name in NAMES.items()}
  variants.append({'label':label,'slice':n.slice,'roles':roles,'compiler_starts_reference':n.starts_reference,'LLVM':n.llvm_record,'nlist_count':n.nlist_count,
   'section_literals':[{'address':hex(a),'bytes':n.read(a,128).split(b'\0')[0].hex()+'00','text':n.read(a,128).split(b'\0')[0].decode()}for a in ([0xa8bdc,0xada99,0xa8be9,0xadaa5]if label=='arm64e'else[0xa401c,0xa8ed9,0xa4029,0xa8ee5])]})
 c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a';libs={p:Dylib(c,p)for p in [BP,CP,DP,XP,MP]};cf={}
 req=[(BP,'libSystem_initializer',0x2cbbed264),(CP,'libc_initializer',0x1805c483c),(CP,'program_vars_init',0x1805c48a8),(CP,'legacy_libc_init',0x1805e8158),
  (DP,'helper_version',0x1804678c0),(DP,'default_program_vars',0x180467a28),(DP,'call_initializer',0x180467a80),
  (XP,'libxpc_initializer',0x184b6c360),(MP,'get_section',0x2cdb1f93c),(MP,'get_section_header',0x2cdb1f97c)]
 for name in ['__NSGetMachExecuteHeader','__NSGetArgc','__NSGetArgv','__NSGetEnviron','__NSGetProgname']:req.append((CP,name,libs[CP].exports[name]['address']))
 for path,role,a in req:
  d=libs[path];f=d.function(a);assert len(f['instructions'])*4==len(bytes.fromhex(f['bytes']));cf[role]={**f,'library':path,'original_nlist':d.symbols_at(a)}
 helper=next(s for s in libs[DP].sections if(s['segment'],s['name'])==('__DATA_CONST','__helper'));apis=next(s for s in libs[DP].sections if(s['segment'],s['name'])==('__TPRO_CONST','__dyld_apis'))
 hp=c.pointer(helper['address']);vp=int(hp['target'],16);methods=[]
 for offset,role in [(0,'helper_version'),(0xb0,'default_program_vars'),(0xc8,'call_initializer')]:
  q=c.pointer(vp+offset);assert q['target']==cf[role]['start'];methods.append({'offset':offset,'role':role,'pointer':q})
 bindings=[{'role':role,**stub(c,a)}for role,a in [('libc_initializer',0x2d00a0840),('__NSGetMachExecuteHeader',0x2d00b4d20)]]
 for q in bindings:assert q['pointer']['target']==cf[q['role']]['start']
 field_rows=[]
 for off,cell,storage,accessor,width in [(0,0x1ed84eda0,None,'__NSGetMachExecuteHeader',8),(8,0x1ed84edc0,0x1ed83b0f8,'__NSGetArgc',4),
   (16,0x1ed84edf0,0x1ed83b100,'__NSGetArgv',8),(24,0x1ed84ed98,0x1ed83b108,'__NSGetEnviron',8),(32,0x1ed84edb8,0x1ed83b118,'__NSGetProgname',8)]:
  field_rows.append({'record_offset':off,'field_bytes':8,'libc_cell':hex(cell),'accessor':accessor,'storage_address':None if storage is None else hex(storage),
   'storage_width_bytes':width,'cell_original_nlist':libs[CP].symbols_at(cell),'storage_original_nlist':[]if storage is None else libs[DP].symbols_at(storage),
   'file_default_cell_bytes':c.read(cell,8).hex(),'native_value_observed':False})
 section=next(s for s in libs[BP].sections if s['name']=='__init_offsets');bb=c.read(section['address'],section['size']);init={'section':section,'bytes':bb.hex(),'image_base':hex(libs[BP].base),'targets':[hex(libs[BP].base+q[0])for q in struct.iter_unpack('<I',bb)]}
 prior=json.loads((ROOT/'registered_port_consumers_source.json').read_text());daemon_path=Path(prior['daemon']['path']);daemon_bytes=daemon_path.read_bytes();dm=macho(daemon_bytes,0,'daemon');assert sha(daemon_path)==prior['daemon']['sha256']and dm['sections']==prior['daemon']['sections'];loader=[]
 for at,cmd,size in commands(daemon_bytes,0):
  if cmd==0xe:
   off=struct.unpack_from('<I',daemon_bytes,at+8)[0];p=at+off;loader.append({'command_bytes':daemon_bytes[at:at+size].hex(),'path':daemon_bytes[p:daemon_bytes.index(0,p)].decode()})
 assert len(loader)==1 and loader[0]['path']==str(DYLD)
 deps=['bootpolicy_cache_reader.py','resolve_kernel_collection_interfaces.py','recover_launchd_variant_binding.py','recover_registered_port_consumers.py','registered_port_consumers_source.json','registered_port_consumers_checks.json']
 headers=[SDK/'usr/include/crt_externs.h',SDK/'usr/include/mach-o/loader.h',SDK/'usr/include/mach/machine.h',SDK/'usr/include/stdint.h',SDK/'usr/include/stddef.h']
 bodies=[r for v in variants for r in v['roles'].values()]+list(cf.values());counts={'dyld_variants':2,'dyld_functions':sum(len(v['roles'])for v in variants),'cache_functions':len(cf),'complete_functions':len(bodies),
  'instructions':sum(len(r['instructions'])for r in bodies),'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in bodies),
  'LLVM_only_dyld_words':sum(len(r['extended'])for v in variants for r in v['roles'].values()),'compiler_starts_compared':sum(v['compiler_starts_reference']['starts_compared']for v in variants),
  'vtable_bindings':len(methods),'cache_stub_bindings':len(bindings),'ProgramVars_fields':len(field_rows),'daemon_sections':len(dm['sections']),'daemon_dyld_load_commands':len(loader)}
 return{'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'dyld_path':str(DYLD),'dyld_sha256':sha(DYLD),'variants':variants,'cache_uuid':c.uuid,
  'cache_libraries':{p:d.uuid for p,d in libs.items()},'cache_functions':cf,'helper_interface':{'section':helper,'object_pointer':hp,'vtable_address_point':hex(vp),'vtable_original_nlist':libs[DP].symbols_at(vp-16),'methods':methods,'APIs_section':apis,'APIs_file_default_bytes':c.read(apis['address'],apis['size']).hex(),'native_object_identity_observed':False},
  'cache_stub_bindings':bindings,'ProgramVars_fields':field_rows,'libSystem_initializer_registration':init,
  'daemon':{'path':str(daemon_path),'sha256':sha(daemon_path),'uuid':dm['uuid'],'sections':dm['sections'],'dyld_load_commands':loader,'native_header_identity_observed':False},
  'cache_files':[{'path':p,'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],
  'inspection_tools':[{'path':str(p),'sha256':sha(p)}for p in [LLVM,Path('/usr/bin/dyld_info')]],'verified_source_counts':counts,**{f:False for f in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
