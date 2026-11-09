#!/usr/bin/env python3
"""Original launchd endpoint construction, receive callbacks and XPC right ABI.
Static file/cache/kernel inspection only. O(B+F+I) time/space.
"""
import json,re,struct
from pathlib import Path
from recover_launchd_variant_binding import variant,binary,PATH,SDK,sha,h,CS
from recover_host_special_registration import fixup_reference
from bootpolicy_cache_reader import Cache,Dylib,CACHE
from kernel_native_reader import Kernel
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;P='launchd_service_endpoint'
FLAGS=['target_executed','target_emulated','mach_port_construct_called','host_special_port_set','native_port_identity_proved','native_right_balance_proved','hardware_PAC_checked','native_RPC700_exchange','full_goal_complete']
ROLES=[{'constructor':0x100047064,'send_object':0x10005cb6c,'send_name':0x100046c28,'factory':0x10000ce68,'construct_or_crash':0x10000ce10,'construct_status':0x10000cdc4,'domain':0x10002f94c,'receive_source':0x10005cd90,'event':0x100047abc,'cancel':0x100047af0,'live_assert':0x1000549f4,'diagnostic':0x100046ca8},{'constructor':0x100046328,'send_object':0x10005bb3c,'send_name':0x100045ef8,'factory':0x10000ccc4,'construct_or_crash':0x10000cc6c,'construct_status':0x10000cc20,'domain':0x10002efb0,'receive_source':0x10005bd60,'event':0x100046d38,'cancel':0x100046d60,'live_assert':0x100053aa8,'diagnostic':0x100045f6c}]
def zero_stores(body):
 rows=[]
 for i in body['instructions']:
  if i['mnemonic']not in['stur','str','stp']:continue
  m=re.fullmatch(r'q0, (q0, )?\[(sp|x22), #(0x[0-9a-f]+)\]',i['operands'])
  if not m:continue
  off=int(m[3],16)-(32 if m[2]=='sp'else 0);size=32 if m[1]else 16
  assert 0<=off and off+size<=255
  rows.append({'site':i['ea'],'offset_bytes':off,'size_bytes':size,'instruction':i})
 return rows
def build():
 meta=binary(PATH);raw=PATH.read_bytes();prior=json.loads((ROOT/'launchd_variant_binding_source.json').read_text());variants=[]
 for j,label in enumerate(['arm64e','arm64e.x1']):
  n=variant(meta,meta['slices'][j],raw);n.prepare(label);bodies={name:n.function(a)for name,a in ROLES[j].items()};stubs=prior['variants'][j]['stubs'];selected={}
  for name,body in bodies.items():
   for i in body['instructions']:
    if i['mnemonic']in['bl','b']and i['operands'].startswith('#'):
     a=i['operands'][1:]
     for sym,row in stubs.items():
      if row['address']==a:selected[sym]=n.stub(int(a,16));assert selected[sym]==row
  strings=[]
  for a in([0x100065962,0x100075c1d,0x100075c6b]if j==0 else[0x100064922,0x100074bdd,0x100074c2b]):strings.append({'address':hex(a),'text':n.cstring(a)})
  variants.append({'label':label,'uuid':n.inv['uuid'],'slice':n.inv['selected_slice'],'roles':bodies,'LLVM':n.llvm_record,'stubs':selected,'fixup_reference':fixup_reference(n),'data_bindings':[n.fixups[a]for a in[0x100086d08,0x100086e40]],'info_zero_stores':zero_stores(bodies['factory']),'strings':strings})
 c=Cache();libs={};functions=[];imports=[]
 def lib(path):
  if path not in libs:libs[path]=Dylib(c,path)
  return libs[path]
 def add(path,a,role):
  d=lib(path);row=d.function(a);assert len(row['instructions'])*4==len(bytes.fromhex(row['bytes']));row.update(role=role,library=path,library_uuid=d.uuid,original_nlist=d.symbols_at(a),exact_exports=[k for k,v in d.exports.items()if v['address']==a]);functions.append(row);return row
 xp='/usr/lib/system/libxpc.dylib';kp='/usr/lib/system/libsystem_kernel.dylib'
 for a,role in[(0x184b737d8,'default_create'),(0x184b737e0,'create_disposition'),(0x184b74268,'get_right'),(0x184b7f7d0,'copy_right'),(0x184b742c0,'dispose'),(0x184b77378,'extract_right')]:add(xp,a,role)
 for a,role in[(0x180548e9c,'construct_wrapper'),(0x180547b10,'construct_trap'),(0x18056df38,'construct_MIG_client')]:add(kp,a,role)
 for a in[0x18806d270,0x18806cf50,0x18806cf40,0x188087440,0x18806eb80,0x1880873f0]:
  b=c.read(a,16);ii=list(CS.disasm(b,a));assert[i.mnemonic for i in ii]==['adrp','add','ldr','braa'];slot=int(ii[0].op_str.split('#')[1],0)+int(ii[1].op_str.split('#')[1],0);ptr=c.pointer(slot);target=int(ptr['target'],16);path=max((r for r in c.images if r['address']<=target),key=lambda r:r['address'])['path'];d=lib(path);names=[k for k,v in d.exports.items()if v['address']==target];assert names;imports.append({'stub':hex(a),'bytes':b.hex(),'pointer':ptr,'target':hex(target),'library':path,'library_uuid':d.uuid,'exact_exports':names})
 type_links=[c.pointer(a)for a in[0x1e0615390,0x1e24197f0]]
 im=Image();k=im.k;sub=next(s for s in im.subsystems()if s['start']<=3231<s['end']);mig=next(r for r in sub['routines']if r['id']==3231);addresses=[0xfffffe000bcdbda4,0xfffffe000bce00b8,0xfffffe000bcd6b60,0xfffffe000bce0624,int(mig['stub']['target'],16)];symbols=k.symbols(addresses+[0xfffffe000be76e18,0xfffffe000bc9dac0,0xfffffe000bc9db70,0xfffffe000be3e3c4]);kf=[]
 for a in addresses:r=k.function(a);r['original_symbols']=symbols[hex(a)];kf.append(r)
 deps=['recover_launchd_variant_binding.py','recover_host_special_registration.py','recover_rpc700_namespace.py','recover_managed_fairplay_bridge.py','bootpolicy_cache_reader.py','kernel_native_reader.py','kernel_vm_mig_tools.py','resolve_kernel_collection_interfaces.py','launchd_variant_binding_source.json','kernel_root_port_construct_source.json']
 counts={'launchd_variants':2,'launchd_functions':sum(len(v['roles'])for v in variants),'launchd_instructions':sum(len(r['instructions'])for v in variants for r in v['roles'].values()),'launchd_function_bytes':sum(len(bytes.fromhex(r['bytes']))for v in variants for r in v['roles'].values()),'LLVM_only_launchd_words':sum(len(r['extended'])for v in variants for r in v['roles'].values()),'cache_functions':len(functions),'cache_instructions':sum(len(r['instructions'])for r in functions),'kernel_functions':len(kf),'kernel_instructions':sum(len(r['instructions'])for r in kf),'fixups_compared':sum(v['fixup_reference']['fixups_compared']for v in variants),'cache_stub_bindings':len(imports),'cache_type_links':len(type_links)}
 return {'generator_sha256':sha(__file__),'dependencies':{p:sha(ROOT/p)for p in deps},'launchd_source_path':str(PATH),'launchd_source_sha256':sha(PATH),'variants':variants,'inspection_tools':[{'path':row['path'],'sha256':sha(row['path'])}for row in prior['tools']],'cache_uuid':c.uuid,'cache_functions':functions,'cache_imports':imports,'cache_type_links':type_links,'cache_constants':[{'address':hex(a),'bytes':c.read(a,8).hex()}for a in[0x18057d6e0,0x18057d3b0,0x18057d6e8]],'cache_files':[{'path':p,'uuid':c.files[p]['uuid'],'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],'kernel_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'kernel_functions':kf,'kernel_exact_symbols':symbols,'MIG3231':mig,'SDK_headers':[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in[SDK/'usr/include/mach/port.h',SDK/'usr/include/mach/message.h',SDK/'usr/include/mach/mach_port.h',SDK/'usr/include/dispatch/source.h',SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/message.h',SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/ndr.h']],'verified_source_counts':counts,**{f:False for f in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
