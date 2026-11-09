#!/usr/bin/env python3
"""Read-only spawn/Conclave descriptor, syscall and bounded receiver census.
O(B+F+I+L) time/space. No target execution, spawn, syscall or request emission.
"""
import json,re,struct
from pathlib import Path
from recover_launchd_variant_binding import variant,binary,PATH,SDK,sha,h,CS
from recover_host_special_registration import fixup_reference
from recover_endpoint_job_lifecycle import local_calls
from bootpolicy_cache_reader import Cache,Dylib,CACHE
from kernel_vm_mig_tools import Image
from resolve_kernel_collection_interfaces import CACHE as KC
ROOT=Path(__file__).resolve().parent;P='spawn_conclave_abi'
FLAGS=['target_executed','target_emulated','native_IPC_emitted','native_spawn_executed',
       'native_Conclave_attribute_effect_proved','whole_kernel_nonuse_proved','hardware_PAC_checked','full_goal_complete']
DEPS=['recover_launchd_variant_binding.py','recover_host_special_registration.py','recover_endpoint_job_lifecycle.py',
      'recover_managed_fairplay_bridge.py','recover_rpc700_namespace.py','resolve_kernel_collection_interfaces.py',
      'bootpolicy_cache_reader.py','kernel_native_reader.py','kernel_vm_mig_tools.py','endpoint_job_lifecycle_source.json',
      'exclaves_notification_contract_source.json','launchd_variant_binding_source.json','kernel_dispatch_contracts.json','native_fairplayd_services.json']

def load_span(i,base):
 """Width-aware literal-base load locator, not a general alias proof."""
 if not i['mnemonic'].startswith('ld')or'['+base not in i['operands']:return None
 m=re.search(r'\['+base+r'(?:, #(-?(?:0x)?[0-9a-f]+))?\]',i['operands']);assert m,i
 mn=i['mnemonic'];assert mn in['ldr','ldp','ldrh','ldrb','ldrsh'],i
 regs=i['operands'].split('[')[0].strip().rstrip(',').split(', ')
 width={'x':8,'w':4,'q':16,'d':8,'s':4,'h':2,'b':1}[regs[0][0]]
 if mn in['ldrh','ldrsh']:width=2
 if mn=='ldrb':width=1
 size=width*(2 if mn=='ldp'else 1);off=int(m[1],0)if m[1]else 0
 return{'instruction':i,'base_register':base,'offset_bytes':off,'size_bytes':size,'end_offset_exclusive':off+size}

def receiver_census(main,helper):
 rows=[r for i in main['instructions']if(r:=load_span(i,'sp'))is not None]
 assert len(rows)==209
 target=(0x2d0,0x2e0)
 overlap=[r for r in rows if r['offset_bytes']<target[1]and r['end_offset_exclusive']>target[0]];assert not overlap
 formations=[i for i in main['instructions']if i['mnemonic']=='add'and i['operands'].endswith('sp, #0x250')];assert len(formations)==2
 aliases=[r for i in helper['instructions']if(r:=load_span(i,'x19'))is not None and r['offset_bytes']==0x30]
 # One entry read uses incoming X0 before allocation changes it.
 incoming=[r for i in helper['instructions']if(r:=load_span(i,'x0'))is not None and r['offset_bytes']==0x30]
 nested=[i for i in helper['instructions']if i['mnemonic']=='ldp'and i['operands']=='x0, x2, [x27, #0x80]']
 assert len(aliases)==3 and len(incoming)==1 and len(nested)==1
 return{'descriptor_frame_offset_bytes':0x250,'Conclave_pair_offset_bytes':0x80,
         'Conclave_frame_interval':list(target),'direct_SP_loads':rows,'overlapping_direct_SP_loads':overlap,
         'literal_descriptor_address_formations':formations,'helper_descriptor_literal_reads':incoming+aliases,
         'nested_MAC_extension_same_offset_loads':nested,
         'scope':'Width-aware direct SP literal loads in complete syscall and selected descriptor-relative helper reads. Does not cover arbitrary aliases, indirect callees, stack inspection, other images or whole-kernel non-use.'}

def build():
 endpoint=json.loads((ROOT/'endpoint_job_lifecycle_source.json').read_text());ex=json.loads((ROOT/'exclaves_notification_contract_source.json').read_text())
 old=json.loads((ROOT/'launchd_variant_binding_source.json').read_text());meta=binary(PATH);raw=PATH.read_bytes();variants=[]
 assert sha(PATH)==ex['source_sha256']
 for j,label in enumerate(['arm64e','arm64e.x1']):
  n=variant(meta,meta['slices'][j],raw);n.prepare(label);roles={'launch_core':n.function(int(endpoint['variants'][j]['roles']['launch_core']['start'],16)),
    'attribute_prepare':n.function(int(ex['variants'][j]['roles']['spawn_attributes']['start'],16))}
  ii=roles['launch_core']['instructions'];init=[];cleanup=[]
  for k,i in enumerate(ii[:-2]):
   if i['mnemonic']=='add'and i['operands']=='x0, sp, #0x38':
    if(ii[k+1]['mnemonic'],ii[k+1]['operands'],ii[k+2]['mnemonic'])==('mov','x1, #0','bl'):init.append(int(ii[k+2]['operands'][1:],0))
    if ii[k+1]['mnemonic']=='bl'and int(ii[k+1]['operands'][1:],0)in n.starts:cleanup.append(int(ii[k+1]['operands'][1:],0))
  assert len(init)==len(cleanup)==1;roles['record_init']=n.function(init[0]);roles['record_cleanup']=n.function(cleanup[0])
  used={};by={r['address']:(name,r)for name,r in old['variants'][j]['stubs'].items()}
  for r in roles.values():
   for i in r['instructions']:
    if i['mnemonic']in['b','bl']and i['operands'].startswith('#')and i['operands'][1:]in by:
     name,q=by[i['operands'][1:]];used[name]=n.stub(int(q['address'],16));assert used[name]==q
  variants.append({'label':label,'uuid':n.inv['uuid'],'roles':roles,'stubs':used,'LLVM':n.llvm_record,'fixup_reference':fixup_reference(n)})
 c=Cache();libkernel=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib');libc=Dylib(c,'/usr/lib/system/libsystem_c.dylib');cf={}
 names=['_posix_spawn','___posix_spawn','_posix_spawnattr_init','_posix_spawnattr_destroy','_posix_spawnattr_set_conclave_id_np','___libkernel_init_late',
        '_posix_spawnattr_getmacpolicyinfo_np','_posix_spawnattr_setmacpolicyinfo_np']
 for name in names:
  a=libkernel.exports[name]['address'];cf[name]={**libkernel.function(a),'exact_export':name,'library':libkernel.path,'original_nlist':libkernel.symbols_at(a)}
 a=libc.exports['_posix_spawnp']['address'];cf['_posix_spawnp']={**libc.function(a),'exact_export':'_posix_spawnp','library':libc.path,'original_nlist':libc.symbols_at(a)}
 # The public wrapper's sole conditional local pre-syscall filter body.
 targets=[int(i['operands'][1:],0)for i in cf['_posix_spawn']['instructions']if i['mnemonic']=='bl'and i['operands']!='#'+cf['___posix_spawn']['start']]
 assert len(targets)==1;a=targets[0];cf['filter']={**libkernel.function(a),'library':libkernel.path,'original_nlist':libkernel.symbols_at(a)}
 shared=[]
 for i in cf['_posix_spawnp']['instructions']:
  if i['mnemonic']!='bl'or not i['operands'].startswith('#'):continue
  a=int(i['operands'][1:],0);b=c.read(a,16);zz=list(CS.disasm(b,a))
  if len(zz)!=4 or[q.mnemonic for q in zz]!=['adrp','add','ldr','braa']:continue
  slot=int(zz[0].op_str.split('#')[1],0)+int(zz[1].op_str.split('#')[1],0);p=c.pointer(slot)
  if p['target']==cf['_posix_spawn']['start']:
   shared.append({'call_site':i['ea'],'stub_address':hex(a),'bytes':b.hex(),'pointer':p,
     'instructions':[{'ea':hex(q.address),'mnemonic':q.mnemonic,'operands':q.op_str}for q in zz]})
 assert len(shared)==2
 cell=0x1eb065e68;filter_cell={'address':hex(cell),'bytes':c.read(cell,8).hex(),'original_nlist':libkernel.symbols_at(cell),'runtime_value_observed':False}
 for r in cf.values():assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']))
 im=Image();dispatch=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text());row=dispatch['bsd_entries'][244];assert row['index']==244 and row['name']=='posix_spawn'
 for field in['handler_pointer','munger_pointer','name_pointer']:
  p=row[field];assert im.pointer(int(p['slot'],16))==p
 kf={'syscall':im.k.function(int(row['handler_pointer']['target'],16)),
     'argument_munger':im.k.function(int(row['munger_pointer']['target'],16)),
     'descriptor_helper':im.k.function(0xfffffe000c2a5450),'copyin':im.k.function(0xfffffe000be76e18)}
 syms=im.k.symbols([int(r['start'],16)for r in kf.values()])
 for r in kf.values():r['original_nlist']=syms[r['start']]
 census=receiver_census(kf['syscall'],kf['descriptor_helper']);name=im.k.read(int(row['name_pointer']['target'],16),64).split(b'\0')[0];assert name.decode()==row['name']
 frozen=json.loads((ROOT/'native_fairplayd_services.json').read_text());jp=Path(frozen['job_path']);assert sha(jp)==frozen['job_sha256']
 bodies=[r for v in variants for r in v['roles'].values()]+list(cf.values())+list(kf.values())
 counts={'launchd_variants':2,'launchd_functions':8,'cache_functions':len(cf),'kernel_functions':len(kf),'complete_functions':len(bodies),
   'instructions':sum(len(r['instructions'])for r in bodies),'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in bodies),
   'LLVM_only_words':sum(len(r['extended'])for v in variants for r in v['roles'].values()),'fixups_compared':4894,
   'spawnp_to_spawn_binding_sites':len(shared),'descriptor_pairs':9,'direct_SP_loads_checked':len(census['direct_SP_loads']),
   'literal_descriptor_address_formations':len(census['literal_descriptor_address_formations']),'helper_descriptor_literal_reads':len(census['helper_descriptor_literal_reads'])}
 headers=['usr/include/spawn.h','usr/include/sys/errno.h','usr/include/mach/mach_param.h','usr/include/sys/types.h']
 return{'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in DEPS},'source_path':str(PATH),'source_sha256':sha(PATH),
   'variants':variants,'cache_uuid':c.uuid,'cache_libraries':[{'path':d.path,'uuid':d.uuid}for d in[libkernel,libc]],'cache_functions':cf,
   'spawnp_to_spawn_bindings':shared,'filter_cell':filter_cell,
   'cache_files':[{'path':p,'uuid':c.files[p]['uuid'],'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],
   'kernel_source_path':str(KC),'kernel_source_sha256':sha(KC),'kernel_functions':kf,'BSD244':row,'syscall_name_bytes':(name+b'\0').hex(),
   'sysent_row_bytes':im.k.read(int(row['handler_pointer']['slot'],16),24).hex(),
   'receiver_census':census,'job_declaration':{'path':str(jp),'sha256':sha(jp),'relevant_plist':frozen['job'],'native_job_identity_observed':False},
   'SDK_headers':[{'path':str(SDK/n),'sha256':sha(SDK/n)}for n in headers],
   'inspection_tools':[{'path':q['path'],'sha256':sha(q['path'])}for q in old['tools']],
   'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
