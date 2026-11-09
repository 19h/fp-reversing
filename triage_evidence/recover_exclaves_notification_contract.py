#!/usr/bin/env python3
"""Read-only Exclaves notification/property/spawn ABI and trap boundary capture.
O(B+F+I+L) time/space for bytes, fixups, selected instructions and locators.
No recovered target execution, IPC, spawn, service or IDB operation.
"""
import bisect,json,plistlib,struct
from pathlib import Path
from recover_launchd_variant_binding import variant,binary,PATH,SDK,sha,h,CS,branches
from recover_host_special_registration import fixup_reference
from recover_port_destroyed_return import literals
from recover_endpoint_job_lifecycle import local_calls
from recover_job_factory_lineage import string_refs
from bootpolicy_cache_reader import Cache,Dylib,CACHE
from kernel_vm_mig_tools import Image
from resolve_kernel_collection_interfaces import CACHE as KC
ROOT=Path(__file__).resolve().parent;P='exclaves_notification_contract'
FLAGS=['target_executed','target_emulated','native_IPC_emitted','native_Exclaves_support_proved',
       'native_notification_registration_proved','native_right_balance_proved','hardware_PAC_checked','full_goal_complete']
IMPORTS=['_exclaves_boot','_exclaves_daemon_notification_register','_exclaves_daemon_notification_deregister','_posix_spawnattr_set_conclave_id_np']
DEPS=['recover_launchd_variant_binding.py','recover_host_special_registration.py','recover_port_destroyed_return.py',
      'recover_endpoint_job_lifecycle.py','recover_job_factory_lineage.py','recover_managed_fairplay_bridge.py',
      'recover_rpc700_namespace.py','resolve_kernel_collection_interfaces.py','bootpolicy_cache_reader.py',
      'kernel_native_reader.py','kernel_vm_mig_tools.py','launchd_variant_binding_source.json',
      'job_factory_lineage_source.json','endpoint_job_lifecycle_source.json','kernel_dispatch_contracts.json','native_fairplayd_services.json']

def build():
 old=json.loads((ROOT/'launchd_variant_binding_source.json').read_text());jobs=json.loads((ROOT/'job_factory_lineage_source.json').read_text())
 lifecycle=json.loads((ROOT/'endpoint_job_lifecycle_source.json').read_text());meta=binary(PATH);raw=PATH.read_bytes();variants=[]
 assert sha(PATH)==jobs['source_sha256']
 for j,label in enumerate(['arm64e','arm64e.x1']):
  n=variant(meta,meta['slices'][j],raw);n.prepare(label);roles={};callers={}
  for name,role in zip(IMPORTS,['boot','publish','remove','spawn_attributes']):
   stub=old['variants'][j]['stubs'][name];assert n.stub(int(stub['address'],16))==stub
   hits=branches(n,int(stub['address'],16));assert len(hits)==1;callers[name]=hits;roles[role]=n.function(int(hits[0]['containing_start'],16))
  schema=jobs['variants'][j]['roles']['property_schema'];roles['property_schema']=n.function(int(schema['start'],16));blocks={}
  for key,role in[('_Conclave','identifier_property'),('DaemonNotifications','notification_property')]:
   site=int(jobs['variants'][j]['property_strings'][key][0]['site'],16);ii=schema['instructions'];ix=next(k for k,i in enumerate(ii)if int(i['ea'],16)==site)
   a,b=ii[ix-3:ix-1];assert(a['mnemonic'],b['mnemonic'])==('adrp','add');at=int(a['operands'].split('#')[1],0)+int(b['operands'].split('#')[1],0)
   ptrs=[n.fixups[at+k]for k in[0,16,24]];assert ptrs[0]['symbol']=='__NSConcreteGlobalBlock'
   roles[role]=n.function(int(ptrs[1]['target'],16));blocks[key]={'address':hex(at),'bytes':n.read(at,32).hex(),'pointers':ptrs,
     'schema_site':hex(site),'schema_neighborhood':ii[ix-3:ix+5]}
  ll=local_calls(n,roles['identifier_property'],'b');assert len(ll)==1;roles['identifier_setter']=n.function(ll[0])
  roles['identifier_duplicate']=n.function(local_calls(n,roles['identifier_setter'])[-1])
  ll=literals(n,roles['notification_property']);assert len(ll)==1;roles['notification_entry']=n.function(ll[0])
  roles['policy_query']=n.function(int(old['variants'][j]['roles']['owner_query']['start'],16))
  roles['send_name']=n.function(int(old['variants'][j]['roles']['send_name']['start'],16))
  roles['job_install']=n.function(int(jobs['variants'][j]['roles']['job_install']['start'],16))
  roles['job_clone']=n.function(int(lifecycle['variants'][j]['roles']['factory_clone']['start'],16))
  roles['endpoint_wrapper']=n.function(int(jobs['variants'][j]['roles']['callback3']['start'],16))
  used={};by={r['address']:(name,r)for name,r in old['variants'][j]['stubs'].items()}
  for r in roles.values():
   for i in r['instructions']:
    if i['mnemonic']in['b','bl']and i['operands'].startswith('#')and i['operands'][1:]in by:
     name,q=by[i['operands'][1:]];used[name]=n.stub(int(q['address'],16));assert used[name]==q
  stores=[{'site':hex(ea),'instruction':i,'containing_start':hex(n.starts[bisect.bisect_right(n.starts,ea)-1])}
    for ea,i in n.llvm.items()if i['mnemonic']=='str'and i['operands'].startswith('x')and '#0x570]'in i['operands']]
  assert len(stores)==3 and{q['containing_start']for q in stores}=={roles[k]['start']for k in['identifier_setter','job_clone']}
  variants.append({'label':label,'uuid':n.inv['uuid'],'roles':roles,'stubs':used,'import_direct_callers':callers,
    'property_blocks':blocks,'policy_jump_table':old['variants'][j]['owner_query_jump_table'],
    'field570_store_candidates':stores,'strings':{k:string_refs(n,r)for k,r in roles.items()},
    'LLVM':n.llvm_record,'fixup_reference':fixup_reference(n),
    'locator_scope':'Aligned direct B/BL to four import stubs; immediate STR-x+0x570 in __text only. Aliases/wider stores/other images excluded.'})
 c=Cache();path='/usr/lib/system/libsystem_kernel.dylib';lib=Dylib(c,path);cf={}
 for name in IMPORTS+['__exclaves_ctl_trap','___libkernel_platform_init']:
  a=lib.exports[name]['address'];r=lib.function(a);assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']))
  cf[name]={**r,'exact_export':name,'original_nlist':lib.symbols_at(a)}
 cell=0x1ed83e8c8;pointer=c.pointer(cell);base=int(pointer['target'],16)
 table={'cell':hex(cell),'cell_original_nlist':lib.symbols_at(cell),'pointer':pointer,'address':hex(base),
   'original_nlist':lib.symbols_at(base),'bytes':c.read(base,128).hex(),
   'offset78_raw_bytes':c.read(base+0x78,8).hex(),'pointers':{hex(off):c.pointer(base+off)for off in[0x58,0x60]},
   'runtime_table_observed':False}
 for role,off in[('generic_strlcpy',0x58),('generic_strlen',0x60)]:
  a=int(table['pointers'][hex(off)]['target'],16);r=lib.function(a);assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']))
  cf[role]={**r,'original_nlist':lib.symbols_at(a)}
 im=Image();trap=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text())['mach_entries'][88]
 registry=im.k.read(0xfffffe0007efb010+24*88,24)
 for name in['handler_pointer','munger_pointer','name_pointer']:
  ptr=trap[name];assert im.pointer(int(ptr['slot'],16))==ptr
 name=im.k.read(int(trap['name_pointer']['target'],16),128).split(b'\0')[0]
 assert name.decode()==trap['name']=='_exclaves_ctl_trap'
 kf={role:im.k.function(int(trap[field]['target'],16))for role,field in[('handler','handler_pointer'),('argument_munger','munger_pointer')]}
 syms=im.k.symbols([int(r['start'],16)for r in kf.values()])
 for r in kf.values():r['original_nlist']=syms[r['start']]
 frozen=json.loads((ROOT/'native_fairplayd_services.json').read_text());jp=Path(frozen['job_path']);job=plistlib.loads(jp.read_bytes())
 assert sha(jp)==frozen['job_sha256']and job==frozen['job']
 bodies=[r for v in variants for r in v['roles'].values()]+list(cf.values())+list(kf.values())
 counts={'launchd_variants':2,'launchd_functions':sum(len(v['roles'])for v in variants),'cache_functions':len(cf),'kernel_functions':len(kf),
   'complete_functions':len(bodies),'instructions':sum(len(r['instructions'])for r in bodies),'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in bodies),
   'LLVM_only_words':sum(len(r['extended'])for v in variants for r in v['roles'].values()),'fixups_compared':4894,
   'direct_import_call_sites':8,'property_block_bindings':4,'field570_store_candidates':6,'trap_handler_instructions':len(kf['handler']['instructions'])}
 headers=['usr/include/mach/mach_param.h','usr/include/mach/kern_return.h','usr/include/mach/port.h','usr/include/sys/errno.h']
 return{'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in DEPS},'source_path':str(PATH),'source_sha256':sha(PATH),
   'variants':variants,'cache_uuid':c.uuid,'cache_library':path,'cache_library_uuid':lib.uuid,'cache_functions':cf,'string_callback_table':table,
   'cache_files':[{'path':p,'uuid':c.files[p]['uuid'],'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],
   'kernel_source_path':str(KC),'kernel_source_sha256':sha(KC),'kernel_functions':kf,'trap88':trap,
   'trap_registry_bytes':registry.hex(),'trap_name_bytes':(name+b'\0').hex(),
   'job_declaration':{'path':str(jp),'sha256':sha(jp),'plist':job,'effective_runtime_configuration_observed':False},
   'SDK_headers':[{'path':str(SDK/q),'sha256':sha(SDK/q)}for q in headers],
   'inspection_tools':[{'path':q['path'],'sha256':sha(q['path'])}for q in old['tools']],
   'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
