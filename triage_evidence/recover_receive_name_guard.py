#!/usr/bin/env python3
"""Static service receive-right name reuse and guard-context preservation.
O(B+F+I) time/space. No target execution, namespace mutation, IPC or IDB effects.
"""
import json
from pathlib import Path
from recover_launchd_variant_binding import variant,binary,PATH,SDK,sha,h,CS
from recover_host_special_registration import fixup_reference
from bootpolicy_cache_reader import Cache,Dylib,CACHE
from kernel_vm_mig_tools import Image
from resolve_kernel_collection_interfaces import CACHE as KC
ROOT=Path(__file__).resolve().parent;P='receive_name_guard'
FLAGS=['target_executed','target_emulated','native_IPC_emitted','native_notification_received','native_receive_name_identity_proved','native_right_balance_proved','native_guard_state_proved','hardware_PAC_checked','full_goal_complete']
KERNEL_ROLES={'construct':0xfffffe000bce00b8,'guard_install':0xfffffe000bce0624,'unguard':0xfffffe000bce0894,'assert_attributes':0xfffffe000bce0f44,'port_destroy':0xfffffe000bccdbb4,'kernel_copyin':0xfffffe000bcc6b10,'kernel_right_copyin':0xfffffe000bcc9718,'link_walk':0xfffffe000bcc08ec,'set_destination':0xfffffe000bcccf0c,'descriptor_copyout':0xfffffe000bcc5564,'right_copyout':0xfffffe000bcc9c1c,'state_snapshot':0xfffffe000bccc258,'entry_reuse':0xfffffe000bcd308c,'reverse_lookup':0xfffffe000bcbdf9c,'entry_lookup':0xfffffe000bcbbf50,'entry_reserve':0xfffffe000bcbc0f0,'receive_publish':0xfffffe000bcd5e24,'thread_owner':0xfffffe000bd7e9c4}
def build():
 old=json.loads((ROOT/'launchd_variant_binding_source.json').read_text());service=json.loads((ROOT/'launchd_service_endpoint_source.json').read_text());returned=json.loads((ROOT/'port_destroyed_return_source.json').read_text());meta=binary(PATH);raw=PATH.read_bytes();variants=[]
 for j,label in enumerate(['arm64e','arm64e.x1']):
  n=variant(meta,meta['slices'][j],raw);n.prepare(label);roles={name:n.function(int(service['variants'][j]['roles'][name]['start'],16))for name in['send_object','factory']};roles.update({name:n.function(int(returned['variants'][j]['roles'][name]['start'],16))for name in['activate','guard_assert','endpoint_reset']});used={};by={r['address']:(name,r)for name,r in old['variants'][j]['stubs'].items()}
  for r in roles.values():
   for i in r['instructions']:
    if i['mnemonic']in['b','bl']and i['operands'].startswith('#')and i['operands'][1:]in by:
     name,q=by[i['operands'][1:]];used[name]=n.stub(int(q['address'],16));assert used[name]==q
  variants.append({'label':label,'uuid':n.inv['uuid'],'slice':n.inv['selected_slice'],'roles':roles,'stubs':used,'LLVM':n.llvm_record,'fixup_reference':fixup_reference(n)})
 im=Image();sub=next(s for s in im.subsystems()if s['start']==3200);migs={str(mid):next(r for r in sub['routines']if r['id']==mid)for mid in[3234,3242]};kr=dict(KERNEL_ROLES)
 for mid,row in migs.items():kr['MIG'+mid]=int(row['stub']['target'],16)
 trap=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text())['mach_entries'][42];assert im.pointer(0xfffffe0007efb010+24*42+8)==trap['handler_pointer'];kr['unguard_trap']=int(trap['handler_pointer']['target'],16);syms=im.k.symbols(list(kr.values()));kf={name:{**im.k.function(a),'original_nlist':syms[hex(a)]}for name,a in kr.items()};policy=[{'index':j,'address':hex(0xfffffe0007e62b70+40*j),'bytes':im.k.read(0xfffffe0007e62b70+40*j,40).hex()}for j in[0,2,4,11]]
 c=Cache();path='/usr/lib/system/libsystem_kernel.dylib';d=Dylib(c,path);cf={}
 for name in['_mach_port_unguard','__kernelrpc_mach_port_unguard_trap','__kernelrpc_mach_port_unguard','_mach_port_assert_attributes']:
  a=d.exports[name]['address'];r=d.function(a);assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']));cf[name]={**r,'exact_export':name,'original_nlist':d.symbols_at(a)}
 a=int(cf['_mach_port_assert_attributes']['instructions'][0]['operands'][1:],0);r=d.function(a);assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']));cf['assert_attributes_MIG']={**r,'original_nlist':d.symbols_at(a)}
 deps=['recover_launchd_variant_binding.py','recover_host_special_registration.py','recover_managed_fairplay_bridge.py','recover_rpc700_namespace.py','resolve_kernel_collection_interfaces.py','bootpolicy_cache_reader.py','kernel_native_reader.py','kernel_vm_mig_tools.py','launchd_variant_binding_source.json','launchd_service_endpoint_source.json','port_destroyed_return_source.json','kernel_dispatch_contracts.json'];bodies=[r for v in variants for r in v['roles'].values()]+list(kf.values())+list(cf.values());counts={'launchd_variants':2,'launchd_functions':10,'kernel_functions':len(kf),'cache_functions':len(cf),'complete_functions':len(bodies),'instructions':sum(len(r['instructions'])for r in bodies),'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in bodies),'LLVM_only_launchd_words':sum(len(r['extended'])for v in variants for r in v['roles'].values()),'fixups_compared':4894,'kernel_policy_rows':len(policy),'MIG_bindings':2,'trap_bindings':1}
 return{'generator_sha256':sha(__file__),'dependencies':{name:sha(ROOT/name)for name in deps},'launchd_source_path':str(PATH),'launchd_source_sha256':sha(PATH),'variants':variants,'kernel_source_path':str(KC),'kernel_source_sha256':sha(KC),'kernel_functions':kf,'kernel_policy_rows':policy,'MIG_bindings':migs,'unguard_trap':trap,'cache_uuid':c.uuid,'cache_library':path,'cache_library_uuid':d.uuid,'cache_functions':cf,'cache_files':[{'path':p,'uuid':c.files[p]['uuid'],'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],'inspection_tools':[{'path':r['path'],'sha256':sha(r['path'])}for r in old['tools']],'SDK_headers':[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in[SDK/'usr/include/mach/message.h',SDK/'usr/include/mach/port.h',SDK/'usr/include/mach/mach_port.h']],'verified_source_counts':counts,**{f:False for f in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
