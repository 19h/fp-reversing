#!/usr/bin/env python3
"""Static endpoint callback, pending launch reason and asynchronous teardown ABI.
O(B+F+I) time/space. No recovered target, spawn, IPC, guard or IDB effects execute.
"""
import bisect,json
from pathlib import Path
from recover_launchd_variant_binding import variant,binary,PATH,SDK,sha,h,CS,refs,branches
from recover_host_special_registration import fixup_reference
from recover_port_destroyed_return import literals
from bootpolicy_cache_reader import Cache,Dylib,CACHE
from kernel_vm_mig_tools import Image
from resolve_kernel_collection_interfaces import CACHE as KC
ROOT=Path(__file__).resolve().parent;P='endpoint_job_lifecycle'
FLAGS=['target_executed','target_emulated','native_IPC_emitted','native_spawn_executed','native_relaunch_proved','native_right_balance_proved','native_guard_state_proved','hardware_PAC_checked','full_goal_complete']
def local_calls(n,r,mn='bl'):return[int(i['operands'][1:],0)for i in r['instructions']if i['mnemonic']==mn and i['operands'].startswith('#')and int(i['operands'][1:],0)in n.starts]
def after(r,mn,op):
 ii=r['instructions'];j=next(j for j,i in enumerate(ii)if i['mnemonic']==mn and i['operands']==op);assert ii[j+1]['mnemonic']=='bl';return int(ii[j+1]['operands'][1:],0)
def build():
 old=json.loads((ROOT/'launchd_variant_binding_source.json').read_text());service=json.loads((ROOT/'launchd_service_endpoint_source.json').read_text());returned=json.loads((ROOT/'port_destroyed_return_source.json').read_text());meta=binary(PATH);raw=PATH.read_bytes();variants=[]
 for j,label in enumerate(['arm64e','arm64e.x1']):
  n=variant(meta,meta['slices'][j],raw);n.prepare(label);roles={name:n.function(int(service['variants'][j]['roles'][src]['start'],16))for name,src in[('constructor','constructor'),('receive_event','event')]};roles.update({name:n.function(int(returned['variants'][j]['roles'][src]['start'],16))for name,src in[('endpoint_reset','endpoint_reset'),('async_prepare','async_reset')]});hits=branches(n,int(roles['constructor']['start'],16));assert len(hits)==1;roles['wrapper']=n.function(int(hits[0]['containing_start'],16));ll=literals(n,roles['wrapper']);assert len(ll)==1;roles['callback']=n.function(ll[0]);roles['start_gate']=n.function(local_calls(n,roles['callback'])[0]);roles['endpoint_remove']=n.function(local_calls(n,roles['callback'])[2]);tt=local_calls(n,roles['callback'],'b');assert len(tt)==1;roles['deactivate']=n.function(tt[0]);tt=local_calls(n,roles['start_gate'],'b');assert len(tt)==1;roles['launch_core']=n.function(tt[0])
  tails=[n.function(a)for a in local_calls(n,roles['deactivate'],'b')];assert len(tails)==2
  for r in tails:
   name='pending_restart'if any(i['mnemonic']=='str'and i['operands']=='wzr, [x0, #0x120]'for i in r['instructions'])else'job_remove';roles[name]=r
  rr=[]
  for a in set(local_calls(n,roles['deactivate'])):
   r=n.function(a)
   if any(i['mnemonic']=='ldr'and i['operands']=='x20, [x0, #0x98]'for i in r['instructions']):rr.append(r)
  assert len(rr)==1;roles['rearm_all']=rr[0];roles['endpoint_rearm']=n.function(local_calls(n,rr[0])[0]);roles['source_restore']=n.function(local_calls(n,rr[0],'b')[0]);ll=literals(n,roles['async_prepare']);assert len(ll)==1;roles['async_block']=n.function(ll[0]);writers=[]
  for ea,i in n.llvm.items():
   if i['mnemonic']=='str'and i['operands'].startswith('w')and '#0x120]'in i['operands']:writers.append({'site':hex(ea),'containing_start':hex(n.starts[bisect.bisect_right(n.starts,ea)-1]),'instruction':i})
  cand=[r for r in writers if r['instruction']['operands']=='w19, [x20, #0x120]'];assert len(cand)==1;roles['pending_writer']=n.function(int(cand[0]['containing_start'],16));fact_refs=refs(n,int(roles['wrapper']['start'],16));pending_refs=refs(n,int(roles['pending_writer']['start'],16));assert fact_refs;factory=min(int(r['containing_start'],16)for r in fact_refs);roles['selected_factory']=n.function(factory);roles['factory_bridge']=n.function(after(roles['selected_factory'],'mov','x7, x23'));roles['factory_clone']=n.function(after(roles['factory_bridge'],'mov','x7, x27'));roles['base_init']=n.function(after(roles['factory_clone'],'mov','x7, x20'));assert int(roles['pending_writer']['start'],16)in literals(n,roles['selected_factory'])and int(roles['wrapper']['start'],16)in literals(n,roles['selected_factory']);used={};by={r['address']:(name,r)for name,r in old['variants'][j]['stubs'].items()}
  for r in roles.values():
   for i in r['instructions']:
    if i['mnemonic']in['b','bl']and i['operands'].startswith('#')and i['operands'][1:]in by:
     name,q=by[i['operands'][1:]];used[name]=n.stub(int(q['address'],16));assert used[name]==q
  strings=[]
  for role in['callback','deactivate','start_gate','pending_writer']:
   ii=roles[role]['instructions']
   for a,b in zip(ii,ii[1:]):
    if a['mnemonic']=='adrp'and b['mnemonic']=='add'and a['operands'].split(',')[0]==b['operands'].split(',')[0]:
     addr=int(a['operands'].split('#')[1],0)+int(b['operands'].split('#')[1],0)
     if any(s['section']=='__cstring'and s['address']<=addr<s['address']+s['size']for s in n.meta['sections']):strings.append({'role':role,'address':hex(addr),'text':n.cstring(addr)})
  variants.append({'label':label,'uuid':n.inv['uuid'],'slice':n.inv['selected_slice'],'roles':roles,'stubs':used,'callback_table_contract':[{'index':k,'table_offset_bytes':8*k,'job_field_offset_bytes':0x218+8*k,'target':hex(a)}for k,a in enumerate(literals(n,roles['selected_factory'])[:8])],'constructor_direct_callers':hits,'wrapper_address_references':fact_refs,'pending_writer_address_references':pending_refs,'pending120_immediate_store_candidates':writers,'strings':strings,'LLVM':n.llvm_record,'fixup_reference':fixup_reference(n),'scope':'Selected factory plus exact-address ADRP+ADD/ADR locators and immediate STR-w+0x120 candidates in __text; indirect factories, aliases, wider stores and native epochs excluded.'})
 im=Image();sub=next(s for s in im.subsystems()if s['start']==3200);mig=next(r for r in sub['routines']if r['id']==3232);trap=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text())['mach_entries'][25];assert im.pointer(0xfffffe0007efb010+24*25+8)==trap['handler_pointer'];aa={'destruct_trap':int(trap['handler_pointer']['target'],16),'destruct_MIG':int(mig['stub']['target'],16),'destruct_core':0xfffffe000bce0714,'entry_lookup':0xfffffe000bcd2f34,'right_destruct':0xfffffe000bcd4ab0,'port_destroy':0xfffffe000bccdbb4};syms=im.k.symbols(list(aa.values()));kf={name:{**im.k.function(a),'original_nlist':syms[hex(a)]}for name,a in aa.items()};c=Cache();libpath='/usr/lib/system/libsystem_kernel.dylib';d=Dylib(c,libpath);cf={}
 for name in['_mach_port_destruct','__kernelrpc_mach_port_destruct_trap','__kernelrpc_mach_port_destruct']:
  a=d.exports[name]['address'];r=d.function(a);assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']));cf[name]={**r,'exact_export':name,'original_nlist':d.symbols_at(a)}
 deps=['recover_launchd_variant_binding.py','recover_port_destroyed_return.py','recover_host_special_registration.py','recover_managed_fairplay_bridge.py','recover_rpc700_namespace.py','resolve_kernel_collection_interfaces.py','bootpolicy_cache_reader.py','kernel_native_reader.py','kernel_vm_mig_tools.py','launchd_variant_binding_source.json','launchd_service_endpoint_source.json','port_destroyed_return_source.json','kernel_dispatch_contracts.json'];bodies=[r for v in variants for r in v['roles'].values()]+list(kf.values())+list(cf.values());counts={'launchd_variants':2,'launchd_functions':sum(len(v['roles'])for v in variants),'kernel_functions':len(kf),'cache_functions':len(cf),'complete_functions':len(bodies),'instructions':sum(len(r['instructions'])for r in bodies),'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in bodies),'LLVM_only_launchd_words':sum(len(r['extended'])for v in variants for r in v['roles'].values()),'fixups_compared':4894,'constructor_direct_call_sites':sum(len(v['constructor_direct_callers'])for v in variants),'wrapper_literal_sites':sum(len(v['wrapper_address_references'])for v in variants),'pending_writer_literal_sites':sum(len(v['pending_writer_address_references'])for v in variants),'pending120_store_candidates':sum(len(v['pending120_immediate_store_candidates'])for v in variants)}
 return{'generator_sha256':sha(__file__),'dependencies':{name:sha(ROOT/name)for name in deps},'launchd_source_path':str(PATH),'launchd_source_sha256':sha(PATH),'variants':variants,'kernel_source_path':str(KC),'kernel_source_sha256':sha(KC),'kernel_functions':kf,'MIG3232':mig,'trap25':trap,'cache_uuid':c.uuid,'cache_library':libpath,'cache_library_uuid':d.uuid,'cache_functions':cf,'cache_files':[{'path':p,'uuid':c.files[p]['uuid'],'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],'inspection_tools':[{'path':r['path'],'sha256':sha(r['path'])}for r in old['tools']],'SDK_headers':[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in[SDK/'usr/include/mach/mach_port.h',SDK/'usr/include/mach/port.h',SDK/'usr/include/spawn.h',SDK/'usr/include/sys/errno.h']],'verified_source_counts':counts,**{f:False for f in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
