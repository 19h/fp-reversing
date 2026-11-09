#!/usr/bin/env python3
"""Static receive-right return via MACH_NOTIFY_PORT_DESTROYED.
O(B+F+I) time/space for original bytes, fixups and selected instructions.
No recovered target code, port operation, IPC emission or IDB mutation executes.
"""
import bisect,json,struct
from pathlib import Path
from recover_launchd_variant_binding import variant,binary,PATH,SDK,sha,h,CS,refs,branches
from recover_host_special_registration import fixup_reference
from bootpolicy_cache_reader import Cache,Dylib,CACHE
from kernel_vm_mig_tools import Image
from resolve_kernel_collection_interfaces import CACHE as KC
ROOT=Path(__file__).resolve().parent;P='port_destroyed_return'
FLAGS=['target_executed','target_emulated','native_IPC_emitted','native_notification_received','native_receive_name_identity_proved','native_right_balance_proved','native_guard_state_proved','hardware_PAC_checked','full_goal_complete']
def direct(r):return[int(i['operands'][1:],0)for i in r['instructions']if i['mnemonic']in['bl','b']and i['operands'].startswith('#')]
def literals(n,r):
 out=[]
 for a,b in zip(r['instructions'],r['instructions'][1:]):
  if a['mnemonic']=='adrp'and b['mnemonic']=='add'and a['operands'].split(',')[0]==b['operands'].split(',')[0]:
   dest=int(a['operands'].split('#')[1],0)+int(b['operands'].split('#')[1],0)
   if dest in n.starts:out.append(dest)
 return out
def build():
 old=json.loads((ROOT/'launchd_variant_binding_source.json').read_text());hand=json.loads((ROOT/'bootstrap_checkin_handoff_source.json').read_text());audit=json.loads((ROOT/'launchd_audit_context_source.json').read_text());meta=binary(PATH);raw=PATH.read_bytes();variants=[]
 for j,label in enumerate(['arm64e','arm64e.x1']):
  n=variant(meta,meta['slices'][j],raw);n.prepare(label);roles={name:n.function(int(hand['variants'][j]['roles'][name]['start'],16))for name in['notify_setup','activate','send_name']};roles['raw_dispatch']=n.function(int(audit['variants'][j]['roles']['raw_dispatch']['start'],16));found=[]
  for seg in n.meta['segments']:
   if not seg['file_size']:continue
   data=n.read(seg['address'],seg['file_size']);start=0
   while True:
    at=data.find(struct.pack('<II',64,73),start)
    if at<0:break
    found.append(seg['address']+at-8);start=at+1
  assert len(found)==1;header=found[0];table=header+32;rows=[]
  for index in range(9):
   at=table+40*index;ptr=n.fixups.get(at+8);rows.append({'id':64+index,'address':hex(at),'bytes':n.read(at,40).hex(),'stub':ptr})
  registry={'address':hex(header),'bytes':n.read(header,32).hex(),'selector':n.fixups[header],'routines':rows};roles['notification_lookup']=n.function(int(registry['selector']['target'],16));roles['id69_stub']=n.function(int(rows[5]['stub']['target'],16));local=[a for a in direct(roles['id69_stub'])if a in n.starts];assert len(local)==1;roles['id69_handler']=n.function(local[0]);local=[a for a in direct(roles['id69_handler'])if a in n.starts];assert len(local)==1;roles['record_lookup']=n.function(local[0]);candidates={r['containing_start']for r in refs(n,table)}-{roles['notification_lookup']['start']};assert len(candidates)==1;roles['notification_demux']=n.function(int(candidates.pop(),16));candidates={r['containing_start']for r in refs(n,int(roles['notification_demux']['start'],16))};assert len(candidates)==1;roles['notification_init']=n.function(int(candidates.pop(),16))
  ll=literals(n,roles['notify_setup']);assert len(ll)==2;roles['event_callback']=n.function(ll[0]);roles['cancel_callback']=n.function(ll[1]);roles['record_insert']=n.function([a for a in direct(roles['notify_setup'])if a in n.starts][-1]);roles['record_unlink']=n.function([a for a in direct(roles['event_callback'])if a in n.starts][-1]);ll=literals(n,roles['activate']);assert len(ll)==4;roles['endpoint_reset']=n.function(ll[0]);ll=[a for a in direct(roles['endpoint_reset'])if a in n.starts and a!=int(roles['send_name']['start'],16)];assert len(ll)==3;roles['guard_assert']=n.function(ll[0]);roles['async_reset']=n.function(ll[1]);roles['receive_drain']=n.function(ll[2])
  writers=[]
  for ea,i in n.llvm.items():
   if i['mnemonic']=='strb'and '#0x29]'in i['operands']:writers.append({'site':hex(ea),'containing_start':hex(n.starts[bisect.bisect_right(n.starts,ea)-1])})
  assert len(writers)==1;roles['explicit_cancel']=n.function(int(writers[0]['containing_start'],16));cancel_callers=branches(n,int(roles['explicit_cancel']['start'],16));assert len(cancel_callers)==1;roles['endpoint_cancel']=n.function(int(cancel_callers[0]['containing_start'],16));roles['record_allocator']=n.function([a for a in direct(roles['notify_setup'])if a in n.starts][0]);used={};by={r['address']:(name,r)for name,r in old['variants'][j]['stubs'].items()}
  for r in roles.values():
   for i in r['instructions']:
    if i['mnemonic']in['b','bl']and i['operands'].startswith('#')and i['operands'][1:]in by:
     name,q=by[i['operands'][1:]];used[name]=n.stub(int(q['address'],16));assert used[name]==q
  datatype=n.fixups[0x100086cf8];assert datatype['symbol']=='__dispatch_source_type_data_add';variants.append({'label':label,'uuid':n.inv['uuid'],'slice':n.inv['selected_slice'],'roles':roles,'stubs':used,'notification_registry':registry,'data_add_type_binding':datatype,'explicit_cancel_byte29_writer_candidates':writers,'explicit_cancel_direct_callers':cancel_callers,'LLVM':n.llvm_record,'fixup_reference':fixup_reference(n),'scope':'Only exact STRB immediate+0x29 LLVM locators and aligned direct B/BL callers. Aliases/partial stores/indirect callers excluded.'})
 im=Image();sub=next(s for s in im.subsystems()if s['start']<=3213<s['end']);routine=next(r for r in sub['routines']if r['id']==3213);row=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text())['mach_entries'][77];ptr=im.pointer(0xfffffe0007efb010+24*77+8);assert ptr==row['handler_pointer'];ka={'request_trap':int(ptr['target'],16),'request_MIG':int(routine['stub']['target'],16),'request_core':0xfffffe000bcdf1ec,'backup_admission':0xfffffe000bccbe54,'request_policy':0xfffffe000bccc064,'port_destroy':0xfffffe000bccdbb4};syms=im.k.symbols(list(ka.values()));kernel={name:{**im.k.function(a),'original_nlist':syms[hex(a)]}for name,a in ka.items()};constant={'address':hex(0xfffffe000700dcb0),'bytes':im.k.read(0xfffffe000700dcb0,8).hex()}
 c=Cache();path='/usr/lib/system/libsystem_kernel.dylib';lib=Dylib(c,path);cf={}
 for role,a in[('request_wrapper',lib.exports['_mach_port_request_notification']['address']),('request_trap',0x180547ccc),('request_MIG',0x18054bd00)]:
  f=lib.function(a);assert len(f['instructions'])*4==len(bytes.fromhex(f['bytes']));cf[role]={**f,'original_nlist':lib.symbols_at(a),'exact_exports':[name for name,r in lib.exports.items()if r['address']==a]}
 constants=[{'address':hex(a),'bytes':c.read(a,8).hex()}for a in[0x18057d3b0,0x18057d650]]
 deps=['recover_launchd_variant_binding.py','recover_host_special_registration.py','recover_managed_fairplay_bridge.py','recover_rpc700_namespace.py','resolve_kernel_collection_interfaces.py','bootpolicy_cache_reader.py','kernel_native_reader.py','kernel_vm_mig_tools.py','launchd_variant_binding_source.json','bootstrap_checkin_handoff_source.json','launchd_audit_context_source.json','kernel_dispatch_contracts.json','kernel_notification_send_source.json'];bodies=[r for v in variants for r in v['roles'].values()]+list(kernel.values())+list(cf.values());counts={'launchd_variants':2,'launchd_functions':sum(len(v['roles'])for v in variants),'kernel_functions':len(kernel),'cache_functions':len(cf),'complete_functions':len(bodies),'instructions':sum(len(r['instructions'])for r in bodies),'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in bodies),'LLVM_only_launchd_words':sum(len(r['extended'])for v in variants for r in v['roles'].values()),'fixups_compared':4894,'notification_registry_rows':18,'explicit_cancel_direct_callers':sum(len(v['explicit_cancel_direct_callers'])for v in variants)}
 return{'generator_sha256':sha(__file__),'dependencies':{name:sha(ROOT/name)for name in deps},'launchd_source_path':str(PATH),'launchd_source_sha256':sha(PATH),'variants':variants,'kernel_source_path':str(KC),'kernel_source_sha256':sha(KC),'kernel_functions':kernel,'kernel_notification_constant':constant,'kernel_request_registration':{'subsystem':{k:v for k,v in sub.items()if k!='routines'},'routine':routine,'trap':row},'cache_uuid':c.uuid,'cache_library':path,'cache_library_uuid':lib.uuid,'cache_functions':cf,'cache_MIG_constants':constants,'cache_files':[{'path':p,'uuid':c.files[p]['uuid'],'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],'inspection_tools':[{'path':r['path'],'sha256':sha(r['path'])}for r in old['tools']],'SDK_headers':[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in[SDK/'usr/include/mach/message.h',SDK/'usr/include/mach/notify.h',SDK/'usr/include/mach/mach_port.h',SDK/'usr/include/mach/port.h']],'verified_source_counts':counts,**{f:False for f in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
