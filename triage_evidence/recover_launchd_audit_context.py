#!/usr/bin/env python3
"""Static launchd caller identity, Mach trailer and XPC metadata provenance.
O(B+F+I) time/space for bytes, fixups/references and selected instructions.
No target execution, IPC emission, fabricated caller records or IDB mutation.
"""
import json,struct
from pathlib import Path
from recover_launchd_variant_binding import variant,binary,PATH,SDK,sha,h,CS,refs,branches
from recover_host_special_registration import fixup_reference
from bootpolicy_cache_reader import Cache,Dylib,CACHE
ROOT=Path(__file__).resolve().parent;P='launchd_audit_context';TOKEN=0x10008b408
FLAGS=['target_executed','target_emulated','native_IPC_emitted','native_sender_identity_proved','native_policy_decision_proved','native_right_balance_proved','hardware_PAC_checked','full_goal_complete']
ROLES=[{'mach_event':0x100046804,'mach_entry':0x10004695c,'dictionary_entry':0x100046188,'raw_dispatch':0x1000462f8,'xpc_dispatch':0x1000464a8,'current_dictionary':0x10003a3a4,'register':0x100045930,'checkin_dispatcher':0x10002e16c,'checkin_handler':0x100038158,'checkin_core':0x100059640},{'mach_event':0x100045aec,'mach_entry':0x100045c38,'dictionary_entry':0x100045470,'raw_dispatch':0x1000455e0,'xpc_dispatch':0x100045790,'current_dictionary':0x100039864,'register':0x100044c60,'checkin_dispatcher':0x10002d830,'checkin_handler':0x100037690,'checkin_core':0x1000586a0}]
def build():
 old=json.loads((ROOT/'launchd_variant_binding_source.json').read_text());meta=binary(PATH);raw=PATH.read_bytes();variants=[]
 for j,label in enumerate(['arm64e','arm64e.x1']):
  n=variant(meta,meta['slices'][j],raw);n.prepare(label);roles={name:n.function(a)for name,a in ROLES[j].items()};by={r['address']:(name,r)for name,r in old['variants'][j]['stubs'].items()};used={}
  for r in roles.values():
   for i in r['instructions']:
    if i['mnemonic']in['b','bl']and i['operands'].startswith('#')and i['operands'][1:]in by:
     name,q=by[i['operands'][1:]];used[name]=n.stub(int(q['address'],16));assert used[name]==q
  ins=roles['xpc_dispatch']['instructions'];ix=next(k for k,i in enumerate(ins)if i['mnemonic']=='ldr'and i['operands']=='w22, [x9, w8, uxtw #2]');tab=int(ins[ix-2]['operands'].split('#')[1],0)+int(ins[ix-1]['operands'].split('#')[1],0);table={'address':hex(tab),'bytes':n.read(tab,56).hex(),'signed32_values':list(struct.unpack('<14i',n.read(tab,56)))};rr=refs(n,TOKEN)
  literals=[]
  for a in([0x100075276,0x1000753ad,0x1000753b7,0x10007550e,0x100075516]if j==0 else[0x100074236,0x10007436d,0x100074377,0x1000744ce,0x1000744d6]):literals.append({'address':hex(a),'text':n.cstring(a)})
  variants.append({'label':label,'uuid':n.inv['uuid'],'slice':n.inv['selected_slice'],'roles':roles,'stubs':used,'routine_group_table':table,'token_address_references':rr,'producer_callers':{'xpc_dispatch':branches(n,int(roles['xpc_dispatch']['start'],16)),'raw_dispatch_literals':refs(n,int(roles['raw_dispatch']['start'],16)),'mach_entry':branches(n,int(roles['mach_entry']['start'],16))},'LLVM':n.llvm_record,'strings':literals,'fixup_reference':fixup_reference(n),'reference_scope':'ADRP+ADD or ADR exact-address locators and aligned direct B/BL scans in __text. Not an exhaustive alias/indirect-writer census.'})
 c=Cache();xp='/usr/lib/system/libxpc.dylib';bsm='/usr/lib/libbsm.0.dylib';lib=Dylib(c,xp);blib=Dylib(c,bsm);functions=[]
 for a in[0x184b72b64,0x184b720ec,0x184b725f4,0x184b723dc,0x184b89370,0x184ba2404,0x184ba2ad8]:
  r=lib.function(a);assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']));r.update(library=xp,library_uuid=lib.uuid,exact_exports=[name for name,v in lib.exports.items()if v['address']==a],original_nlist=lib.symbols_at(a));functions.append(r)
 audit_fields=[]
 for ix,suffix in enumerate(['auid','euid','egid','ruid','rgid','pid','asid','pidversion']):
  name='_audit_token_to_'+suffix;a=blib.exports[name]['address'];r=blib.function(a);assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']));r.update(library=bsm,library_uuid=blib.uuid,exact_export=name,original_nlist=blib.symbols_at(a));functions.append(r);audit_fields.append({'index':ix,'offset_bytes':4*ix,'width_bytes':4,'name':suffix,'export':name,'address':hex(a),'global_address':hex(TOKEN+4*ix)})
 cache_stubs=[];libs={xp:lib,bsm:blib}
 for a in[0x18806eb80,0x1880876a0,0x18806d230,0x18806d240]:
  b=c.read(a,16);ii=list(CS.disasm(b,a));assert[i.mnemonic for i in ii]==['adrp','add','ldr','braa'];slot=int(ii[0].op_str.split('#')[1],0)+int(ii[1].op_str.split('#')[1],0);p=c.pointer(slot);target=int(p['target'],16);path=max((r for r in c.images if r['address']<=target),key=lambda r:r['address'])['path'];d=libs.setdefault(path,Dylib(c,path));names=[name for name,v in d.exports.items()if v['address']==target];assert names;cache_stubs.append({'stub':hex(a),'bytes':b.hex(),'pointer':p,'target':hex(target),'library':path,'uuid':d.uuid,'exact_exports':names})
 deps=['recover_launchd_variant_binding.py','recover_host_special_registration.py','recover_managed_fairplay_bridge.py','recover_rpc700_namespace.py','resolve_kernel_collection_interfaces.py','bootpolicy_cache_reader.py','launchd_variant_binding_source.json','bootstrap_checkin_handoff_source.json'];all_bodies=[r for v in variants for r in v['roles'].values()]+functions
 counts={'launchd_variants':2,'launchd_functions':sum(len(v['roles'])for v in variants),'cache_functions':len(functions),'complete_functions':len(all_bodies),'instructions':sum(len(r['instructions'])for r in all_bodies),'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in all_bodies),'LLVM_only_launchd_words':sum(len(r['extended'])for v in variants for r in v['roles'].values()),'fixups_compared':4894,'token_address_locator_hits':sum(len(v['token_address_references'])for v in variants),'named_audit_fields':len(audit_fields),'cache_stub_bindings':len(cache_stubs)}
 return {'generator_sha256':sha(__file__),'dependencies':{name:sha(ROOT/name)for name in deps},'launchd_source_path':str(PATH),'launchd_source_sha256':sha(PATH),'variants':variants,'audit_token_global':hex(TOKEN),'audit_fields':audit_fields,'cache_uuid':c.uuid,'cache_functions':functions,'cache_stubs':cache_stubs,'cache_files':[{'path':p,'uuid':c.files[p]['uuid'],'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],'inspection_tools':[{'path':r['path'],'sha256':sha(r['path'])}for r in old['tools']],'SDK_headers':[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in[SDK/'usr/include/mach/message.h',SDK/'usr/include/bsm/libbsm.h',SDK/'usr/include/bsm/audit.h']],'verified_source_counts':counts,**{f:False for f in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
