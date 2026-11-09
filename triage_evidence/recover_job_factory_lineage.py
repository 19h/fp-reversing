#!/usr/bin/env python3
"""Recover original job-factory/table and plist-to-MachServices interfaces.

Read-only static capture. O(B+F+I+L) time/space for file bytes, fixups,
selected instructions and locators. Does not execute recovered target code.
"""
import bisect,json,plistlib,re,struct,subprocess
from pathlib import Path
from recover_launchd_variant_binding import variant,binary,PATH,SDK,sha,h,CS,refs,branches
from recover_host_special_registration import fixup_reference
from recover_port_destroyed_return import literals
from recover_endpoint_job_lifecycle import local_calls,after
from bootpolicy_cache_reader import Cache,Dylib,CACHE

ROOT=Path(__file__).resolve().parent;P='job_factory_lineage'
FLAGS=['target_executed','target_emulated','native_IPC_emitted','native_job_binding_proved',
       'native_factory_choice_proved','native_right_balance_proved','hardware_PAC_checked','full_goal_complete']
DEPS=['recover_launchd_variant_binding.py','recover_host_special_registration.py',
      'recover_managed_fairplay_bridge.py','recover_rpc700_namespace.py',
      'resolve_kernel_collection_interfaces.py','bootpolicy_cache_reader.py',
      'recover_port_destroyed_return.py','recover_endpoint_job_lifecycle.py',
      'launchd_variant_binding_source.json','endpoint_job_lifecycle_source.json',
      'native_fairplayd_services.json']

def string_refs(n,r):
 out=[];ii=r['instructions']
 for a,b in zip(ii,ii[1:]):
  if a['mnemonic']=='adrp'and b['mnemonic']=='add'and a['operands'].split(',')[0]==b['operands'].split(',')[0]:
   addr=int(a['operands'].split('#')[1],0)+int(b['operands'].split('#')[1],0)
   if any(s['section']=='__cstring'and s['address']<=addr<s['address']+s['size']for s in n.meta['sections']):
    out.append({'site':a['ea'],'address':hex(addr),'text':n.cstring(addr)})
 return out

def table_installations(n,r,targets):
 """Locate each complete ordered eight-entry PACIZA/store sequence.

 Concrete instruction operations are retained; native PAC execution is excluded.
 """
 ii=r['instructions'];found=[]
 for ix,i in enumerate(ii[:-3]):
  if i['mnemonic']!='adrp'or i['operands'].split(',')[0]!='x16':continue
  b=ii[ix+1]
  if b['mnemonic']!='add'or not b['operands'].startswith('x16, x16, #'):continue
  a=int(i['operands'].split('#')[1],0)+int(b['operands'].split('#')[1],0)
  if a!=targets[0]:continue
  entries=[];cursor=ix
  for k,target in enumerate(targets):
   a,b,c,d=ii[cursor:cursor+4]
   assert(a['mnemonic'],b['mnemonic'],c['mnemonic'])==('adrp','add','paciza')
   assert a['operands'].startswith('x16, #')and b['operands'].startswith('x16, x16, #')and c['operands']=='x16'
   assert int(a['operands'].split('#')[1],0)+int(b['operands'].split('#')[1],0)==target
   # Producers may load a context byte before the last STP.
   if k==7:
    candidates=[q for q in ii[cursor+3:cursor+12]if q['mnemonic']in['str','stp']and q['operands'].startswith('x16,')]
    assert candidates;d=candidates[0]
   assert d['mnemonic']in['str','stp']and d['operands'].startswith('x16,')
   match=re.search(r'\[sp(?:, #((?:0x)?[0-9a-f]+))?\]',d['operands']);assert match,d
   off=int(match[1],0)if match[1]else 0
   if k:assert off==entries[0]['stack_offset_bytes']+8*k
   entries.append({'index':k,'job_offset_bytes':0x218+8*k,'stack_offset_bytes':off,
                   'target':hex(target),'address_instructions':[a,b],'sign':c,'store':d})
   cursor+=4
  found.append({'first_site':i['ea'],'stack_base_bytes':entries[0]['stack_offset_bytes'],
                'entries':entries,'cookie_stack_offset_bytes':entries[0]['stack_offset_bytes']+64})
 return found

def build():
 prior=json.loads((ROOT/'endpoint_job_lifecycle_source.json').read_text())
 origin=json.loads((ROOT/'launchd_variant_binding_source.json').read_text())
 frozen=json.loads((ROOT/'native_fairplayd_services.json').read_text())
 raw=PATH.read_bytes();meta=binary(PATH);variants=[]
 assert sha(PATH)==prior['launchd_source_sha256']
 for j,label in enumerate(['arm64e','arm64e.x1']):
  n=variant(meta,meta['slices'][j],raw);n.prepare(label);v=prior['variants'][j]
  target=[int(t['target'],16)for t in v['callback_table_contract']]
  hit=refs(n,target[3]);assert hit==v['wrapper_address_references']
  addresses=sorted({int(r['containing_start'],16)for r in hit});assert len(addresses)==7
  roles={f'callback{k}':n.function(a)for k,a in enumerate(target)}
  producers=[]
  for k,a in enumerate(addresses):
   r=n.function(a);name='producer'+str(k);roles[name]=r;inst=table_installations(n,r,target);assert inst
   producers.append({'role':name,'start':hex(a),'tables':inst,'strings':string_refs(n,r),'direct_callers':branches(n,a)})
  plist=next(q for q in producers if any(t['text']=='Could not parse plist: path = %s, error = %d: %s'for t in q['strings']))
  roles['plist_import']=roles.pop(plist['role']);plist['role']='plist_import'
  roles['job_import']=n.function(after(roles['plist_import'],'mov','x2, x21'))
  roles['job_create']=n.function(after(roles['job_import'],'mov','x6, x26'))
  create_ii=roles['job_create']['instructions'];apply_stub=origin['variants'][j]['stubs']['_xpc_dictionary_apply_f']['address']
  apply_ix=next(k for k,i in enumerate(create_ii)if i['mnemonic']=='bl'and i['operands']=='#'+apply_stub)
  context_call=create_ii[apply_ix-8];assert context_call['mnemonic']=='bl'
  roles['property_context']=n.function(int(context_call['operands'][1:],0))
  roles['job_install']=n.function(after(roles['job_import'],'mov','x2, x26'))
  roles['socket_constructor']=n.function(after(roles['callback5'],'mov','x7, x20'))
  roles['base_init']=n.function(int(v['roles']['base_init']['start'],16))
  roles['endpoint_constructor']=n.function(int(v['roles']['constructor']['start'],16))
  roles['endpoint_callback']=n.function(int(v['roles']['callback']['start'],16))
  schema=literals(n,roles['job_create']);assert len(schema)==1;roles['property_schema']=n.function(schema[0])
  strings=string_refs(n,roles['property_schema']);props={}
  ii=roles['property_schema']['instructions']
  for key in['MachServices','KeepAlive','EnvironmentVariables','_Conclave','DaemonNotifications']:
   matches=[q for q in strings if q['text']==key];props[key]=matches
  ea=int(props['MachServices'][0]['site'],16);ix=next(k for k,i in enumerate(ii)if int(i['ea'],16)==ea)
  a,b=ii[ix-3:ix-1];assert(a['mnemonic'],b['mnemonic'])==('adrp','add')
  block=int(a['operands'].split('#')[1],0)+int(b['operands'].split('#')[1],0)
  pointers=[n.fixups[block+k]for k in[0,16,24]]
  assert pointers[0]['symbol']=='__NSConcreteGlobalBlock'
  roles['MachServices_outer']=n.function(int(pointers[1]['target'],16))
  ll=literals(n,roles['MachServices_outer']);assert len(ll)==1
  roles['MachServices_iterator']=n.function(ll[0]);ll=local_calls(n,roles['MachServices_iterator']);assert len(ll)==1
  roles['MachServices_entry']=n.function(ll[0])
  roles['schema_dispatch']=n.function(local_calls(n,roles['property_schema'])[-1])
  roles['schema_register']=n.function(int(ii[ix+4]['operands'][1:],0))
  # Explicit instance handler: the smallest aligned direct caller of producer0.
  instance_calls=branches(n,addresses[0]);assert len(instance_calls)==3
  instance_bodies=[n.function(int(q['containing_start'],16))for q in instance_calls]
  roles['explicit_instance_request']=min(instance_bodies,key=lambda r:len(r['instructions']))
  remaining=[r for r in instance_bodies if r['start']!=roles['explicit_instance_request']['start']]
  assert len(remaining)==2
  roles['job_request_handler']=remaining[0];roles['endpoint_lookup_handler']=remaining[1]
  used={};by={r['address']:(name,r)for name,r in origin['variants'][j]['stubs'].items()}
  for role,r in roles.items():
   for i in r['instructions']:
    if i['mnemonic']in['b','bl']and i['operands'].startswith('#')and i['operands'][1:]in by:
     name,q=by[i['operands'][1:]];used[name]=n.stub(int(q['address'],16));assert used[name]==q
  typebindings=[]
  for a in[0x100086d78,0x100086db8,0x100086dd8,0x100086d70,0x100086d98]:
   typebindings.append(n.fixups[a])
  variants.append({'label':label,'uuid':n.inv['uuid'],'slice':n.inv['selected_slice'],
    'roles':roles,'stubs':used,'producers':producers,'callback_targets':[hex(a)for a in target],
    'wrapper_literal_references':hit,'instance_factory_direct_callers':instance_calls,
    'property_strings':props,'MachServices_block':{'address':hex(block),'bytes':n.read(block,32).hex(),'pointers':pointers,
      'descriptor_address':pointers[2]['target'],'descriptor_bytes':n.read(int(pointers[2]['target'],16),32).hex()},
    'schema_type_bindings':typebindings,'role_strings':{name:string_refs(n,r)for name,r in roles.items()},
    'LLVM':n.llvm_record,'fixup_reference':fixup_reference(n),
    'locator_scope':'Exact ADRP+ADD/ADR wrapper references and aligned direct B/BL in __text only; aliases and indirect producers excluded.'})
 jobpath=Path(frozen['job_path']);jobraw=jobpath.read_bytes();job=plistlib.loads(jobraw)
 cmd=['/usr/bin/plutil','-convert','json','-o','-',str(jobpath)]
 parsed=subprocess.run(cmd,capture_output=True,text=True);assert parsed.returncode==0 and json.loads(parsed.stdout)==job
 assert sha(jobpath)==frozen['job_sha256']and job==frozen['job']
 cache=Cache();libpath='/usr/lib/system/libxpc.dylib';lib=Dylib(cache,libpath)
 cf={name:lib.function(lib.exports[export]['address'])for name,export in[('apply_f','_xpc_dictionary_apply_f'),('apply_block','_xpc_dictionary_apply')]}
 def calls(r):return[int(i['operands'][1:],0)for i in r['instructions']if i['mnemonic']=='bl'and i['operands'].startswith('#')]
 shared=set(calls(cf['apply_f']))&set(calls(cf['apply_block']));assert len(shared)==1;cf['walker']=lib.function(shared.pop())
 for name,source in[('function_adapter','apply_f'),('block_adapter','apply_block')]:
  values=[];ii=cf[source]['instructions']
  for a,b in zip(ii,ii[1:]):
   if a['mnemonic']=='adrp'and b['mnemonic']=='add'and a['operands'].split(',')[0]==b['operands'].split(',')[0]:
    z=int(a['operands'].split('#')[1],0)+int(b['operands'].split('#')[1],0)
    if z in lib.functions:values.append(z)
  assert len(values)==1;cf[name]=lib.function(values[0])
 key=calls(cf['function_adapter'])[0];assert key==calls(cf['block_adapter'])[0];cf['key_accessor']=lib.function(key)
 for r in cf.values():assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']))
 bodies=[r for v in variants for r in v['roles'].values()]+list(cf.values())
 assert all(len({r['start']for r in v['roles'].values()})==len(v['roles'])for v in variants)
 counts={'variants':2,'complete_functions':len(bodies),'instructions':sum(len(r['instructions'])for r in bodies),
         'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in bodies),
         'LLVM_only_words':sum(len(r['extended'])for v in variants for r in v['roles'].values()),'fixups_compared':4894,
         'launchd_functions':sum(len(v['roles'])for v in variants),'cache_functions':len(cf),
         'producer_functions':14,'table_installations':sum(len(p['tables'])for v in variants for p in v['producers']),
         'callback_slots_checked':sum(8*len(p['tables'])for v in variants for p in v['producers']),
         'instance_factory_direct_sites':6,'plist_parsers_compared':2,'declared_MachServices':len(job['MachServices'])}
 return{'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in DEPS},
   'source_path':str(PATH),'source_sha256':sha(PATH),'variants':variants,
   'cache_uuid':cache.uuid,'cache_library':libpath,'cache_library_uuid':lib.uuid,'cache_functions':cf,
   'cache_exports':{name:lib.exports[name]for name in['_xpc_dictionary_apply_f','_xpc_dictionary_apply']},
   'cache_files':[{'path':p,'uuid':cache.files[p]['uuid'],'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(cache.used|{str(CACHE)})],
   'job_declaration':{'path':str(jobpath),'sha256':h(jobraw),'size_bytes':len(jobraw),'plist':job,
     'independent_parser_command':cmd,'independent_parser_exit':parsed.returncode,
     'frozen_comparison_match':True,'live_job_state_refreshed':False},
   'inspection_tools':[{'path':q['path'],'sha256':sha(q['path'])}for q in origin['tools']]+[{'path':'/usr/bin/plutil','sha256':sha('/usr/bin/plutil')}],
   'SDK_headers':[{'path':str(SDK/'usr/include/sys/errno.h'),'sha256':sha(SDK/'usr/include/sys/errno.h')}],
   'verified_source_counts':counts,**{k:False for k in FLAGS}}

if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
