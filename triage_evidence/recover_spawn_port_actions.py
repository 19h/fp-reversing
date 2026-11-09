#!/usr/bin/env python3
"""Static spawn port-action and frame-origin capture; no target effects.
O(original bytes+fixups+selected instructions+finite locator work) resources.
"""
import json,struct
from pathlib import Path
from recover_spawn_conclave_abi import build as prior_build,ROOT,sha,SDK,h
from bootpolicy_cache_reader import Cache,Dylib,CACHE
from kernel_vm_mig_tools import Image
from analyze_spawn_port_frame import analyze
from recover_launchd_variant_binding import variant,binary,PATH,CS
P='spawn_port_actions'
FLAGS=['target_executed','target_emulated','native_IPC_emitted','native_spawn_executed',
 'native_port_identity_proved','native_right_balance_proved','native_Conclave_attribute_effect_proved',
 'whole_kernel_nonuse_proved','hardware_PAC_checked','full_goal_complete']
SETTERS=['_posix_spawnattr_setspecialport_np','_posix_spawnattr_setexceptionports_np',
 '_posix_spawnattr_setauditsessionport_np','_posix_spawnattr_set_importancewatch_port_np',
 '_posix_spawnattr_set_registered_ports_np','_posix_spawnattr_set_ptrauth_task_port_np',
 '_posix_spawnattr_set_virtual_env_np']
KERNEL={'port_prepare':0xfffffe000c2a5724,'port_import':0xfffffe000bcc9658,
 'send_release':0xfffffe000bcd0448,'special_front':0xfffffe000bcfa548,
 'special_store':0xfffffe000bcfa334,'registered_store':0xfffffe000bcfa5fc,
 'exception_store':0xfffffe000bcfc69c,'importance_store':0xfffffe000bd4ff08,
 'virtual_environment':0xfffffe000c2a5b04,'audit_join':0xfffffe000c25a0ec}

def build():
 s=prior_build();s['generator_sha256']=sha(__file__)
 for n in ['recover_spawn_conclave_abi.py','spawn_conclave_abi_source.json','analyze_spawn_port_frame.py','port_destroyed_return_source.json']:
  s['dependencies'][n]=sha(ROOT/n)
 for v in s['variants']:v['roles']={k:r for k,r in v['roles'].items()if k in ['launch_core','attribute_prepare']}
 s['cache_functions']={k:v for k,v in s['cache_functions'].items()if k=='_posix_spawn'}
 c=Cache();assert c.uuid==s['cache_uuid'];d=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib')
 for name in SETTERS:
  a=d.exports[name]['address'];f=d.function(a);assert len(f['instructions'])*4==len(bytes.fromhex(f['bytes']))
  s['cache_functions'][name]={**f,'exact_export':name,'original_nlist':d.symbols_at(a)}
 a=0x180553694;f=d.function(a);s['cache_functions']['port_append']={**f,'original_nlist':d.symbols_at(a)}
 s['kind_literals']=[{'address':hex(a),'bytes':c.read(a,8).hex(),'u32_words':list(struct.unpack('<II',c.read(a,8)))}for a in range(0x18057d328,0x18057d350,8)]
 paths={r['path']for r in s['cache_files']}|c.used|{str(CACHE)}
 s['cache_files']=[{'path':p,'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(paths)]
 im=Image();syms=im.k.symbols(KERNEL.values());s['kernel_functions']={k:v for k,v in s['kernel_functions'].items()if k in ['syscall','descriptor_helper','copyin']}
 for name,a in KERNEL.items():s['kernel_functions'][name]={**im.k.function(a),'original_nlist':syms[hex(a)]}
 notification=json.loads((ROOT/'port_destroyed_return_source.json').read_text())
 binding=json.loads((ROOT/'launchd_variant_binding_source.json').read_text());meta=binary(PATH);raw=PATH.read_bytes();shared=[]
 for j,v in enumerate(s['variants']):
  n=variant(meta,meta['slices'][j],raw)
  selected=[('registered_input',v['roles']['launch_core'],'ldr','w9, [x9, #0xf20]','spawn_port_actions_source.json'),
   ('notification_destination',notification['variants'][j]['roles']['notify_setup'],'ldr','w4, [x8, #0xf20]','port_destroyed_return_source.json'),
   ('fixed_host22',binding['variants'][j]['roles']['fixed22'],'ldr','w2, [x8, #0xf20]','launchd_variant_binding_source.json'),
   ('fixed_host16',binding['variants'][j]['roles']['fixed16'],'ldr','w2, [x8, #0xf20]','launchd_variant_binding_source.json')]
  for role,f,mn,op,provenance in selected:
   hits=[k for k,i in enumerate(f['instructions'])if(i['mnemonic'],i['operands'])==(mn,op)];assert len(hits)==1
   ix=hits[0];a=int(f['instructions'][ix-1]['ea'],16);bb=n.read(a,8);decoded=list(CS.disasm(bb,a));assert len(decoded)==2
   assert [(q.mnemonic,q.op_str)for q in decoded]==[(i['mnemonic'],i['operands'])for i in f['instructions'][ix-1:ix+1]]
   shared.append({'label':v['label'],'role':role,'global_cell':'0x10008af20','source_capture':provenance,
    'start':hex(a),'bytes':bb.hex(),'sha256':h(bb),
    'instructions':[{'ea':hex(q.address),'mnemonic':q.mnemonic,'operands':q.op_str}for q in decoded]})
 s['shared_cell_interfaces']=shared
 s['frame_alias_analysis']=analyze(s['kernel_functions']['syscall']);s.pop('receiver_census')
 s['record_geometry']={'attribute_pointer_offset':0xc8,'descriptor_pair_offset':0x20,
  'array_header_bytes':8,'action_stride_bytes':24,'kind_offset':0,'mask_offset':4,'port_name_offset':8,
  'behavior_offset':12,'flavor_offset':16,'selector_offset':20,'temporary_base_SP':0xf0,
  'temporary_count_offsets':[0,4,8],'temporary_registered_ports_offset':0x20,
  'temporary_registered_admitted_max':3,'temporary_registered_error_max':4,'temporary_bytes':64}
 s['SDK_headers']=[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in
  [SDK/'usr/include/spawn.h',SDK/'usr/include/mach/message.h',SDK/'usr/include/mach/port.h',
   SDK/'usr/include/mach/task_special_ports.h',SDK/'usr/include/mach/exception_types.h',SDK/'usr/include/sys/errno.h']]
 bodies=[r for v in s['variants']for r in v['roles'].values()]+list(s['cache_functions'].values())+list(s['kernel_functions'].values())
 s['verified_source_counts']={'launchd_variants':2,'launchd_functions':4,'cache_functions':len(s['cache_functions']),
  'kernel_functions':len(s['kernel_functions']),'complete_functions':len(bodies),'instructions':sum(len(r['instructions'])for r in bodies),
  'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in bodies),'fixups_compared':4894,
  'LLVM_only_words':sum(len(r['extended'])for v in s['variants']for r in v['roles'].values()),'cross_interface_cell_sites':len(shared),'cross_interface_fragment_bytes':sum(len(bytes.fromhex(q['bytes']))for q in shared),'port_setters':len(SETTERS),'kind_literals':len(s['kind_literals']),**s['frame_alias_analysis']['counts']}
 # The locator's instruction count is local; retain a separate total body count.
 s['verified_source_counts']['syscall_instructions']=s['verified_source_counts'].pop('instructions')
 s['verified_source_counts']['instructions']=sum(len(r['instructions'])for r in bodies)
 s.update({f:False for f in FLAGS});return s
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
