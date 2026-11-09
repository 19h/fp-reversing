#!/usr/bin/env python3
"""Original static dictionary/serializer/resource and transaction lifetime sources.
Read-only cache recovery; no native IPC, target execution/emulation or IDB writes.
"""
import json,struct
from pathlib import Path
from recover_xpc_reply_transport import Cache,Dylib,CACHE,CS,Image,ROOT,SDK,XP,DP,KP,PP,DAEMON,FLAGS,sha,h
P='xpc_resource_lifecycle';MP='/usr/lib/system/libsystem_malloc.dylib';OP='/usr/lib/libobjc.A.dylib'
FUNCTIONS={
 'object_dealloc':(XP,0x184b6ee44),'dictionary_dispose':(XP,0x184b6f3e8),
 'node_free':(XP,0x184b6f4e4),'data_dispose':(XP,0x184b6f174),
 'base_dispose':(XP,0x184b6efe4),'payload_dealloc':(XP,0x184b72c18),
 'serializer_dispose':(XP,0x184b7207c),'serializer_cleanup':(XP,0x184b71eb4),
 'clear_sent':(XP,0x184b71e54),'release_message':(XP,0x184b77c5c),
 'sent_event':(XP,0x184b77974),'begin':(XP,0x184ba0a7c),'end':(XP,0x184ba0af0),
 'begin_impl':(XP,0x184b885c8),'end_impl':(XP,0x184b88700),
 'release':(XP,0x184b6d6c4),'retain':(XP,0x184b6d638),
 'request_destroy':(XP,0x184b72cdc),'received_destroy':(XP,0x184b72c90),
 'xref_retain':(DP,0x185513f00),'xref_release':(DP,0x185513ffc),
 'internal_release':(DP,0x185513e60),'object_dispose':(DP,0x1855148dc),
 'object_alloc':(DP,0x18551483c)}
STUBS={
 0x188087470:(DP,'__os_object_release_without_xref_dispose'),0x188087480:(DP,'__os_object_retain'),
 0x188087460:(DP,'__os_object_release_internal'),0x188087440:(DP,'__os_object_alloc_realized'),
 0x18806d180:(DP,'_dispatch_release'),0x1880862f0:(DP,'_os_release'),
 0x18806d1b0:(DP,'_dispatch_set_context'),0x1880875e0:(DP,'_dispatch_get_context'),
 0x1880876a0:(DP,'_dispatch_mach_msg_get_msg'),0x18806c9e0:(MP,'_free'),
 0x18806d550:(PP,'_OSAtomicDequeue'),0x18806cad0:(PP,'_os_unfair_lock_lock_with_options'),
 0x18806cae0:(PP,'_os_unfair_lock_unlock'),0x18806cee0:(KP,'_getpid'),
 0x188087b30:(KP,'_proc_set_dirty'),0x18806d7b0:(KP,'__exit'),
 0x18806cf40:(KP,'_mach_port_deallocate'),0x18806d240:(KP,'_mach_msg_destroy'),
 0x18806d260:(KP,'_mach_port_destruct'),0x18806e620:(OP,'_class_createInstance')}
TYPE_SLOTS={'base':0x1e0615310,'data':0x1e0615340,'dictionary':0x1e0615350,'serializer':0x1e06153b8}
def build():
 c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a';libs={p:Dylib(c,p)for p in[XP,DP,KP,PP,MP,OP]};functions={}
 for role,(path,a)in FUNCTIONS.items():
  d=libs[path];f=d.function(a);assert len(f['instructions'])*4==len(bytes.fromhex(f['bytes']))
  functions[role]={**f,'library':path,'library_uuid':d.uuid,'original_nlist':d.symbols_at(a)}
 stubs={}
 for a,(path,name)in STUBS.items():
  bb=c.read(a,16);ii=list(CS.disasm(bb,a));assert[q.mnemonic for q in ii]==['adrp','add','ldr','braa']
  slot=int(ii[0].op_str.split('#')[1],0)+int(ii[1].op_str.split('#')[1],0);p=c.pointer(slot)
  d=libs[path];target=d.exports[name]['address'];assert p['target']==hex(target),(hex(a),name,p['target'],hex(target))
  stubs[hex(a)]={'bytes':bb.hex(),'pointer':p,'library':path,'exact_export':name,'export_address':hex(target),
   'original_nlist':d.symbols_at(target),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
 types={};base=0x1ed891ab0;table=0x1e2418f70
 for role,slot in TYPE_SLOTS.items():
  cl=c.pointer(slot);a=int(cl['target'],16);vslot=table+2*(a-base)+0x60;dis=c.pointer(vslot)
  target=int(functions[role+'_dispose'if role!='dictionary'else 'dictionary_dispose']['start'],16)
  assert int(dis['target'],16)==target
  types[role]={'class_pointer':cl,'class_original_nlist':libs[XP].symbols_at(a),
   'dispose_slot':dis,'dispose_original_nlist':libs[XP].symbols_at(target),'table_base':hex(table),'base_class':hex(base)}
 bounds={hex(a):c.pointer(a)for a in[0x1e06153d0,0x1e06153e8]}
 recaptured=[]
 for name in['xpc_reply_transport_source.json','xpc_receive_context_source.json']:
  prior=json.loads((ROOT/name).read_text())
  for role,f in prior['functions'].items():
   bb=bytes.fromhex(f['bytes']);assert c.read(int(f['start'],16),len(bb))==bb
   recaptured.append({'source':name,'role':role,'start':f['start'],'bytes_checked':len(bb),'sha256':h(bb)})
 prior=json.loads((ROOT/'daemon_xpc_reply_lifecycle_source.json').read_text());u=Image(DAEMON)
 assert sha(DAEMON)==prior['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for f in prior['fragments'].values():assert u.read(int(f['start'],16),len(bytes.fromhex(f['bytes']))).hex()==f['bytes']
 for q in prior['calls']:
  assert u.read(int(q['site'],16)-4,8).hex()==q['bytes']
  assert struct.unpack('<Q',u.read(int(q['slot'],16),8))[0]==int(q['pointer_word'],16)
 selector=c.read(0x188009bf0,16);selector_i=list(CS.disasm(selector,0x188009bf0));assert[q.mnemonic for q in selector_i]==['adrp','add','b','brk']
 assert c.read(0x1f4b86030,8)==b'dealloc\0'
 headers=[SDK/'usr/include'/q for q in['xpc/xpc.h','mach/message.h','mach/port.h','stdint.h']]
 deps=['recover_xpc_reply_transport.py','bootpolicy_cache_reader.py','verify_interface_contracts.py',
  'xpc_reply_transport_source.json','xpc_receive_context_source.json','daemon_xpc_reply_lifecycle_source.json']
 counts={'complete_functions':len(functions),'instructions':sum(len(f['instructions'])for f in functions.values()),
  'function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in functions.values()),'stub_bindings':len(stubs),
  'dispose_type_bindings':len(types),'class_range_bound_pointers':len(bounds),'prior_cache_ranges_recaptured':len(recaptured),
  'prior_cache_bytes_recaptured':sum(q['bytes_checked']for q in recaptured),'daemon_fragments_recaptured':len(prior['fragments']),
  'daemon_bytes_recaptured':sum(len(bytes.fromhex(f['bytes']))for f in prior['fragments'].values()),'daemon_call_bindings_rechecked':len(prior['calls']),
  'selector_stubs':1,'SDK_headers':len(headers)}
 return{'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cache_uuid':c.uuid,
  'cache_libraries':{p:d.uuid for p,d in libs.items()},'functions':functions,'stubs':stubs,'dispose_types':types,
  'class_range_bounds':bounds,'prior_cache_ranges':recaptured,
  'dealloc_selector':{'start':'0x188009bf0','bytes':selector.hex(),'selector_address':'0x1f4b86030','selector_bytes':'6465616c6c6f6300',
   'dispatch_target':'0x188000800','native_IMP_lookup_proved':False,'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in selector_i]},
  'daemon':{'path':str(DAEMON),'sha256':sha(DAEMON),'calls':prior['calls']},
  'cache_files':[{'path':p,'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],
  'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
