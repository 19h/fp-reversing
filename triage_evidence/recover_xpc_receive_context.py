#!/usr/bin/env python3
"""Read-only cache ingress, received-context and audit-token source recovery.
No target code execution/emulation, Mach requests or IDB mutation.
"""
import bisect,json,struct
from recover_xpc_reply_transport import Cache,Dylib,CACHE,CS,Image,ROOT,SDK,XP,DP,KP,PP,DAEMON,FLAGS,sha,h
P='xpc_receive_context';BP='/usr/lib/libbsm.0.dylib';CP='/usr/lib/system/libsystem_collections.dylib'
FUNCTIONS={
 'unpack':(XP,0x184b77dfc),'receive':(XP,0x184b720ec),'validate_header':(XP,0x184b89370),
 'payload':(XP,0x184b723dc),'graph':(XP,0x184b725f4),'set_connection':(XP,0x184b789f0),
 'destroy_received':(XP,0x184b72c90),'destroy_request':(XP,0x184b72cdc),
 'dictionary_audit':(XP,0x184b72b64),'connection_audit':(XP,0x184b82f58),
 'peer_requirement':(XP,0x184b9415c),'mach_event':(XP,0x184b77fa0),
 'call_handler':(XP,0x184b79fb8),'wire_apply':(XP,0x184b870e4),
 'deserialize_apply':(XP,0x184b871dc),'set_remote':(XP,0x184b8839c),
 'sync_caller':(XP,0x184b7744c),'async_caller':(XP,0x184b7b7d8),
 'audit_pid':(BP,0x20638d720),'audit_pidversion':(BP,0x20638d750),
 'install_handler':(XP,0x184b75db8),'copy_handler':(XP,0x184b75fc8)}
STUBS={
 0x1880876a0:(DP,'_dispatch_mach_msg_get_msg'),0x1880863d0:(DP,'_voucher_copy'),
 0x1880874a0:(DP,'__os_object_retain_with_resurrect'),0x1880862f0:(DP,'_os_release'),
 0x188087a20:(CP,'_os_map_128_find'),0x188087a40:(CP,'_os_map_128_insert'),
 0x18806cf40:(KP,'_mach_port_deallocate'),0x18806d1a0:(DP,'_dispatch_retain'),
 0x188087440:(DP,'__os_object_alloc_realized'),0x18806cad0:(PP,'_os_unfair_lock_lock_with_options'),
 0x18806cae0:(PP,'_os_unfair_lock_unlock'),0x18806d240:(KP,'_mach_msg_destroy')}
def build():
 c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a';libs={p:Dylib(c,p)for p in[XP,DP,KP,PP,BP,CP]};functions={}
 for role,(path,a)in FUNCTIONS.items():
  d=libs[path];f=d.function(a);assert len(f['instructions'])*4==len(bytes.fromhex(f['bytes']))
  functions[role]={**f,'library':path,'library_uuid':d.uuid,'original_nlist':d.symbols_at(a)}
 stubs={}
 for a,(path,name)in STUBS.items():
  bb=c.read(a,16);ii=list(CS.disasm(bb,a));assert[q.mnemonic for q in ii]==['adrp','add','ldr','braa']
  slot=int(ii[0].op_str.split('#')[1],0)+int(ii[1].op_str.split('#')[1],0);p=c.pointer(slot)
  d=libs[path];target=d.exports[name]['address'];assert p['target']==hex(target),(hex(a),name,p['target'],hex(target))
  stubs[hex(a)]={'bytes':bb.hex(),'pointer':p,'library':path,'exact_export':name,
   'original_nlist':d.symbols_at(target),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
 prior=json.loads((ROOT/'xpc_reply_transport_source.json').read_text());recaptured=[]
 for role,f in prior['functions'].items():
  bb=bytes.fromhex(f['bytes']);assert c.read(int(f['start'],16),len(bb))==bb
  recaptured.append({'role':role,'start':f['start'],'bytes_checked':len(bb),'sha256':h(bb)})
 listener=json.loads((ROOT/'daemon_xpc_listener_source.json').read_text());u=Image(DAEMON)
 assert sha(DAEMON)==listener['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 daemon_ranges={**listener['complete_functions'],**listener['fragments']}
 for f in daemon_ranges.values():assert u.read(int(f['start'],16),len(bytes.fromhex(f['bytes']))).hex()==f['bytes']
 for q in listener['calls']:
  assert u.read(int(q['site'],16)-4,8).hex()==q['bytes']
  assert struct.unpack('<Q',u.read(int(q['slot'],16),8))[0]==int(q['pointer_word'],16)
 # Exhaust all text words for direct BL/B targets; indirect references are outside this census.
 d=libs[XP];sec=next(q for q in d.sections if q['name']=='__text');raw=c.read(sec['address'],sec['size']);assert len(raw)%4==0;calls=[]
 targets={0x184b77dfc,0x184b8839c}
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
  if w&0x7c000000!=0x14000000:continue
  a=sec['address']+4*j;delta=w&0x3ffffff;delta=delta-(1<<26)if delta&(1<<25)else delta;target=a+delta*4
  if target not in targets:continue
  ii=list(CS.disasm(raw[4*j:4*j+4],a));assert len(ii)==1 and ii[0].mnemonic in['b','bl']and int(ii[0].op_str[1:],0)==target
  start=d.functions[bisect.bisect_right(d.functions,a)-1]
  calls.append({'site':hex(a),'bytes':raw[4*j:4*j+4].hex(),'instruction':ii[0].mnemonic,'target':hex(target),'caller':hex(start),'original_nlist':d.symbols_at(start)})
 assert len(calls)==3 and{q['site']for q in calls}=={'0x184b776cc','0x184b783fc','0x184b7b914'}
 headers=[SDK/'usr/include'/q for q in['xpc/xpc.h','xpc/connection.h','mach/message.h','bsm/libbsm.h']]
 counts={'complete_functions':len(functions),'instructions':sum(len(f['instructions'])for f in functions.values()),
  'function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in functions.values()),'stub_bindings':len(stubs),
  'prior_cache_ranges_recaptured':len(recaptured),'prior_cache_bytes_recaptured':sum(q['bytes_checked']for q in recaptured),
  'daemon_ranges_recaptured':len(daemon_ranges),'daemon_bytes_recaptured':sum(len(bytes.fromhex(f['bytes']))for f in daemon_ranges.values()),
  'daemon_call_bindings_rechecked':len(listener['calls']),'text_words_scanned':len(raw)//4,'direct_unpack_callers':len(calls),'SDK_headers':len(headers)}
 deps=['recover_xpc_reply_transport.py','bootpolicy_cache_reader.py','verify_interface_contracts.py','daemon_xpc_listener_source.json','xpc_reply_transport_source.json']
 return{'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cache_uuid':c.uuid,
  'cache_libraries':{p:d.uuid for p,d in libs.items()},'functions':functions,'stubs':stubs,'prior_cache_ranges':recaptured,
  'direct_call_census':{'section':sec,'section_sha256':h(raw),'calls':calls,'indirect_coverage':False},
  'wire_selector_words':{'address':'0x184bb3380','bytes':c.read(0x184bb3380,16).hex()},
  'daemon':{'path':str(DAEMON),'sha256':sha(DAEMON),'calls':listener['calls'],'native_context_producer_observed':False},
  'cache_files':[{'path':p,'size_bytes':__import__('pathlib').Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],
  'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
