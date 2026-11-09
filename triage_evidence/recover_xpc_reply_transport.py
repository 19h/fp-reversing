#!/usr/bin/env python3
"""Read-only original-cache reply context, byte copy and Mach2 handoff evidence.
No dlopen, target execution/emulation, native Mach requests or IDB mutation.
O(selected bytes + function/export metadata + selected chain walks).
"""
import hashlib,json,struct
from pathlib import Path
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from verify_interface_contracts import Image
ROOT=Path(__file__).resolve().parent;P='xpc_reply_transport'
SDK=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
XP='/usr/lib/system/libxpc.dylib';DP='/usr/lib/system/libdispatch.dylib'
KP='/usr/lib/system/libsystem_kernel.dylib';PP='/usr/lib/system/libsystem_platform.dylib'
DAEMON=Path('/Users/___/Downloads/zut/fairplayd.arm64e')
FLAGS=['target_executed','target_emulated','FairPlay_requests_sent','native_image_pairing_proved',
 'native_port_identity_proved','native_delivery_proved','native_output_ownership_proved',
 'native_authorization_proved','hardware_PAC_checked','IDB_mutated','full_goal_complete']
FUNCTIONS={
 'create_reply':(XP,0x184b80820),'set_data':(XP,0x184b7447c),
 'data_create':(XP,0x184b6e0fc),'data_wrap':(XP,0x184b6e30c),
 'set_value':(XP,0x184b96068),'insert':(XP,0x184b6d310),
 'retain':(XP,0x184b6d638),'release':(XP,0x184b6d6c4),
 'send_message':(XP,0x184b7901c),'pack_message':(XP,0x184b77790),
 'extract_reply_port':(XP,0x184b70cdc),'get_remote':(XP,0x184b77864),
 'serializer':(XP,0x184b70d20),'enqueue':(XP,0x184b79150),
 'get_msg':(DP,0x1855314a8),'send_result':(DP,0x18552ea5c),
 'send_async_result':(DP,0x18552f178),'dispatch_send':(DP,0x18552e844),
 'dispatch_emit':(DP,0x185532504),'dispatch_push':(DP,0x185533200),
 'data_alloc':(DP,0x18554f4ec),'dispatch_data_create':(DP,0x185544014),
 'mach2':(KP,0x18055a894),'mach2_trap':(KP,0x180547c18)}
STUBS={
 0x188087440:(DP,'__os_object_alloc_realized'),0x188087490:(DP,'__os_object_retain_internal'),
 0x18806cbd0:(KP,'_vm_allocate'),0x18806ca70:(PP,'__platform_memmove'),
 0x188087570:(DP,'_dispatch_data_create_alloc'),0x188087560:(DP,'_dispatch_data_create'),
 0x18806d180:(DP,'_dispatch_release'),0x18806d1a0:(DP,'_dispatch_retain'),
 0x1880875c0:(DP,'_dispatch_data_get_size'),0x188087690:(DP,'_dispatch_mach_msg_create'),
 0x1880876a0:(DP,'_dispatch_mach_msg_get_msg'),0x1880876f0:(DP,'_dispatch_mach_send_with_result'),
 0x188087700:(DP,'_dispatch_mach_send_with_result_and_async_reply_4libxpc'),
 0x18808c4f0:(KP,'_mach_msg2_internal')}
DATAPTRS={0x1e0615350:(XP,'__xpc_type_dictionary'),0x1e0615338:(XP,'__xpc_type_connection'),
 0x1e01c86b8:(DP,'__dispatch_data_destructor_vm_deallocate'),0x1e01c86c0:(DP,'__dispatch_data_empty')}
def h(b):return hashlib.sha256(b).hexdigest()
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def build():
 c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a'
 libs={p:Dylib(c,p)for p in[XP,DP,KP,PP]};functions={}
 for name,(path,a)in FUNCTIONS.items():
  d=libs[path];f=d.function(a);assert len(f['instructions'])*4==len(bytes.fromhex(f['bytes']))
  functions[name]={**f,'library':path,'library_uuid':d.uuid,'original_nlist':d.symbols_at(a)}
 stubs={}
 for a,(path,name)in STUBS.items():
  bb=c.read(a,16);ii=list(CS.disasm(bb,a));assert[q.mnemonic for q in ii]==['adrp','add','ldr','braa']
  slot=int(ii[0].op_str.split('#')[1],0)+int(ii[1].op_str.split('#')[1],0);p=c.pointer(slot)
  d=libs[path];target=d.exports[name]['address'];assert p['target']==hex(target)
  stubs[hex(a)]={'bytes':bb.hex(),'pointer':p,'library':path,'exact_export':name,
   'original_nlist':d.symbols_at(target),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
 pointers={}
 for a,(path,name)in DATAPTRS.items():
  p=c.pointer(a);names=libs[path].symbols_at(int(p['target'],16));assert any(q['name']==name for q in names)
  pointers[hex(a)]={'pointer':p,'library':path,'original_symbol':name,'original_nlist':names}
 prior=json.loads((ROOT/'daemon_xpc_reply_lifecycle_source.json').read_text());u=Image(DAEMON)
 assert sha(DAEMON)==prior['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for f in prior['fragments'].values():assert u.read(int(f['start'],16),len(bytes.fromhex(f['bytes']))).hex()==f['bytes']
 for q in prior['calls']:
  assert u.read(int(q['site'],16)-4,8).hex()==q['bytes']
  assert struct.unpack('<Q',u.read(int(q['slot'],16),8))[0]==int(q['pointer_word'],16)
 headers=[SDK/'usr/include'/q for q in['xpc/xpc.h','xpc/connection.h','mach/message.h','dispatch/data.h']]
 counts={'complete_functions':len(functions),'instructions':sum(len(f['instructions'])for f in functions.values()),
  'function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in functions.values()),'stub_bindings':len(stubs),
  'data_pointer_bindings':len(pointers),'daemon_fragments_recaptured':len(prior['fragments']),
  'daemon_bytes_recaptured':sum(len(bytes.fromhex(f['bytes']))for f in prior['fragments'].values()),
  'daemon_call_bindings_rechecked':len(prior['calls']),'SDK_headers':len(headers)}
 deps=['bootpolicy_cache_reader.py','verify_interface_contracts.py','daemon_xpc_reply_lifecycle_source.json']
 return{'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},
  'cache_uuid':c.uuid,'cache_libraries':{p:d.uuid for p,d in libs.items()},'functions':functions,
  'stubs':stubs,'data_pointers':pointers,'header_initializer':{'address':'0x184bb3350','bytes':c.read(0x184bb3350,16).hex()},
  'daemon':{'path':str(DAEMON),'sha256':sha(DAEMON),'calls':prior['calls'],'paired_native_cache_observed':False},
  'cache_files':[{'path':p,'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],
  'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
