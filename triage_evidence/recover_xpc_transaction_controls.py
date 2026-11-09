#!/usr/bin/env python3
"""Original transaction flag producers, control request and proc_info ABI.
Read-only binary/source capture; no native process, signal, IPC or IDB effects.
"""
import bisect,json,struct
from pathlib import Path
from recover_xpc_reply_transport import Cache,Dylib,CACHE,CS,Image,ROOT,SDK,XP,DP,KP,PP,DAEMON,FLAGS,sha,h
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import chained_rebases,CACHE as KC
from recover_registered_port_consumers import daemon_record
P='xpc_transaction_controls';CP='/usr/lib/system/libsystem_c.dylib'
FUNCTIONS={
 'enable':(XP,0x184b82720),'track':(XP,0x184b82cbc),'exit_clean':(XP,0x184b84e00),
 'interrupt':(XP,0x184b86024),'initializer':(XP,0x184b6c360),'vproc_enable':(XP,0x184b872d0),
 'service_request':(XP,0x184b86128),'interface':(XP,0x184b706f0),'encode':(XP,0x184b8a790),
 'set_uint64':(XP,0x184b70674),'pipe_routine':(XP,0x184ba24d8),
 'once':(PP,0x185559d0c),'allocate':(PP,0x185559d58),
 'proc_track':(KP,0x18054b0ec),'proc_dirty':(KP,0x18054b14c),'proc_info':(KP,0x180549100),
 'signal':(CP,0x1805c67ac)}
STUBS={0x188087b40:(KP,'_proc_track_dirty'),0x188087b30:(KP,'_proc_set_dirty'),
 0x188087bf0:(CP,'_signal'),0x18806ce20:(PP,'__os_alloc_once'),0x18806cee0:(KP,'_getpid'),
 0x18806d7b0:(KP,'__exit'),0x18806cad0:(PP,'_os_unfair_lock_lock_with_options'),
 0x18806cae0:(PP,'_os_unfair_lock_unlock'),0x18806ca00:(CP,'_getenv')}
KERNEL={'proc_info_entry':0xfffffe000c368544,'proc_info_core':0xfffffe000c368588,'dirty_control':0xfffffe000c36a664}
STRINGS={'environment':0x184bb7122,'yesno':0x184bb89f9,'type':0x184bba2da,
 'handle':0x184bba2df,'self':0x184bb8b06,'subsystem':0x184bb3685,'routine':0x184bb368f}
def build():
 c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a';libs={p:Dylib(c,p)for p in[XP,DP,KP,PP,CP]};functions={}
 for role,(path,a)in FUNCTIONS.items():
  d=libs[path];f=d.function(a);assert len(f['instructions'])*4==len(bytes.fromhex(f['bytes']))
  functions[role]={**f,'library':path,'library_uuid':d.uuid,'original_nlist':d.symbols_at(a)}
 stubs={}
 for a,(path,name)in STUBS.items():
  bb=c.read(a,16);ii=list(CS.disasm(bb,a));assert[q.mnemonic for q in ii]==['adrp','add','ldr','braa']
  slot=int(ii[0].op_str.split('#')[1],0)+int(ii[1].op_str.split('#')[1],0);p=c.pointer(slot)
  d=libs[path];target=d.exports[name]['address'];assert p['target']==hex(target)
  stubs[hex(a)]={'bytes':bb.hex(),'pointer':p,'library':path,'exact_export':name,'export_address':hex(target),
   'original_nlist':d.symbols_at(target),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
 # Exhaust text words for direct B/BL references to three public controls.
 d=libs[XP];sec=next(q for q in d.sections if q['name']=='__text');raw=c.read(sec['address'],sec['size']);calls=[]
 targets={0x184b82720,0x184b84e00,0x184b86024}
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
  if w&0x7c000000!=0x14000000:continue
  a=sec['address']+4*j;delta=w&0x3ffffff;delta=delta-(1<<26)if delta&(1<<25)else delta;target=a+4*delta
  if target not in targets:continue
  start=d.functions[bisect.bisect_right(d.functions,a)-1];ii=list(CS.disasm(raw[4*j:4*j+4],a));assert int(ii[0].op_str[1:],0)==target
  calls.append({'site':hex(a),'target':hex(target),'caller':hex(start),'original_nlist':d.symbols_at(start),'bytes':raw[4*j:4*j+4].hex()})
 assert{q['site']for q in calls}=={'0x184b6c824','0x184b82d80','0x184b872d0'}
 strings={name:{'address':hex(a),'value':c.cstring(a),'bytes':(c.cstring(a)+'\0').encode().hex()}for name,a in STRINGS.items()}
 atoms={hex(a):{'bytes':c.read(a,32).hex(),'original_nlist':d.symbols_at(a)}for a in[0x1e241a230,0x1e241a250]}
 once=c.pointer(0x1e01c8ac0);once['file_template_32B']=c.read(int(once['target'],16),32).hex()
 prior=json.loads((ROOT/'registered_port_consumers_source.json').read_text());u=Image(DAEMON)
 assert sha(DAEMON)==prior['daemon']['sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for f in prior['cache_functions'].values():assert c.read(int(f['start'],16),len(bytes.fromhex(f['bytes']))).hex()==f['bytes']
 queried=['_xpc_transactions_enable','_xpc_track_activity','_xpc_transaction_exit_clean','_xpc_transaction_interrupt_clean_exit','__vproc_transactions_enable']
 imports=prior['daemon']['imports'];assert not any(q['symbol']in queried for q in imports)
 # Fresh import/section parse with independent dyld_info and otool comparisons.
 assert daemon_record()==prior['daemon']
 k=Kernel();base,rebases,meta=chained_rebases(k.data)
 disp=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text());bsd=next(q for q in disp['bsd_entries']if q['index']==336)
 for field in['handler_pointer','munger_pointer','name_pointer']:
  q=bsd[field];off=int(q['file_offset'],16);assert off in rebases and meta[off]['target']==q['target']and meta[off]['raw']==q['raw']
  assert struct.unpack('<Q',k.read(int(q['slot'],16),8))[0]==int(q['raw'],16)
 assert int(bsd['handler_pointer']['target'],16)==KERNEL['proc_info_entry']and bsd['name']=='proc_info'
 kr={name:k.function(a)for name,a in KERNEL.items()};syms=k.symbols(KERNEL.values())
 for name,f in kr.items():f['original_nlist']=syms[f['start']]
 jt=k.read(0xfffffe000c368aec,80);targets8=[hex(0xfffffe000c3685c4+x)for x in struct.unpack('<20i',jt)]
 assert targets8[7]=='0xfffffe000c368814'
 resource=json.loads((ROOT/'xpc_resource_lifecycle_source.json').read_text());recaptured=[]
 for role,f in resource['functions'].items():
  bb=bytes.fromhex(f['bytes']);assert c.read(int(f['start'],16),len(bb))==bb
  recaptured.append({'role':role,'start':f['start'],'bytes_checked':len(bb),'sha256':h(bb)})
 headers=[SDK/'usr/include'/q for q in['libproc.h','sys/proc_info.h','signal.h','errno.h','xpc/xpc.h']]
 deps=['recover_xpc_reply_transport.py','bootpolicy_cache_reader.py','verify_interface_contracts.py','kernel_native_reader.py',
  'resolve_kernel_collection_interfaces.py','recover_registered_port_consumers.py','registered_port_consumers_source.json','kernel_dispatch_contracts.json','xpc_resource_lifecycle_source.json']
 counts={'cache_functions':len(functions),'kernel_functions':len(kr),'complete_functions':len(functions)+len(kr),
  'instructions':sum(len(f['instructions'])for f in list(functions.values())+list(kr.values())),
  'function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in list(functions.values())+list(kr.values())),
  'stub_bindings':len(stubs),'control_strings':len(strings),'Boolean_atoms':len(atoms),'BSD_bindings':1,'kernel_jump_entries':20,
  'direct_control_callers':len(calls),'text_words_scanned':len(raw)//4,'daemon_imports_checked':len(imports),
  'prior_registered_cache_ranges_recaptured':len(prior['cache_functions']),'prior_resource_ranges_recaptured':len(recaptured),
  'prior_resource_bytes_recaptured':sum(q['bytes_checked']for q in recaptured),'SDK_headers':len(headers)}
 return{'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cache_uuid':c.uuid,
  'cache_libraries':{p:d.uuid for p,d in libs.items()},'functions':functions,'stubs':stubs,'strings':strings,'Boolean_atoms':atoms,
  'once_root':once,'direct_call_census':{'section':sec,'sha256':h(raw),'calls':calls,'indirect_coverage':False},
  'daemon':{'path':str(DAEMON),'sha256':sha(DAEMON),'named_imports_checked':imports,'queried_transaction_imports':queried,'matching_named_imports':[]},
  'kernel':{'path':str(KC),'sha256':k.sha256,'uuid':k.kernel['uuid'],'BSD336':bsd,'functions':kr,
   'jump_table':{'start':'0xfffffe000c368aec','bytes':jt.hex(),'targets':targets8,'callnum8_target':targets8[7]}},
  'prior_resource_ranges':recaptured,'cache_files':[{'path':p,'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],
  'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
