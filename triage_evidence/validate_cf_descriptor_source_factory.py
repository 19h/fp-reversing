#!/usr/bin/env python3
"""Source-pinned descriptor/source factory, readiness and callback ABI checks.
Independent replay; exhaustive original four-instruction u16 permission slice;
SDK compile; separately replayed daemon producer/consumer; altered-record tests.
O(source bytes+V*F+J+H*R+2**16) time, O(source+J+R) space.
Private Unicorn only: no native IPC, scheduler, allocator, dispatch or PAC proof.
"""
import copy,json,struct,subprocess,zlib,base64
from collections import Counter
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,arm64_const as A
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache
from recover_cf_descriptor_source_factory import P,FLAGS,sha,build,CREATE,SOURCE,SOURCECREATE,DAEMON
from replay_cf_descriptor_source_factory import Replay,FDO,READ,WRITE,QUEUE,SRC,B,RL
from replay_daemon_descriptor_source import Replay as DaemonReplay
from recover_daemon_descriptor_source import SDK

def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');assert s==build();cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};prior=get('cf_runloop_wake_port_profiles.json');kernel=prior['kernel_cases'][2];c=Counter();ct=Counter();dt=Counter();summaries=[];cache=Cache()
 for o,n in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert o['generator_sha256']==sha(ROOT/n)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 for f in cs['CF_functions']+cs['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in cs['cache_files']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 for e in s['lower_stubs']:assert cache.read(int(e['address'],16),16).hex()==e['bytes16_hex']and e['exact_exports']
 types=[e for e in cs['extra_pointer_fixups']if int(e['address'],16)in(0x1e01c8750,0x1e01c8788)];assert len(types)==2 and [e['target']for e in types]==['0x1e24b2250','0x1e24b2290']and all(e['exact_exports']for e in types)
 c.update(complete_CF_functions_recaptured=len(cs['CF_functions']),captured_CF_instructions=sum(len(f['instructions'])for f in cs['CF_functions'])+4*len(cs['import_stubs']),cache_files_hashed=len(cs['cache_files']),named_lower_stub_targets_checked=len(s['lower_stubs']),dispatch_type_fixups_checked=2)
 # Execute the actual scalar slice, including condition codes, for every u16.
 start=0x1847b5700;code=cache.read(start,16);u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(start&~4095,4096);u.mem_write(start,code);u.mem_map(0x70000000,4096);u.reg_write(A.UC_ARM64_REG_SP,0x70000000);part=Counter()
 for mode in range(65536):
  u.mem_write(0x70000084,struct.pack('<H',mode));u.emu_start(start,start+16);read=u.reg_read(A.UC_ARM64_REG_W27);write=bool(mode&0x80);expected=int(not(mode&0x180)or bool(mode&0x100));assert read==expected;part[('read'if read else'')+('_write'if write else'')]+=1
 assert dict(part)=={'read':32768,'_write':16384,'read_write':16384};c['original_permission_slice_u16_inputs_checked']=65536;c['original_permission_slice_instruction_visits_checked']=262144
 headers=[SDK/'usr/include'/n for n in('sys/stat.h','sys/fcntl.h','sys/select.h','sys/errno.h')]+[SDK/'System/Library/Frameworks/CoreFoundation.framework/Headers'/n for n in('CFRunLoop.h','CFFileDescriptor.h')]
 header_rows=[{'path':str(q),'sha256':sha(q),'size_bytes':q.stat().st_size}for q in headers]
 layout='''#include <stddef.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/errno.h>
#include <CoreFoundation/CFFileDescriptor.h>
#include <CoreFoundation/CFRunLoop.h>
_Static_assert(sizeof(struct stat)==144,"stat144");
_Static_assert(offsetof(struct stat,st_mode)==4,"mode4");
_Static_assert(S_IRUSR==0x100,"readbit");
_Static_assert(S_IWUSR==0x80,"writebit");
_Static_assert(F_DUPFD_CLOEXEC==67,"dup67");
_Static_assert(sizeof(struct timespec)==16,"timespec16");
_Static_assert(EINTR==4,"EINTR4");
_Static_assert(EAGAIN==35,"EAGAIN35");
_Static_assert(EIO==5,"EIO5");
_Static_assert(sizeof(CFRunLoopSourceContext)==80,"sourcecontext80");
_Static_assert(offsetof(CFRunLoopSourceContext,info)==8,"info8");
_Static_assert(offsetof(CFRunLoopSourceContext,schedule)==56,"schedule56");
_Static_assert(offsetof(CFRunLoopSourceContext,cancel)==64,"cancel64");
_Static_assert(offsetof(CFRunLoopSourceContext,perform)==72,"perform72");
_Static_assert(sizeof(CFFileDescriptorContext)==40,"fdcontext40");
_Static_assert(sizeof(CFOptionFlags)==8,"flags8");
_Static_assert(kCFFileDescriptorReadCallBack==1,"read1");
_Static_assert(kCFFileDescriptorWriteCallBack==2,"write2");
'''
 command=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(SDK),'-std=c11','-fsyntax-only','-x','c','-'];res=subprocess.run(command,input=layout,text=True,capture_output=True);assert res.returncode==0,res.stderr;c['SDK_arm64e_assertions_checked']=18;c['SDK_headers_hashed']=6
 assert len(p['cases'])==16
 for r in p['cases']:
  ct.update(Replay(r,kernel,cs).run());cfg=r['configuration'];label=cfg['label'];b=bytes.fromhex(r['final_descriptor112_hex']);src=bytes.fromhex(r['final_source184_hex']);pcs=Counter(e['pc']for e in r['source_visits']);mods=r['mode_models'];backend=r['final_descriptor_backend'];cb=r['descriptor_callback_entry'];failed=label in('fstat_failure','duplicate_failure','descriptor_storage_null');nullsrc=label=='source_storage_null'
  assert r['final_factory_globals'][1]['bytes_hex']=='ff'*8
  if failed:
   assert cb is None and r['boundary']['kind']=='original_descriptor_factory_null'and pcs[hex(SOURCE)]==0
   assert backend['closed']==({'duplicate_failure':[12],'descriptor_storage_null':[11,12]}.get(label,[]))
  else:
   mode=cfg.get('permissions',0x180);read=not(mode&0x180)or bool(mode&0x100);write=bool(mode&0x80);fds=(7,11 if read else-1,(12 if read else 11)if write else-1);assert struct.unpack_from('<iii',b,20)==fds and q(b,0x40)==DAEMON and b[0x48:]==bytes(40)and q(b,8)&2 and struct.unpack_from('<I',b,16)[0]==0
   assert(q(b,0x20),q(b,0x28))==(READ if read else 0,WRITE if write else 0)
   getter=next(e for e in r['factory_returns']if e['stage']=='fd_get');assert getter['registers31'][0]=='0x7'
   assert r['final_factory_globals'][0]['bytes_hex']==struct.pack('<Q',QUEUE).hex()
   c['original_native_descriptor_getter_and_layout_oracles_checked']+=1
   if nullsrc:assert q(b,0x38)==0 and cb is None and r['boundary']['kind']=='original_descriptor_source_factory_null'
   else:
    assert q(b,0x38)==SRC and(q(src,0x50),q(src,0x60),q(src,0x68),q(src,0x70))==(0,B+0xaf200,0,FDO)
    assert[q(src,o)for o in range(0x78,0xb8,8)]==[0x1846db030,0x1846e1278,0x18480f8a4,0,0,0x1847b6074,0x1847c968c,0x1847b7ca0]
    assert q(src,8)&8 and src[0x32:0x34]==bytes(2)and b[0x32:0x34]==bytes(2)
    expected_timestamp=100 if cfg['events']or cfg.get('enable_ready')else 0;assert q(src,0x58)==expected_timestamp
    state=r['final_model_state'];assert state['members']==[['0x507','0x607'],['0x507','0x707'],['0x507','0x807']]and state['collections'][hex(B+0xaf000)]==[hex(SRC)]and state['collections'][hex(B+0xaf200)]==[hex(RL)]
    assert pcs[hex(SOURCECREATE)]==1 and pcs[hex(SOURCE)]==cfg.get('source_repeat',1)
    mask=cfg.get('enable_mask',1);deliver=bool(cfg['events']or cfg.get('enable_ready'))and cfg.get('perform_ready',True)and cfg.get('poll_error')!=5
    assert bool(cb)==deliver
    if cb:assert cb['arguments3']==[hex(FDO),hex(mask),'0x0']
    assert len(r['SVC_return_contracts'])==len(cfg['events'])
    for e in r['SVC_return_contracts']:assert e['before']['original_header24_hex']==struct.pack('<6I',0x13,24,0x807,0,0,0).hex()
    if cfg.get('poll_error'):assert backend['poll_counts']['perform']==(2 if cfg['poll_error']in(4,35)else 1)
    for e in mods:
     if e['name']=='declared_pselect_readiness':assert e['timespec16_hex']==struct.pack('<qq',0,1000).hex()
     if e['name'].startswith('declared_copy_dispatch_'):assert e['original_block_size_bytes']==(48 if e['name'].endswith('event')else 44)
    c['original_source0_context_registration_readiness_and_callback_oracles_checked']+=1
  raw=zlib.decompress(base64.b64decode(r['final_private_RAM']['zlib_base64']))
  for at,n in((FDO,112),(SRC,184),(READ,192),(WRITE,192),(QUEUE,128),(B+0xc4000,64),(B+0xc5000,64),(B+0xc6000,64),(B+0xc7000,64),(B+0xc8000,64),(B+0xc9000,4),(B+0xbf000,64)):assert raw[at-B+n]==165
  summaries.append({'label':label,'original_visits':len(r['source_visits']),'callback_arguments3':cb and cb['arguments3'],'original_wake_SVC_visits':len(r['SVC_return_contracts']),'declared_poll_counts':backend['poll_counts'],'declared_close_requests':backend['closed'],'boundary':r['boundary']['kind']});print(json.dumps(summaries[-1]),flush=True)
 # Separate epochs verify matching producer input, getter output and callback ABI.
 daemon=get('daemon_descriptor_source_profiles.json');init=daemon['initializer'];setup=daemon['setup_cases'][0];callback=daemon['callback_cases'][0]
 for r,origin in((init,None),(setup,init),(callback,setup)):dt.update(DaemonReplay(r,origin).run())
 created=next(e for e in setup['imports']if e['name']=='CoreFoundation/_CFFileDescriptorCreate');assert created['arguments8'][:5]==['0x0','0x7','0x1',hex(DAEMON),'0x0']
 got=next(e for e in callback['imports']if e['name']=='CoreFoundation/_CFFileDescriptorGetNativeDescriptor');assert got['result']=='0x7';c['separate_daemon_producer_consumer_epochs_replayed']=3;c['separate_component_ABI_joins_checked']=3
 rejected=[]
 for tag in('factory_instruction','saved_callback_literal','source_perform_pointer','sync_block_capture','sync_entry_CPU','handler_copy_patch','callback_arguments','final_queue_global'):
  bad=copy.deepcopy(p['cases'][0])
  if tag=='factory_instruction':next(e for e in bad['source_visits']if e['pc']==hex(CREATE))['bytes_hex']='00000000'
  elif tag=='saved_callback_literal':e=next(e for e in bad['factory_returns']if e['stage']=='fd_create');b=bytearray.fromhex(e['descriptor112_hex']);b[0x40]^=1;e['descriptor112_hex']=b.hex()
  elif tag=='source_perform_pointer':e=next(e for e in bad['factory_returns']if e['stage']=='source_create');b=bytearray.fromhex(e['source184_hex']);b[0xb0]^=1;e['source184_hex']=b.hex()
  elif tag=='sync_block_capture':b=bytearray.fromhex(bad['dispatch_sync_calls'][0]['block_bytes_hex']);b[-1]^=1;bad['dispatch_sync_calls'][0]['block_bytes_hex']=b.hex()
  elif tag=='sync_entry_CPU':bad['dispatch_sync_calls'][0]['entry']['registers31'][0]='0x0'
  elif tag=='handler_copy_patch':
   for key in('imports','runloop_models','mode_models'):
    e=next(e for e in bad[key]if e['name']=='declared_copy_dispatch_event');b=bytearray.fromhex(e['patches'][0]['after_hex']);b[32]^=1;e['patches'][0]['after_hex']=b.hex()
  elif tag=='callback_arguments':bad['descriptor_callback_entry']['arguments3'][1]='0x2'
  else:bad['final_factory_globals'][0]['bytes_hex']='00'*8
  try:Replay(bad,kernel,cs).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('altered evidence accepted',tag))
 c['altered_evidence_controls_rejected']=len(rejected)
 positive=ct['original_instruction_visits_checked']+dt['original_instruction_visits_checked'];ram=ct['whole_final_private_RAM_bytes_checked']+dt['complete_final_mutable_RAM_bytes_checked']
 deps=[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','replay_cf_wake_send_wrapper.py','replay_cf_source_wake_callers.py','cf_runloop_wake_port_profiles.json','daemon_descriptor_source_profiles.json','replay_daemon_descriptor_source.py']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(c),'independent_CF_replay':dict(ct),'independent_daemon_replay':dict(dt),'case_summaries':summaries,'permission_slice':{'start':hex(start),'bytes16_hex':code.hex(),'inputs_checked':65536,'partition_counts':dict(part),'instruction_visits':262144,'scope':'four original instructions only; no constructor reachability proof'},'SDK_headers':header_rows,'SDK_compile':{'command':command,'inline_C':layout,'exit_code':res.returncode},'altered_evidence_rejected':rejected,'aggregate_positive_visits':positive,'complete_final_private_RAM_bytes_checked':ram,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'CF':dict(ct),'daemon':dict(dt),'positive_visits':positive,'RAM_B':ram,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
