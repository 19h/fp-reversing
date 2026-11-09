#!/usr/bin/env python3
"""Verify one-epoch original daemon/CF creation/callback/removal/Stop contracts.
Source recapture, complete private replay/CPU/RAM/journals, SDK, semantic ABI
oracles and altered evidence. No native startup/IPC/PAC/ownership proof.
O(source+V*F+J+H*R) time,O(source+J+R) space.
"""
import copy,json,struct,subprocess,zlib,base64,hashlib
from collections import Counter
from pathlib import Path
from daemon_receive_tools import ROOT,IMAGE
from bootpolicy_cache_reader import Cache
from recover_daemon_cf_descriptor_bridge import P,FLAGS,sha,build,INIT,SETUP,CALLBACK,HEADER,INVALID,SOURCEINV,REMOVE_CALLBACK,REMOVE,GETMAIN
from replay_daemon_cf_descriptor_bridge import Replay,HEAP,FDO,READ,WRITE,RL,MODE,SRC,SET0,BAG,EXTRA
from recover_daemon_descriptor_source import SDK

def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def decode(e):
 b=zlib.decompress(base64.b64decode(e['zlib_base64']));assert len(b)==e['size_bytes']and hashlib.sha256(b).hexdigest()==e['sha256'];return b

def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');assert s==build();cache=Cache();c=Counter();tot=Counter();summary=[];cs={**s['CF_source'],'root_caller_options':s['root_caller_options'],'bridge_bindings':[{'slot':e['binding']['slot'],'target':hex(e['captured_CF_export']['address'])}for e in s['daemon_to_CF_bindings']]};kernel=get('cf_runloop_wake_port_profiles.json')['kernel_cases'][2]
 for o,n in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert o['generator_sha256']==sha(ROOT/n)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 for f in cs['CF_functions']+cs['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for f in s['original_daemon_ranges']:assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in cs['cache_files']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 assert len(s['daemon_to_CF_bindings'])==9 and s['default_mode_original_addend']['combined_addend']==0
 expected=[{'_dispatch_channel_cancel','_dispatch_source_cancel'},{'_shutdown'},{'_open'},{'_dup2'}];assert[set(e['exact_exports'])for e in s['new_lower_stubs']]==expected
 for e in s['new_lower_stubs']:assert cache.read(int(e['address'],16),16).hex()==e['bytes16_hex']and e['pointer']['chain_membership_verified']
 c.update(complete_cache_functions_recaptured=len(cs['CF_functions']),captured_cache_instructions=sum(len(f['instructions'])for f in cs['CF_functions'])+4*len(cs['import_stubs']),cache_files_hashed=len(cs['cache_files']),selected_daemon_CF_slots_checked=9,original_daemon_static_ranges_checked=len(s['original_daemon_ranges']),new_lower_stub_identities_checked=4)
 headers=[SDK/'usr/include'/n for n in('sys/event.h','sys/signal.h','sys/socket.h','sys/fcntl.h','mach/message.h')]+[SDK/'System/Library/Frameworks/CoreFoundation.framework/Headers'/n for n in('CFFileDescriptor.h','CFRunLoop.h')];header_rows=[{'path':str(v),'size_bytes':v.stat().st_size,'sha256':sha(v)}for v in headers]
 layout='''#include <stddef.h>
#include <sys/event.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <mach/message.h>
#include <CoreFoundation/CFFileDescriptor.h>
#include <CoreFoundation/CFRunLoop.h>
_Static_assert(sizeof(struct kevent)==32,"kevent32");
_Static_assert(offsetof(struct kevent,ident)==0,"ident0");
_Static_assert(offsetof(struct kevent,filter)==8,"filter8");
_Static_assert(offsetof(struct kevent,data)==16,"data16");
_Static_assert(offsetof(struct kevent,udata)==24,"udata24");
_Static_assert(EVFILT_SIGNAL==-6,"signal filter");
_Static_assert(EVFILT_PROC==-5,"proc filter");
_Static_assert(SIGTERM==15,"SIGTERM15");
_Static_assert(SHUT_RDWR==2,"shutdown2");
_Static_assert(O_RDONLY==0,"read only0");
_Static_assert(sizeof(CFOptionFlags)==8,"options8");
_Static_assert(sizeof(CFFileDescriptorContext)==40,"context40");
_Static_assert(kCFFileDescriptorReadCallBack==1,"read1");
_Static_assert(__builtin_types_compatible_p(__typeof__(&CFRunLoopRun),void(*)(void)),"void Run");
_Static_assert(MACH_SEND_MSG==1,"send1");
_Static_assert(MACH_SEND_TIMEOUT==0x10,"send timeout16");
''';cmd=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(SDK),'-std=c11','-fsyntax-only','-x','c','-'];res=subprocess.run(cmd,input=layout,text=True,capture_output=True);assert res.returncode==0,res.stderr;c['SDK_headers_hashed']=7;c['SDK_arm64e_assertions_checked']=16
 assert len(p['cases'])==11
 for r in p['cases']:
  tot.update(Replay(r,kernel,cs).run());cfg=r['configuration'];label=cfg['label'];pcs=Counter(e['pc']for e in r['source_visits']);h=bytes.fromhex(r['final_header96_hex']);b=bytes.fromhex(r['final_descriptor112_hex']);src=bytes.fromhex(r['final_source184_hex']);root=bytes.fromhex(r['final_runloop2720_hex']);stop=cfg['entry']=='run';dm=r['daemon_external_models'];callbacks=r['original_daemon_callbacks'];assert len(callbacks)==1 and pcs[hex(INIT)]==pcs[hex(SETUP)]==pcs[hex(CALLBACK)]==1
  assert not r['daemon_callback_return_calls']and not r['declared_callback_effects']and not any(e['name']=='declared_daemon_descriptor_void_callback_return'for e in r['imports']);assert all(not e['name'].startswith('CoreFoundation/')or e['name']=='CoreFoundation/_CFMachPortInvalidate'for e in dm)
  setup=r['bridge_component_entries'][1];setup_header=bytes.fromhex(setup['returned']['header96_hex']);assert q(setup_header,0)==HEAP and q(setup_header,8)==100 and q(setup_header,80)==FDO and struct.unpack_from('<I',setup_header,72)[0]==(7+0x060ed969)
  entry=callbacks[0]['entry_after'];assert int(entry['registers31'][0],16)==FDO and int(entry['registers31'][1],16)==1 and int(entry['registers31'][2],16)==0 and q(bytes.fromhex(entry['header96_hex']),80)==FDO and callbacks[0]['return_pc']=='0x1847b7e04'
  for row in s['daemon_to_CF_bindings']:
   slot=int(row['binding']['slot'],16);region=next(e for e in r['final_daemon_regions']if int(e['address'],16)<=slot<int(e['address'],16)+e['size_bytes']);raw=decode(region);assert q(raw,slot-int(region['address'],16))==row['captured_CF_export']['address']
  native_reads=[e for e in r['source_reads']if int(e['address'],16)==FDO+0x14 and 0x1847b802c<=int(e['pc'],16)<0x1847b80b8];assert native_reads and any(e['bytes_hex']=='07000000'for e in native_reads)
  event=next(e for e in dm if e['name']=='libSystem/_kevent'and e['before']['daemon_phase']=='callback');assert event['arguments8'][0]=='0x7'and event['arguments8'][1:3]==['0x0','0x0'];assert int(event['event_output'],16)==int(entry['SP'],16)-0x149c
  registration=next(e for e in dm if e['name']=='libSystem/_kevent'and e['before']['daemon_phase']=='setup');assert registration['change32_hex']==struct.pack('<QhHIqQ',15,-6,1,0,0,0).hex()and registration['result']==hex(cfg.get('registration_status',0)&0xffffffff)
  assert q(h,80)==FDO and root[84]==0 and q(root,0xa60)==0 and not r['final_model_state']['dictionary']and r['final_model_state']['members']==[['0x507','0x607'],['0x507','0x707'],['0x507','0x807']]
  if stop:
   assert pcs[hex(INVALID)]==pcs[hex(SOURCEINV)]==pcs[hex(REMOVE_CALLBACK)]==1 and pcs[hex(GETMAIN)]==2 and pcs[hex(REMOVE)]==2
   assert struct.unpack_from('<i',b,16)[0]==2 and struct.unpack_from('<i',b,20)[0]==-1 and q(b,32)==q(b,40)==q(b,56)==0 and q(src,8)&8==0 and q(src,88)==q(src,96)==0
   assert r['final_model_state']['collections'][hex(SET0)]==[]and r['cancel_requests']==[hex(READ),hex(WRITE)]and r['final_descriptor_backend']['closed']==([13,7,11,12]if cfg.get('drain_cancel')else[13,7])
   assert len(r['SVC_return_contracts'])==1 and r['SVC_return_contracts'][0]['before']['original_header24_hex']==struct.pack('<6I',0x13,24,0x807,0,0,0).hex();main=next(e for e in r['bridge_frames']if e['pc']=='0x1003c132c');assert main['registers31'][0]==hex(RL)and q(bytes.fromhex(main['runloop2720_hex']),0xa60)==MODE
   internal=next(e for e in r['public_RUN_frames']if e['pc']=='0x184831c10');assert internal['registers31'][0]=='0x2';c['same_epoch_original_callback_invalidate_GetMain_Stop_wake_oracles_checked']+=1
  else:
   assert pcs[hex(INVALID)]==pcs[hex(SOURCEINV)]==0 and pcs[hex(GETMAIN)]==1 and not r['cancel_requests']and not r['SVC_return_contracts']and r['boundary']['registers31'][0]=='0x4'and q(src,8)&8 and struct.unpack_from('<i',b,20)[0]==7;c['original_nonsignal_and_event_result_variants_checked']+=1
  heap=decode(r['final_daemon_regions'][2]);fill=cfg.get('heap_fill',0)
  for j in range(100):assert heap[j*896:j*896+876]==bytes([fill])*876 and heap[j*896+876:(j+1)*896]==struct.pack('<I',0x4577df49)+bytes(16)
  assert heap[89600]==165;c['original_initializer_record_tail_and_guard_oracles_checked']+=1
  assert len(r['declared_cancel_deliveries'])==(2 if cfg.get('drain_cancel')else 0)
  summary.append({'label':label,'original_visits':len(r['source_visits']),'original_callback_return_to_CF':callbacks[0]['return_pc'],'Stop_wake_SVC_visits':len(r['SVC_return_contracts']),'final_descriptor_invalid_state':struct.unpack_from('<I',b,16)[0],'final_descriptor_fd_signed32':struct.unpack_from('<i',b,20)[0],'source_valid':bool(q(src,8)&8),'mode_source0_members':r['final_model_state']['collections'][hex(SET0)],'close_requests':r['final_descriptor_backend']['closed'],'explicit_cancel_handler_deliveries':len(r['declared_cancel_deliveries'])});print(json.dumps(summary[-1]),flush=True)
 rejected=[]
 for tag in('logical_CF_binding','callback_instruction','callback_return_CPU','GetMain_context','kevent_output','source_invalid_bit','final_heap_tail','cancel_block_capture','setup_descriptor_ref','main_registration'):
  bad=copy.deepcopy(p['cases'][9 if tag=='cancel_block_capture'else 0])
  if tag in('logical_CF_binding','main_registration'):
   target=0x10109fea0 if tag=='logical_CF_binding'else 0x1ed8913f0;e=next(e for e in bad['bridge_initial']if int(e['address'],16)==target);b=bytearray.fromhex(e['after_hex']);b[0]^=1;e['after_hex']=b.hex()
  elif tag=='callback_instruction':next(e for e in bad['source_visits']if e['pc']==hex(CALLBACK))['bytes_hex']='00000000'
  elif tag=='callback_return_CPU':bad['original_daemon_callbacks'][0]['returned']['registers31'][19]='0x0'
  elif tag=='GetMain_context':e=next(e for e in bad['bridge_frames']if e['pc']==hex(GETMAIN));b=bytearray.fromhex(e['runloop2720_hex']);b[0xa60]^=1;e['runloop2720_hex']=b.hex()
  elif tag=='kevent_output':e=next(e for e in bad['daemon_external_models']if e['name']=='libSystem/_kevent'and e['before']['daemon_phase']=='callback');b=bytearray.fromhex(e['patches'][0]['after_hex']);b[8]^=1;e['patches'][0]['after_hex']=b.hex()
  elif tag=='source_invalid_bit':e=next(e for e in bad['bridge_frames']if e['pc']==hex(REMOVE_CALLBACK));b=bytearray.fromhex(e['source184_hex']);b[8]^=8;e['source184_hex']=b.hex()
  elif tag=='final_heap_tail':e=bad['final_daemon_regions'][2];b=bytearray(decode(e));b[876]^=1;e['zlib_base64']=base64.b64encode(zlib.compress(bytes(b))).decode();e['sha256']=hashlib.sha256(b).hexdigest()
  elif tag=='cancel_block_capture':e=bad['declared_cancel_deliveries'][0];b=bytearray.fromhex(e['copied44_hex']);b[40]^=1;e['copied44_hex']=b.hex()
  else:e=bad['bridge_component_entries'][1]['returned'];b=bytearray.fromhex(e['header96_hex']);b[80]^=1;e['header96_hex']=b.hex()
  try:Replay(bad,kernel,cs).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('altered evidence accepted',tag))
 c['altered_evidence_controls_rejected']=len(rejected);ram=tot['whole_final_private_RAM_bytes_checked']+tot['whole_final_additional_daemon_mutable_bytes_checked'];visits=tot['original_instruction_visits_checked']
 deps=[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','probe_cf_public_runloop.py','replay_cf_public_runloop.py','cf_runloop_wake_port_profiles.json','daemon_descriptor_source_profiles.json']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(c),'independent_combined_replay':dict(tot),'case_summaries':summary,'SDK_headers':header_rows,'SDK_compile':{'command':cmd,'inline_C':layout,'exit_code':res.returncode},'aggregate_positive_visits':visits,'complete_final_private_RAM_bytes_checked':ram,'altered_evidence_rejected':rejected,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'combined':dict(tot),'positive_visits':visits,'RAM_B':ram,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
