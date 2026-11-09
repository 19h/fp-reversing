#!/usr/bin/env python3
"""Verify public entry/context/TSD/Stop/cleanup and explicit evidence bounds.
Independent original instruction/CPU/RAM replay, source recapture, SDK compile,
all-u8 normalization, all70 TSD slots and invalid-index diagnostics; negatives.
O(source+V*F+J+H*R+slots) time,O(source+J+R) space. No native target effects.
"""
import copy,json,struct,subprocess
from collections import Counter
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,arm64_const as A
from daemon_receive_tools import ROOT,CS
from bootpolicy_cache_reader import Cache
from recover_cf_public_runloop import P,FLAGS,sha,build,SPEC,INMODE,PUBLICRUN,WITH,CLEAN,CURRENT,GET,GETCREATE,TABLE,SET,STOP
from recover_cf_receive import RUN
from replay_cf_public_runloop import Replay,B,RL,MODE,SRC,TSD,PREVIOUS
from replay_daemon_descriptor_source import Replay as DaemonReplay
from recover_daemon_descriptor_source import SDK

def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def normalize(cache):
 raw=cache.read(SPEC,8);u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(SPEC&~4095,4096);u.mem_write(SPEC,raw);out=[]
 for value in range(256):u.reg_write(A.UC_ARM64_REG_X2,value);u.emu_start(SPEC,SPEC+8);answer=u.reg_read(A.UC_ARM64_REG_X2);assert answer==int(value!=0);out.append(answer)
 return{'start':hex(SPEC),'bytes8_hex':raw.hex(),'all_u8_inputs_checked':256,'outputs':out,'instruction_visits':512,'scope':'two original instructions; not256 public run-loop executions'}

def tsd_cases(s,cache):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.ctl_set_cpu_model(A.UC_CPU_ARM64_MAX);selected=[f for f in s['CF_source']['CF_functions']if int(f['start'],16)in(GET,GETCREATE,TABLE,SET)];pages=set()
 for f in selected:
  for pg in range(int(f['start'],16)&~4095,((int(f['end'],16)-1)&~4095)+4096,4096):pages.add(pg)
 errors={0x1848d34d8:'getter_index',0x1848d3500:'setter_index'}
 for a in errors:pages.add(a&~4095)
 for pg in pages:u.mem_map(pg,4096);u.mem_write(pg,cache.read(pg,4096))
 tls=0x70000000;table=tls+0x1000;halt=tls+0x2f00;u.mem_map(tls,0x4000);u.mem_write(tls+0x1b8,struct.pack('<Q',table));u.reg_write(A.UC_ARM64_REG_TPIDRRO_EL0,tls);visits=[];failure=[]
 def code(u,a,n,d):
  if a in errors:failure.append(hex(a));u.emu_stop();return
  raw=bytes(u.mem_read(a,4));assert raw==cache.read(a,4);visits.append({'pc':hex(a),'bytes_hex':raw.hex()});i=next(CS.disasm(raw,a))
  if i.mnemonic in('pacibsp','autibsp'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
  elif i.mnemonic=='retab':u.reg_write(A.UC_ARM64_REG_PC,u.reg_read(A.UC_ARM64_REG_X30))
  else:assert i.mnemonic not in('svc','brk','hvc','smc')
 u.hook_add(UC_HOOK_CODE,code)
 initial=bytearray(1128);struct.pack_into('<Q',initial,0,0x1122334455667788)
 for j in range(70):struct.pack_into('<Q',initial,8+j*8,0x5000010000+16*j);struct.pack_into('<Q',initial,0x238+j*8,0x5000020000+16*j)
 rows=[]
 def call(target,args):
  begin=len(visits);failure.clear()
  for j in range(31):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),0)
  for j,v in enumerate(args):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
  u.reg_write(A.UC_ARM64_REG_X30,halt);u.reg_write(A.UC_ARM64_REG_SP,tls+0x3f00);u.reg_write(A.UC_ARM64_REG_NZCV,0x40000000);u.emu_start(target,halt,count=200)
  return{'target':hex(target),'arguments':[hex(v)for v in args],'return_X0':hex(u.reg_read(A.UC_ARM64_REG_X0)),'stopped_before_error_helper':list(failure),'original_visits':visits[begin:]}
 for index in range(70):
  u.mem_write(table,bytes(initial)+b'\xa5');value=0x5000030000+16*index;destructor=0x1855148ec if index==13 else 0x5000040000+16*index;wanted=bytearray(initial);struct.pack_into('<Q',wanted,8+index*8,value);struct.pack_into('<Q',wanted,0x238+index*8,destructor);a=call(SET,(index,value,destructor));assert not a['stopped_before_error_helper']and a['return_X0']==hex(q(initial,8+index*8))and bytes(u.mem_read(table,1129))==bytes(wanted)+b'\xa5';b=call(GET,(index,));assert b['return_X0']==hex(value)and not b['stopped_before_error_helper']and bytes(u.mem_read(table,1129))==bytes(wanted)+b'\xa5';c=call(SET,(index,q(initial,8+index*8),q(initial,0x238+index*8)));assert c['return_X0']==hex(value)and bytes(u.mem_read(table,1129))==bytes(initial)+b'\xa5';rows.append({'index':index,'new_value':hex(value),'new_destructor':hex(destructor),'calls':[a,b,c],'initial_and_restored_TSD1128_hex':bytes(initial).hex(),'changed_TSD1128_hex':bytes(wanted).hex()})
 for target,error in((GET,0x1848d34d8),(SET,0x1848d3500)):
  u.mem_write(table,bytes(initial)+b'\xa5');e=call(target,(70,0,0));assert e['stopped_before_error_helper']==[hex(error)]and bytes(u.mem_read(table,1129))==bytes(initial)+b'\xa5';rows.append({'index':70,'calls':[e],'error_helper_prefix16_hex':cache.read(error,16).hex(),'scope':'stop before original diagnostic helper; no native failure claim'})
 return rows

def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');assert s==build();cache=Cache();cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};kernel=get('cf_runloop_wake_port_profiles.json')['kernel_cases'][2];c=Counter();ct=Counter();dt=Counter();summaries=[]
 for o,n in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert o['generator_sha256']==sha(ROOT/n)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 for f in cs['CF_functions']+cs['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in cs['cache_files']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 assert[e['symbol']for e in s['selected_daemon_bindings']]==['_CFRunLoopRun','_CFRunLoopStop','_CFRunLoopGetMain']and s['public_RUN_duration']['seconds']==10000000000 and s['internal_deadline_threshold']['seconds']==504911232 and s['public_RUN_duration']['seconds']>s['internal_deadline_threshold']['seconds']
 c.update(complete_cache_functions_recaptured=len(cs['CF_functions']),captured_instructions=sum(len(f['instructions'])for f in cs['CF_functions'])+4*len(cs['import_stubs']),cache_files_hashed=len(cs['cache_files']),selected_original_daemon_bindings_checked=3)
 headers=[SDK/'System/Library/Frameworks/CoreFoundation.framework/Headers'/n for n in('CFRunLoop.h','CFBase.h')]+[SDK/'usr/include/mach/message.h'];header_rows=[{'path':str(v),'size_bytes':v.stat().st_size,'sha256':sha(v)}for v in headers]
 layout='''#include <CoreFoundation/CFRunLoop.h>
#include <mach/message.h>
_Static_assert(sizeof(Boolean)==1,"Boolean8");
_Static_assert(sizeof(CFTimeInterval)==8,"interval64");
_Static_assert(sizeof(CFIndex)==8,"index64");
_Static_assert(kCFRunLoopRunFinished==1,"finished1");
_Static_assert(kCFRunLoopRunStopped==2,"stopped2");
_Static_assert(kCFRunLoopRunHandledSource==4,"handled4");
_Static_assert(MACH_RCV_TIMEOUT==0x100,"receive timeout option");
_Static_assert(MACH_RCV_TIMED_OUT==0x10004003,"receive timeout result");
_Static_assert(sizeof(CFRunLoopSourceContext)==80,"context80");
_Static_assert(__builtin_types_compatible_p(__typeof__(&CFRunLoopRun),void(*)(void)),"Run void ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&CFRunLoopRunInMode),CFRunLoopRunResult(*)(CFRunLoopMode,CFTimeInterval,Boolean)),"InMode ABI");
''';cmd=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(SDK),'-std=c11','-fsyntax-only','-x','c','-'];res=subprocess.run(cmd,input=layout,text=True,capture_output=True);assert res.returncode==0,res.stderr;c['SDK_headers_hashed']=3;c['SDK_arm64e_assertions_checked']=11
 assert len(p['cases'])==21
 for r in p['cases']:
  ct.update(Replay(r,kernel,cs).run());cfg=r['configuration'];label=cfg['label'];frames=r['public_RUN_frames'];root=bytes.fromhex(r['final_runloop2720_hex']);depth=cfg.get('depth',0);index=depth+1;pcs=Counter(e['pc']for e in r['source_visits']);entered=pcs[hex(RUN)]>0;normal=r['boundary']['kind']=='original_public_runloop_returned';idle=label=='no_pending';effects=r['declared_callback_effects'];calls=r['daemon_callback_return_calls'];expected_prev=PREVIOUS if cfg.get('previous_mode')else 0
  assert pcs[hex(WITH)]==1 and q(bytes.fromhex(r['final_TSD1129_hex']),88)==RL and r['final_TSD1129_hex']==r['public_initial'][0]['after_hex']and r['final_warning_once8_hex']=='ff'*8
  if cfg['entry']in('run','inmode'):assert pcs[hex(CURRENT)]==pcs[hex(GET)]==pcs[hex(GETCREATE)]==pcs[hex(TABLE)]==1
  if entered:
   published=next(e for e in frames if e['pc']=='0x184831bc0');b=bytes.fromhex(published['runloop2720_hex']);assert b[84]==index and q(b,0xa60)==MODE and q(b,0x258+index*8)==(0 if cfg['entry']=='run'else int(cfg.get('boolean',1)!=0))and b[0x55+index]==b[0x153+index]==0
   assert r['active_receive_buffer']==hex(int(r['active_RUN_frame_base'],16)+0xd0)
   if normal:assert root[84]==depth and q(root,0xa60)==expected_prev and pcs[hex(CLEAN)]==1
   else:assert idle and root[84]==index and q(root,0xa60)==MODE and pcs[hex(CLEAN)]==0
   c['actual_public_mode_depth_publication_oracles_checked']+=1
  elif normal:assert root[84]==depth and q(root,0xa60)==expected_prev and r['boundary']['registers31'][0]=='0x1'
  if cfg.get('callback_stop'):
   assert len(effects)==len(calls)==len(r['SVC_return_contracts'])==1;before=bytes.fromhex(effects[0]['before']['runloop2720_hex']);after=bytes.fromhex(effects[0]['original_Stop_return']['runloop2720_hex']);assert before[84]==after[84]==index and q(before,0xa60)==q(after,0xa60)==MODE and before[0x55+index]==0 and after[0x55+index]==1
   svc=r['SVC_return_contracts'][0];assert svc['before']['original_header24_hex']==struct.pack('<6I',0x13,24,0x807,0,0,0).hex();internal=next(e for e in frames if e['pc']=='0x184831c10')['registers31'][0];expect=2 if cfg['entry']=='run'or not cfg.get('boolean',1)else 4;assert internal==hex(expect)and root[0x55+index]==int(expect==4);c['same_CF_epoch_Stop_current_mode_index_and_original_wake_oracles_checked']+=1
  else:assert not effects and not r['SVC_return_contracts']
  if label in('specific_stale','specific_EIO'):assert entered and not calls and r['boundary']['registers31'][0]=='0x4'
  # Ownership levels derive from successful lower calls, starting at public0.
  start=r['public_handoffs'][-1]['after']['source_visit_index'];ledger={RL+16:0,MODE+16:0,SRC+16:0};underflow=[];steps=[];pending=list(calls);at_callback=[]
  for e in r['CF_models']:
   if e['before_source_visit_index']<start or e['pc']not in('0x1880773c0','0x1880773e0'):continue
   while pending and pending[0]['source_visit_index']<e['before_source_visit_index']:at_callback.append({'source_visit_index':pending.pop(0)['source_visit_index'],'levels':{hex(a):v for a,v in ledger.items()}})
   at=int(e['before']['registers31'][0],16)
   if at not in ledger:continue
   delta=1 if e['pc']=='0x1880773c0'else-1
   if delta<0 and ledger[at]==0:underflow.append({'address':hex(at),'return_pc':e['return_pc'],'source_visit_index':e['before_source_visit_index']})
   else:ledger[at]+=delta
   steps.append({'source_visit_index':e['before_source_visit_index'],'address':hex(at),'delta':delta,'level_after':ledger[at]})
  while pending:at_callback.append({'source_visit_index':pending.pop(0)['source_visit_index'],'levels':{hex(a):v for a,v in ledger.items()}})
  assert all(all(v==0 for v in e['levels'].values())for e in at_callback)
  if label=='empty_mode':assert len(underflow)==1 and underflow[0]['address']==hex(MODE+16)and underflow[0]['return_pc']=='0x184831b70';c['diagnostic_empty_mode_extra_unlock_requests_checked']+=1
  else:assert not underflow;c['public_entry_zero_initial_lock_ledgers_checked']+=1
  expected=1 if label in('depth254','depth255')else 0;assert ledger=={RL+16:expected,MODE+16:expected,SRC+16:0}
  summaries.append({'label':label,'original_visits':len(r['source_visits']),'entry':cfg['entry'],'entered_internal_RUN':entered,'completed_cleanup':bool(normal and entered),'final_depth':root[84],'final_current_mode':hex(q(root,0xa60)),'original_Stop_and_wake':len(effects),'daemon_callback_calls':len(calls),'boundary':r['boundary']['kind'],'boundary_X0':r['boundary']['registers31'][0],'public_void_return_X0_has_no_status_meaning':cfg['entry']=='run','conditional_lock_ledger':{'initial_levels':'all zero','steps':steps,'callback_levels':at_callback,'unmatched_unlock_requests':underflow,'final_levels':{hex(a):v for a,v in ledger.items()}}});print(label,len(r['source_visits']),flush=True)
 norm=normalize(cache);tsd=tsd_cases(s,cache);c['u8_boolean_normalization_inputs_checked']=256;c['boolean_slice_visits_checked']=512;c['valid_TSD_slots_round_tripped']=70;c['TSD_invalid_index_diagnostics_checked']=2;c['isolated_TSD_function_calls_checked']=sum(len(r['calls'])for r in tsd);c['isolated_TSD_original_visits_checked']=sum(len(e['original_visits'])for r in tsd for e in r['calls'])
 daemon=get('daemon_descriptor_source_profiles.json');init=daemon['initializer'];setup=daemon['setup_cases'][0];callback=daemon['callback_cases'][0]
 for r,origin in((init,None),(setup,init),(callback,setup)):dt.update(DaemonReplay(r,origin).run())
 c['separate_daemon_producer_consumer_epochs_replayed']=3
 rejected=[]
 for tag in('public_instruction','TSD_current_reference','published_current_mode','saved_previous_mode','dynamic_receive_pointer','Stop_entry_context','Stop_resume_CPU','final_warning_once'):
  bad=copy.deepcopy(p['cases'][3 if tag.startswith('Stop_')else 0])
  if tag=='public_instruction':next(e for e in bad['source_visits']if e['pc']==hex(SPEC))['bytes_hex']='00000000'
  elif tag=='TSD_current_reference':e=bad['public_initial'][0];raw=bytearray.fromhex(e['after_hex']);raw[88]^=1;e['after_hex']=raw.hex()
  elif tag=='published_current_mode':e=next(e for e in bad['public_RUN_frames']if e['pc']=='0x184831bc0');raw=bytearray.fromhex(e['runloop2720_hex']);raw[0xa60]^=1;e['runloop2720_hex']=raw.hex()
  elif tag=='saved_previous_mode':e=next(e for e in bad['public_RUN_frames']if e['pc']=='0x184832a48');e['registers31'][8]='0x1'
  elif tag=='dynamic_receive_pointer':bad['runloop_frames'][0]['receive_buffer_address']='0x0'
  elif tag=='Stop_entry_context':e=bad['declared_callback_effects'][0]['entry'];raw=bytearray.fromhex(e['runloop2720_hex']);raw[84]^=1;e['runloop2720_hex']=raw.hex()
  elif tag=='Stop_resume_CPU':bad['declared_callback_effects'][0]['declared_callback_resume']['registers31'][0]='0x0'
  else:bad['final_warning_once8_hex']='00'*8
  try:Replay(bad,kernel,cs).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('altered record accepted',tag))
 c['altered_evidence_controls_rejected']=len(rejected);positive=ct['original_instruction_visits_checked']+dt['original_instruction_visits_checked'];ram=ct['whole_final_private_RAM_bytes_checked']+dt['complete_final_mutable_RAM_bytes_checked']
 deps=[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','probe_cf_source0_scheduler.py','replay_cf_source0_scheduler.py','cf_runloop_wake_port_profiles.json','daemon_descriptor_source_profiles.json','replay_daemon_descriptor_source.py']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(c),'independent_CF_replay':dict(ct),'independent_daemon_replay':dict(dt),'case_summaries':summaries,'u8_normalization':norm,'isolated_TSD_cases':tsd,'SDK_headers':header_rows,'SDK_compile':{'command':cmd,'inline_C':layout,'exit_code':res.returncode},'aggregate_positive_visits':positive,'complete_final_private_RAM_bytes_checked':ram,'altered_evidence_rejected':rejected,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'CF':dict(ct),'daemon':dict(dt),'positive_visits':positive,'RAM_B':ram,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
