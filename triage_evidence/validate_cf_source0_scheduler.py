#!/usr/bin/env python3
"""Independent source0 scheduler/ABI/ordering/CPU/RAM verification.
Original code and data recapture, SDK compile, full private component replays,
finite original comparator cases, altered-evidence rejection. No native IPC,
thread/dispatch/ObjC/CF runtime/PAC or daemon callback body proof.
O(source+V*F+J+H*R) time,O(source+J+R) space.
"""
import copy,json,struct,subprocess
from collections import Counter
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,arm64_const as A
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache
from recover_cf_source0_scheduler import P,FLAGS,sha,build,DO,COLLECT,ONE,CALLOUT,COMPARE
from recover_cf_descriptor_source_factory import PERFORM,DAEMON
from replay_cf_source0_scheduler import Replay,POOL
from replay_cf_source_scheduling import B,RL,MODE,SRC,SET0
from replay_daemon_descriptor_source import Replay as DaemonReplay
from recover_daemon_descriptor_source import SDK

def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def scalar_cases(cache):
 code=cache.read(COMPARE,80);u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.ctl_set_cpu_model(A.UC_CPU_ARM64_MAX);u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20);u.reg_write(A.UC_ARM64_REG_FPCR,0);u.reg_write(A.UC_ARM64_REG_FPSR,0);u.mem_map(COMPARE&~4095,4096);u.mem_write(COMPARE,code);u.mem_map(0x70000000,4096);left=0x70000000;right=left+0x100;halt=0x70000800;visits=[];u.hook_add(UC_HOOK_CODE,lambda u,a,n,d:visits.append({'pc':hex(a),'bytes_hex':bytes(u.mem_read(a,4)).hex()}))
 rows=[(0,0,0,0),(0,1,200,100),(1,0,100,200),(-1,0,200,100),(0,-1,100,200),(-(1<<63),(1<<63)-1,200,100),((1<<63)-1,-(1<<63),100,200),(0,0,100,200),(0,0,200,100),(0,0,(1<<53),(1<<53)+1),(0,0,(1<<53)+1,(1<<53)),(0,0,(1<<53)+1,(1<<53)+2),(0,0,(1<<64)-2,(1<<64)-1),(0,0,0,(1<<64)-1)];out=[]
 for o0,o1,t0,t1 in rows:
  for a,o,t in((left,o0,t0),(right,o1,t1)):u.mem_write(a,bytes(256));u.mem_write(a+0x50,struct.pack('<qQ',o,t))
  u.reg_write(A.UC_ARM64_REG_X0,left);u.reg_write(A.UC_ARM64_REG_X1,right);u.reg_write(A.UC_ARM64_REG_X30,halt);u.reg_write(A.UC_ARM64_REG_NZCV,0x40000000);begin=len(visits);u.emu_start(COMPARE,halt,count=30);v=u.reg_read(A.UC_ARM64_REG_X0);v=v-(1<<64)if v>>63 else v;expect=(-1 if o0<o1 else 1 if o0>o1 else-1 if float(t0)<float(t1)else 1 if float(t0)>float(t1)else 0);assert v==expect
  out.append({'orders_signed64':[o0,o1],'timestamps_unsigned64':[t0,t1],'binary64_timestamps':[float(t0).hex(),float(t1).hex()],'original_result_signed64':v,'original_visits':visits[begin:],'scope':'isolated original comparator; not a multi-source sort or native timing proof'})
 assert out[9]['original_result_signed64']==out[10]['original_result_signed64']==out[12]['original_result_signed64']==0
 return out

def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');assert s==build();cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};kernel=get('cf_runloop_wake_port_profiles.json')['kernel_cases'][2];cache=Cache();c=Counter();ct=Counter();dt=Counter();summaries=[]
 for o,n in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert o['generator_sha256']==sha(ROOT/n)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 for f in cs['CF_functions']+cs['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in cs['cache_files']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 expected=['_objc_autoreleasePoolPush','_objc_autoreleasePoolPop','_kdebug_trace','_pthread_mutex_lock','_pthread_mutex_unlock'];assert[e['exact_exports']for e in s['new_lower_stubs']]==[[n]for n in expected]
 for e in s['new_lower_stubs']:assert cache.read(int(e['address'],16),16).hex()==e['bytes16_hex']and e['pointer']['chain_membership_verified']
 c.update(complete_CF_functions_recaptured=len(cs['CF_functions']),captured_CF_instructions=sum(len(f['instructions'])for f in cs['CF_functions'])+4*len(cs['import_stubs']),cache_files_hashed=len(cs['cache_files']),new_lower_stub_identities_checked=5,original_RUN_scheduler_callsite_checked=1)
 headers=[SDK/'System/Library/Frameworks/CoreFoundation.framework/Headers'/n for n in('CFRunLoop.h','CFBase.h')]+[SDK/'usr/include/mach/message.h'];header_rows=[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers]
 layout='''#include <CoreFoundation/CFRunLoop.h>
#include <mach/message.h>
_Static_assert(kCFRunLoopRunHandledSource==4,"handled4");
_Static_assert(kCFRunLoopRunFinished==1,"finished1");
_Static_assert(kCFRunLoopRunStopped==2,"stopped2");
_Static_assert(kCFRunLoopRunTimedOut==3,"timedout3");
_Static_assert(MACH_RCV_TIMEOUT==0x100,"timeout_option");
_Static_assert(MACH_RCV_TIMED_OUT==0x10004003,"receive_timed_out");
_Static_assert(sizeof(CFIndex)==8,"index64");
_Static_assert((CFIndex)-1<0,"index_signed");
_Static_assert(sizeof(CFRunLoopSourceContext)==80,"context80");
_Static_assert(sizeof(double)==8,"double8");
_Static_assert(__DBL_MANT_DIG__==53,"binary64_precision");
''';command=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(SDK),'-std=c11','-fsyntax-only','-x','c','-'];res=subprocess.run(command,input=layout,text=True,capture_output=True);assert res.returncode==0,res.stderr;c['SDK_arm64e_assertions_checked']=11;c['SDK_headers_hashed']=3
 assert len(p['cases'])==16
 for r in p['cases']:
  ct.update(Replay(r,kernel,cs).run());cfg=r['configuration'];label=cfg['label'];frames=r['scheduler_frames'];src=bytes.fromhex(r['final_source184_hex']);pcs=Counter(e['pc']for e in r['source_visits']);mods=r['mode_models'];calls=r['daemon_callback_return_calls'];late=bool(cfg.get('late_change'));eligible=cfg.get('enable_ready',True)and cfg.get('source_valid',True)and not cfg.get('source_version')and not cfg.get('clear_signal');dispatched=eligible and not late;perform=dispatched and not cfg.get('null_perform');cb=perform and cfg.get('perform_ready',True)and cfg.get('poll_error')!=5
  assert not any(e['name']=='no_pending_source0'for e in r['imports'])and pcs[hex(DO)]==pcs[hex(COLLECT)]==1 and pcs[hex(ONE)]==int(eligible)and pcs[hex(CALLOUT)]==int(dispatched)and pcs[hex(PERFORM)]==int(perform)and len(calls)==int(cb)
  returns=[e for e in frames if e['pc']=='0x1847586dc'];assert len(returns)==1 and returns[0]['registers31'][0]==hex(int(dispatched))
  timestamp=q(src,0x58);expected_tick=100 if label in('invalid_source','version1_diagnostic')else 0;assert timestamp==expected_tick and q(src,8)>>8&0x3ff==46
  if eligible and not(cfg.get('late_change')=='unsignal'):
   before=next(e for e in frames if e['pc']=='0x184758804');after=next(e for e in frames if e['pc']=='0x184758808');assert q(bytes.fromhex(before['source184_hex']),0x58)==100 and q(bytes.fromhex(after['source184_hex']),0x58)==0;c['original_clear_before_validity_and_callout_oracles_checked']+=1
  for e in calls:assert e['arguments3']==[hex(B+0xc0000),hex(cfg.get('enable_mask',1)),'0x0']and q(bytes.fromhex(e['source184_hex']),0x58)==0
  poll=[e for e in mods if e['name']=='declared_source0_nonblocking_receive_timeout'];assert len(poll)==int(dispatched)
  if dispatched:assert r['boundary']['kind']=='original_source0_RUN_returned'and r['boundary']['registers31'][0]=='0x4'
  else:assert r['boundary']['kind']=='before_original_source0_idle_receive'
  pools=r['declared_pool_events'];havepool=dispatched and not cfg.get('pool_disabled');assert len(pools)==2*int(havepool)
  if havepool:assert[p['operation']for p in pools]==['push','pop']and pools[0]['token']==pools[1]['token']==hex(POOL)
  if cfg.get('poll_error'):assert r['final_descriptor_backend']['poll_counts']['perform']==(2 if cfg['poll_error']in(4,35)else 1)
  assert not r['SVC_return_contracts']and r['final_model_state']['members']==[['0x507','0x607'],['0x507','0x707'],['0x507','0x807']]and r['final_pool65_hex']==(bytes(64)+b'\xa5').hex()
  if dispatched:
   unlocks=[e for e in r['CF_models']if e['pc']=='0x1880773e0'];locks=[e for e in r['CF_models']if e['pc']=='0x1880773c0'];assert any(e['before']['registers31'][0]==hex(MODE+16)and e['return_pc']=='0x1847585c8'for e in unlocks)and any(e['before']['registers31'][0]==hex(RL+16)and e['return_pc']=='0x1847585d0'for e in unlocks)and any(e['before']['registers31'][0]==hex(RL+16)and e['return_pc']=='0x184758688'for e in locks)and any(e['before']['registers31'][0]==hex(MODE+16)and e['return_pc']=='0x184758690'for e in locks);c['mode_runloop_unlock_callout_relock_oracles_checked']+=1
  # Conditional recursive-lock ledger: internal RUN entry assumes caller-held
  # mode/run-loop locks; no pthread ownership or native exclusion is asserted.
  entry=next(e for e in r['public_handoffs']if e['kind']=='AddSource0_to_original_RUN')['after']['source_visit_index'];ledger={RL+16:1,MODE+16:1,SRC+16:0};steps=[];cb_ledger=[];pending=list(calls)
  for e in r['CF_models']:
   if e['before_source_visit_index']<entry or e['pc']not in('0x1880773c0','0x1880773e0'):continue
   while pending and pending[0]['source_visit_index']<e['before_source_visit_index']:cb_ledger.append({'source_visit_index':pending.pop(0)['source_visit_index'],'levels':{hex(a):n for a,n in ledger.items()}})
   at=int(e['before']['registers31'][0],16)
   if at not in ledger:continue
   delta=1 if e['pc']=='0x1880773c0'else-1;assert delta==1 or ledger[at]>0;ledger[at]+=delta;steps.append({'source_visit_index':e['before_source_visit_index'],'address':hex(at),'delta':delta,'level_after':ledger[at]})
  while pending:cb_ledger.append({'source_visit_index':pending.pop(0)['source_visit_index'],'levels':{hex(a):n for a,n in ledger.items()}})
  assert all(all(n==0 for n in e['levels'].values())for e in cb_ledger)and ledger=={RL+16:int(dispatched),MODE+16:int(dispatched),SRC+16:0};c['conditional_internal_RUN_lock_ledgers_checked']+=1
  summaries.append({'conditional_lock_ledger':{'premise':'internal RUN entry holds mode/runloop locks once; source unlocked','steps':steps,'callback_levels':cb_ledger,'final_levels':{hex(a):n for a,n in ledger.items()}},'label':label,'original_visits':len(r['source_visits']),'collected':bool(eligible),'dispatch_handled':bool(dispatched),'Perform_called':bool(perform),'daemon_callback_arguments3':[e['arguments3']for e in calls],'final_signal_ticks':timestamp,'pool_push_pop':havepool,'nonblocking_timeout_contracts':len(poll),'boundary':r['boundary']['kind'],'RUN_return_value':r['boundary']['registers31'][0]if dispatched else None});print(json.dumps(summaries[-1]),flush=True)
 comparator=scalar_cases(cache);c['isolated_original_comparator_cases_checked']=len(comparator);c['isolated_original_comparator_visits_checked']=sum(len(e['original_visits'])for e in comparator)
 daemon=get('daemon_descriptor_source_profiles.json');init=daemon['initializer'];setup=daemon['setup_cases'][0];callback=daemon['callback_cases'][0]
 for r,origin in((init,None),(setup,init),(callback,setup)):dt.update(DaemonReplay(r,origin).run())
 created=next(e for e in setup['imports']if e['name']=='CoreFoundation/_CFFileDescriptorCreate');assert created['arguments8'][:5]==['0x0','0x7','0x1',hex(DAEMON),'0x0'];c['separate_daemon_producer_consumer_epochs_replayed']=3
 rejected=[]
 for tag in('scheduler_instruction','runtime_type_header','post_clear_timestamp','callout_perform_argument','pool_token','callback_arguments','receive_timeout_result','late_source_change'):
  bad=copy.deepcopy(p['cases'][14 if tag=='late_source_change'else 0])
  if tag=='scheduler_instruction':next(e for e in bad['source_visits']if e['pc']==hex(DO))['bytes_hex']='00000000'
  elif tag=='runtime_type_header':
   for key in('imports','runloop_models','mode_models'):
    e=next(e for e in bad[key]if e['name']=='declared_source0_runtime_header_type46');raw=bytearray.fromhex(e['patches'][0]['after_hex']);raw[9]^=1;e['patches'][0]['after_hex']=raw.hex()
  elif tag=='post_clear_timestamp':e=next(e for e in bad['scheduler_frames']if e['pc']=='0x184758808');raw=bytearray.fromhex(e['source184_hex']);raw[0x58]^=1;e['source184_hex']=raw.hex()
  elif tag=='callout_perform_argument':next(e for e in bad['scheduler_frames']if e['pc']==hex(CALLOUT))['registers31'][0]='0x0'
  elif tag=='pool_token':bad['declared_pool_events'][1]['token']='0x0'
  elif tag=='callback_arguments':bad['daemon_callback_return_calls'][0]['arguments3'][1]='0x2'
  elif tag=='receive_timeout_result':
   for key in('imports','runloop_models','mode_models'):next(e for e in bad[key]if e['name']=='declared_source0_nonblocking_receive_timeout')['result']='0x0'
  else:bad['declared_late_source_variants'][0]['patches'][0]['after_hex']='00'*8
  try:Replay(bad,kernel,cs).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('altered record accepted',tag))
 c['altered_evidence_controls_rejected']=len(rejected);positive=ct['original_instruction_visits_checked']+dt['original_instruction_visits_checked'];ram=ct['whole_final_private_RAM_bytes_checked']+dt['complete_final_mutable_RAM_bytes_checked']
 deps=[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','probe_cf_descriptor_source_factory.py','replay_cf_descriptor_source_factory.py','cf_runloop_wake_port_profiles.json','daemon_descriptor_source_profiles.json','replay_daemon_descriptor_source.py']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(c),'independent_CF_replay':dict(ct),'independent_daemon_replay':dict(dt),'case_summaries':summaries,'isolated_original_comparator_cases':comparator,'SDK_headers':header_rows,'SDK_compile':{'command':command,'inline_C':layout,'exit_code':res.returncode},'aggregate_positive_visits':positive,'complete_final_private_RAM_bytes_checked':ram,'altered_evidence_rejected':rejected,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(c),'CF_totals':dict(ct),'daemon_totals':dict(dt),'positive_visits':positive,'RAM_B':ram,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
