#!/usr/bin/env python3
"""Source/ABI/original-replay checks for descriptor registration and lifecycle.
Independent original ISA execution, complete RAM/CPU/journals, inline SDK
compilation, local full-domain SMT and altered-evidence rejection. No native
IPC/signal/event/CF runtime/PAC proof. O(source + replay + RAM + journals).
"""
import copy,json,struct,subprocess
from collections import Counter
from pathlib import Path
from daemon_receive_tools import ROOT,IMAGE,CS
from recover_daemon_descriptor_source import P,FLAGS,sha,build,SDK,HEAP,HEADER,OUT,CFREF,CFSRC,CALLBACK,MODE,REGIONS
from replay_daemon_descriptor_source import Replay,CFReplay,decode

def get(n):return json.loads((ROOT/n).read_text())
def names(r):return[e['name'].split('/',1)[1]for e in r['imports']]
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');assert s==build();c=Counter();tot=Counter();ct=Counter();summary=[]
 for o,n in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert o['generator_sha256']==sha(ROOT/n)and all(o[k]is False for k in FLAGS)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
 for f in s['original_ranges']:assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 expected=['libSystem/_kqueue','libSystem/_signal','libSystem/_kevent','0x100001f2c','CoreFoundation/_CFFileDescriptorEnableCallBacks','CoreFoundation/_CFFileDescriptorCreateRunLoopSource','CoreFoundation/_CFRunLoopGetMain','CoreFoundation/_CFRunLoopAddSource','CoreFoundation/_CFRelease'];assert[e['target']for e in s['exhaustive_banks_256']]==expected and all(e['inputs_checked']==256 for e in s['exhaustive_banks_256'])
 assert len(s['IDA_original_byte_matches'])==4 and sum(e['bytes_checked']for e in s['IDA_original_byte_matches'])==1600 and len(s['selected_bindings'])==11 and s['default_mode_binding']['combined_addend']==0 and s['default_mode_binding']['binding']['total_addend']==0x7ed8f1f2
 for e in s['SDK_headers']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 layout='''#include <stddef.h>
#include <sys/event.h>
#include <sys/signal.h>
#include <CoreFoundation/CFFileDescriptor.h>
_Static_assert(sizeof(struct kevent)==32,"kevent32");
_Static_assert(_Alignof(struct kevent)==4,"kevent align");
_Static_assert(offsetof(struct kevent,filter)==8,"filter");
_Static_assert(offsetof(struct kevent,flags)==10,"flags");
_Static_assert(offsetof(struct kevent,fflags)==12,"fflags");
_Static_assert(offsetof(struct kevent,data)==16,"data");
_Static_assert(offsetof(struct kevent,udata)==24,"udata");
_Static_assert(SIGTERM==15,"SIGTERM");
_Static_assert(EVFILT_SIGNAL==-6,"signal filter");
_Static_assert(EVFILT_PROC==-5,"process filter");
_Static_assert(EV_ADD==1,"add");
_Static_assert(kCFFileDescriptorReadCallBack==1,"read callback");
_Static_assert(sizeof(CFFileDescriptorContext)==40,"context40");
_Static_assert(sizeof(CFOptionFlags)==8,"option flags64");
''';command=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(SDK),'-std=c11','-fsyntax-only','-x','c','-'];compiled=subprocess.run(command,input=layout,text=True,capture_output=True);assert compiled.returncode==0,compiled.stderr
 definitions="""(declare-fun x () (_ BitVec 32))
(define-fun a () (_ BitVec 32) (bvadd (bvxor x #x4eefd9fd) (bvand (bvshl x #x00000001) #x9ddfb3fa)))
(define-fun enc () (_ BitVec 32) (bvadd a #xb71eff6c))
(define-fun dec () (_ BitVec 32) (bvxor (bvadd (bvsub x (bvand (bvshl x #x00000001) #xf2d09d8a)) #x79684ec5) #x79684ec5))
(define-fun pred () Bool (= (bvlshr (bvnot (bvadd a #xb10f93db #x00009228)) #x0000001f) #x00000001))
"""
 obligations=[('stored_descriptor32','(= enc (bvadd x #x060ed969))'),('callback_descriptor32','(= dec x)'),('signed_descriptor_admission','(= pred (bvsge x #x00000000))')];proofs=[]
 for name,claim in obligations:
  query=definitions+'(assert (not '+claim+'))\n(check-sat)\n';answer=subprocess.run(['z3','-T:30','-in','-smt2'],input=query,text=True,capture_output=True,check=True,timeout=35).stdout.strip();assert answer=='unsat',(name,answer);proofs.append({'name':name,'query':query,'result':answer,'domain_bits':32})
 c.update(original_static_ranges_recaptured=13,captured_static_instructions=973,exhaustive_256_banks_checked=9,selected_original_bindings_checked=11,default_mode_nonzero_addend_cancellation_checked=1,IDA_byte_ranges_checked=4,IDA_original_bytes_checked=1600,SDK_headers_hashed=3,SDK_arm64e_assertions_checked=14,full_domain_local_SMT_proofs=3)
 def run(r,origin=None):
  counts=Replay(r,origin).run();tot.update(counts);summary.append({'label':r['configuration']['label'],'phase':r['configuration']['phase'],'original_visits':len(r['source_visits']),'external_calls':names(r),'boundary':r['boundary']['kind']});print(r['configuration']['label'],len(r['source_visits']),flush=True)
 run(p['initializer']);run(p['poison_initializer'])
 for r in p['setup_cases']:run(r,p['initializer'])
 run(p['poison_setup'],p['poison_initializer'])
 for r in p['callback_cases']:run(r,p['setup_cases'][0])
 for r in p['poison_callback_cases']:run(r,p['poison_setup'])
 # Original initializer touches exactly the20-byte tail of each896-byte record.
 wanted={j*896+k for j in range(100)for k in range(876,896)}
 for r,fill in((p['initializer'],0),(p['poison_initializer'],165)):
  written=set()
  for e in r['source_writes']:
   a=int(e['address'],16);written.update(v-HEAP for v in range(max(a,HEAP),min(a+e['size_bytes'],HEAP+89600)))
  assert written==wanted;raw=decode(r['final_regions'][3]);assert q(bytes.fromhex(r['final_header96_hex']),0)==HEAP and q(bytes.fromhex(r['final_header96_hex']),8)==100
  for j in range(100):assert raw[j*896:j*896+876]==bytes([fill])*876 and raw[j*896+876:(j+1)*896]==struct.pack('<I',0x4577df49)+bytes(16)
 c['original_initialized_record_tail_bytes_checked']=2000;c['record_stride_bytes']=896;c['original_record_count']=100
 for r in p['setup_cases']+[p['poison_setup']]:
  cfg=r['configuration'];ns=names(r);h=bytes.fromhex(r['final_header96_hex']);assert struct.unpack_from('<I',h,0x48)[0]==(cfg['fd']+0x060ed969)&0xffffffff
  if cfg['fd']<0:assert ns==['_kqueue']and q(h,0x50)==0;continue
  change=next(e for e in r['imports']if e['name']=='libSystem/_kevent')['change32_hex'];assert change==struct.pack('<QhHIqQ',15,-6,1,0,0,0).hex();created=next(e for e in r['imports']if e['name']=='CoreFoundation/_CFFileDescriptorCreate');assert created['arguments8'][:5]==['0x0',hex(cfg['fd']),'0x1',hex(CALLBACK),'0x0']
  if cfg.get('null_cf'):assert q(h,0x50)==0 and '_CFFileDescriptorCreateRunLoopSource'not in ns
  else:
   assert q(h,0x50)==CFREF
   if cfg.get('null_source'):assert '_CFFileDescriptorInvalidate'not in ns and '_CFRelease'in ns and '_CFRunLoopAddSource'not in ns
   else:assert ns[-3:]==['_CFRunLoopGetMain','_CFRunLoopAddSource','_CFRelease'];add=next(e for e in r['imports']if e['name']=='CoreFoundation/_CFRunLoopAddSource');assert add['arguments8'][1:3]==[hex(CFSRC),hex(MODE)]
  c['setup_record_wrapper_source_and_mode_oracles_checked']+=1
 a,b=p['setup_cases'][0],p['setup_cases'][5];assert a['source_visits']==b['source_visits']and a['final_regions']==b['final_regions']and a['boundary']==b['boundary'];c['declared_registration_error_same_original_control_and_final_state_checked']=1
 for r in p['callback_cases']+p['poison_callback_cases']:
  cfg=r['configuration'];ns=names(r);stop=(cfg['filter']==-6 and cfg['ident']==15 and(cfg['event_result']>0 or cfg['event_seed']));assert ns.count('_CFRunLoopStop')==int(stop)and ns.count('_CFFileDescriptorInvalidate')==int(stop)and ns.count('_CFMachPortInvalidate')==int(stop and cfg['mach_object'])and ns.count('_CFFileDescriptorEnableCallBacks')==(2 if cfg['filter']==-5 and cfg['event_result']>0 else 1)
  assert q(bytes.fromhex(r['final_header96_hex']),0x50)==CFREF;c['callback_event_dispatch_and_retained_CF_field_oracles_checked']+=1
  event=next(e for e in r['imports']if e['name']=='libSystem/_kevent');index=event['before']['source_visit_index'];assert not any(e['visit']<index and int(e['address'],16)<OUT+32 and int(e['address'],16)+e['size_bytes']>OUT for e in r['source_writes']);c['event_output_has_no_original_prequery_initialization_checked']+=1
 for a,b in((p['callback_cases'][0],p['poison_callback_cases'][0]),(p['callback_cases'][3],p['poison_callback_cases'][1])):assert a['source_visits']==b['source_visits']and a['boundary']==b['boundary'];c['poisoned_backing_same_original_path_and_final_CPU_checked']+=1
 assert tot['original_instruction_visits_checked']==79643 and tot['complete_final_mutable_RAM_bytes_checked']==19*sum(n for _,n in REGIONS)and len(summary)==19
 rejected=[]
 for tag in('original_callback_instruction','registered_callback_argument','event_bytes','inherited_setup_pointer','final_descriptor_field','origin_heap_snapshot'):
  r=copy.deepcopy(p['callback_cases'][0]if tag in('original_callback_instruction','event_bytes','final_descriptor_field')else p['setup_cases'][0]);origin=p['setup_cases'][0]if r['configuration']['phase']=='callback'else p['initializer']
  if tag=='original_callback_instruction':r['source_visits'][0]['bytes_hex']='00000000'
  elif tag=='registered_callback_argument':next(e for e in r['imports']if e['name']=='CoreFoundation/_CFFileDescriptorCreate')['arguments8'][3]='0x0'
  elif tag=='event_bytes':e=next(e for e in r['imports']if e['name']=='libSystem/_kevent');b=bytearray.fromhex(e['patches'][0]['after_hex']);b[8]^=1;e['patches'][0]['after_hex']=b.hex()
  elif tag=='inherited_setup_pointer':r['fixture_patches'][0]['after_hex']='00'*8
  elif tag=='final_descriptor_field':b=bytearray.fromhex(r['final_header96_hex']);b[0x50]^=1;r['final_header96_hex']=b.hex()
  else:r['origin']['region_sha256'][3]='0'*64
  try:Replay(r,origin).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('altered evidence accepted',tag))
 cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};prior=get('cf_runloop_wake_port_profiles.json');stop=s['CF_stop_export'];assert stop['daemon_binding']['symbol']=='_CFRunLoopStop'and len(stop['original_function']['instructions'])==53
 from bootpolicy_cache_reader import Cache
 cache=Cache();f=stop['original_function'];assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for r in p['CF_cases']:
  ct.update(CFReplay(r,prior['kernel_cases'][2],cs).run());active=r['configuration']['active_mode'];pcs=[e['pc']for e in r['source_visits']];assert pcs.count('0x184784250')==1 and pcs.count('0x1847842e8')==int(active)and pcs.count('0x18473ae10')==int(active)and r['final_stop_flag_byte_hex']==('01'if active else'00')and len(r['SVC_return_contracts'])==int(active);summary.append({'label':r['configuration']['label'],'phase':'CF_Stop','original_visits':len(r['source_visits']),'active_mode':active,'stop_byte_hex':r['final_stop_flag_byte_hex'],'SVC_visits':len(r['SVC_return_contracts'])})
 for tag in('CF_Stop_mode_premise','CF_Stop_final_flag'):
  r=copy.deepcopy(p['CF_cases'][2])
  if tag=='CF_Stop_mode_premise':r['CF_stop_fixture']['after_hex']='00'*8
  else:r['final_stop_flag_byte_hex']='00'
  try:CFReplay(r,prior['kernel_cases'][2],cs).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('altered CF evidence accepted',tag))
 assert ct['original_instruction_visits_checked']==4066 and ct['whole_final_private_RAM_bytes_checked']==9437184 and len(summary)==22
 c.update(CF_stop_original_instructions_captured=53,CF_stop_daemon_bind_export_and_body_checked=1,CF_stop_active_and_dormant_cases_checked=3,cache_files_hashed=9)
 c['altered_evidence_controls_rejected']=len(rejected)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','daemon_rpc502_probe.py','daemon_receive_tools.py','cf_runloop_wake_port_profiles.json','replay_cf_wake_send_wrapper.py']},'source_recapture_match':True,'verified_counts':dict(c),'independent_daemon_replay':dict(tot),'independent_CF_replay':dict(ct),'aggregate_positive_visits':83709,'complete_final_private_RAM_bytes_checked':55820288,'SDK_layout_validation':{'command':command,'source':layout,'exit_code':0,'native_executed':False},'full_domain_proofs':proofs,'case_summaries':summary,'altered_evidence_rejected':rejected,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'replay':dict(tot),'CF_visits':ct['original_instruction_visits_checked'],'aggregate_positive_visits':83709,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
