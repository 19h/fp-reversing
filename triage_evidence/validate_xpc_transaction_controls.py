#!/usr/bin/env python3
"""Static transaction flag, request schema and BSD proc_info route checks."""
import copy,itertools,json,struct,subprocess
from recover_xpc_transaction_controls import *
PATTERNS='''
enable|0x184b82758|tbnz|w8, #0, #0x184b82794
enable|0x184b8275c|ldrb|w8, [x19, #0xa9]
enable|0x184b82760|cbnz|w8, #0x184b82770
enable|0x184b8276c|bl|#0x188087b40
enable|0x184b82774|strb|w20, [x19, #0xa8]
enable|0x184b8277c|cbz|w8, #0x184b8278c
enable|0x184b82788|bl|#0x188087b30
track|0x184b82d08|cbz|w8, #0x184b82d48
track|0x184b82d4c|strb|w8, [x19, #0xa9]
track|0x184b82d58|ldrb|w8, [x19, #0xc0]
track|0x184b82d5c|mov|w9, #7
track|0x184b82d60|mov|w10, #0x13
track|0x184b82d68|csel|w19, w10, w9, ne
track|0x184b82d74|bl|#0x188087b40
track|0x184b82d78|tst|w0, #0xffffffef
track|0x184b82d80|bl|#0x184b82720
track|0x184b82d84|mov|w0, #0xf
track|0x184b82d88|mov|w1, #1
track|0x184b82d8c|bl|#0x188087bf0
exit_clean|0x184b84e40|strb|w8, [x19, #0xaa]
exit_clean|0x184b84e48|cbz|w8, #0x184b84f28
exit_clean|0x184b84e5c|tbz|w8, #2, #0x184b84ec8
exit_clean|0x184b84e60|bl|#0x184b86128
exit_clean|0x184b84e80|bl|#0x184b96068
exit_clean|0x184b84e94|mov|w0, #2
exit_clean|0x184b84e98|mov|w1, #0x2cb
exit_clean|0x184b84ea8|bl|#0x184b706f0
exit_clean|0x184b84f2c|bl|#0x18806d7b0
interrupt|0x184b86060|strb|wzr, [x19, #0xaa]
interrupt|0x184b86068|tbz|w8, #2, #0x184b860dc
interrupt|0x184b8608c|bl|#0x184b96068
interrupt|0x184b860a0|mov|w0, #2
interrupt|0x184b860a4|mov|w1, #0x2cb
interrupt|0x184b860b4|bl|#0x184b706f0
initializer|0x184b6c700|str|x0, [x19, #8]
initializer|0x184b6c818|tbnz|w8, #0xd, #0x184b6c8a8
initializer|0x184b6c81c|tbnz|w8, #4, #0x184b6c8b4
initializer|0x184b6c820|tbz|w8, #3, #0x184b6c8b8
initializer|0x184b6c824|bl|#0x184b82720
initializer|0x184b6c8ac|strb|w9, [x19, #0xc0]
initializer|0x184b6c8b4|bl|#0x184b82cbc
vproc_enable|0x184b872d0|b|#0x184b82720
service_request|0x184b86168|mov|w2, #6
service_request|0x184b8616c|bl|#0x184b70674
service_request|0x184b8617c|mov|x2, #0
service_request|0x184b86180|bl|#0x184b70674
service_request|0x184b861a0|bl|#0x184b96068
encode|0x184b8a7bc|mov|w2, w0
encode|0x184b8a7cc|bl|#0x184b70674
encode|0x184b8a7d0|sxtw|x2, w19
encode|0x184b8a7e0|bl|#0x184b70674
encode|0x184b8a7e4|mov|w19, #0
interface|0x184b70784|bl|#0x184b8a790
interface|0x184b707d0|ldr|x0, [x23, #0x18]
interface|0x184b707e4|bl|#0x184ba24d8
interface|0x184b70874|bl|#0x184b72b64
interface|0x184b7087c|cmp|w8, #1
once|0x185559d40|bl|#0x185559ba0
once|0x185559d44|ldr|x0, [x19, #8]
allocate|0x185559dd4|str|x0, [x8, #8]
proc_track|0x18054b0fc|mov|w3, w1
proc_track|0x18054b100|mov|w0, #8
proc_track|0x18054b108|mov|w2, #1
proc_track|0x18054b114|bl|#0x180549100
proc_dirty|0x18054b15c|mov|w3, w1
proc_dirty|0x18054b160|mov|w0, #8
proc_dirty|0x18054b168|mov|w2, #2
proc_dirty|0x18054b174|bl|#0x180549100
proc_info|0x180549100|mov|x16, #0x150
proc_info|0x180549104|svc|#0x80
signal|0x1805c67ac|mov|w2, #1
proc_info_entry|0xfffffe000c368554|ldr|w0, [x1]
proc_info_entry|0xfffffe000c368558|ldr|w8, [x1, #8]
proc_info_entry|0xfffffe000c36855c|ldr|w4, [x1, #0x10]
proc_info_entry|0xfffffe000c368560|ldp|x5, x6, [x1, #0x18]
proc_info_entry|0xfffffe000c368564|ldr|w7, [x1, #0x28]
proc_info_entry|0xfffffe000c368578|bl|#0xfffffe000c368588
proc_info_core|0xfffffe000c3685a0|sub|w16, w0, #1
proc_info_core|0xfffffe000c3685c0|ldrsw|x16, [x17, x16, lsl #2]
proc_info_core|0xfffffe000c368818|mov|x0, x1
proc_info_core|0xfffffe000c36881c|mov|x1, x4
proc_info_core|0xfffffe000c368820|mov|x2, x5
proc_info_core|0xfffffe000c368824|mov|x3, x19
proc_info_core|0xfffffe000c36883c|b|#0xfffffe000c36a664
dirty_control|0xfffffe000c36a6c0|bl|#0xfffffe000c5f312c
dirty_control|0xfffffe000c36a6cc|cbz|w26, #0xfffffe000c36a724
dirty_control|0xfffffe000c36a7d8|bl|#0xfffffe000c2cebc4
dirty_control|0xfffffe000c36a7ec|bl|#0xfffffe000c2e7f28
dirty_control|0xfffffe000c36a87c|bl|#0xfffffe000c2e7aec
'''
def verify(s):
 assert s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a'
 fs={**s['functions'],**s['kernel']['functions']}
 for role,f in fs.items():
  a=int(f['start'],16);bb=bytes.fromhex(f['bytes']);ii=list(CS.disasm(bb,a));assert h(bb)==f['sha256']and len(bb)==int(f['end'],16)-a==4*len(ii)
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]
 rows=[]
 for line in PATTERNS.strip().splitlines():
  role,pc,mn,op=line.split('|');hits=[i for i in fs[role]['instructions']if i['ea']==pc]
  assert len(hits)==1 and(hits[0]['mnemonic'],hits[0]['operands'])==(mn,op),(role,pc);rows.append({'role':role,**hits[0]})
 for a,(path,name)in STUBS.items():
  q=s['stubs'][hex(a)];assert q['library']==path and q['exact_export']==name and q['export_address']==q['pointer']['target']and q['pointer']['chain_membership_verified']
  w=int(q['pointer']['raw_word'],16);assert int(q['pointer']['target'],16)==int(q['pointer']['value_add'],16)+(w&0x3ffffffff)and w>>63
 expected={'environment':'XPC_FLAGS','yesno':'yesno','type':'type','handle':'handle','self':'self','subsystem':'subsystem','routine':'routine'}
 assert{n:q['value']for n,q in s['strings'].items()}==expected
 assert any(n['name']=='__xpc_bool_true'for n in s['Boolean_atoms']['0x1e241a230']['original_nlist'])
 assert any(n['name']=='__xpc_bool_false'for n in s['Boolean_atoms']['0x1e241a250']['original_nlist'])
 assert not s['direct_call_census']['indirect_coverage']and len(s['direct_call_census']['calls'])==3
 assert not s['daemon']['matching_named_imports']and len(s['daemon']['named_imports_checked'])==243
 k=s['kernel'];r=k['BSD336'];assert(r['index'],r['name'],r['argument_count'],r['u32_argument_bytes'])==(336,'proc_info',6,28)
 assert r['handler_pointer']['target']==k['functions']['proc_info_entry']['start']
 jt=k['jump_table'];actual=[hex(0xfffffe000c3685c4+x)for x in struct.unpack('<20i',bytes.fromhex(jt['bytes']))]
 assert actual==jt['targets']and actual[7]==jt['callnum8_target']=='0xfffffe000c368814'
 assert all(s[f]is False for f in FLAGS);return rows
def sdk_checks():
 code='''#define OS_OBJECT_USE_OBJC 0
#include <libproc.h>
#include <sys/proc_info.h>
#include <signal.h>
#include <errno.h>
#include <xpc/xpc.h>
#define A(x) static_assert((x),#x)
A(sizeof(void*)==8);A(sizeof(pid_t)==4);A(sizeof(uint32_t)==4);A(sizeof(uint64_t)==8);A(sizeof(bool)==1);
A(PROC_DIRTY_TRACK==1);A(PROC_DIRTY_ALLOW_IDLE_EXIT==2);A(PROC_DIRTY_DEFER==4);A(PROC_DIRTY_DEFER_ALWAYS==16);
A((PROC_DIRTY_TRACK|PROC_DIRTY_ALLOW_IDLE_EXIT|PROC_DIRTY_DEFER)==7);
A((PROC_DIRTY_TRACK|PROC_DIRTY_ALLOW_IDLE_EXIT|PROC_DIRTY_DEFER_ALWAYS)==19);
A(EBUSY==16);A(SIGTERM==15);
A(__is_same(decltype(&proc_track_dirty),int(*)(pid_t,uint32_t)));
A(__is_same(decltype(&proc_set_dirty),int(*)(pid_t,bool)));
A(__is_same(decltype(&xpc_dictionary_set_uint64),void(*)(xpc_object_t,const char*,uint64_t)));
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True)
 assert r.returncode==0 and not r.stderr,r.stderr
 signal=SDK/'usr/include/sys/signal.h';lines=[q for q in signal.read_text().splitlines()if q.startswith('#define SIG_IGN')];assert any('(void (*)(int))1'in q for q in lines)
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,
  'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'SIG_IGN_source':{'path':str(signal),'sha256':sha(signal),'matching_definitions':lines}}
def proofs():
 qs=[('enable_bit_idempotence_all_byte_states','''(declare-fun e () (_ BitVec 8))
(define-fun after () (_ BitVec 8) (ite (distinct (bvand e #x01) #x00) e #x01))
(assert (or (= (bvand after #x01) #x00)
 (distinct (ite (distinct (bvand after #x01) #x00) after #x01) after)))'''),
 ('tracking_return_mask_all32','''(declare-fun r () (_ BitVec 32))
(assert (distinct (= (bvand r #xffffffef) #x00000000) (or (= r #x00000000) (= r #x00000010))))'''),
 ('proc_info_jump_domain_all32','''(declare-fun c () (_ BitVec 32))
(assert (distinct (bvule (bvsub c #x00000001) #x00000013) (and (bvuge c #x00000001) (bvule c #x00000014))))'''),
 ('initializer_selected_priority_all64','''(declare-fun f () (_ BitVec 64))
(define-fun track () Bool (distinct (bvand f #x0000000000000010) #x0000000000000000))
(define-fun en () Bool (distinct (bvand f #x0000000000000008) #x0000000000000000))
(define-fun action () (_ BitVec 8) (ite track #x02 (ite en #x01 #x00)))
(assert (or (distinct (= action #x02) track)
 (distinct (= action #x01) (and (not track) en))
 (distinct (= action #x00) (and (not track) (not en)))))''')]
 out=[]
 for name,body in qs:
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True)
  assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Source-matched scalar predicates at declared branch/epoch; no whole initializer, native registration, permission, IPC or process-effect proof.'})
 return out
def models():
 enable=[]
 for e,t,n in itertools.product(range(256),[0,1,255],[0,1,0xffffffff]):
  active=bool(e&1);enable.append({'enabled_byte':e,'tracked_byte':t,'counter_u32':n,
   'flag_after':e if active else 1,'track_dirty_called':not active and t==0,'track_flags':1,
   'set_dirty_1_called':not active and n!=0,'registration_result_checked':False})
 tracking=[]
 for t,defer,status in itertools.product([0,1,255],[0,1,255],[0,16,1,0xffffffff]):
  first=t==0;tracking.append({'tracked_byte':t,'defer_byte':defer,'proc_result_u32':status,
   'flag_after':1 if first else t,'register_called':first,'register_flags':19 if defer else 7,
   'continuation_to_enable_signal':first and status in[0,16]})
 clean=[]
 for count,service,interrupt in itertools.product([0,1,0xffffffff],[False,True],[False,True]):
  clean.append({'count_u32':count,'service_bit':service,'interrupt':interrupt,'exit_flag_after':0 if interrupt else 1,
   'immediate_exit_request':not interrupt and count==0,'control_715_requested':service and(interrupt or count!=0),
   'yesno':not interrupt,'interface_u32':2,'routine_u32':715,'type_uint64':6,'handle_uint64':0,'self_bool':True})
 syscalls=[]
 for pid in[0,1,0x7fffffff,0x80000000,0xffffffff]:
  for flavor,args in[(1,[0,1,7,19,0xffffffff]),(2,[0,1])]:
   for arg in args:
    syscalls.append({'pid_u32':pid,'flavor_u32':flavor,'argument_u64':arg,'selector':336,
     'user_slots':[8,pid,flavor,arg,0,0],'kernel_frame_offsets_bytes':[0,8,16,24,32,40],
     'dirty_dispatch_arguments':['pid','flavor','argument','return_value_pointer']})
 flags=[]
 for d,t,e in itertools.product([False,True],repeat=3):
  f=(0x2000 if d else 0)|(16 if t else 0)|(8 if e else 0)
  flags.append({'word_u64':f,'defer_always_byte_set':d,'selected_call':'track_activity'if t else 'transactions_enable'if e else 'none','tracking_flags':19 if d else 7})
 return{'enable_cases':enable,'track_cases':tracking,'clean_cases':clean,'syscall_cases':syscalls,'initializer_flag_cases':flags,
  'scope':'Finite source/scalar/request-schema cases only; none invokes a native control or recovered CPU path.'}
def patch(q,role,pc,mn,op,kernel=False):
 fs=q['kernel']['functions']if kernel else q['functions'];i=next(i for i in fs[role]['instructions']if i['ea']==pc);i.update(mnemonic=mn,operands=op)
def alterations(s):
 changes=[('wrong_exit_flag',lambda q:patch(q,'exit_clean','0x184b84e40','strb','w8, [x19, #0xa8]')),
  ('wrong_initializer_priority',lambda q:patch(q,'initializer','0x184b6c81c','tbnz','w8, #3, #0x184b6c8b4')),
  ('wrong_control_routine',lambda q:patch(q,'exit_clean','0x184b84e98','mov','w1, #0x2cc')),
  ('wrong_signal_disposition',lambda q:patch(q,'track','0x184b82d88','mov','w1, #0')),
  ('wrong_dirty_flavor',lambda q:patch(q,'proc_dirty','0x18054b168','mov','w2, #1')),
  ('wrong_syscall_selector',lambda q:patch(q,'proc_info','0x180549100','mov','x16, #0x151')),
  ('wrong_kernel_route',lambda q:q['kernel']['jump_table'].__setitem__('callnum8_target','0xfffffe000c368840')),
  ('invented_native_permission',lambda q:q.__setitem__('native_authorization_proved',True))]
 out=[]
 for name,change in changes:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'name':name,'rejected':True});continue
  raise AssertionError(name)
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();m=models();al=alterations(s)
 counts={**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),
  **{n:len(m[n])for n in['enable_cases','track_cases','clean_cases','syscall_cases','initializer_flag_cases']},'rejected_evidence_alterations':len(al)}
 result={'generator_sha256':sha(__file__),'source_sha256':sha(ROOT/(P+'_source.json')),'source_recapture_match':True,
  'instruction_assertions':rows,'SDK_checks':sdk,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'proofs':pr,'models':m,'alterations':al,'verified_counts':counts,'all_checks_pass':True,
  'static_scope':'Conditional XPC transaction enable/track/clean-exit flag producers, selected initializer priority, signal/dirty tracking requests, interface2/routine715 Boolean request and proc_info336/callnum8/flavor1/2 kernel route. Native flags/registration/permission/process effects, actual port identity/IPC delivery, image pairing and successful daemon-kext exchange remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
