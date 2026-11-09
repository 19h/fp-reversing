#!/usr/bin/env python3
"""Original instruction checks, actual SDK layouts and bounded scalar proofs.
No target execution or native host/Mach/launchd mutation.
"""
import copy,json,struct,subprocess
from recover_host_special_registration import ROOT,P,FLAGS,SDK,build,sha,h,instructions
EXPECTED='''
100003750|adrp|x8, #0x100089000
100003754|ldrb|w8, [x8, #0xab8]
100003758|cmp|w8, #1
10000375c|b.eq|#0x100003874
100003760|mov|w22, #1
100003874|ldrb|w8, [x19, #0x586]
100003878|ubfx|w22, w8, #6, #1
10000387c|and|w0, w22, #1
1000302b0|str|w8, [x19, #0x50]
1000302b8|mov|w8, #0x18
1000302bc|str|w8, [x19, #0x54]
1000302d0|mov|w1, #2
1000302d4|bl|#0x100003708
1000302d8|tbz|w0, #0, #0x1000302fc
1000302e0|cbz|w24, #0x10003034c
1000302f0|cmp|x8, x9
1000302f4|b.ne|#0x100030328
100030348|str|wzr, [x19, #0x54]

fffffe000bcf2350|sub|w8, w1, #0x25
fffffe000bcf2354|cmn|w8, #0x1d
fffffe000bcf2358|b.lo|#0xfffffe000bcf23bc
fffffe000bcf2370|ldr|x8, [x0, #0x4d8]
fffffe000bcf2374|and|x8, x8, #0xf000000000000
fffffe000bcf2378|mov|x9, #0x7000000000000
fffffe000bcf2384|mov|w0, #8
fffffe000bcf2390|bl|#0xfffffe000bccb4c0
fffffe000bcf23b4|b|#0xfffffe000bcf23cc
fffffe000bcf23b8|mov|w0, #0x35
fffffe000bcf2410|cmp|x0, x8
fffffe000bcf241c|bl|#0xfffffe000bd7deec
fffffe000bcf2424|ldr|x16, [x8, #0x668]
fffffe000bcf2444|cmp|w20, #0x14
fffffe000bcf2458|bl|#0xfffffe000c5a7254
fffffe000bcf2464|ldrb|w8, [x8, #0xc60]
fffffe000bcf2468|tbz|w8, #2, #0xfffffe000bcf247c
fffffe000bcf2474|bl|#0xfffffe000c617964
fffffe000bcf2478|cbz|w0, #0xfffffe000bcf2490
fffffe000bcf247c|mov|w0, #8
fffffe000bcf24ac|b|#0xfffffe000bcf2194
fffffe000bcf21b0|cmp|w1, #0x24
fffffe000bcf21b8|sub|w8, w19, #8
fffffe000bcf21bc|cmn|w8, #4
fffffe000bcf21c4|cmp|w19, #0x1a
fffffe000bcf21cc|mov|w0, #0x2e
fffffe000bcf21ec|casa|x8, x9, [x11]
fffffe000bcf21f8|add|x8, x0, #0x10
fffffe000bcf21fc|ubfiz|x10, x19, #3, #0x20
fffffe000bcf2228|autda|x16, x17
fffffe000bcf223c|pacda|x17, x16
fffffe000bcf2250|str|x17, [x9]
fffffe000bcf2264|casl|w2, wzr, [x10]
fffffe000bcf2274|add|x8, x21, #1
fffffe000bcf2280|cmp|w19, #0x21
fffffe000bcf22d0|bl|#0xfffffe000bcd0448
fffffe000bcf336c|ldr|x16, [x0, #0x2d0]
fffffe000bcf3380|cmp|x19, x16
fffffe000bcf3384|b.ne|#0xfffffe000bcf3394
fffffe000bcf3394|mov|x0, #0
fffffe000bcf33b8|cmp|w8, #0x19
fffffe000bcf33c0|ldr|x16, [x19, #0x50]!
fffffe000bcf33d0|mov|x0, x16
fffffe000bcf33e0|cmp|x0, x8
fffffe000bd83ec8|cmp|w8, #1
fffffe000bd83ed4|cmp|w8, #0x40
fffffe000bd83edc|ldrh|w8, [x0, #0x2e]
fffffe000bd83ee4|cmp|w8, #0x110, lsl #12
fffffe000bd83f14|bl|#0xfffffe000bcf334c
fffffe000bd83f1c|ldr|w1, [x21, #8]
fffffe000bd83f20|ldr|x16, [x17, #0x24]!
fffffe000bd83f5c|bl|#0xfffffe000bcf2330
fffffe000bd83f60|str|w0, [x19, #8]
fffffe000bd83f94|cmp|w8, #0x30
fffffe000bd83fd0|ldr|w2, [x20, #0xc]
fffffe000bd83fd8|bl|#0xfffffe000bcf24b0
fffffe000c6179d4|ldr|x10, [x10, #0x3f0]
fffffe000c6179f8|ldr|x0, [x0, #0x10]
fffffe000c6179fc|mov|x1, x20
fffffe000c617a00|mov|x2, x19
fffffe000c617a08|blraa|x25, x17
fffffe000c617ac4|mov|x0, x21
180568978|stp|w20, w2, [sp, #0x20]
180568994|str|w1, [sp, #0x38]
1805689c4|movk|x2, #0x8000, lsl #16
1805689c8|movk|x2, #0x34, lsl #32
1805689d8|mov|x4, #0x19d00000000
1805689dc|mov|w6, #0x2c
1805689e4|bl|#0x18055a894
180568a20|cmp|w8, #0x201
180568a48|ldr|w19, [sp, #0x28]
180548ac0|mov|x4, #0x19c00000000
180548acc|bl|#0x18055a894
180548b0c|cmp|w8, #0x200
180548b90|ldr|w8, [sp, #0x1c]
180548b94|str|w8, [x19]
100047124|adrp|x16, #0x10005c000
100047128|add|x16, x16, #0x840
10004713c|stp|x19, x20, [sp, #0x30]
100047148|bl|#0x10005f500
10005c864|mov|x0, x2
10005c868|bl|#0x10005f720
10005c90c|bl|#0x10005f740
10005c914|cmp|x0, #8
10005c91c|cmp|x21, #0x24
10005c924|str|w21, [x20, #0x54]
10005cae0|bl|#0x10005e360
10005cb14|bl|#0x1000479cc
1000479dc|cmp|w1, #6
1000479e0|b.hi|#0x1000479f4
1000479f4|cmp|w1, #0xb
1000479f8|b.gt|#0x100047a04
1000479fc|str|w1, [x0, #0x50]
100030498|ldrsw|x21, [x19, #0x54]
10003049c|cbz|w21, #0x100030568
1000304ac|cmp|w21, #0x18
1000304dc|ldr|x24, [x23, x21, lsl #3]
10003050c|str|wzr, [x19, #0x54]
100030534|bl|#0x100043fd0
10003053c|bl|#0x10005e340
100030548|mov|w1, #1
10003054c|bl|#0x100046c28
100030550|mov|x2, x0
100030558|mov|x1, x21
10003055c|bl|#0x10005e260
100030560|cbnz|w0, #0x100030590
100030564|str|x19, [x23, x21, lsl #3]
100030568|mov|w0, #0
100030594|bl|#0x10005d870
100030598|b|#0x100030564
100046c3c|bl|#0x10005cb6c
100046c58|b|#0x10005f780
10005cc48|mov|w1, #0x11
10005cc4c|bl|#0x10005f770
10002feb0|and|w8, w20, #0xfffffffb
10002feb4|cmp|w8, #0x19
10002fec4|mov|w2, #0
10002fec8|bl|#0x10005e260
10002fed8|str|xzr, [x8, x20, lsl #3]
10002d494|mov|w1, #0x16
10002d498|bl|#0x10005e260
100035a00|mov|w1, #0x10
100035a04|bl|#0x10005e260
'''
def verify(s):
 fs=s['kernel_functions']+s['cache_functions']+s['launchd']['ranges'];rows={i['ea']:(i['mnemonic'],i['operands'])for f in fs for i in f['instructions']};count=0
 for line in EXPECTED.strip().splitlines():
  if not line.strip():continue
  a,m,o=line.split('|');a=hex(int(a,16));assert rows[a]==(m,o),(a,rows.get(a));count+=1
 for f in fs:
  raw=bytes.fromhex(f['bytes']);assert h(raw)==f['sha256']and len(raw)==int(f['end'],16)-int(f['start'],16)and instructions(raw,int(f['start'],16))==f['instructions']
 assert [(r['id'],r['stub']['target'],r['reply_size_word1c'])for r in s['MIG_records']]==[(412,'0xfffffe000bd83f84',52),(413,'0xfffffe000bd83eb8',44)]
 assert len(s['kernel_setter_branch_candidates'])==7 and len(s['launchd']['setter_branch_candidates'])==4
 assert s['launchd']['reference']['all_matches']and s['launchd']['reference']['fixups_compared']==2447
 st={r['address']:r['binding']['symbol']for r in s['launchd']['stubs']};assert st['0x10005e260']=='_host_set_special_port'and st['0x10005f500']=='_xpc_dictionary_apply'and st['0x10005f780']=='_xpc_mach_send_get_right'and st['0x10005f770']=='_xpc_mach_send_create_with_disposition'and st['0x10005d870']=='__os_assumes_log'
 assert [r['text']for r in s['launchd']['strings']][:2]==['TaskSpecialPort','HostSpecialPort']
 jump=s['launchd']['owner_query_jump_table'];assert jump['targets'][2]==jump['targets'][3]=='0x100003750'and len(bytes.fromhex(jump['bytes40_hex']))==40
 assert 'Non-system service'in s['launchd']['strings'][3]['text']
 lit={r['address']:bytes.fromhex(r['bytes8_hex'])for r in s['cache_constants']};assert struct.unpack('<II',lit['0x18057d400'])==(0x80001513,52)and lit['0x18057d410'][6:]==bytes([19,0])and struct.unpack('<II',lit['0x18057d470'])==(0,413)
 assert [r['index']for r in s['host_slot_static_words']]==[17,31,34]and s['host_slot_static_words'][-1]['address']=='0xfffffe000cad0358'
 assert all(s[f]is False for f in FLAGS)
 return count
USER_CPP='''#define __MigPackStructs 1
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/mig_errors.h>
#include <stddef.h>
static_assert(sizeof(mach_msg_header_t)==24,"user header");
static_assert(sizeof(mach_msg_port_descriptor_t)==12,"user descriptor");
static_assert(sizeof(__Request__host_set_special_port_t)==52,"set request");
static_assert(offsetof(__Request__host_set_special_port_t,port)==28,"set descriptor");
static_assert(offsetof(__Request__host_set_special_port_t,NDR)==40,"set NDR");
static_assert(offsetof(__Request__host_set_special_port_t,which)==48,"set index");
static_assert(sizeof(__Request__host_get_special_port_t)==40,"get request");
static_assert(offsetof(__Request__host_get_special_port_t,node)==32,"get node");
static_assert(offsetof(__Request__host_get_special_port_t,which)==36,"get index");
static_assert(sizeof(__Reply__host_set_special_port_t)==36,"set reply");
static_assert(offsetof(__Reply__host_set_special_port_t,RetCode)==32,"set result");
static_assert(sizeof(__Reply__host_get_special_port_t)==40,"get complex reply");
static_assert(MACH_MSG_TYPE_COPY_SEND==19,"copy send");
static_assert(MACH_MSG_TYPE_PORT_SEND==17,"received send");
static_assert(MACH_MSG_TYPE_MAKE_SEND_ONCE==21,"reply right");
static_assert(KERN_INVALID_ARGUMENT==4 && KERN_NO_ACCESS==8,"argument/access");
static_assert(KERN_NOT_SUPPORTED==46 && KERN_DENIED==53,"unsupported/denied");
static_assert(MIG_BAD_ARGUMENTS==-304 && MIG_TYPE_ERROR==-300,"MIG checks");
static_assert(HOST_UNFREED_PORT==17 && HOST_FAIRPLAYD_PORT==31,"published slots");
static_assert(HOST_MANAGEDAPPDISTD_PORT==34 && HOST_NODE_PORT==26,"slot names");
'''
KERNEL_CPP='''#include <mach/message.h>
#include <mach/ndr.h>
#include <mach/kern_return.h>
#include <stddef.h>
#pragma pack(push,4)
struct set_request { mach_msg_header_t h; mach_msg_body_t b; mach_msg_port_descriptor_t p; NDR_record_t n; int which; };
struct get_request { mach_msg_header_t h; NDR_record_t n; int node; int which; };
struct set_reply { mach_msg_header_t h; NDR_record_t n; kern_return_t result; };
struct get_reply { mach_msg_header_t h; mach_msg_body_t b; mach_msg_port_descriptor_t p; };
#pragma pack(pop)
static_assert(sizeof(mach_msg_header_t)==32,"kernel header");
static_assert(sizeof(mach_msg_port_descriptor_t)==16,"kernel descriptor");
static_assert(sizeof(set_request)==64,"derived set request");
static_assert(offsetof(set_request,p)==36,"derived port");
static_assert(offsetof(set_request,n)==52,"derived NDR");
static_assert(offsetof(set_request,which)==60,"derived index");
static_assert(sizeof(get_request)==48,"derived get request");
static_assert(offsetof(get_request,node)==40,"derived node");
static_assert(offsetof(get_request,which)==44,"derived index");
static_assert(sizeof(set_reply)==44,"derived set reply");
static_assert(offsetof(set_reply,result)==40,"derived result");
static_assert(sizeof(get_reply)==52,"derived get reply");
'''
def sdk_checks():
 records=[];kh=SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers'
 for code,kernel in[(USER_CPP,False),(KERNEL_CPP,True)]:
  cmd=['clang++','-target','arm64e-apple-macos13','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-']
  if kernel:cmd[1:1]=['-I',str(kh),'-DKERNEL','-fapple-kext','-fno-exceptions','-fno-rtti']
  r=subprocess.run(cmd,input=code,text=True,capture_output=True);assert r.returncode==0,r.stderr;records.append({'argv':cmd,'source':code,'exit_code':r.returncode,'scope':'Generated public SDK types or explicitly derived kernel layout using actual Kernel SDK types; no target execution.'})
 return records
def proofs():
 queries={
 'setter_u32_range':'''(declare-fun v () (_ BitVec 32))
(define-fun t () (_ BitVec 32) (bvsub v #x00000025))
(define-fun carry () Bool (bvuge (bvadd ((_ zero_extend 1) t) (_ bv29 33)) (_ bv4294967296 33)))
(assert (distinct carry (and (bvuge v #x00000008) (bvule v #x00000024))))''',
 'storage_u32_range':'''(declare-fun v () (_ BitVec 32))
(define-fun t () (_ BitVec 32) (bvsub v #x00000008))
(define-fun carry () Bool (bvuge (bvadd ((_ zero_extend 1) t) (_ bv4 33)) (_ bv4294967296 33)))
(assert (distinct (and (bvule v #x00000024) (not carry)) (or (bvule v #x00000003) (and (bvuge v #x00000008) (bvule v #x00000024)))))''',
 'launchd_integer64':'''(declare-fun v () (_ BitVec 64))
(assert (distinct (and (not (bvslt v #x0000000000000008)) (not (bvugt v #x0000000000000024))) (and (bvuge v #x0000000000000008) (bvule v #x0000000000000024))))''',
 'task_slot_helper32':"""(declare-fun v () (_ BitVec 32))
(assert (distinct (and (bvugt v #x00000006) (not (bvsgt v #x0000000b))) (or (and (bvuge v #x00000007) (bvule v #x0000000b)) (bvslt v #x00000000))))""",
 'cleanup_indices32':'''(declare-fun v () (_ BitVec 32))
(assert (distinct (= (bvand v #xfffffffb) #x00000019) (or (= v #x00000019) (= v #x0000001d))))''',
 'port_sentinels64':'''(declare-fun v () (_ BitVec 64))
(assert (distinct (bvult (bvadd v #x0000000000000001) #x0000000000000002) (or (= v #x0000000000000000) (= v #xffffffffffffffff))))'''};out=[]
 for name,body in queries.items():
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr;out.append({'name':name,'query':q,'result':'unsat','scope':'Complete declared scalar domain of a manual translation matched to original instructions; excludes native policy, objects and reachability.'})
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();n=verify(s);negative=[]
 def instruction(t,address,operand):
  rows=t['kernel_functions']+t['cache_functions']+t['launchd']['ranges'];next(i for f in rows for i in f['instructions']if i['ea']==address)['operands']=operand
 for name in['converter_type','setter_range','policy_callback','service_field','failure_cache_branch','descriptor_disposition','MIG_binding','reply_geometry','release_request','native_effect']:
  t=copy.deepcopy(s)
  if name=='converter_type':instruction(t,'0xfffffe000bcf33b8','w8, #0')
  elif name=='setter_range':instruction(t,'0xfffffe000bcf2354','w8, #0x24')
  elif name=='policy_callback':instruction(t,'0xfffffe000c6179d4','x10, [x10, #0x3f8]')
  elif name=='service_field':instruction(t,'0x10005c924','w21, [x20, #0x50]')
  elif name=='failure_cache_branch':instruction(t,'0x100030598','#0x100030568')
  elif name=='descriptor_disposition':next(r for r in t['cache_constants']if r['address']=='0x18057d410')['bytes8_hex']='0000000000001400'
  elif name=='MIG_binding':t['MIG_records'][1]['stub']['target']='0x0'
  elif name=='reply_geometry':t['MIG_records'][1]['reply_size_word1c']=52
  elif name=='release_request':instruction(t,'0xfffffe000bcf22d0','#0xfffffe000bcd044c')
  else:t['host_special_port_set']=True
  try:verify(t)
  except AssertionError:negative.append(name)
  else:raise AssertionError('Alteration accepted: '+name)
 compiled=sdk_checks();proof=proofs();counts={**s['verified_source_counts'],'instruction_assertions':n,'SDK_assertions':sum(r['source'].count('static_assert')for r in compiled),'SDK_compilations':len(compiled),'scalar_queries_unsat':len(proof),'rejected_alterations':len(negative)}
 out={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'verified_counts':counts,'source_recapture_match':True,'SDK_checks':compiled,'proofs':proof,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'rejected_controls':negative,'static_scope':{'original_launchd_slices_examined':1,'runtime_launchd_slice_unknown':True,'reference_source_target_build_equivalence_unknown':True,'native_registration_or_right_balance_unknown':True,'slot34_object_and_RPC700_receiver_unknown':True,'target_execution_or_emulation':False},'all_checks_pass':True,**{f:False for f in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts))
if __name__=='__main__':main()
