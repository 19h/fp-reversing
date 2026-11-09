#!/usr/bin/env python3
"""Static XPC listener, callback, original binding and bounded ABI checks.
No recovered code execution, native message fixture or IDB write.
"""
import copy,json,struct,subprocess
from recover_daemon_xpc_listener import ROOT,P,FLAGS,SDK,CS,sha,h,build,SPECS,COMPLETE,FRAGMENTS,unwrap
PATTERNS='''
listener_create|add|x0, x11, x12
listener_create|mov|x1, x24
listener_create|mov|w2, #1
listener_create|blraa|x10, x17
listener_install|mov|w11, #0x40000000
listener_install|stp|x17, x11, [sp, #0x1c0]
listener_install|adrp|x16, #0x100007000
listener_install|add|x16, x16, #0x78c
listener_install|str|x16, [sp, #0x1d0]
listener_install|stp|x10, x24, [sp, #0x1d8]
listener_install|add|x1, sp, #0x1c0
listener_install|mov|x25, x0
peer_callback|mov|x19, x1
peer_callback|ldr|x1, [x0, #0x20]
peer_callback|mov|x0, x19
peer_callback|mov|w9, #0x40000000
peer_callback|stp|x17, x9, [sp]
peer_callback|adrp|x16, #0x10044d000
peer_callback|add|x16, x16, #0x2fc
peer_callback|str|x16, [sp, #0x10]
peer_callback|stp|x8, x19, [sp, #0x18]
peer_callback|mov|x1, sp
event_callback|str|x0, [sp, #8]
event_callback|str|x1, [sp, #0x10]
event_callback|mov|x0, x1
event_callback|cmp|x0, x8
other_event|ldr|x0, [sp, #0x10]
other_event|cmp|x0, x8
forward_record|ldr|x9, [sp, #8]
forward_record|ldr|x9, [x9, #0x20]
forward_record|str|x9, [sp, #0x48]
forward_record|ldr|x9, [sp, #0x10]
forward_record|stp|x8, x9, [sp, #0x38]
forward_record|str|w9, [sp, #0x50]
forward_record|add|x0, sp, #0x38
forward_record|add|x1, sp, #0x28
cancel_other|ldr|x0, [x8, #0x20]
cancel_invalid|ldr|x0, [x10, #0x20]
message_adapter|mov|x19, x1
message_adapter|ldr|x21, [x19]
message_adapter|sub|x1, x21, #0x50
message_adapter|str|x1, [x20]
message_adapter|mov|x1, x20
message_adapter|ubfiz|x8, x8, #4, #0x10
message_adapter|str|x8, [x19]
protected_entry|mov|x20, x0
protected_entry|ldr|x9, [x1]
protected_entry|add|x9, x9, #0x50
protected_entry|str|x9, [x1]
protected_entry|ldr|w11, [x0, #0x18]
protected_entry|ldp|x9, x19, [x0]
protected_entry|add|x0, sp, #0x3c4
protected_entry|mov|w1, #0
protected_entry|mov|w2, #0x20
protected_entry|add|x1, sp, #0x3c4
protected_entry|mov|x0, x19
protected_entry|ldr|x13, [x20, #0x10]
protected_entry|str|x13, [sp, #0xc0]
'''
EXPECTED_IMPORTS={'listener_create':'_xpc_connection_create_mach_service','listener_set_handler':'_xpc_connection_set_event_handler','listener_activate':'_xpc_connection_activate','peer_target_queue':'_xpc_connection_set_target_queue','peer_set_handler':'_xpc_connection_set_event_handler','peer_resume':'_xpc_connection_resume','event_get_type':'_xpc_get_type','event_type_recheck':'_xpc_get_type','cancel_other':'_xpc_connection_cancel','cancel_invalid':'_xpc_connection_cancel','audit_token':'_xpc_dictionary_get_audit_token','core_get_type':'_xpc_get_type'}

def verify(s):
 assert s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 allranges={**s['complete_functions'],**s['fragments']};rows=[]
 for f in allranges.values():
  bb=bytes.fromhex(f['bytes']);cc=list(CS.disasm(bb,int(f['start'],16)));assert h(bb)==f['sha256']and len(bb)==int(f['end'],16)-int(f['start'],16)==4*len(cc)==4*len(f['instructions'])
  assert[(i['ea'],i['mnemonic'],i['operands'])for i in f['instructions']]==[(hex(i.address),i.mnemonic,i.op_str)for i in cc]
  if f['complete_compiler_body']:assert f['compiler_start']==f['start']and f['next_compiler_start']==f['end']
 for role,a in COMPLETE.items():assert s['complete_functions'][role]['start']==hex(a)
 for role,a in FRAGMENTS.items():assert s['fragments'][role]['start']==hex(a)
 for line in PATTERNS.strip().splitlines():
  role,mn,op=line.split('|');hits=[i for i in allranges[role]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(role,mn,op);rows.extend({'role':role,**i}for i in hits)
 for label,pair,key,add,base,bias in SPECS:
  r=s['banks'][label];l,rr=bytes.fromhex(r['left_bytes']),bytes.fromhex(r['right_bytes']);assert len(l)==len(rr)==256
  outputs=[i^rr[l[i]^key]for i in range(256)];assert outputs==r['results_256']and set(outputs)=={int(r['constant'],16)}
  assert(r['left'],r['right'],int(r['key'],16),int(r['additive'],16))==(hex(pair[0]),hex(pair[1]),key,add)
  assert int(r['slot'],16)==base+8*(add+outputs[0])
 for r in s['calls']:
  bank=s['banks'][r['role']];assert r['slot']==bank['slot']and r['target']==bank['target'];w=int(r['pointer_word'],16)
  assert w>>63 and(w>>32&65535)==r['modifier_u16']and not(w>>48&1)and(w>>49&3)==0
  ii=list(CS.disasm(bytes.fromhex(r['bytes']),int(r['site'],16)-4));assert len(ii)==2 and ii[0].mnemonic=='mov'and ii[0].op_str==f'x17, #{hex(r["modifier_u16"])}'and ii[1].mnemonic=='blraa'
  if r['role']in EXPECTED_IMPORTS:assert r['target']=='libSystem/'+EXPECTED_IMPORTS[r['role']]
 assert s['banks']['message_adapter']['target']=='0x100ba80a8'and s['banks']['protected_entry']['target']=='0x100b27b78'and s['banks']['audit_clear']['target']=='0x10046faf8'
 assert s['service_literal']=={'address':'0x100f23670','bytes':(b'com.apple.fairplayd.xpc\0').hex(),'preceding_byte':'37'}
 for r in s['block_descriptors']:
  assert r['reserved_u64']==0 and r['block_size_bytes']==40 and r['signature']=='v16@?0^v8'and r['signature_bytes']==b'v16@?0^v8\0'.hex()
  bb=bytes.fromhex(r['prefix24_bytes']);assert struct.unpack_from('<QQ',bb)==(0,40)
 assert [r['target']for r in s['branches']]==['0x1002fa1ac','0x1001c8e2c','0x100288b38','0x1001572a8','0x1001bce68','0x100288b38','0x10016b184','0x100b09274','0x100b12c30']
 assert len(s['biased_bank_origins'])==10
 for r in s['biased_bank_origins']:assert (r['fixup']['target']+int(r['bias'],16))&((1<<64)-1)==int(r['result'],16)
 imports={r['symbol']:r for r in s['imports']}
 for name,add in[('__dispatch_main_q',0x44ef996b),('__NSConcreteStackBlock',0x78801bdb),('__xpc_type_error',0x256d84e2),('__xpc_type_dictionary',0x63f36eae),('__xpc_error_connection_invalid',0x4319569e)]:assert imports[name]['total_addend']==add
 assert s['compiler_starts_reference']['starts_compared']==1005 and s['fixup_reference']['catalog_memberships_compared']==61737
 assert len(s['IDA_matches'])==6 and sum(r['bytes_checked']for r in s['IDA_matches'])==2820 and all(r['match']for r in s['IDA_matches'])
 assert all(s[k]is False for k in FLAGS);return rows

def sdk_checks():
 code='''#define OS_OBJECT_USE_OBJC 0
#include <xpc/xpc.h>
#include <xpc/connection.h>
#include <dispatch/dispatch.h>
#include <mach/message.h>
#include <stdint.h>
#include <stddef.h>
#define A(x) static_assert((x), #x)
struct ReconstructedBlock {void* isa;uint32_t flags,reserved;void(*invoke)(void*,void*);const void* descriptor;void* capture;};
struct ReconstructedDescriptorPrefix {uint64_t reserved,size;const char* signature;};
struct ReconstructedMessageRecord {uint64_t encoded;xpc_object_t event;xpc_connection_t peer;uint32_t code,padding_unknown;};
A(sizeof(void*)==8);A(sizeof(xpc_object_t)==8);A(sizeof(xpc_connection_t)==8);A(sizeof(dispatch_queue_t)==8);
A(sizeof(ReconstructedBlock)==40);A(offsetof(ReconstructedBlock,invoke)==16);A(offsetof(ReconstructedBlock,descriptor)==24);A(offsetof(ReconstructedBlock,capture)==32);
A(sizeof(ReconstructedDescriptorPrefix)==24);A(sizeof(ReconstructedMessageRecord)==32);A(alignof(ReconstructedMessageRecord)==8);
A(offsetof(ReconstructedMessageRecord,event)==8);A(offsetof(ReconstructedMessageRecord,peer)==16);A(offsetof(ReconstructedMessageRecord,code)==24);
A(sizeof(audit_token_t)==32);A(alignof(audit_token_t)==4);A(XPC_CONNECTION_MACH_SERVICE_LISTENER==1);
A(__is_same(decltype(&xpc_connection_create_mach_service),xpc_connection_t(*)(const char*,dispatch_queue_t,uint64_t)));
A(__is_same(decltype(&xpc_connection_set_event_handler),void(*)(xpc_connection_t,xpc_handler_t)));
A(__is_same(decltype(&xpc_connection_set_target_queue),void(*)(xpc_connection_t,dispatch_queue_t)));
A(__is_same(decltype(&xpc_get_type),xpc_type_t(*)(xpc_object_t)));
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fblocks','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Public XPC/dispatch types, listener flag and audit-token geometry; block/descriptor/message records explicitly reconstructed, not canonical private type declarations.'}

def proofs():
 q1='''(declare-fun r () (_ BitVec 32))
(assert (= (bvand r (_ bv7 32)) (_ bv0 32)))
(define-fun callback_expr () (_ BitVec 32) (bvxor (bvadd (bvor r #xd07cf28b) (bvor #x2f830d74 (bvnot r))) #x374e20e8))
(define-fun code () (_ BitVec 32) (bvadd (bvmul callback_expr #xba209ef7) #x00003a8a #x00003d16))
(define-fun core_expr () (_ BitVec 32) (bvxor (bvadd (bvsub (bvor r #x2d0e36f9) r) (bvand r #xd2f1c906)) #xca3ce49b))
(define-fun selector () (_ BitVec 32) (bvsub code (bvmul core_expr #xba209ef7)))
(assert (distinct selector #x000077a0))'''
 q2='''(declare-fun seed () (_ BitVec 64))
(declare-fun result () (_ BitVec 32))
(define-fun hint () (_ BitVec 64) (bvand (bvadd (bvshl (bvlshr (bvadd (bvmul seed (_ bv11973 64)) (_ bv1 64)) (_ bv60 64)) (_ bv4 64)) (_ bv31 64)) (_ bv496 64)))
(define-fun delta () (_ BitVec 64) (bvshl ((_ zero_extend 48) ((_ extract 15 0) (bvsub result ((_ extract 31 0) seed)))) (_ bv4 64)))
(assert (or (bvult hint (_ bv16 64)) (bvugt hint (_ bv256 64)) (distinct (bvand hint (_ bv15 64)) (_ bv0 64)) (bvugt delta (_ bv1048560 64)) (distinct (bvand delta (_ bv15 64)) (_ bv0 64))))'''
 decl='(declare-fun base () (_ BitVec 64))\n'
 terms=[]
 for add in[0x44ef996b,0x78801bdb,0x256d84e2,0x63f36eae,0x4319569e]:terms.append(f'(distinct (bvadd (bvadd base (_ bv{add} 64)) (_ bv{(-add)&((1<<64)-1)} 64)) base)')
 q3=decl+'(assert (or '+' '.join(terms)+'))'
 out=[]
 for name,body in[('aligned_record_decodes_internal_selector77a0',q1),('adapter_hint_and_delta_ranges',q2),('five_imported_data_addend_cancellations',q3)]:
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Manually instruction-matched scalar identities under explicit alignment/width assumptions; no native mapping, pointer validity, control-flow reachability, memory-alias or protected-policy proof.'})
 return out

def event_models():
 out=[]
 for error in[False,True]:
  for dictionary in[False,True]:
   for invalid in[False,True]:
    first=0xa777^(0xa0*int(not error))
    if error:
     target=0x68f4|(9*int(invalid));effect='cancel'if invalid else'forward'
    else:target=0xab7f^(0xda*int(not dictionary));effect='forward'if dictionary else'cancel'
    assert first==(0xa777 if error else 0xa7d7)
    assert target==({'cancel':0x68fd,'forward':0x68f4}[effect]if error else{'cancel':0xaba5,'forward':0xab7f}[effect])
    out.append({'first_type_is_error':error,'second_type_is_dictionary':dictionary,'event_is_invalid_error':invalid,'first_index':hex(first),'second_index':hex(target),'selected_effect':effect})
 return{'cases':out,'scope':'Eight Boolean combinations of the selected classifier inputs; second type query occurs only on the non-error path. Analyst-written model, no recovered-code execution or native XPC delivery.'}

def alterations(s):
 def bank(q):
  r=q['banks']['listener_create'];b=bytearray.fromhex(r['left_bytes']);b[0]^=1;r['left_bytes']=b.hex()
 def name(q):q['service_literal']['bytes']=(b'7com.apple.fairplayd.xpc\0').hex()
 def flags(q):next(i for i in q['fragments']['listener_create']['instructions']if i['ea']=='0x1000935dc').update(operands='w2, #0')
 def size(q):q['block_descriptors'][0]['block_size_bytes']=32
 def callback(q):next(i for i in q['complete_functions']['peer_callback']['instructions']if i['ea']=='0x1000079b4').update(operands='x16, x16, #0x300')
 def target(q):q['banks']['protected_entry']['target']='0x100430ac8'
 def audit(q):next(i for i in q['fragments']['protected_entry']['instructions']if i['ea']=='0x100b27e34').update(operands='w2, #0x10')
 def scope(q):q['native_peer_identity_proved']=True
 out=[]
 for label,change in[('bank_byte',bank),('service_literal_start',name),('listener_flag',flags),('block_size',size),('event_callback',callback),('wrong_bank_callee',target),('audit_extent',audit),('native_peer_claim',scope)]:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'alteration':label,'rejected':True})
  else:raise AssertionError('Accepted altered evidence '+label)
 return out

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();neg=alterations(s);models=event_models()
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':rows,'SDK_checks':sdk,'proofs':pr,'alterations':neg,'event_models':models,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'classifier_model_cases':len(models['cases']),'rejected_evidence_alterations':len(neg)},'all_checks_pass':True,
  'static_scope':'Conditional original main listener creation/install; complete compiler spans for peer/event callbacks, message stack adapter and fill helper; selected error/dictionary/cancel/forward continuations; protected entry record/selector and audit acquisition prefix. Native startup/peer/authorization, full application control/alias flow and payload/reply semantics remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
