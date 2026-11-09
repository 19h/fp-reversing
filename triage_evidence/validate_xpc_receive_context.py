#!/usr/bin/env python3
"""Original ingress/context/audit instructions and bounded scalar verification."""
import copy,json,struct,subprocess,itertools
from recover_xpc_receive_context import *
PATTERNS='''
unpack|0x184b77e40|bl|#0x184b9415c
unpack|0x184b77e44|tbz|w0, #0, #0x184b77e74
unpack|0x184b77f28|bl|#0x184b720ec
unpack|0x184b77f58|ldur|q0, [x21, #0x14]
unpack|0x184b77f5c|ldur|q1, [x21, #0x24]
unpack|0x184b77f60|stur|q1, [x20, #0x78]
unpack|0x184b77f64|stur|q0, [x20, #0x68]
receive|0x184b7213c|bl|#0x184b89370
receive|0x184b7216c|ldp|w9, w8, [x19, #4]
receive|0x184b72170|str|wzr, [x19, #8]
receive|0x184b72180|csel|w11, w11, wzr, ne
receive|0x184b72190|csel|w10, w13, wzr, eq
receive|0x184b72194|orr|w10, w10, w11
receive|0x184b72198|stp|w8, wzr, [sp, #0x10]
receive|0x184b7219c|str|x23, [sp, #0x18]
receive|0x184b721a0|strb|w10, [sp, #0x20]
receive|0x184b721a4|stur|wzr, [sp, #0x21]
receive|0x184b721a8|str|wzr, [sp, #0x24]
receive|0x184b721ac|add|x8, x9, #3
receive|0x184b721b0|and|x8, x8, #0x1fffffffc
receive|0x184b721b8|ldur|q0, [x9, #0x14]
receive|0x184b721bc|ldur|q1, [x9, #0x24]
receive|0x184b721c0|stp|q0, q1, [sp, #0x30]
receive|0x184b721c4|str|xzr, [sp, #0x28]
receive|0x184b721d4|bl|#0x184b789f0
receive|0x184b721e0|bl|#0x184b723dc
receive|0x184b7221c|ldr|w2, [x21, #0xd0]
receive|0x184b72300|bl|#0x184b725f4
receive|0x184b7233c|str|x21, [x20]
receive|0x184b72348|bl|#0x184b72c90
validate_header|0x184b89378|add|w8, w9, w8
validate_header|0x184b8937c|ror|w8, w8, #0x1c
validate_header|0x184b89380|cmp|w8, #2
validate_header|0x184b893a4|ccmp|w8, #0x12, #4, ne
validate_header|0x184b893b8|cbz|w8, #0x184b893ac
graph|0x184b72620|cmp|w2, #4
graph|0x184b726bc|ldr|w11, [x11, w2, uxtw #2]
graph|0x184b726cc|cmp|w10, #5
graph|0x184b726f4|cmp|w8, #0xf, lsl #12
graph|0x184b72858|and|w8, w8, #0xfffffffc
graph|0x184b7285c|orr|w8, w8, #1
graph|0x184b728e8|ldr|q0, [x19]
graph|0x184b728ec|stur|q0, [x20, #0x58]
graph|0x184b728f0|stp|xzr, xzr, [x19]
graph|0x184b728f4|ldp|x8, x9, [x19, #0x10]
graph|0x184b728f8|stp|xzr, xzr, [x19, #0x10]
graph|0x184b728fc|stp|x8, x9, [x20, #0x68]
graph|0x184b72900|ldp|q0, q1, [x19, #0x20]
graph|0x184b72904|stur|q0, [x20, #0x78]
graph|0x184b72908|stur|q1, [x20, #0x88]
set_connection|0x184b78a24|bl|#0x184b6d638
set_connection|0x184b78a34|bl|#0x1880874a0
set_connection|0x184b78a38|ldr|x0, [x20, #0x18]
set_connection|0x184b78a40|bl|#0x184b6d6c4
set_connection|0x184b78a44|str|x19, [x20, #0x18]
dictionary_audit|0x184b72ba8|ldur|q0, [x20, #0x78]
dictionary_audit|0x184b72bac|ldur|q1, [x20, #0x88]
dictionary_audit|0x184b72bbc|ldur|q0, [x20, #0x58]
dictionary_audit|0x184b72bc0|ldur|q1, [x20, #0x68]
dictionary_audit|0x184b72bc4|stp|q0, q1, [x19]
dictionary_audit|0x184b72bd0|stp|q0, q0, [x19]
dictionary_audit|0x184b72bd4|str|wzr, [x19, #0x14]
connection_audit|0x184b82f7c|ldur|q0, [x20, #0x68]
connection_audit|0x184b82f80|ldur|q1, [x20, #0x78]
peer_requirement|0x184b94194|ldr|w8, [x0, #0x18]
peer_requirement|0x184b94198|cmp|w8, #2
peer_requirement|0x184b941bc|ldr|w8, [x19, #0x7c]
peer_requirement|0x184b941c0|ldr|w9, [x22, #0x28]
peer_requirement|0x184b941c4|cmp|w8, w9
peer_requirement|0x184b941cc|ldr|w23, [x19, #0x84]
peer_requirement|0x184b941d0|ldr|w22, [x22, #0x30]
peer_requirement|0x184b941dc|cmp|w23, w22
peer_requirement|0x184b941e4|ldr|x8, [x19, #0xf0]
peer_requirement|0x184b94218|smov|x21, v0.s[0]
peer_requirement|0x184b9421c|sxtw|x22, w23
peer_requirement|0x184b9422c|bl|#0x188087a20
peer_requirement|0x184b94310|ldr|x9, [x8, #0x18]!
peer_requirement|0x184b94314|ldur|x0, [x8, #-8]
peer_requirement|0x184b94324|add|x1, sp, #0x10
peer_requirement|0x184b94328|mov|x2, x20
peer_requirement|0x184b94334|blrab|x9, x17
peer_requirement|0x184b94338|cbz|w0, #0x184b942c4
peer_requirement|0x184b9434c|mov|w3, #1
peer_requirement|0x184b94350|bl|#0x188087a40
destroy_received|0x184b72ca8|bl|#0x184b72cdc
destroy_request|0x184b72d00|tbz|w8, #0, #0x184b72d38
destroy_request|0x184b72d44|bl|#0x18806cf40
destroy_request|0x184b72d54|bl|#0x1880862f0
destroy_request|0x184b72d84|b|#0x184ba0af0
mach_event|0x184b783fc|bl|#0x184b77dfc
mach_event|0x184b78410|bl|#0x184b79fb8
call_handler|0x184b79fd8|cmp|w8, #1
call_handler|0x184b7a01c|ldr|x8, [x16, #0x10]!
call_handler|0x184b7a020|mov|x1, x19
call_handler|0x184b7a024|blraa|x8, x16
call_handler|0x184b7a040|mov|x0, x19
call_handler|0x184b7a04c|blrab|x8, x17
audit_pid|0x20638d720|ldr|w0, [x0, #0x14]
audit_pidversion|0x20638d750|ldr|w0, [x0, #0x1c]
install_handler|0x184b75ddc|bl|#0x184b75fc8
install_handler|0x184b75de8|add|x16, x19, #0x20
install_handler|0x184b75df4|pacdb|x17, x16
install_handler|0x184b75e3c|mov|w23, #1
install_handler|0x184b75e54|caspl|x2, x3, x22, x23, [x17]
install_handler|0x184b75f94|b|#0x1880876b0
'''
def verify(s):
 assert s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a'
 for role,(path,a)in FUNCTIONS.items():
  f=s['functions'][role];bb=bytes.fromhex(f['bytes']);ii=list(CS.disasm(bb,a))
  assert f['start']==hex(a)and f['library']==path and h(bb)==f['sha256']
  assert len(bb)==int(f['end'],16)-a==4*len(ii)
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]
 rows=[]
 for line in PATTERNS.strip().splitlines():
  role,pc,mn,op=line.split('|');hits=[i for i in s['functions'][role]['instructions']if i['ea']==pc]
  assert len(hits)==1 and(hits[0]['mnemonic'],hits[0]['operands'])==(mn,op),(role,pc)
  rows.append({'role':role,**hits[0]})
 for a,(path,name)in STUBS.items():
  q=s['stubs'][hex(a)];assert q['library']==path and q['exact_export']==name and q['pointer']['chain_membership_verified']
  assert any(n['name']==name and n['n_value']==q['pointer']['target']for n in q['original_nlist'])
  w=int(q['pointer']['raw_word'],16);assert int(q['pointer']['target'],16)==int(q['pointer']['value_add'],16)+(w&0x3ffffffff)
  assert q['pointer']['authenticated']and w>>63
 census=s['direct_call_census'];assert not census['indirect_coverage']and len(census['calls'])==3
 assert{q['site']for q in census['calls']}=={'0x184b776cc','0x184b783fc','0x184b7b914'}
 assert all(s[k]is False for k in FLAGS)and not s['daemon']['native_context_producer_observed']
 return rows
def sdk_checks():
 code='''#define OS_OBJECT_USE_OBJC 0
#include <xpc/xpc.h>
#include <mach/message.h>
#include <bsm/libbsm.h>
#include <stddef.h>
#define A(x) static_assert((x),#x)
A(sizeof(void*)==8);A(sizeof(size_t)==8);A(sizeof(mach_port_t)==4);A(sizeof(audit_token_t)==32);
A(sizeof(mach_msg_header_t)==24);A(sizeof(mach_msg_audit_trailer_t)==52);
A(offsetof(mach_msg_header_t,msgh_remote_port)==8);A(offsetof(mach_msg_header_t,msgh_size)==4);
A(offsetof(mach_msg_audit_trailer_t,msgh_audit)==20);A(offsetof(audit_token_t,val[5])==20);A(offsetof(audit_token_t,val[7])==28);
A(MACH_MSG_TYPE_MOVE_SEND_ONCE==18);A(MACH_MSG_TRAILER_FORMAT_0==0);
A(__is_same(decltype(&audit_token_to_pid),pid_t(*)(audit_token_t)));
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True)
 assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang')}
def proofs():
 qs=[('header_classifier_all32_IDs_names_dispositions','''(declare-fun id () (_ BitVec 32)) (declare-fun p () (_ BitVec 32)) (declare-fun bits () (_ BitVec 32))
(define-fun r () (_ BitVec 32) ((_ rotate_right 28) (bvadd id #xf0000000)))
(define-fun common () Bool (or (= p #x00000000) (= (bvand bits #x0000001f) #x00000012)))
(define-fun actual () Bool (ite (bvult r #x00000002) common (ite (= r #x00000002) (= p #x00000000) (and (= r #x00000003) common))))
(define-fun expected () Bool (or (and (or (= id #x10000000) (= id #x20000000) (= id #x40000000)) common) (and (= id #x30000000) (= p #x00000000))))
(assert (distinct actual expected))'''),
 ('trailer_rounding_u32_to_u64','''(declare-fun n () (_ BitVec 32))
(define-fun w () (_ BitVec 64) ((_ zero_extend 32) n))
(define-fun rounded () (_ BitVec 64) (bvand (bvadd w #x0000000000000003) #x00000001fffffffc))
(assert (or (bvult rounded w) (bvugt (bvsub rounded w) #x0000000000000003)
 (distinct (bvand rounded #x0000000000000003) #x0000000000000000)
 (bvugt rounded #x0000000100000000)))'''),
 ('ordinary_context_port_and_flags','''(declare-fun p () (_ BitVec 32)) (declare-fun b () Bool) (declare-fun sync () Bool)
(define-fun flags () (_ BitVec 32) (bvor (ite b #x00000002 #x00000000) (ite sync #x00000004 #x00000000)))
(define-fun first () (_ BitVec 64) (concat #x00000000 p))
(assert (or (distinct (bvand flags #x00000001) #x00000000)
 (distinct (distinct first #x0000000000000000) (distinct p #x00000000))
 (distinct ((_ extract 31 0) first) p)))'''),
 ('peer_requirement_signed_key_and_identity_gate','''(declare-fun kind () (_ BitVec 32))
(declare-fun pid () (_ BitVec 32)) (declare-fun pv () (_ BitVec 32))
(declare-fun cp () (_ BitVec 32)) (declare-fun cv () (_ BitVec 32))
(declare-fun req () Bool) (declare-fun hit () Bool) (declare-fun callback () Bool)
(define-fun identity () Bool (ite (= kind #x00000002) (and (= pid cp) (= pv cv)) true))
(define-fun admit () Bool (and identity (ite req (or hit callback) true)))
(define-fun pk () (_ BitVec 64) ((_ sign_extend 32) pid))
(define-fun vk () (_ BitVec 64) ((_ sign_extend 32) pv))
(assert (or (distinct admit (and (or (distinct kind #x00000002) (and (= pid cp) (= pv cv))) (or (not req) hit callback)))
 (distinct ((_ extract 31 0) pk) pid) (distinct ((_ extract 31 0) vk) pv)))''')]
 out=[]
 for name,body in qs:
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True)
  assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Source-matched scalar identity; no native token provenance, policy, rights, buffer validity or delivery proof.'})
 return out
def models():
 ids=sorted({x for base in[0,0x10000000,0x20000000,0x30000000,0x40000000,0xffffffff]for x in[(base-1)&0xffffffff,base,(base+1)&0xffffffff]});headers=[]
 for mid,p,disp in itertools.product(ids,[0,1,0x10203,0x80000000,0xffffffff],range(32)):
  r=(((mid-0x10000000)&0xffffffff)<<4|(((mid-0x10000000)&0xffffffff)>>28))&0xffffffff
  common=p==0 or disp==18;actual=common if r<2 else p==0 if r==2 else common if r==3 else False
  expected=(mid in[0x10000000,0x20000000,0x40000000]and common)or(mid==0x30000000 and p==0);assert actual==expected
  headers.append({'id_u32':mid,'name_u32':p,'disposition_u5':disp,'header_predicate':actual})
 contexts=[]
 for p,b,sync in itertools.product([0,1,0x10203,0xffffffff],[False,True],[False,True]):
  voucher=0x1122334455667788;peer=0xaabbccddeeff0011;token=bytes(range(32))
  ctx=struct.pack('<IIQ',p,0,voucher)+bytes([(2 if b else 0)|(4 if sync else 0)])+bytes(7)+struct.pack('<Q',peer)+token
  assert len(ctx)==64
  dictionary=bytearray(0x100);dictionary[0x58:0x98]=ctx
  consumed=bytes(32)+ctx[32:];reply_context=bytes(dictionary[0x58:0x70])
  assert int.from_bytes(reply_context[:8],'little')==p and not(reply_context[16]&1)
  assert dictionary[0x78:0x98]==token and int.from_bytes(dictionary[0x70:0x78],'little')==peer
  contexts.append({'name_u32':p,'caller_flag':b,'sync_ID':sync,'temporary64':ctx.hex(),
   'temporary_after_move':consumed.hex(),'dictionary_reply_context24':reply_context.hex(),'dictionary_audit32':token.hex()})
 gates=[]
 for kind2,pm,vm,req,hit,cb in itertools.product([False,True],repeat=6):
  identity=(not kind2)or(pm and vm);accepted=identity and((not req)or hit or cb)
  gates.append({'kind2':kind2,'PID_equal':pm,'PIDversion_equal':vm,'requirement_present':req,'cache_hit':hit,'callback_nonzero':cb,'accepted':accepted,'callback_reached':identity and req and not hit})
 rounds=[{'size_u32':n,'rounded_extent_u64':(n+3)&0x1fffffffc}for n in[0,1,2,3,4,23,24,25,0xfffffffc,0xfffffffd,0xfffffffe,0xffffffff]]
 getters=[]
 for mode in range(4):
  data=bytes((j*7+3)&255 for j in range(256));out=data[0x78:0x98]if mode==1 else data[0x58:0x78]if mode==3 else bytes([255])*20+bytes(4)+bytes([255])*8
  assert len(out)==32;getters.append({'mode':mode,'audit_bytes':out.hex(),'source_offset':0x78 if mode==1 else 0x58 if mode==3 else None,'sentinel_PID_zero':mode in[0,2]})
 return{'header_cases':headers,'context_cases':contexts,'policy_cases':gates,'rounding_cases':rounds,'getter_cases':getters,
  'scope':'Finite scalar/byte models only; no recovered code, native message or authorization callback executes.'}
def patch(q,role,pc,mn,op):
 i=next(i for i in q['functions'][role]['instructions']if i['ea']==pc);i.update(mnemonic=mn,operands=op)
def alterations(s):
 changes=[('wrong_header_clear_width',lambda q:patch(q,'receive','0x184b72170','str','xzr, [x19, #8]')),
  ('wrong_audit_source',lambda q:patch(q,'receive','0x184b721b8','ldur','q0, [x9, #0x18]')),
  ('missing_context_clear',lambda q:patch(q,'graph','0x184b728f0','nop','')),
  ('wrong_getter_mode1_offset',lambda q:patch(q,'dictionary_audit','0x184b72ba8','ldur','q0, [x20, #0x58]')),
  ('unsigned_PIDversion_key',lambda q:patch(q,'peer_requirement','0x184b9421c','mov','w22, w23')),
  ('wrong_map_binding',lambda q:q['stubs']['0x188087a20'].__setitem__('exact_export','_os_map_64_find')),
  ('claimed_indirect_census',lambda q:q['direct_call_census'].__setitem__('indirect_coverage',True)),
  ('invented_native_authentication',lambda q:q.__setitem__('native_authorization_proved',True))]
 out=[]
 for name,change in changes:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'name':name,'rejected':True});continue
  raise AssertionError(name)
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();m=models();al=alterations(s)
 counts={**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,
  'scalar_queries_unsat':len(pr),**{n:len(m[n])for n in['header_cases','context_cases','policy_cases','rounding_cases','getter_cases']},'rejected_evidence_alterations':len(al)}
 result={'generator_sha256':sha(__file__),'source_sha256':sha(ROOT/(P+'_source.json')),'source_recapture_match':True,
  'instruction_assertions':rows,'SDK_checks':sdk,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'proofs':pr,'models':m,'alterations':al,'verified_counts':counts,'all_checks_pass':True,
  'static_scope':'Conditional ordinary Mach event/unpack/received-context construction, header predicate and ownership transfer, trailer-to-dictionary/connection audit copies, raw getters and kind2 PID/PIDversion plus configured requirement gates; event block delivery and source cleanup. Full field deserialization, actual kernel trailer provenance, native callback/policy/namespace/right/lifetime/delivery and daemon-kext success remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
