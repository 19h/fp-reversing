#!/usr/bin/env python3
"""Static original instruction, SDK, scalar and finite-model verification."""
import copy,json,struct,subprocess
from recover_xpc_reply_transport import *
PATTERNS='''
create_reply|0x184b80854|ldr|w8, [x19, #0x1c]
create_reply|0x184b80858|and|w8, w8, #3
create_reply|0x184b8085c|cmp|w8, #1
create_reply|0x184b80868|ldr|x8, [x21, #0x58]!
create_reply|0x184b80878|mov|w1, #0x80
create_reply|0x184b80890|and|w8, w8, #0xfffffffc
create_reply|0x184b80894|orr|w8, w8, #2
create_reply|0x184b8089c|ldr|q0, [x21]
create_reply|0x184b808a0|str|q0, [x0, #0x60]
create_reply|0x184b808a4|ldr|x8, [x21, #0x10]
create_reply|0x184b808a8|str|x8, [x0, #0x70]
create_reply|0x184b808ac|stp|xzr, xzr, [x21]
create_reply|0x184b808b0|str|xzr, [x21, #0x10]
create_reply|0x184b808b4|ldr|x0, [x19, #0x70]
create_reply|0x184b808bc|bl|#0x184b6d638
create_reply|0x184b808c0|str|x0, [x20, #0x58]
set_data|0x184b74498|mov|x0, x2
set_data|0x184b7449c|mov|x1, x3
set_data|0x184b744a0|bl|#0x184b6e0fc
set_data|0x184b744b8|bl|#0x184b96068
set_data|0x184b744dc|b|#0x184b6d6c4
data_create|0x184b6e124|cbz|x1, #0x184b6e1d4
data_create|0x184b6e128|mov|x19, x1
data_create|0x184b6e12c|mov|x20, x0
data_create|0x184b6e130|cbz|x0, #0x184b6e2f8
data_create|0x184b6e138|cmp|x19, #4, lsl #12
data_create|0x184b6e13c|b.ls|#0x184b6e1f0
data_create|0x184b6e180|bl|#0x18806cbd0
data_create|0x184b6e190|mov|x0, x21
data_create|0x184b6e194|mov|x1, x20
data_create|0x184b6e198|mov|x2, x19
data_create|0x184b6e19c|bl|#0x18806ca70
data_create|0x184b6e1b8|bl|#0x188087560
data_create|0x184b6e1dc|bl|#0x184b6e30c
data_create|0x184b6e1f8|bl|#0x188087570
data_create|0x184b6e20c|ldr|x0, [sp, #0x28]
data_create|0x184b6e210|mov|x1, x20
data_create|0x184b6e214|mov|x2, x19
data_create|0x184b6e218|bl|#0x18806ca70
data_wrap|0x184b6e368|str|x0, [x20, #0x28]
data_wrap|0x184b6e36c|str|x19, [x20, #0x18]
data_wrap|0x184b6e374|bl|#0x18806d1a0
set_value|0x184b960e0|b|#0x184b6d310
insert|0x184b6d520|mov|x0, x20
insert|0x184b6d524|bl|#0x184b6d638
insert|0x184b6d528|str|x0, [x25, #0x10]
send_message|0x184b79094|mov|x0, x20
send_message|0x184b79098|mov|x1, x19
send_message|0x184b7909c|mov|w2, #0
send_message|0x184b790a0|bl|#0x184b77790
send_message|0x184b790c8|bl|#0x184b79150
extract_reply_port|0x184b70cf4|mov|w8, #0x58
extract_reply_port|0x184b70cfc|mov|w8, #0x60
extract_reply_port|0x184b70d04|ldrb|w8, [x9, #0x10]
extract_reply_port|0x184b70d08|tbnz|w8, #0, #0x184b70d18
extract_reply_port|0x184b70d0c|ldr|w0, [x9]
extract_reply_port|0x184b70d10|str|wzr, [x9]
get_remote|0x184b778b4|ldr|x0, [x19, #0x70]
get_remote|0x184b778bc|ldr|x0, [x19, #0x58]
pack_message|0x184b777b8|bl|#0x184b70cdc
pack_message|0x184b777c4|bl|#0x184b77864
pack_message|0x184b777d0|cmp|x0, x22
pack_message|0x184b777d4|b.ne|#0x184b77854
pack_message|0x184b7780c|bl|#0x184b70d20
pack_message|0x184b77818|str|w8, [x0, #0x14]
pack_message|0x184b7781c|mov|w8, #0x12
pack_message|0x184b77824|mov|w8, #0x13
pack_message|0x184b77834|str|w8, [x0]
pack_message|0x184b77838|stp|w20, w19, [x0, #8]
serializer|0x184b71074|ldr|x8, [x9, #8]
serializer|0x184b71078|str|xzr, [x9, #8]
serializer|0x184b71084|str|x8, [x20, #0x80]
serializer|0x184b71118|stp|w9, w22, [x21]
serializer|0x184b71124|stur|q0, [x21, #8]
enqueue|0x184b791a8|ldrb|w8, [x0, #1]
enqueue|0x184b791ac|tst|w8, #0x1f
enqueue|0x184b791b0|b.eq|#0x184b791f4
enqueue|0x184b791ec|bl|#0x188087700
enqueue|0x184b79218|bl|#0x1880876f0
send_result|0x18552ea8c|bl|#0x18552e844
send_result|0x18552eac4|mov|w9, #0xa
dispatch_send|0x18552e944|and|w8, w8, #0x1f
dispatch_send|0x18552e94c|cmp|w8, #0x12
dispatch_send|0x18552e958|ldr|w8, [x24, #0x58]
dispatch_send|0x18552e960|ldr|w8, [x20, #0x50]
dispatch_send|0x18552e978|bl|#0x185532504
dispatch_send|0x18552e9c8|bl|#0x185533200
dispatch_emit|0x185532580|cmp|w23, #0x12
dispatch_emit|0x1855325ac|b|#0x1855327a8
dispatch_emit|0x1855325f0|str|w8, [x22, #8]
dispatch_emit|0x185532824|stp|x22, xzr, [sp, #0x60]
dispatch_emit|0x185532828|stp|w9, wzr, [sp, #0x70]
dispatch_emit|0x185532838|stp|x8, xzr, [sp, #0x78]
dispatch_emit|0x18553283c|stp|w9, wzr, [sp, #0x88]
dispatch_emit|0x18553284c|ldr|x3, [x22, #8]
dispatch_emit|0x185532850|ldp|w11, w12, [x22, #0x10]
dispatch_emit|0x185532864|orr|x4, x11, x12, lsl #32
dispatch_emit|0x185532870|orr|x1, x8, x10
dispatch_emit|0x185532874|orr|x2, x9, #0x200000000
dispatch_emit|0x185532878|mov|x7, #0
dispatch_emit|0x18553287c|bl|#0x18808c4f0
mach2|0x18055a8dc|bl|#0x180547c18
mach2_trap|0x180547c18|mov|x16, #-0x2f
mach2_trap|0x180547c1c|svc|#0x80
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
  role,pc,mn,op=line.split('|');f=s['functions'][role]
  hits=[i for i in f['instructions']if i['ea']==pc];assert len(hits)==1 and(hits[0]['mnemonic'],hits[0]['operands'])==(mn,op),(role,pc)
  rows.append({'role':role,**hits[0]})
 for a,(path,name)in STUBS.items():
  q=s['stubs'][hex(a)];assert q['library']==path and q['exact_export']==name
  assert any(n['name']==name for n in q['original_nlist'])and q['pointer']['chain_membership_verified']
  w=int(q['pointer']['raw_word'],16);assert int(q['pointer']['target'],16)==int(q['pointer']['value_add'],16)+(w&0x3ffffffff)
  assert q['pointer']['authenticated']and w>>63
 for a,(path,name)in DATAPTRS.items():assert s['data_pointers'][hex(a)]['original_symbol']==name
 assert bytes.fromhex(s['header_initializer']['bytes'])==struct.pack('<4I',0,0,0,0x10000000)
 assert all(s[k]is False for k in FLAGS)and not s['daemon']['paired_native_cache_observed']
 return rows
def sdk_checks():
 code='''#define OS_OBJECT_USE_OBJC 0
#include <xpc/xpc.h>
#include <xpc/connection.h>
#include <mach/message.h>
#include <stddef.h>
#define A(x) static_assert((x),#x)
A(sizeof(void*)==8);A(sizeof(size_t)==8);A(sizeof(mach_port_t)==4);A(sizeof(mach_msg_header_t)==24);
A(offsetof(mach_msg_header_t,msgh_bits)==0);A(offsetof(mach_msg_header_t,msgh_size)==4);
A(offsetof(mach_msg_header_t,msgh_remote_port)==8);A(offsetof(mach_msg_header_t,msgh_local_port)==12);
A(offsetof(mach_msg_header_t,msgh_voucher_port)==16);A(offsetof(mach_msg_header_t,msgh_id)==20);
A(MACH_MSG_TYPE_MOVE_SEND_ONCE==18);A(MACH_MSG_TYPE_COPY_SEND==19);A(MACH_MSGH_BITS_COMPLEX==0x80000000u);
A(MACH_SEND_MSG==1);A(MACH_MSGH_BITS(18,0)==18);
A(__is_same(decltype(&xpc_data_create),xpc_object_t(*)(const void*,size_t)));
A(__is_same(decltype(&xpc_dictionary_set_data),void(*)(xpc_object_t,const char*,const void*,size_t)));
A(__is_same(decltype(&xpc_connection_send_message),void(*)(xpc_connection_t,xpc_object_t)));
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True)
 assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang')}
def proofs():
 qs=[('reply_mode_and_header_dispositions','''(declare-fun f () (_ BitVec 32)) (declare-fun p () (_ BitVec 32)) (declare-fun c () Bool)
(define-fun rf () (_ BitVec 32) (bvor (bvand f #xfffffffc) #x00000002))
(define-fun bits () (_ BitVec 32) (bvor (ite c #x80000000 #x00000000) (ite (= p #x00000000) #x00000013 #x00000012)))
(assert (or (distinct (bvand rf #x00000003) #x00000002)
 (distinct (bvand rf #xfffffffc) (bvand f #xfffffffc))
 (distinct (bvand bits #x0000001f) (ite (= p #x00000000) #x00000013 #x00000012))
 (distinct (bvand bits #x00001f00) #x00000000)))'''),
 ('reply_port_zeroing_is_four_bytes','''(declare-fun ctx () (_ BitVec 192))
(define-fun p () (_ BitVec 32) ((_ extract 31 0) ctx))
(define-fun consumed () (_ BitVec 192) (bvand ctx #xffffffffffffffffffffffffffffffffffffffff00000000))
(assert (or (distinct ((_ extract 31 0) consumed) #x00000000)
 (distinct ((_ extract 191 32) consumed) ((_ extract 191 32) ctx))
 (distinct (concat ((_ extract 191 32) ctx) p) ctx)))'''),
 ('direct_reply_vector_slots_all_names_and_sizes','''(declare-fun p () (_ BitVec 32)) (declare-fun n () (_ BitVec 32))
(declare-fun d () (_ BitVec 32)) (declare-fun c () Bool) (declare-fun thread () Bool)
(define-fun bits () (_ BitVec 32) (bvor (ite c #x80000000 #x00000000) #x00000012))
(define-fun opt () (_ BitVec 32) (bvor #x00000001 (ite thread #x00040000 #x00000000)))
(define-fun x1 () (_ BitVec 64) (bvor ((_ sign_extend 32) opt) #x0000000500000000))
(define-fun x2 () (_ BitVec 64) (bvor ((_ zero_extend 32) bits) #x0000000200000000))
(define-fun x3 () (_ BitVec 64) (concat #x00000000 p))
(define-fun x4 () (_ BitVec 64) (bvor #x0000000000000000 (bvshl #x0000000020000000 #x0000000000000020)))
(define-fun x5 () (_ BitVec 64) (ite c ((_ zero_extend 32) d) #x0000000000000000))
(assert (or (distinct x1 (ite thread #x0000000500040001 #x0000000500000001))
 (distinct ((_ extract 63 32) x2) #x00000002)
 (distinct ((_ extract 31 0) x2) bits)
 (distinct ((_ extract 63 32) x3) #x00000000)
 (distinct ((_ extract 31 0) x3) p)
 (distinct x4 #x2000000000000000)
 (distinct x5 (ite c ((_ zero_extend 32) d) #x0000000000000000))))''')]
 out=[]
 for name,body in qs:
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True)
  assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Source-matched scalar identities under stated path conditions; no native routing, ownership or delivery proof.'})
 return out
def models():
 ports=[0,1,0x10203,0x80000000,0xffffffff];cases=[]
 for mode in range(4):
  for flags in range(256):
   for p in ports:
    selected=mode in[1,2]and not(flags&1);out=p if selected else 0
    cases.append({'mode':mode,'flags':flags,'input_name_u32':p,'extracted_u32':out,
     'context_offset':0x58 if mode==1 else 0x60 if mode==2 else None,
     'name_cleared':selected,'remote_disposition':18 if out else 19})
 copycases=[{'length_u64':n,'path':'empty'if n==0 else 'dispatch_alloc_copy'if n<=16384 else 'VM_copy',
  'source_read_required':n!=0,'copy_length_u64':n}for n in[0,1,16383,16384,16385,0xffffffff,0x100000000,0xffffffffffffffff]]
 # These length classifications make no allocation/termination claim for extreme sizes.
 contexts=[]
 for raw in[bytes(24),bytes(range(24)),bytes([255])*24,bytes.fromhex('030201000000000011223344556677880200000000000000')]:
  dest=raw;source=bytes(24);after=bytes(4)+dest[4:]
  assert after[4:]==raw[4:]and int.from_bytes(dest[:4],'little')==int.from_bytes(raw[:4],'little')
  contexts.append({'request_before':raw.hex(),'reply_context_after_move':dest.hex(),'request_after_move':source.hex(),'reply_after_port_extraction':after.hex()})
 return{'port_cases':cases,'copy_boundary_cases':copycases,'context_cases':contexts,
  'scope':'Finite scalar/byte models only; neither recovered instructions nor requests execute.'}
def alterations(s):
 changes=[('wrong_send_binding',lambda q:q['stubs']['0x1880876f0'].__setitem__('exact_export','_dispatch_mach_send')),
  ('wrong_port_width',lambda q:patch(q,'extract_reply_port','0x184b70d0c','ldr','x0, [x9]')),
  ('wrong_remote_disposition',lambda q:patch(q,'pack_message','0x184b7781c','mov','w8, #0x13')),
  ('truncated_copy_length',lambda q:patch(q,'data_create','0x184b6e214','mov','w2, w19')),
  ('missing_context_clear',lambda q:patch(q,'create_reply','0x184b808b0','nop','')),
  ('wrong_trap_selector',lambda q:patch(q,'mach2_trap','0x180547c18','mov','x16, #-0x1f')),
  ('invented_native_pairing',lambda q:q.__setitem__('native_image_pairing_proved',True)),
  ('altered_header_id',lambda q:q['header_initializer'].__setitem__('bytes',bytes(16).hex()))]
 out=[]
 for name,change in changes:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'name':name,'rejected':True});continue
  raise AssertionError(name)
 return out
def patch(q,role,pc,mn,op):
 i=next(i for i in q['functions'][role]['instructions']if i['ea']==pc);i.update(mnemonic=mn,operands=op)
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build()
 rows=verify(s);sdk=sdk_checks();pr=proofs();m=models();al=alterations(s)
 counts={**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],
  'SDK_compilations':1,'scalar_queries_unsat':len(pr),'port_model_cases':len(m['port_cases']),
  'copy_boundary_cases':len(m['copy_boundary_cases']),'context_model_cases':len(m['context_cases']),'rejected_evidence_alterations':len(al)}
 result={'generator_sha256':sha(__file__),'source_sha256':sha(ROOT/(P+'_source.json')),'source_recapture_match':True,
  'instruction_assertions':rows,'SDK_checks':sdk,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'proofs':pr,'models':m,'alterations':al,'verified_counts':counts,'all_checks_pass':True,
  'static_scope':'Conditional cache reply-context transfer/consumption, full-width data-copy call paths and retained dictionary value, Mach header remote/local/disposition/ID, dispatch queue versus direct-send routes and original Mach2 vector/SVC handoff. Native daemon/cache pairing, actual port names/rights/ownership, scheduling, delivery, authorization and successful daemon-kext exchange remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
