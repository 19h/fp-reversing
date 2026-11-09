#!/usr/bin/env python3
"""Static disposal/reference/transaction source and finite lifetime verification."""
import copy,itertools,json,struct,subprocess
from recover_xpc_resource_lifecycle import *
PATTERNS='''
dictionary_dispose|0x184b6f410|ldr|x22, [x0]
dictionary_dispose|0x184b6f414|bl|#0x184b6f4e4
dictionary_dispose|0x184b6f424|cmp|x20, #7
dictionary_dispose|0x184b6f430|and|w9, w8, #3
dictionary_dispose|0x184b6f440|tbnz|w8, #3, #0x184b6f4b4
dictionary_dispose|0x184b6f444|add|x0, x19, #0x58
dictionary_dispose|0x184b6f464|b|#0x184b72c90
dictionary_dispose|0x184b6f470|ldr|x1, [x19, #0x58]
dictionary_dispose|0x184b6f474|add|x0, x19, #0x60
dictionary_dispose|0x184b6f478|bl|#0x184b72cdc
dictionary_dispose|0x184b6f47c|ldr|x0, [x19, #0x58]
dictionary_dispose|0x184b6f4a0|b|#0x184b6d6c4
dictionary_dispose|0x184b6f4b4|ldr|x0, [x19, #0x98]
dictionary_dispose|0x184b6f4b8|bl|#0x1880862f0
dictionary_dispose|0x184b6f4c4|bl|#0x18806d550
dictionary_dispose|0x184b6f4d0|ldr|x0, [x0, #8]
dictionary_dispose|0x184b6f4d4|bl|#0x184b6d6c4
node_free|0x184b6f4e8|cmp|w8, #2
node_free|0x184b6f4ec|b.eq|#0x184b6f554
node_free|0x184b6f504|cmp|w8, #3
node_free|0x184b6f50c|ldr|x0, [x19, #0x20]
node_free|0x184b6f510|bl|#0x184b6d6c4
node_free|0x184b6f514|ldp|x8, x9, [x19]
node_free|0x184b6f51c|str|x9, [x8, #8]
node_free|0x184b6f520|str|x8, [x9]
node_free|0x184b6f528|stp|x8, x8, [x19]
node_free|0x184b6f52c|ldr|x0, [x19, #0x10]
node_free|0x184b6f530|bl|#0x184b6d6c4
node_free|0x184b6f550|b|#0x18806c9e0
data_dispose|0x184b6f174|ldr|x0, [x0, #0x18]
data_dispose|0x184b6f178|b|#0x18806d180
payload_dealloc|0x184b72c38|bl|#0x18806d180
payload_dealloc|0x184b72c58|bl|#0x18806d240
payload_dealloc|0x184b72c60|bl|#0x18806d180
serializer_dispose|0x184b7209c|tbnz|w8, #1, #0x184b720c8
serializer_dispose|0x184b720b4|ubfx|w1, w8, #8, #5
serializer_dispose|0x184b720b8|bl|#0x184b7f6ec
serializer_dispose|0x184b720c0|bl|#0x18806d240
serializer_dispose|0x184b720c8|bl|#0x18806d180
serializer_dispose|0x184b720e8|b|#0x184b71eb4
serializer_cleanup|0x184b71ec8|ldr|x8, [x0, #0x40]
serializer_cleanup|0x184b71edc|b.eq|#0x184b71f64
serializer_cleanup|0x184b71ee4|blraaz|x8
serializer_cleanup|0x184b71ee8|str|xzr, [x19, #0x40]
serializer_cleanup|0x184b71f28|bl|#0x18806c9e0
serializer_cleanup|0x184b71f30|ldr|x0, [x19, #0x80]
serializer_cleanup|0x184b71f38|bl|#0x1880862f0
serializer_cleanup|0x184b71f3c|str|xzr, [x19, #0x80]
serializer_cleanup|0x184b71f44|tbz|w8, #4, #0x184b71f58
serializer_cleanup|0x184b71f48|bl|#0x184ba0af0
serializer_cleanup|0x184b71f50|and|w8, w8, #0xffffffef
clear_sent|0x184b71e64|tbnz|w8, #0, #0x184b71e98
clear_sent|0x184b71e6c|tbz|w8, #0, #0x184b71ea4
clear_sent|0x184b71e74|str|xzr, [x0, #0x40]
clear_sent|0x184b71e78|orr|w8, w8, #2
clear_sent|0x184b71e7c|strb|w8, [x0, #0x9c]
clear_sent|0x184b71e94|b|#0x184b71eb4
release_message|0x184b77cac|mov|x0, x19
release_message|0x184b77cb0|bl|#0x184b71e54
release_message|0x184b77cb8|bl|#0x184b6d6c4
release_message|0x184b77ce8|b|#0x188087460
sent_event|0x184b779b4|bl|#0x1880875e0
sent_event|0x184b77a18|b|#0x184b77c5c
object_dealloc|0x184b6ef0c|sub|x9, x0, x8
object_dealloc|0x184b6ef18|add|x8, x10, x9, lsl #1
object_dealloc|0x184b6ef28|ldr|x9, [x8, #0x60]!
object_dealloc|0x184b6ef34|movk|x17, #0xa020, lsl #48
object_dealloc|0x184b6ef38|blraa|x9, x17
object_dealloc|0x184b6ef54|bl|#0x18806ea60
object_alloc|0x185514850|sub|x20, x1, #8
object_alloc|0x185514858|bl|#0x18806e620
object_alloc|0x185514870|str|w8, [x0, #8]
object_alloc|0x185514874|str|w8, [x0, #0xc]
xref_retain|0x185513f04|ldr|w9, [x0, #0xc]
xref_retain|0x185513f18|ldadd|w9, w8, [x8]
xref_release|0x185514000|ldr|w9, [x0, #0xc]
xref_release|0x185514014|ldaddl|w9, w8, [x8]
xref_release|0x185514028|b|#0x185513e60
internal_release|0x185513e64|ldr|w9, [x0, #8]
internal_release|0x185513e78|ldaddl|w9, w8, [x8]
internal_release|0x185513e8c|b|#0x1855148dc
object_dispose|0x1855148e0|ldapr|wzr, [x8]
object_dispose|0x1855148e4|b|#0x188009bf0
begin|0x184ba0aa4|add|x0, x19, #0xb0
begin|0x184ba0ab4|bl|#0x184b885c8
end|0x184ba0b28|bl|#0x184b88700
begin_impl|0x184b885dc|ldr|w22, [x0, #0xac]
begin_impl|0x184b885e0|adds|w8, w22, #1
begin_impl|0x184b885e4|str|w8, [x0, #0xac]
begin_impl|0x184b885e8|b.hs|#0x184b886ec
begin_impl|0x184b8869c|cmp|w22, #0
begin_impl|0x184b886a8|cmp|w8, #1
begin_impl|0x184b886b4|mov|w1, #1
begin_impl|0x184b886b8|bl|#0x188087b30
end_impl|0x184b88714|ldr|w22, [x0, #0xac]
end_impl|0x184b88718|sub|w20, w22, #1
end_impl|0x184b8871c|str|w20, [x0, #0xac]
end_impl|0x184b88724|b.le|#0x184b887b8
end_impl|0x184b8875c|cmp|w22, #1
end_impl|0x184b88774|mov|w1, #0
end_impl|0x184b88778|bl|#0x188087b30
end_impl|0x184b887a4|b.eq|#0x184b887c8
end_impl|0x184b887cc|bl|#0x18806d7b0
'''
def verify(s):
 assert s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a'
 for role,(path,a)in FUNCTIONS.items():
  f=s['functions'][role];bb=bytes.fromhex(f['bytes']);ii=list(CS.disasm(bb,a));assert f['start']==hex(a)and f['library']==path and h(bb)==f['sha256']
  assert len(bb)==int(f['end'],16)-a==4*len(ii)and f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]
 rows=[]
 for line in PATTERNS.strip().splitlines():
  role,pc,mn,op=line.split('|');hits=[i for i in s['functions'][role]['instructions']if i['ea']==pc]
  assert len(hits)==1 and(hits[0]['mnemonic'],hits[0]['operands'])==(mn,op),(role,pc);rows.append({'role':role,**hits[0]})
 for a,(path,name)in STUBS.items():
  q=s['stubs'][hex(a)];assert q['library']==path and q['exact_export']==name and q['export_address']==q['pointer']['target']and q['pointer']['chain_membership_verified']
  if q['original_nlist']:assert any(n['name']==name and n['n_value']==q['pointer']['target']for n in q['original_nlist'])
  w=int(q['pointer']['raw_word'],16);assert int(q['pointer']['target'],16)==int(q['pointer']['value_add'],16)+(w&0x3ffffffff)and w>>63
 for role,q in s['dispose_types'].items():
  cl=int(q['class_pointer']['target'],16);slot=int(q['table_base'],16)+2*(cl-int(q['base_class'],16))+0x60
  p=q['dispose_slot'];assert int(p['address'],16)==slot and p['chain_membership_verified']and int(p['raw_word'],16)>>63
  assert int(p['raw_word'],16)>>34&65535==0xa020
  target=s['functions'][role+'_dispose']['start'];assert p['target']==target
  assert any(n['n_value']==target for n in q['dispose_original_nlist'])
 sel=s['dealloc_selector'];assert not sel['native_IMP_lookup_proved']and sel['selector_bytes']==b'dealloc\0'.hex()
 assert[(i['mnemonic'],i['operands'])for i in sel['instructions']]==[('adrp','x1, #0x1f4b86000'),('add','x1, x1, #0x30'),('b','#0x188000800'),('brk','#1')]
 assert all(s[k]is False for k in FLAGS);return rows
def sdk_checks():
 code='''#define OS_OBJECT_USE_OBJC 0
#include <xpc/xpc.h>
#include <mach/message.h>
#include <mach/port.h>
#include <stdint.h>
#define A(x) static_assert((x),#x)
A(sizeof(void*)==8);A(sizeof(size_t)==8);A(sizeof(mach_port_t)==4);A(sizeof(uint32_t)==4);A(sizeof(int32_t)==4);
A(sizeof(mach_msg_header_t)==24);A(MACH_SEND_INVALID_DEST==0x10000003);
A(MACH_MSG_TYPE_MOVE_SEND_ONCE==18);A(MACH_MSG_TYPE_MOVE_RECEIVE==16);A(INT32_MAX==0x7fffffff);
A(__is_same(decltype(&xpc_release),void(*)(xpc_object_t)));
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True)
 assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang')}
def proofs():
 qs=[('dispose_slot_and_auth_modifier','''(define-fun base () (_ BitVec 64) #x00000001ed891ab0)
(define-fun cl () (_ BitVec 64) #x00000001ed891f60)
(define-fun slot () (_ BitVec 64) (bvadd #x00000001e2418f70 (bvshl (bvsub cl base) #x0000000000000001) #x0000000000000060))
(define-fun mod () (_ BitVec 64) (bvor (bvand slot #x0000ffffffffffff) #xa020000000000000))
(assert (or (distinct slot #x00000001e2419930) (distinct mod #xa0200001e2419930)))'''),
 ('reference_counter_partition_and_ordinary_pair','''(declare-fun n () (_ BitVec 32))
(define-fun immortal () Bool (= n #x7fffffff))
(define-fun release () (_ BitVec 32) (ite immortal n (bvsub n #x00000001)))
(define-fun final () Bool (and (not immortal) (bvsle n #x00000001) (= n #x00000001)))
(assert (or (distinct final (= n #x00000001))
 (and (bvuge n #x00000001) (bvule n #x7ffffffd)
  (distinct (bvsub (bvadd n #x00000001) #x00000001) n))
 (and immortal (distinct release n))))'''),
 ('voucher_and_transaction_cleanup_second_pass','''(declare-fun flags () (_ BitVec 8)) (declare-fun v () (_ BitVec 64))
(define-fun moved () (_ BitVec 8) (ite (distinct (bvand flags #x02) #x00) #x10 #x00))
(define-fun source () (_ BitVec 8) (bvand flags #xfd))
(define-fun cleared () (_ BitVec 8) (bvand moved #xef))
(assert (or (distinct (bvand source #x02) #x00)
 (distinct (distinct (bvand moved #x10) #x00) (distinct (bvand flags #x02) #x00))
 (distinct (bvand cleared #x10) #x00)))'''),
 ('transaction_inverse_in_nonnegative_counter_domain','''(declare-fun n () (_ BitVec 32))
(assert (bvule n #x7ffffffe))
(define-fun up () (_ BitVec 32) (bvadd n #x00000001))
(define-fun down () (_ BitVec 32) (bvsub up #x00000001))
(assert (or (distinct down n) (bvsle up #x00000000) (= n #xffffffff)))''')]
 out=[]
 for name,body in qs:
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True)
  assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Source-matched scalar identities, with ordinary counter bounds where stated; no native resource balance or execution proof.'})
 return out
def models():
 lifecycle=[]
 for port,voucher,transaction,peer,phase in itertools.product([False,True],[False,True],[False,True],[False,True],range(4)):
  if phase and not port:continue
  # phase0 request only; 1 reply before pack; 2 packed/uncommitted; 3 marked sent.
  record={'port_present':port,'voucher_present':voucher,'transaction_flag':transaction,'peer_present':peer,'phase':phase,
   'request_context_cleanup':phase==0,'reply_context_cleanup':phase==1,'serializer_cleanup':phase>=2,
   'context_port_deallocate_calls':int(port and phase<2),'header_destroy_requests':int(phase==2),
   'sent_descriptor_marker':phase==3,'voucher_release_calls':int(voucher),'transaction_end_calls':int(transaction),
   'peer_retains_at_reply_create':int(peer and phase>0),'peer_release_calls':int(peer)*(2 if phase else 1),
   'second_serializer_cleanup_voucher_calls':0,'second_serializer_cleanup_transaction_calls':0}
  assert record['peer_release_calls']-record['peer_retains_at_reply_create']==int(peer)
  assert record['context_port_deallocate_calls']+record['header_destroy_requests']+int(record['sent_descriptor_marker'])==int(port)
  lifecycle.append(record)
 nodes=[]
 for k in range(7):
  for kinds in itertools.product([0,2,3],repeat=k):
   frees=sum(t!=2 for t in kinds);extra=sum(t==3 for t in kinds)
   nodes.append({'node_kinds':list(kinds),'seven_buckets_visited':7,'node_helper_calls':k,'node_free_calls':frees,
    'value_release_calls':frees,'kind3_extra_release_calls':extra,'kind2_noop_calls':k-frees})
 counters=[]
 for old in[0,1,2,0x7ffffffe,0x7fffffff,0x80000000,0xfffffffe,0xffffffff]:
  signed=old if old<0x80000000 else old-0x100000000
  counters.append({'old_u32':old,'old_s32':signed,'immortal_skip':old==0x7fffffff,
   'xref_retain_after_u32':old if old==0x7fffffff else(old+1)&0xffffffff,
   'xref_release_after_u32':old if old==0x7fffffff else(old-1)&0xffffffff,
   'release_invokes_internal':old==1,'retain_nonpositive_old_error':signed<=0,
   'release_nonpositive_old_error':signed<=0,'transaction_begin_after_u32':(old+1)&0xffffffff,
   'transaction_begin_carry_error':old==0xffffffff,'transaction_end_after_u32':(old-1)&0xffffffff,
   'transaction_end_nonpositive_old_error':signed<=0})
 flags=[{'u8':f,'mode':f&3,'mode1_lazy':(f&3)==1 and bool(f&8),
  'received_cleanup':(f&3)==1,'reply_cleanup':(f&3)==2,'no_context_cleanup':(f&3)in[0,3]}for f in range(256)]
 return{'lifecycle_cases':lifecycle,'finite_node_cases':nodes,'counter_boundary_cases':counters,'dictionary_flag_cases':flags,
  'scope':'Finite ownership/call-count/scalar models with valid finite chains and declared phases; no target or recovered code executes, no native reference/right balance is inferred.'}
def patch(q,role,pc,mn,op):
 i=next(i for i in q['functions'][role]['instructions']if i['ea']==pc);i.update(mnemonic=mn,operands=op)
def alterations(s):
 changes=[('wrong_reply_context',lambda q:patch(q,'dictionary_dispose','0x184b6f474','add','x0, x19, #0x58')),
  ('wrong_bucket_count',lambda q:patch(q,'dictionary_dispose','0x184b6f424','cmp','x20, #8')),
  ('wrong_voucher_cell',lambda q:patch(q,'serializer_cleanup','0x184b71f30','ldr','x0, [x19, #0x88]')),
  ('missing_voucher_clear',lambda q:patch(q,'serializer_cleanup','0x184b71f3c','nop','')),
  ('wrong_xref_counter',lambda q:patch(q,'xref_release','0x185514000','ldr','w9, [x0, #8]')),
  ('wrong_dirty_flag',lambda q:patch(q,'end_impl','0x184b88774','mov','w1, #1')),
  ('wrong_dispose_target',lambda q:q['dispose_types']['dictionary']['dispose_slot'].__setitem__('target','0x184b6f174')),
  ('invented_native_lifetime',lambda q:q.__setitem__('native_output_ownership_proved',True))]
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
  **{n:len(m[n])for n in['lifecycle_cases','finite_node_cases','counter_boundary_cases','dictionary_flag_cases']},'rejected_evidence_alterations':len(al)}
 result={'generator_sha256':sha(__file__),'source_sha256':sha(ROOT/(P+'_source.json')),'source_recapture_match':True,
  'instruction_assertions':rows,'SDK_checks':sdk,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'proofs':pr,'models':m,'alterations':al,'verified_counts':counts,'all_checks_pass':True,
  'static_scope':'Conditional dictionary/node/data/payload disposal, two-counter release and dealloc-selector frontier, exact dispose table bindings, serializer sent/uncommitted cleanup, voucher/transaction transfer and begin/end counter/dirty/exit requests. Native ObjC IMP lookup, concurrency, reference/right balance, image pairing, actual delivery/policy and daemon-kext success remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
