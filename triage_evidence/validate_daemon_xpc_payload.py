#!/usr/bin/env python3
"""Instruction-matched static ABI identities and evidence-integrity controls."""
import copy,json,struct,subprocess
from recover_daemon_xpc_payload import ROOT,P,FLAGS,SDK,CS,sha,h,build,SPECS,FRAGMENTS,BRANCHES
PATTERNS='''
entry|str|xzr, [sp, #0x390]
entry|mov|w8, #0x81
entry|mov|w9, #0x538f
entry|add|w0, w27, w9
entry|stp|x12, x10, [sp, #0x10]
type_gate|mov|w9, #-0x7383
type_gate|mov|w10, #0xf5f7
type_gate|add|w19, w0, w9
type_gate|eor|w24, w19, w10
type_gate|mov|x0, x13
type_gate|mov|w10, #0x1253
type_gate|eor|w10, w10, #0x78
dictionary_gate|cmp|x0, x9
dictionary_gate|mov|x13, x21
get_data|ldr|x9, [sp, #0x10]
get_data|add|x1, x9, x10
get_data|add|x2, sp, #0x390
get_data|mov|x0, x13
get_data|cmp|x0, #0
allocate_data|mov|x22, x0
allocate_data|ldr|x0, [sp, #0x390]
allocate_data|str|x0, [sp, #0x820]
copy_gate|ldr|x9, [sp, #0x390]
copy_gate|lsl|x11, x9, #1
copy_gate|and|w10, w10, w11
copy_gate|subs|w12, w9, w10
copy_prepare|mov|w10, #0
copy_prepare|movk|w9, #0x4c6c, lsl #16
copy_prepare|add|w9, w12, w9
copy_prepare|eor|w11, w11, w9
copy_prepare|ands|w13, w11, #7
copy_prepare|mov|x9, x11
copy_tail|sub|x9, x9, #1
copy_tail|ldrb|w14, [x22, x9]
copy_tail|strb|w14, [x0, x9]
copy_tail|add|w10, w10, #1
copy_tail|cmp|w10, w13
copy_group_gate|cmp|w11, #8
copy_group_gate|mov|w11, #0xd4
copy_group|eor|x12, x10, x14
copy_group|subs|x9, x9, #8
copy_group|ldrb|w12, [x22, x9]
copy_group|strb|w12, [x0, x9]
copy_done|ldr|x9, [sp, #0x390]
copy_done|lsl|x11, x9, x11
encode_length|and|x11, x11, x12
encode_length|str|x9, [sp, #0x498]
encode_length|str|x0, [sp, #0x268]
encode_length|str|w22, [sp, #0x57c]
allocate_record|str|x0, [sp, #0x430]
allocate_record|mov|w0, #0x10
allocate_record|str|x0, [sp, #0x700]
zero_record|mov|x8, #0
zero_record|stp|xzr, xzr, [x0]
record_loop_gate|subs|x11, x10, x8
record_nonempty|ldr|x9, [sp, #0x430]
record_minimum|cmp|x11, x13
record_extent|add|x11, x8, #6
record_extent|lsl|w11, w11, #0x18
record_extent|orr|w11, w11, w12, lsl #16
record_extent|orr|w11, w11, w12, lsl #8
record_extent|add|x12, x8, #9
record_extent|add|x12, x8, #0xa
record_extent|add|x11, x11, x12
record_extent|cmp|x11, x10
record_extent|cset|w10, ls
record_failure|str|w23, [sp, #0x81c]
record_failure|ldr|x13, [sp, #0x1c8]
'''
def verify(s):
 assert s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for name,a in FRAGMENTS.items():
  f=s['fragments'][name];bb=bytes.fromhex(f['bytes']);ii=list(CS.disasm(bb,a))
  assert f['start']==hex(a)and h(bb)==f['sha256']and len(bb)==int(f['end'],16)-a==4*len(ii)
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]
 rows=[]
 for line in PATTERNS.strip().splitlines():
  name,mn,op=line.split('|');hits=[i for i in s['fragments'][name]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(name,mn,op);rows.extend({'role':name,**i}for i in hits)
 for name,pair,key,add,base,bias in SPECS:
  r=s['banks'][name];l,rr=bytes.fromhex(r['left_bytes']),bytes.fromhex(r['right_bytes']);outputs=[i^rr[l[i]^key]for i in range(256)]
  assert len(l)==len(rr)==256 and outputs==r['results_256']and set(outputs)=={int(r['constant'],16)}
  assert(r['left'],r['right'],int(r['key'],16),int(r['additive'],16))==(hex(pair[0]),hex(pair[1]),key,add)
  assert int(r['slot'],16)==base+8*(add+outputs[0])and int(r['bias'],16)==bias
 expected={'get_type':'_xpc_get_type','get_data':'_xpc_dictionary_get_data','allocate_data':'_malloc','allocate_record':'_malloc'}
 for r in s['calls']:
  b=s['banks'][r['role']];assert r['slot']==b['slot']and r['target']==b['target']=='libSystem/'+expected[r['role']]
  w=int(r['pointer_word'],16);ii=list(CS.disasm(bytes.fromhex(r['bytes']),int(r['site'],16)-4))
  assert w>>63 and(w>>32&65535)==r['modifier_u16']and not(w>>48&1)and not(w>>49&3)
  assert ii[0].op_str==f'x17, #{hex(r["modifier_u16"])}'and ii[1].mnemonic=='blraa'
 assert [(r['role'],r['source'],int(r['index'],16),int(r['target'],16))for r in s['branches']]==BRANCHES
 for r in s['branches']:
  assert int(r['slot'],16)==0x101039ef0+8*int(r['index'],16)
  w=int(r['pointer_word'],16);assert(w>>32&65535)==r['modifier_u16']and w>>63
 assert s['data_key']=={'address':'0x100e86130','bytes':b'data\0'.hex()}
 assert s['banks']['data_key']['target']=='0x100e86130'and s['banks']['classic_header']['target']=='0x1010c4cd8'
 imp={r['symbol']:r for r in s['imports']}
 assert imp['__xpc_type_error']['total_addend']==0x256d84e2 and imp['__xpc_type_dictionary']['total_addend']==0x63f36eae
 assert s['fixup_reference']['catalog_memberships_compared']==61737
 assert all(s[k]is False for k in FLAGS);return rows

def sdk_checks():
 code='''#define OS_OBJECT_USE_OBJC 0
#include <xpc/xpc.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#define A(x) static_assert((x),#x)
A(sizeof(size_t)==8);A(sizeof(void*)==8);A(sizeof(uint32_t)==4);
A(sizeof(xpc_object_t)==8);A(sizeof(audit_token_t)==32);
A(__is_same(decltype(&xpc_dictionary_get_data),const void*(*)(xpc_object_t,const char*,size_t*)));
A(__is_same(decltype(&malloc),void*(*)(size_t)));
A(__is_same(decltype(&xpc_get_type),xpc_type_t(*)(xpc_object_t)));
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return {'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang')}

def proofs():
 qs=[('copy_zero_iff_low32_zero','''(declare-fun n () (_ BitVec 32))
(define-fun r () (_ BitVec 32) (bvsub n (bvand (bvshl n #x00000001) #x98d8f669)))
(assert (distinct (= r #x00000000) (= n #x00000000)))'''),
 ('copy_count_recovers_low32','''(declare-fun n () (_ BitVec 32))
(define-fun r () (_ BitVec 32) (bvsub n (bvand (bvshl n #x00000001) #x98d8f669)))
(assert (distinct (bvxor (bvadd r #x4c6c7b34) #x4c6c7b34) n))'''),
 ('stored_length_xor_identity','''(declare-fun l () (_ BitVec 64))
(define-fun encoded () (_ BitVec 64) (bvadd (bvsub (bvadd l #x000000000000b1f9) (bvand (bvshl l #x0000000000000001) #x0ea7becdbb1fe36e)) #x0753df66dd8f3fbe))
(assert (distinct encoded (bvxor l #x0753df66dd8ff1b7)))'''),
 ('big_endian_length_identity','''(declare-fun a () (_ BitVec 8)) (declare-fun b () (_ BitVec 8))
(declare-fun c () (_ BitVec 8)) (declare-fun d () (_ BitVec 8))
(define-fun hi () (_ BitVec 32) (concat a b c #x00))
(define-fun lo () (_ BitVec 32) ((_ zero_extend 24) d))
(define-fun p () (_ BitVec 32) (bvadd (bvsub hi (bvand #x0befae00 (bvshl hi #x00000001))) #x85f7d7f2))
(define-fun q () (_ BitVec 32) (bvadd (bvsub lo (bvand #x0000015c (bvshl lo #x00000001))) #xabd69cae))
(define-fun decoded () (_ BitVec 32) (bvxor (bvand (bvxor p #x0f98f1bf) (bvxor q #x54296351)) (bvand q #x219099b2) #xabffbeef))
(assert (distinct decoded (concat a b c d)))'''),
 ('full_length_vs_copy_extent','''(declare-fun l () (_ BitVec 64))
(define-fun n () (_ BitVec 64) ((_ zero_extend 32) ((_ extract 31 0) l)))
(assert (or (bvugt n l) (bvugt n #x00000000ffffffff)))'''),
 ('first_record_bound_no_sum_wrap','''(declare-fun n () (_ BitVec 32)) (declare-fun p () (_ BitVec 32))
(define-fun end () (_ BitVec 64) (bvadd ((_ zero_extend 32) p) #x000000000000000a))
(assert (or (bvult end ((_ zero_extend 32) p))
 (distinct (bvule end ((_ zero_extend 32) n))
 (and (bvuge ((_ zero_extend 32) n) #x000000000000000a) (bvule ((_ zero_extend 32) p) (bvsub ((_ zero_extend 32) n) #x000000000000000a))))))''')]
 out=[]
 for name,body in qs:
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Analyst-written instruction-matched scalar identities only; no native mapping, object lifetime, application policy, whole CFG or recovered-code execution.'})
 return out

def copy_models():
 out=[]
 for n in list(range(129))+[0x7fffffff,0x80000000,0xfffffffe,0xffffffff]:
  tail=n%8;groups=n//8;remaining=n-tail
  assert remaining==groups*8 and tail+8*groups==n and 0<=tail<8
  if n<=128:
   indices=list(range(n-1,n-tail-1,-1))
   for j in range(groups):indices.extend(range(remaining-8*j-1,remaining-8*j-9,-1))
   assert indices==list(range(n-1,-1,-1))
  out.append({'n_u32':n,'tail_bytes':tail,'groups_of_eight':groups,'bytes_copied':tail+8*groups})
 # Explicit static state reductions through initial cursor/minimum/extent gates.
 assert (0xcb2f-0x7383)==0x57ac and(0x57ac^0xf5f7)==0xa25b
 assert(0x1ea86^(0xa25b<<1))==0xae30 and(0xa25b^0x1acc)==0xb897
 assert ((0xb897^0xa294)*7)==0xb615 and(0xae30^0xb615^0x1870)==0x55
 assert(0xbf79-0xa778)|0x2014==0x3815
 assert (((0x23b7^0x2f01)<<1)+0x4663)==0x5fcf
 assert(0x5fcf^((-0x5fce)&((1<<64)-1)))==((1<<64)-3)
 w9=(0x2282+0x6e1a5cdb)&0x91e5bbfe;w13=(w9+0x94ffa420)&0x6b007cfb;w12=w9+0x23fe
 assert(w9,w13,w12)==(0x3b5c,0x5c78,0x5f5a)
 assert((w12^0x8b3d3683)+w13)==(0xdd8ff1b7^0x56b237e6)
 assert (((0x2eba+0x198f)|0x2222)^0x6a62)==9
 return {'cases':out,'scope':'Finite analyst-written arithmetic and copy-index model; first cursor only. All-length loop coverage follows the retained quotient/remainder induction, not execution of recovered code.'}

def alterations(s):
 def bank(q):
  r=q['banks']['get_data'];b=bytearray.fromhex(r['left_bytes']);b[0]^=1;r['left_bytes']=b.hex()
 def instruction(q,role,ea,op):next(i for i in q['fragments'][role]['instructions']if i['ea']==ea).update(operands=op)
 out=[]
 changes=[('bank_byte',bank),('dictionary_wrong_key',lambda q:q['banks']['dictionary_type'].update(key='0x54')),
  ('key_literal',lambda q:q['data_key'].update(bytes=b'Data\0'.hex())),
  ('allocation_width',lambda q:instruction(q,'allocate_data','0x100ba9a58','w0, [sp, #0x390]')),
  ('copy_width',lambda q:instruction(q,'copy_prepare','0x100a80f90','x9, x12')),
  ('header_endian',lambda q:instruction(q,'record_extent','0x100a6c0b4','w11, w11, #8')),
  ('authentication_modifier',lambda q:q['calls'][1].update(modifier_u16=0)),
  ('native_authorization',lambda q:q.update(native_authorization_proved=True))]
 for name,change in changes:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence '+name)
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();models=copy_models();neg=alterations(s)
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':rows,'SDK_checks':sdk,'proofs':pr,'copy_models':models,'alterations':neg,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
 'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'copy_model_cases':len(models['cases']),'rejected_evidence_alterations':len(neg)},'all_checks_pass':True,
 'static_scope':'Original XPC dictionary type/data gate, full-size allocation, low32 reverse copy, XOR length storage, separate 16 B allocation and first 10 B record/BE32 extent gate. Native peer, authorization, payload meaning, later iteration/dispatch/reply/cleanup and daemon-kext processing remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
