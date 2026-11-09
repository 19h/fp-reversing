#!/usr/bin/env python3
"""Static record-type/value/layout checks; no recovered code execution."""
import copy,json,struct,subprocess
from recover_daemon_xpc_records import ROOT,P,FLAGS,SDK,CS,sha,h,build,SPECS,FRAGMENTS,BRANCHES
PATTERNS='''
header|eor|x10, x8, x10
header|and|x17, x17, x8, lsl #1
header|ldrb|w17, [x9, x17]
header|lsl|w17, w17, w5
header|lsl|w5, w5, w6
header|orr|w17, w17, w5, lsl #8
header|eor|w4, w14, w16
header|add|x10, x8, #4
header|add|x15, x8, #5
header|orr|w10, w15, w10, lsl #8
header|and|w17, w10, w17
header|and|w15, w15, #8
header|sub|w10, w10, w15, lsl #1
header|sxth|w15, w15
signed_root|cmp|w15, w1, sxth
signed_root|cset|w1, lt
signed_lower|cmp|w15, w14, uxth
signed_ge|cmp|w15, w1, sxth
middle|cmp|w17, w15, uxth
upper|cmp|w15, w13
u32_extent|cmp|w13, w17
u64_extent|cmp|w13, w16
u32_value|orr|w12, w13, w12, lsl #24
u32_value|orr|w12, w12, w13, lsl #8
u32_value|str|w8, [sp, #0x42c]
u64_value|lsl|x12, x12, #0x38
u64_value|orr|x12, x12, x16, lsl #48
u64_value|orr|x12, x12, x17, lsl #40
u64_value|orr|x12, x12, x13, lsl #32
u64_value|str|x8, [sp, #0x358]
value_join|str|x11, [sp, #0x450]
variable|add|x17, x9, x12
variable|str|x17, [sp, #0x388]
variable|str|x11, [sp, #0x450]
argument_load|ldr|x0, [sp, #0x700]
argument_load|ldr|w8, [sp, #0x42c]
argument_load|ldr|x11, [sp, #0x358]
argument_load|ldr|x19, [sp, #0x388]
local_record|str|x13, [sp, #0x538]
local_record|str|x0, [sp, #0x7e0]
local_record|str|w4, [sp, #0xa40]
local_record|strh|w10, [sp, #0xa46]
local_record|str|w24, [sp, #0xa48]
local_record|str|w8, [sp, #0xa4c]
local_record|str|x11, [sp, #0xa50]
local_record|str|x19, [sp, #0xa58]
object_gate|cmn|w8, #0xa
object_gate|cset|w8, lo
allocate_object|mov|w0, #0x20
allocate_object|str|x0, [sp, #0x410]
allocate_buffer|stp|xzr, xzr, [x0]
allocate_buffer|str|w0, [x21, #0x10]
allocate_buffer|str|x0, [x21, #0x18]
allocate_buffer|str|x8, [sp, #0xa60]
helper_return|ldr|x8, [sp, #0x538]
result|str|w8, [sp, #0x81c]
publish_result|ldr|x10, [sp, #0x568]
publish_result|str|x8, [x10]
inherited_allocate_record|str|xzr, [sp, #0x388]
inherited_allocate_record|str|w8, [sp, #0x42c]
inherited_allocate_record|str|x8, [sp, #0x358]
'''
def verify(s):
 assert s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for name,a in FRAGMENTS.items():
  f=s['fragments'][name];bb=bytes.fromhex(f['bytes']);ii=list(CS.disasm(bb,a));assert f['start']==hex(a)and h(bb)==f['sha256']and len(bb)==int(f['end'],16)-a==4*len(ii)
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]
 rows=[]
 for line in PATTERNS.strip().splitlines():
  name,mn,op=line.split('|');hits=[i for i in s['fragments'][name]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(name,mn,op);rows.extend({'role':name,**i}for i in hits)
 for name,pair,key,add in SPECS:
  r=s['banks'][name];l,rr=bytes.fromhex(r['left_bytes']),bytes.fromhex(r['right_bytes']);outputs=[i^rr[l[i]^key]for i in range(256)]
  assert len(l)==len(rr)==256 and outputs==r['results_256']and set(outputs)=={int(r['constant'],16)}
  assert (r['left'],r['right'],int(r['key'],16),int(r['additive'],16))==(hex(pair[0]),hex(pair[1]),key,add)
  assert int(r['slot'],16)==0x101039ef0+8*(add+outputs[0])
 for r in s['calls']:
  b=s['banks'][r['role']];w=int(r['pointer_word'],16);ii=list(CS.disasm(bytes.fromhex(r['bytes']),int(r['site'],16)-4))
  assert r['slot']==b['slot']=='0x10109ff58'and r['target']==b['target']=='libSystem/_malloc'
  assert w>>63 and(w>>32&65535)==r['modifier_u16']==0x6aa4 and not(w>>48&1)and not(w>>49&3)
  assert ii[0].op_str=='x17, #0x6aa4'and ii[1].mnemonic=='blraa'
 assert [(r['role'],r['source'],int(r['index'],16),int(r['target'],16))for r in s['branches']]==BRANCHES
 for r in s['branches']:
  w=int(r['pointer_word'],16);assert int(r['slot'],16)==0x101039ef0+8*int(r['index'],16)and w>>63 and(w>>32&65535)==r['modifier_u16']
 assert len(s['imports'])==1 and s['imports'][0]['symbol']=='_malloc'
 assert s['fixup_reference']['catalog_memberships_compared']==61737 and all(s[k]is False for k in FLAGS)
 return rows

def sdk_checks():
 code='''#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#define A(x) static_assert((x),#x)
struct LocalRecord {uint32_t tag;uint16_t unknown,discriminator;uint32_t extent,u32_value;uint64_t u64_value;const void* bytes;};
struct HeapPrefix {void* unknown0;void* unknown8;uint32_t length,unknown20;void* buffer;};
A(sizeof(void*)==8);A(sizeof(uint16_t)==2);A(sizeof(uint32_t)==4);A(sizeof(uint64_t)==8);
A(sizeof(LocalRecord)==32);A(offsetof(LocalRecord,discriminator)==6);A(offsetof(LocalRecord,extent)==8);
A(offsetof(LocalRecord,u32_value)==12);A(offsetof(LocalRecord,u64_value)==16);A(offsetof(LocalRecord,bytes)==24);
A(sizeof(HeapPrefix)==32);A(offsetof(HeapPrefix,length)==16);A(offsetof(HeapPrefix,buffer)==24);
A(__is_same(decltype(&malloc),void*(*)(size_t)));A(sizeof(size_t)==8);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return {'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Reconstructed layout/width assertions; not canonical Apple private types.'}

def proofs():
 qs=[]
 terms=[]
 for j in range(4):
  c=(0x40810295066000a1+j)&((1<<64)-1)
  terms.append(f'(distinct (bvadd t #x{c:016x}) (bvadd cursor (_ bv{j} 64)))')
 qs.append(('header_offsets0_through3','(declare-fun cursor () (_ BitVec 64))\n(define-fun t () (_ BitVec 64) (bvadd (bvxor cursor #xbf7efd6af99fff5f) (bvand #x7efdfad5f33ffebe (bvshl cursor #x0000000000000001))))\n(assert (or '+' '.join(terms)+'))'))
 base='''(declare-fun n () (_ BitVec 32))
(define-fun hi () (_ BitVec 32) (bvand n #xffffff00))
(define-fun lo () (_ BitVec 32) (bvand n #x000000ff))
(define-fun a () (_ BitVec 32) (bvadd (bvsub hi (bvand #x0befae00 (bvshl hi #x00000001))) #x85f7d7f2))
(define-fun b () (_ BitVec 32) (bvadd (bvsub lo (bvand #x0000015c (bvshl lo #x00000001))) #xabd69cae))
(define-fun shared () (_ BitVec 32) (bvand (bvxor a #x0f98f1bf) (bvxor b #x54296351)))
'''
 qs.append(('header_and_u32_value_encoding',base+'''(assert (or
 (distinct (bvxor shared (bvand b #x219099b2) #x20c278be) (bvxor n #x8b3dc651))
 (distinct (bvxor shared (bvand b #x011081b2) #x004260be) (bvxor n #x8b3dc651))
 (distinct (= (bvxor shared (bvand b #x219099b2)) #xabffbeef) (= n #x00000000))))'''))
 qs.append(('all_discriminator_membership','''(declare-fun u () (_ BitVec 16))
(define-fun t () (_ BitVec 16) (bvadd (bvxor u #x11c3) #x0003))
(define-fun lower () Bool (bvslt t #x9549))
(define-fun middle () Bool (and (not lower) (bvslt t #x411b)))
(define-fun upper () Bool (and (not lower) (not (bvslt t #x411b))))
(assert (or (distinct (and lower (= t #x86b7)) (= u #x9777))
 (distinct (and middle (= t #x9549)) (= u #x8485))
 (distinct (and upper (= t #x411b)) (= u #x50db))))'''))
 terms=[]
 for c,mask,shift in [(0x912ba00892000000,0x124,24),(0xcac5265e25230000,0x46,16),(0x2d4d03d3cc9d2e00,0x5c,8)]:
  terms.append(f'(distinct (bvxor (bvadd #x{c:016x} (bvshl (bvsub v (bvand (_ bv{mask} 64) (bvshl v (_ bv1 64)))) (_ bv{shift} 64))) #x{c:016x}) (bvshl v (_ bv{shift} 64)))')
 qs.append(('u64_middle_byte_insertions','(declare-fun byte () (_ BitVec 8))\n(define-fun v () (_ BitVec 64) ((_ zero_extend 56) byte))\n(assert (or '+' '.join(terms)+'))'))
 qs.append(('u64_value_encoding','''(declare-fun n () (_ BitVec 64))
(define-fun hi () (_ BitVec 64) (bvand n #xffffffffffffff00))
(define-fun lo () (_ BitVec 64) (bvand n #x00000000000000ff))
(define-fun a () (_ BitVec 64) (bvadd (bvsub hi (bvand #x5532bc7ed0d2fe66 (bvshl hi #x0000000000000001))) #x2a995e3f68697f13))
(define-fun b () (_ BitVec 64) (bvadd (bvsub lo (bvand #x000000000000016c (bvshl lo #x0000000000000001))) #xb05f467430dd7fb6))
(assert (distinct (bvxor (bvand (bvxor a #x0137beb08ba759b3) (bvxor b #x4fa0b98bcf228049)) (bvand b #x000002200001d95f) #x078ce897f8ad861d) (bvxor n #x2c220a381b62f9ab)))'''))
 qs.append(('constructor_extent_recovery','''(declare-fun p () (_ BitVec 32))
(define-fun e () (_ BitVec 32) (bvxor p #x8b3dc651))
(define-fun a () (_ BitVec 32) (bvxor (bvadd (bvxor e #x98db7b4e) #x672484b2) (bvadd (bvxor e #x57c78a08) #xa83875f8)))
(define-fun x () (_ BitVec 32) (bvxor (bvadd (bvxor e #x44213717) #xbbdec8e9) a))
(assert (distinct (bvadd x #x8b3dc651) p))'''))
 qs.append(('buffer_size_p_plus10','''(declare-fun p () (_ BitVec 32))
(define-fun e () (_ BitVec 32) (bvxor p #x8b3dc651))
(define-fun a () (_ BitVec 32) (bvxor (bvadd (bvxor e #x55759c84) #xaa8a637c) (bvadd (bvxor e #x49e278ca) #xb61d8736) (bvadd (bvxor e #x97aa221f) #x6855dde1)))
(assert (distinct (bvadd a #x8b3dc65b) (bvadd p #x0000000a)))'''))
 qs.append(('initial_fit_implies_constructor_extent_bound','''(declare-fun p () (_ BitVec 32)) (declare-fun n () (_ BitVec 32))
(assert (bvule (bvadd ((_ zero_extend 32) p) #x000000000000000a) ((_ zero_extend 32) n)))
(assert (not (bvult p #xfffffff6)))'''))
 out=[]
 for name,body in qs:
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Manually instruction-matched scalar identities under the inherited frame contract; no native reachability, valid pointers, authorization, whole CFG or recovered-code execution.'})
 return out

def type_models():
 def signed(x):return x-65536 if x&32768 else x
 counts={'lower':0,'middle':0,'upper':0};accepted=[];digest=bytearray()
 for u in range(65536):
  t=((u^0x11c3)+3)&65535
  if signed(t)<signed(0x9549):leaf='lower';ok=t==0x86b7;role='BE32'
  elif signed(t)<signed(0x411b):leaf='middle';ok=t==0x9549;role='BE64'
  else:leaf='upper';ok=t==0x411b;role='variable'
  counts[leaf]+=1;digest.extend(bytes([{'lower':0,'middle':1,'upper':2}[leaf],int(ok)]))
  if ok:accepted.append({'wire_u16':hex(u),'stored_u16':hex(u^0x11c3),'role':role,'required_extent_bytes':{'BE32':4,'BE64':8,'variable':None}[role]})
 assert [(r['wire_u16'],r['role'])for r in accepted]==[('0x50db','variable'),('0x8485','BE64'),('0x9777','BE32')]
 # Constant states, shifts and branch bases, independently reduced from retained instructions.
 assert ((0x6a6b+0x59bc154b)&0xa643f7e9)==0x77a0
 assert ((0x6a6b+0x5bf7f54a)&0xa407abff)==0xbb5
 assert (0xbb5-0xb9d,0x77a0^0x77b0)==(24,16)
 assert ((0x77a0-0x6996)|0x20d1)==0x2edb
 assert (0x2edb+0x666e)==0x9549 and((0x2edb+0x1240)&65535)==0x411b
 assert (0x2edb+0x14e0,0x2edb-0x2326)==(0x43bb,0xbb5)
 assert(0x43bb-0x85b)==0x3b60 and(0x43bb-0x307b)|0x2820==0x3b60
 assert(0x3b60-0x3b53)==13
 assert ((0x5f5a+0x805f7060)&0x7fa0b97f)==0x893a
 assert (((0x5938^0x5d18)*0x1d+0xbbddf868)&0xffffffff)^(0x5938+0x5fa9)==0xbbdec8e9
 variable_cases=[{'tag_is_zero':z,'extent_is_zero':e,'selected_role':'result'if z else'construct'}for z in[False,True]for e in[False,True]]
 return {'variable_tag_cases':variable_cases,'cases_checked':65536,'signed_leaf_counts':counts,'accepted':accepted,'rejected_discriminators':65533,'routing_membership_sha256':h(digest),'scope':'Exhaustive analyst-written 16-bit discriminator model. Extent and outer-record gates remain prerequisites; membership is not whole-protocol acceptance.'}

def alterations(s):
 def instruction(q,name,ea,op):next(i for i in q['fragments'][name]['instructions']if i['ea']==ea).update(operands=op)
 def bank(q):
  r=q['banks']['allocate_object'];b=bytearray.fromhex(r['left_bytes']);b[0]^=1;r['left_bytes']=b.hex()
 changes=[('bank_byte',bank),('signed_discriminator',lambda q:instruction(q,'signed_root','0x100d31e34','w1, lo')),
  ('u32_endian',lambda q:instruction(q,'u32_value','0x100a8a6d0','w12, w13, w12, lsl #8')),
  ('u64_width',lambda q:instruction(q,'u64_value','0x100a611ec','w12, w12, #0x18')),
  ('local_record_extent_offset',lambda q:instruction(q,'local_record','0x100a86154','w24, [sp, #0xa44]')),
  ('object_allocation_size',lambda q:instruction(q,'allocate_object','0x1009ba540','w0, #0x10')),
  ('authentication_modifier',lambda q:q['calls'][1].update(modifier_u16=0)),
  ('native_authorization',lambda q:q.update(native_authorization_proved=True))]
 out=[]
 for name,change in changes:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence '+name)
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();models=type_models();neg=alterations(s)
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':rows,'SDK_checks':sdk,'proofs':pr,'type_models':models,'alterations':neg,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
 'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'discriminator_model_cases':models['cases_checked'],'variable_tag_model_cases':len(models['variable_tag_cases']),'rejected_evidence_alterations':len(neg)},'all_checks_pass':True,
 'static_scope':'Initial fitted record: header fields, all 16-bit discriminator patterns, three value branches, local argument layout, selected constructor allocations and result/saved-continuation frontiers. Later serialization, container insertion/iteration, dispatch/reply/cleanup and native daemon-kext behavior remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
