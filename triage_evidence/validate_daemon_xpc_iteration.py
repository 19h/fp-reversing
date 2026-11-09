#!/usr/bin/env python3
"""Static loop/status/linked-lookup contracts and bounded arithmetic checks."""
import copy,hashlib,json,struct,subprocess
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from recover_daemon_xpc_iteration import ROOT,P,FLAGS,SDK,CS,sha,h,build,FRAGMENTS,BRANCHES
PATTERNS='''
helper_status|cmp|w23, w9
helper_status|mov|w8, #0x77a2
helper_status|mov|w9, #0x1141
resume|ldr|x8, [sp, #0x450]
resume|ldr|w22, [sp, #0x680]
loop_gate|subs|x11, x10, x8
loop_gate|cset|w14, hi
minimum|cmp|x11, x13
extent|add|x12, x8, #0xa
extent|add|x11, x11, x12
extent|cmp|x11, x10
outer|ldr|w8, [sp, #0x7b8]
outer_signed|cmp|w8, w12
outer_signed|cset|w13, lt
outer_upper|movk|w13, #0x57de, lsl #16
outer_equal|cmp|w8, w13
outer_status|cmp|w23, w9
outer_status|ldr|x13, [sp, #0x1c8]
prepare_lookup|add|x13, sp, #0x82c
prepare_lookup|mov|w8, #0x57b9
prepare_lookup|movk|w8, #0xff76, lsl #16
prepare_lookup|add|x11, sp, #0x898
lookup_entry|ldr|x20, [x11]
lookup_entry|str|x9, [sp, #0x460]
lookup_entry|str|x13, [sp, #0x2c0]
lookup_entry|str|xzr, [sp, #0x718]
lookup_nonnull|add|x9, sp, #0x718
query_setup|str|x10, [sp, #0x520]
search_entry|str|w8, [sp, #0xa6c]
search_entry|str|x9, [sp, #0xa70]
next_node|ldr|x10, [x20]
next_node|str|x10, [sp, #0xa78]
next_node|mov|x20, #0
candidate|ldr|x10, [x10, #0x18]
candidate|mov|x1, x19
decode_setup|ldr|x20, [x28, w12, sxtw #3]
decode_bytes|ldr|x20, [x28, w16, sxtw #3]
decode_bytes|ldrb|w26, [x17]
decode_bytes|ldrb|w23, [x27]
decode_bytes|ldrb|w25, [x24]
decode_bytes|ldrb|w16, [x1]
decode_bytes|bic|w10, w10, w16
decode_bytes|and|w16, w16, w9
decode_bytes|orr|w1, w10, w16
compare|ldr|w27, [sp, #0x234]
compare|ldr|w11, [sp, #0xa6c]
compare|cmp|w10, w11
compare|ldr|x20, [sp, #0xa78]
advance_node|add|w8, w27, #0x38c
output_node|ldr|x9, [sp, #0xa70]
output_node|str|x20, [x9]
output_node|ldr|x10, [sp, #0x520]
search_status|cmp|w23, w9
found_node|ldr|x11, [sp, #0x718]
found_node|ldr|x10, [x11, #0x18]
found_node|ldr|w11, [x11, #0x10]
lookup_return|ldr|x9, [sp, #0x460]
value_continuation|ldr|w8, [sp, #0x82c]
failure|str|w23, [sp, #0x81c]
'''
def verify(s):
 assert s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 rows=[]
 for name,a in FRAGMENTS.items():
  f=s['fragments'][name];bb=bytes.fromhex(f['bytes']);ii=list(CS.disasm(bb,a));assert f['start']==hex(a)and h(bb)==f['sha256']and len(bb)==int(f['end'],16)-a==4*len(ii)
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]
  assert ii[-1].mnemonic=='braa'
 for line in PATTERNS.strip().splitlines():
  name,mn,op=line.split('|');hits=[i for i in s['fragments'][name]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(name,mn,op);rows.extend({'role':name,**i}for i in hits)
 assert [(r['role'],r['source'],int(r['index'],16),int(r['target'],16))for r in s['branches']]==BRANCHES
 for r in s['branches']:
  w=int(r['pointer_word'],16);assert int(r['slot'],16)==0x101039ef0+8*int(r['index'],16)and w>>63 and(w>>32&65535)==r['modifier_u16']and not(w>>48&1)and not(w>>49&3)
 assert not s['banks']and not s['calls']and not s['imports']
 dec=s['fragments']['decode_bytes']['instructions'];assert len(dec)==540
 assert [i['ea']for i in dec if i['mnemonic']=='ldrb']==['0x100c9f134','0x100c9f198','0x100c9f514','0x100c9f720']
 assert not any(i['mnemonic'].startswith(('st','bl'))for i in dec)
 # Decoder register-role checks; static Capstone access metadata, not execution.
 detail=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);detail.detail=True
 for name,held,before in [('query_setup',{'x8','x9','x20'},None),('decode_setup',{'x1','x10','x16'},None),('decode_setup',{'x12'},0x100c4d988)]:
  f=s['fragments'][name]
  for i in detail.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)):
   if before is not None and i.address>=before:break
   writes={i.reg_name(r)for r in i.regs_access()[1]}
   writes={('x'+r[1:])if r.startswith('w')and r[1:].isdigit()else r for r in writes}
   assert not writes&held,(name,hex(i.address),writes&held)
 assert s['fixup_reference']['catalog_memberships_compared']==61737 and all(s[k]is False for k in FLAGS)
 return rows

def sdk_checks():
 code='''#include <stdint.h>
#include <stddef.h>
#define A(x) static_assert((x),#x)
struct QPrefix {void* head;void* unknown8;};
struct NodePrefix {void* next;void* unknown8;uint32_t length,unknown20;void* buffer;};
A(sizeof(void*)==8);A(sizeof(uint32_t)==4);A(sizeof(uint64_t)==8);
A(sizeof(QPrefix)==16);A(offsetof(QPrefix,head)==0);
A(sizeof(NodePrefix)==32);A(offsetof(NodePrefix,next)==0);A(offsetof(NodePrefix,length)==16);A(offsetof(NodePrefix,buffer)==24);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return {'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Analytical prefix layouts only, not canonical Apple private types.'}

def proofs():
 qs=[('loop_fit_progress_and_header_range','''(declare-fun n () (_ BitVec 32)) (declare-fun p () (_ BitVec 32)) (declare-fun c () (_ BitVec 64))
(define-fun N () (_ BitVec 64) ((_ zero_extend 32) n))
(define-fun P () (_ BitVec 64) ((_ zero_extend 32) p))
(define-fun end () (_ BitVec 64) (bvadd c #x000000000000000a P))
(assert (bvule c N))
(assert (or (bvult end c)
 (and (bvule end N) (or (bvule end c) (bvult (bvsub end c) #x000000000000000a) (bvult (bvsub N c) #x000000000000000a)))))'''),
 ('loop_remaining_count_restore','''(declare-fun n () (_ BitVec 32))
(define-fun encoded () (_ BitVec 32) (bvxor n #x8b3dc651))
(define-fun recovered () (_ BitVec 32) (bvxor #x8b3dc651 encoded))
(assert (distinct ((_ zero_extend 32) recovered) ((_ zero_extend 32) n)))'''),
 ('status_gate_targets','''(declare-fun s () (_ BitVec 32))
(define-fun eq () (_ BitVec 32) (ite (= s #x8b3dc651) #x00000001 #x00000000))
(define-fun a () (_ BitVec 32) (bvxor #x00005c78 (bvmul eq #x0000fd79)))
(define-fun b () (_ BitVec 32) (bvxor #x000077ae (bvmul eq #x0000fa70)))
(assert (or (distinct a (ite (= s #x8b3dc651) #x0000a101 #x00005c78))
 (distinct b (ite (= s #x8b3dc651) #x00008dde #x000077ae))))''')]
 terms=[]
 for j in range(4):terms.append(f'(distinct (bvadd base #x661a590b302baf96 (_ bv{(0x99e5a6f4cfd4506a+j)&((1<<64)-1)} 64)) (bvadd base (_ bv{j} 64)))')
 qs.append(('four_candidate_byte_addresses','(declare-fun base () (_ BitVec 64))\n(assert (or '+' '.join(terms)+'))'))
 qs.append(('decoder_final_merge_identity','''(declare-fun n () (_ BitVec 32))
(define-fun s () (_ BitVec 32) (bvand n #xffffff00))
(define-fun c () (_ BitVec 32) (bvxor (bvand n #x000000ff) #x8ec35f5b))
(define-fun d () (_ BitVec 32) (bvxor (bvor (bvand c (bvnot s)) (bvand s #x713ca000)) #x05fe9959))
(assert (distinct d (bvxor n #x8b3dc602)))'''))
 out=[]
 for name,body in qs:
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Instruction-matched scalar formulas under recorded cursor/frame constraints; opaque address-mask circuits remain retained, not proved equivalent to wire H.'})
 return out

def models():
 counts={'end':0,'short':0,'fits':0,'exceeds':0};digest=hashlib.sha256();cases=0
 for n in range(65):
  for c in range(n+1):
   for p in [0,1,4,8,64,0xffffffff]:
    rem=n-c;end=c+10+p
    role='end'if rem==0 else'short'if rem<10 else'fits'if end<=n else'exceeds'
    if role=='fits':assert c<end<=n and end-c>=10
    counts[role]+=1;cases+=1;digest.update(json.dumps([n,c,p,role,end if role=='fits'else None],separators=(',',':')).encode())
 lookup=[]
 for n in range(9):
  for mask in range(1<<n):
   expected=next((j for j in range(n)if mask>>j&1),None)
   actual=None
   for j in range(n):
    if mask>>j&1:actual=j;break
   assert actual==expected;lookup.append([n,mask,actual])
 assert len(lookup)==511
 # Independent constant reductions for retained frame/control path.
 op=0x77a0;assert ((op+0x011d181f)&0xfee27bf5)==0xbb5
 assert((op^0x77a2)*0x1141)==0x2282 and(0x2282^0x8b3de4d3)==0x8b3dc651
 w20=0x44877a43;assert w20>=((w20+0xdd438951)&0xffffffff)
 assert ((w20+0xbb793ad5)&0xffffffff)^0x703a==0xc522
 assert (0xfc3677ae&0x03c9ffff)==0x77ae
 assert ((op+0x506d4857)&0xaf924269)==0x261
 assert ((0x261+0x219f)|0x53a0)==op
 assert((op+0x7c72081c)&0x838dfb6f)==0x7b2c
 assert op+0x38c==0x7b2c and((op-0x764c)|0x5200)==0x5354
 assert (0x5354-0x52f5)==0x5f and(op-0x2d6b)==0x4a35
 assert ((0x5290|0xc28)+0xa84e+0x8b3cbf4b)&0xffffffff==0x8b3dc651
 return {'loop_cases':cases,'loop_classes':counts,'loop_models_sha256':digest.hexdigest(),'lookup_cases':len(lookup),'lookup_models_sha256':h(json.dumps(lookup,separators=(',',':')).encode()),'scope':'Analyst-written scalar/frame models and abstract finite chains. No recovered-code execution or native object fixtures; cycles and ownership remain outside finite-chain assumptions.'}

def alterations(s):
 def instruction(q,name,ea,op):next(i for i in q['fragments'][name]['instructions']if i['ea']==ea).update(operands=op)
 changes=[('resume_cursor_slot',lambda q:instruction(q,'resume','0x100bd6fe0','x8, [sp, #0x448]')),
 ('next_link_offset',lambda q:instruction(q,'next_node','0x100bb5ab4','x10, [x20, #8]')),
 ('candidate_buffer_offset',lambda q:instruction(q,'candidate','0x100b09100','x10, [x10, #0x10]')),
 ('comparison_width',lambda q:instruction(q,'compare','0x100c1c2d8','x10, x11')),
 ('query_literal',lambda q:instruction(q,'prepare_lookup','0x100bb019c','w8, #0x57b8')),
 ('fourth_byte_address',lambda q:instruction(q,'decode_bytes','0x100c9f720','w16, [x1, #1]')),
 ('branch_modifier',lambda q:q['branches'][0].update(modifier_u16=0)),
 ('native_authorization',lambda q:q.update(native_authorization_proved=True))]
 out=[]
 for name,change in changes:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence '+name)
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();mm=models();neg=alterations(s)
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':rows,'SDK_checks':sdk,'proofs':pr,'models':mm,'alterations':neg,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
 'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'loop_model_cases':mm['loop_cases'],'lookup_model_cases':mm['lookup_cases'],'rejected_evidence_alterations':len(neg)},'all_checks_pass':True,
 'static_scope':'Conditional record-loop advance and outer result/status selection; fixed encoded lookup query, Q/node traversal, four address-dependent candidate bytes, 32-bit comparison, output and return continuations. Full mask/packing-to-wire correspondence, later value extraction/dispatch, lifecycle, native authorization and daemon-kext interaction remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
