#!/usr/bin/env python3
"""Static XPC consumer partition, audit-copy paths and protected handoff checks."""
import copy,json,struct,subprocess
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from recover_daemon_xpc_core_bridge import ROOT,P,FLAGS,SDK,CS,sha,h,build,FRAGMENTS,COMPLETE,SPECS,BRANCHES,PRIOR_PROOFS
PATTERNS='''
value_load|ldr|w8, [sp, #0x82c]
consumer|cmp|w8, w12
consumer|cset|w12, lt
lower_test|cmp|w8, w10
upper_test|cmp|w8, w11
fallback|ldr|x8, [sp, #0x820]
fallback|ldr|x9, [sp, #0x498]
fallback|eor|x9, x9, x10
fallback|str|x8, [sp, #0x850]
fallback|str|x9, [sp, #0x858]
fallback|ldr|x8, [sp, #0xc0]
fallback|str|x8, [sp, #0x860]
fallback|add|x23, sp, #0x850
fallback|add|x0, sp, #0x3c4
fallback|add|x1, x23, #0x18
fallback|mov|w2, #0x20
fallback|add|x8, sp, #0x408
fallback|add|x9, sp, #0x6e8
fallback|str|x8, [sp, #0x888]
fallback|str|x9, [sp, #0x890]
fallback|stur|x8, [x29, #-0xa0]
fallback|stur|x23, [x29, #-0x90]
fallback|stp|w8, w11, [x29, #-0x98]
fallback|ldr|x8, [x8]
fallback|str|x8, [sp, #0xa98]
fallback|sub|x0, x29, #0xa0
fallback|add|x1, sp, #0xa98
fallback|ldr|x9, [sp, #0xa98]
fallback|mov|sp, x8
fallback|ldur|w20, [x29, #-0x88]
special_lower|add|x0, sp, #0x3c4
special_lower|add|x1, sp, #0x784
special_lower|mov|w2, #0x20
special_lower|ldr|x26, [sp, #0x18]
special_lower|ldr|x9, [x26, #0x10]
special_lower|stur|w10, [x29, #-0xa0]
special_lower|stur|x9, [x29, #-0x98]
special_lower|sub|x0, x29, #0xa0
special_upper|mov|w0, #0x10
copy_helper|eor|w8, w1, w0
copy_helper|subs|w8, w8, #1
copy_helper|subs|x9, x9, #1
fallback_adapter|mov|x19, x1
fallback_adapter|ldr|x21, [x19]
fallback_adapter|sub|x16, x21, #0xe0
fallback_adapter|str|x16, [x20]
fallback_adapter|mov|x1, x20
fallback_adapter|ubfiz|x8, x8, #4, #0x10
fallback_adapter|str|x8, [x19]
getter_tag_return|strh|w1, [sp, #0x8ce]
'''
def copy_paths():
 def entries(pcs):
  out=[];off=0
  for a,size in pcs:
   out.append({'load_site':hex(a),'store_site':hex(a+4),'source_offset':off,'destination_offset':off,'bytes':size});off+=size
  assert off==32;return out
 bytepcs=[(a,1)for a in range(0x10046f9e4,0x10046fa24,8)]
 lowerpcs=[(a,1)for a in range(0x10046f948,0x10046f968,8)]+[(a,8)for a in range(0x10046fa58,0x10046fa70,8)]+[(a,1)for a in range(0x10046fad4,0x10046faf4,8)]
 return [{'role':'fallback','source_mod8':4,'destination_mod8':0,'prefix_bytes':0,'bulk_bytes':32,'tail_bytes':0,'byte_iterations':4,'entries':entries(bytepcs*4),'terminal':'0x10046fa2c'},
 {'role':'special_lower','source_mod8':4,'destination_mod8':4,'prefix_bytes':4,'bulk_bytes':24,'tail_bytes':4,'byte_iterations':None,'entries':entries(lowerpcs),'terminal':'0x10046faf4'}]

def verify(s):
 assert s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 rows=[]
 for name,f in s['fragments'].items():
  a=int(f['start'],16);bb=bytes.fromhex(f['bytes']);ii=list(CS.disasm(bb,a));assert h(bb)==f['sha256']and len(bb)==int(f['end'],16)-a==4*len(ii)
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]
  assert a==(FRAGMENTS.get(name)or COMPLETE[name][0])
 for line in PATTERNS.strip().splitlines():
  name,mn,op=line.split('|');hits=[i for i in s['fragments'][name]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(name,mn,op);rows.extend({'role':name,**i}for i in hits)
 for name,pair,key,add,base,bias in SPECS:
  r=s['banks'][name];l,rr=bytes.fromhex(r['left_bytes']),bytes.fromhex(r['right_bytes']);outputs=[i^rr[l[i]^key]for i in range(256)]
  assert len(l)==len(rr)==256 and outputs==r['results_256']and set(outputs)=={int(r['constant'],16)}
  assert(r['left'],r['right'],int(r['key'],16),int(r['additive'],16))==(hex(pair[0]),hex(pair[1]),key,add)
  assert int(r['slot'],16)==base+8*(add+outputs[0])and int(r['bias'],16)==bias
 targets={'fallback_copy':'0x10046f89c','lower_copy':'0x10046f89c','fallback_adapter':'0x10065ffd8','lower_acquire':'0x10043e280','upper_malloc':'libSystem/_malloc','protected_core':'0x10061a2d0'}
 for r in s['calls']:
  b=s['banks'][r['role']];w=int(r['pointer_word'],16);ii=list(CS.disasm(bytes.fromhex(r['bytes']),int(r['site'],16)-4))
  assert r['target']==b['target']==targets[r['role']]and r['slot']==b['slot']
  assert w>>63 and(w>>32&65535)==r['modifier_u16']and not(w>>48&1)and not(w>>49&3)
  assert ii[0].op_str==f'x17, #{hex(r["modifier_u16"])}'and ii[1].mnemonic=='blraa'
 assert s['banks']['budget_cell']['target']=='0x1010c4d68'
 assert [(r['role'],r['source'],int(r['index'],16),int(r['target'],16))for r in s['branches']]==BRANCHES
 for r in s['branches']:
  w=int(r['pointer_word'],16);assert w>>63 and(w>>32&65535)==r['modifier_u16']and int(r['slot'],16)==0x101039ef0+8*int(r['index'],16)
 assert s['complete_functions']==['copy_helper']and s['adapter_compiler_span']=={'start':'0x10065ffd8','next_start':'0x100873194','selected_return_end':'0x100660254'}
 assert s['compiler_starts_reference']['starts_compared']==1005 and s['fixup_reference']['catalog_memberships_compared']==61737
 assert len(s['prior_source_recaptures'])==49 and sum(r['bytes_checked']for r in s['prior_source_recaptures'])==19016
 # Static instruction access metadata verifies helper preservation and adapter X0.
 detail=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);detail.detail=True
 for name in ['copy_helper','fallback_adapter']:
  f=s['fragments'][name]
  for i in detail.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)):
   if name=='fallback_adapter'and i.address>=0x10066022c:break
   writes={i.reg_name(r)for r in i.regs_access()[1]};writes={('x'+r[1:])if r.startswith('w')and r[1:].isdigit()else r for r in writes}
   held={'sp'}|{'x'+str(j)for j in range(19,30)}if name=='copy_helper'else{'x0'}
   assert not writes&held,(name,hex(i.address),writes&held)
  if name=='copy_helper':assert not any(i['mnemonic'].startswith('bl')for i in f['instructions'])
 byea={i['ea']:i for i in s['fragments']['copy_helper']['instructions']}
 for path in copy_paths():
  covered=[]
  for e in path['entries']:
   load,st=byea[e['load_site']],byea[e['store_site']];n=e['bytes'];reg='x10'if n==8 else'w9'if e['load_site']<'0x10046fab0'else'w8'
   assert load['mnemonic']==('ldr'if n==8 else'ldrb')and st['mnemonic']==('str'if n==8 else'strb')
   assert load['operands'].startswith(reg+', [x0]')and st['operands'].startswith(reg+', [x1]')
   covered.extend(range(e['source_offset'],e['source_offset']+n))
  assert covered==list(range(32))
 assert all(s[k]is False for k in FLAGS);return rows

def sdk_checks():
 code='''#define OS_OBJECT_USE_OBJC 0
#include <xpc/xpc.h>
#include <stdint.h>
#include <stddef.h>
#define A(x) static_assert((x),#x)
struct Bridge72 {void* bytes;uint64_t length;xpc_connection_t peer;audit_token_t audit;void* output0;void* output1;};
struct Protected32 {uint64_t encoded;uint32_t primary,operation;void* borrowed;uint32_t result,unknown28;};
struct Acquire16 {uint32_t control,unknown4;void* captured;};
A(sizeof(void*)==8);A(sizeof(uint32_t)==4);A(sizeof(uint64_t)==8);A(sizeof(audit_token_t)==32);
A(sizeof(Bridge72)==72);A(offsetof(Bridge72,length)==8);A(offsetof(Bridge72,peer)==16);A(offsetof(Bridge72,audit)==24);A(offsetof(Bridge72,output0)==56);A(offsetof(Bridge72,output1)==64);
A(sizeof(Protected32)==32);A(offsetof(Protected32,primary)==8);A(offsetof(Protected32,operation)==12);A(offsetof(Protected32,borrowed)==16);A(offsetof(Protected32,result)==24);
A(sizeof(Acquire16)==16);A(offsetof(Acquire16,captured)==8);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return {'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Reconstructed private layouts and public XPC/audit widths; no native object/type attestation.'}

def proofs():
 qs=[('all_u32_consumer_partition','''(declare-fun v () (_ BitVec 32))
(define-fun lower () Bool (bvslt v #xab924931))
(define-fun eq () (_ BitVec 32) (ite (= v #xab924931) #x00000001 #x00000000))
(define-fun x () (_ BitVec 32) (bvxor #x00008970 eq))
(define-fun y () (_ BitVec 32) (bvnot x))
(define-fun z () (_ BitVec 32) (bvshl (bvand #x00000001 (bvnot x)) #x00000001))
(define-fun mux () (_ BitVec 32) (bvor (bvand z #xfffffffb) (bvshl (bvand y #x00000001) #x00000002)))
(define-fun upper_index () (_ BitVec 32) (bvxor mux #x00002d1b))
(assert (or
 (distinct upper_index (ite (= v #xab924931) #x00002d1b #x00002d1d)) (distinct (and lower (= v #x88594abe)) (= v #x88594abe))
 (distinct (and (not lower) (= v #xab924931)) (= v #xab924931))
 (distinct (not (or (and lower (= v #x88594abe)) (and (not lower) (= v #xab924931))))
 (and (distinct v #x88594abe) (distinct v #xab924931)))))'''),
 ('acquisition_caller_prekey_aligned','''(declare-fun r () (_ BitVec 32))
(assert (= (bvand r #x00000007) #x00000000))
(define-fun original () (_ BitVec 32) (bvxor (bvsub (bvxor (bvor r #x36146cee) #xfffffffe) (bvor #xc9eb9311 (bvnot r))) #x51953f9b))
(assert (distinct original (bvxor r #x987eac8a)))'''),
 ('fallback_pointer_control_phase','''(declare-fun u () (_ BitVec 64))
(assert (or (distinct (bvxor (bvadd (_ bv41526 64) #x1c0b9f7ce10e801f) u) (bvxor u #x1c0b9f7ce10f2255))
 (distinct (bvadd #x00004f79 #x00001d7b) #x00006cf4)))'''),
 ('adapter_hint_and_delta','''(declare-fun seed () (_ BitVec 64)) (declare-fun result () (_ BitVec 32))
(define-fun hint () (_ BitVec 64) (bvand (bvadd (bvshl (bvlshr (bvadd (bvmul seed #x0000000000002e95) #x0000000000000001) #x000000000000003c) #x0000000000000004) #x000000000000001f) #x00000000000001f0))
(define-fun delta () (_ BitVec 64) (bvshl ((_ zero_extend 48) ((_ extract 15 0) (bvsub result ((_ extract 31 0) seed)))) #x0000000000000004))
(assert (or (bvult hint #x0000000000000010) (bvugt hint #x0000000000000100) (distinct (bvand hint #x000000000000000f) #x0000000000000000) (bvugt delta #x00000000000ffff0)))'''),
 ('audit_copy_alignment_geometry','''(declare-fun sp () (_ BitVec 64))
(assert (= (bvand sp #x000000000000000f) #x0000000000000000))
(assert (or (distinct (bvand (bvadd sp #x00000000000003c4) #x0000000000000007) #x0000000000000004)
 (distinct (bvand (bvadd sp #x0000000000000784) #x0000000000000007) #x0000000000000004)
 (distinct (bvand (bvadd sp #x0000000000000868) #x0000000000000007) #x0000000000000000)))''')]
 for path in copy_paths():
  pieces=[f'((_ extract {8*(e["source_offset"]+e["bytes"])-1} {8*e["source_offset"]}) token)'for e in reversed(path['entries'])]
  qs.append(('all_256_audit_bits_'+path['role'],'(declare-fun token () (_ BitVec 256))\n(assert (distinct (concat '+' '.join(pieces)+') token))'))
 out=[]
 for name,body in qs:
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Instruction-matched caller/ABI equations and two declared 32 B copy paths; no native transport, credentials, hardware PAC or recovered-code execution.'})
 for name in PRIOR_PROOFS:
  p=ROOT/name;q='(set-option :timeout 10000)\n'+p.read_text();r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True,timeout=20)
  assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'prior_original_file':name,'prior_original_sha256':sha(p),'result':'unsat','scope':'Freshly re-solved retained original constructor/phase obligation. Source ranges separately recaptured; prior CPU/API experiments are not replayed or made native.'})
 return out

def models():
 vals=sorted({0,1,0x7fffffff,0x80000000,0xffffffff,*[(v+d)&0xffffffff for v in[0x88594abe,0xab924931]for d in[-1,0,1]]})
 rows=[]
 for v in vals:
  signed=lambda x:x-(1<<32)if x>>31 else x
  role='special_lower'if signed(v)<signed(0xab924931)and v==0x88594abe else'special_upper'if signed(v)>=signed(0xab924931)and v==0xab924931 else'fallback'
  rows.append({'consumer_word':hex(v),'role':role,'phase_W19':hex(0x4f79)if role=='fallback'else None})
 assert(0x2d1d+0x32697962)&0xcd96dde9==0x8469
 assert(0x2d1d+0x493832de)&0xb6c7ef7d==0x4f79
 assert(0x4f79+0x8858fb45)==0x88594abe and(0x2d1b+0x225e)==0x4f79
 assert(0x8469-0x2b2c)==0x593d
 assert((0x4f79^0x4f6b)*0x903)==0xa236
 assert((32+7)>>3)==4 and(32&7)==0
 assert(32-4)==28 and(28>>3)==3 and(28&7)==4
 return {'consumer_boundary_cases':rows,'copy_paths':copy_paths(),'scope':'Analyst-written scalar/path ledgers. Copy source/destination buffers are disjoint; no target CPU or native sender fixture executes.'}

def alterations(s):
 def instruction(q,name,ea,op):next(i for i in q['fragments'][name]['instructions']if i['ea']==ea).update(operands=op)
 def bank(q):
  r=q['banks']['fallback_adapter'];b=bytearray.fromhex(r['left_bytes']);b[0]^=1;r['left_bytes']=b.hex()
 changes=[('bank_byte',bank),('consumer_signedness',lambda q:instruction(q,'consumer','0x100d281e4','w12, lo')),
 ('forwarded_length_width',lambda q:instruction(q,'fallback','0x100a86c94','w9, [sp, #0x858]')),
 ('peer_slot',lambda q:instruction(q,'fallback','0x100a86c9c','x8, [sp, #0x858]')),
 ('audit_copy_source',lambda q:instruction(q,'fallback','0x100a86cf4','x0, sp, #0x3c0')),
 ('core_target',lambda q:q['banks']['protected_core'].update(target='0x100b27b78')),
 ('call_modifier',lambda q:q['calls'][2].update(modifier_u16=0)),('native_authorization',lambda q:q.update(native_authorization_proved=True))]
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
 'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'consumer_boundary_cases':len(mm['consumer_boundary_cases']),'audit_copy_paths':2,'audit_copy_entries':sum(len(p['entries'])for p in mm['copy_paths']),'rejected_evidence_alterations':len(neg)},'all_checks_pass':True,
 'static_scope':'Conditional local consumer partition, two audit-copy paths, 72 B XPC fallback record, aligned protected tag/operation constructor, adapter/core targets and special synchronization/allocation requests. Retained A70 policy paths keep prior framework/setup assumptions. Full getter/wire-value correspondence, native authorization, replies and daemon-kext exchange remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
