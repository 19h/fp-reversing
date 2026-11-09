#!/usr/bin/env python3
"""Recheck original bytes and conditional output contracts; no target execution."""
import copy,json,subprocess
from recover_daemon_xpc_error_outputs import ROOT,P,FLAGS,SDK,CS,sha,h,build,FIXED,BLOCKS,EDGES,SCOPE
PATTERNS='''
prologue|pacibsp|
prologue|stp|d11, d10, [sp, #-0x80]!
prologue|stp|x29, x30, [sp, #0x70]
prologue|add|x29, sp, #0x70
prologue|mov|w9, #0xd50
prologue|movk|w9, #1, lsl #16
prologue|sub|sp, sp, #0x10, lsl #12
prologue|sub|sp, sp, #0xd50
prologue|stur|x8, [x29, #-0x88]
xpc_prologue|stp|x28, x27, [sp, #-0x60]!
xpc_prologue|add|x29, sp, #0x50
xpc_prologue|sub|sp, sp, #0xee0
save_record|str|x0, [sp, #0x580]
xpc_cells|add|x8, sp, #0x408
xpc_cells|add|x9, sp, #0x6e8
xpc_cells|str|x8, [sp, #0x888]
xpc_cells|str|x9, [sp, #0x890]
a70_head|ldp|x24, x27, [x19, #0x38]
a70_head|str|x24, [sp, #0x1a30]
a70_head|str|x27, [sp, #0x7098]
status_gate|mov|w8, #-0x5bf2
status_gate|mov|w9, #0x8a1
status_gate|add|w8, w19, w8
status_gate|orr|w8, w8, w9
status_gate|add|x9, sp, #4, lsl #12
status_gate|ldr|w6, [x9, #0x4a4]
status_gate|mov|w9, #0xc651
status_gate|movk|w9, #0x8b3d, lsl #16
status_gate|cmp|w6, w9
status_gate|cset|w9, eq
status_gate|mov|w10, #0x19b5
status_gate|eor|w10, w8, w10
status_gate|mul|w9, w9, w10
status_gate|mov|w10, #-0x29f2
status_gate|add|w10, w19, w10
status_gate|eor|w9, w9, w10
clear_outputs|ldr|x9, [sp, #0x1a30]
clear_outputs|str|xzr, [x9]
clear_outputs|ldr|x9, [sp, #0x7098]
clear_outputs|ldr|x9, [sp, #0x9d8]
clear_outputs|ldr|x8, [x9, w8, sxtw #3]
result_return|ldr|x8, [sp, #0x580]
result_return|str|w6, [x8, #0x18]
result_return|ldur|x8, [x29, #-0x88]
result_return|ldr|x9, [x9, #0xe18]
result_return|ldr|x9, [x9]
result_return|cmp|x9, x8
result_return|b.ne|#0x100528e24
result_return|add|sp, sp, #0x10, lsl #12
result_return|add|sp, sp, #0xd50
result_return|ldp|x29, x30, [sp, #0x70]
result_return|ldp|x20, x19, [sp, #0x60]
result_return|ldp|x22, x21, [sp, #0x50]
result_return|ldp|x24, x23, [sp, #0x40]
result_return|ldp|x26, x25, [sp, #0x30]
result_return|ldp|x28, x27, [sp, #0x20]
result_return|ldp|d9, d8, [sp, #0x10]
result_return|ldp|d11, d10, [sp], #0x80
result_return|retab|
guard_failure|bl|#0x100e2aad0
guard_stub|adrp|x17, #0x1010b1000
guard_stub|add|x17, x17, #0xd00
guard_stub|ldr|x16, [x17]
xpc_return|ldr|x9, [sp, #0xa98]
xpc_return|add|x8, x8, x9
xpc_return|mov|sp, x8
xpc_return|ldur|w20, [x29, #-0x88]
adapter_return|sub|sp, x29, #0x20
adapter_return|ldp|x29, x30, [sp, #0x20]
adapter_return|ldp|x22, x21, [sp], #0x30
adapter_return|retab|
adapter_return|ldr|w8, [x20]
adapter_return|sub|w8, w8, w21
adapter_return|ubfiz|x8, x8, #4, #0x10
adapter_return|str|x8, [x19]
adapter_budget_init|sub|x16, x21, #0xe0
adapter_budget_init|str|x16, [x20]
core_budget_update|ldr|x9, [x1]
core_budget_update|add|x9, x9, #0xe0
core_budget_update|str|x9, [x1]
'''

def verify(s):
 assert s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and s['static_scope']==SCOPE
 for n,f in s['fragments'].items():
  bb=bytes.fromhex(f['bytes']);a=int(f['start'],16);ii=list(CS.disasm(bb,a))
  assert len(bb)==int(f['end'],16)-a==4*len(ii)and h(bb)==f['sha256']
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]
  if n in FIXED:assert(a,int(f['end'],16))==FIXED[n]
  else:assert a==BLOCKS[n]and ii[-1].mnemonic in('braa','retab')
 assert set(s['fragments'])==set(FIXED)|set(BLOCKS)
 rows=[]
 for line in PATTERNS.strip().splitlines():
  n,mn,op=line.split('|');hits=[i for i in s['fragments'][n]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(n,mn,op);rows.extend({'role':n,**i}for i in hits)
 assert[(r['role'],r['source'],int(r['index'],16),int(r['target'],16))for r in s['branches']]==EDGES
 for r in s['branches']:
  w=int(r['pointer_word'],16);assert w>>63 and(w>>32&65535)==r['modifier_u16']and not(w>>48&1)and not(w>>49&3)
  assert int(r['slot'],16)==0x101039ef0+8*int(r['index'],16)
 imports={r['symbol']:r for r in s['imports']};assert set(imports)=={'___stack_chk_fail','___stack_chk_guard','___chkstk_darwin'}
 assert all(r['total_addend']==0 for r in imports.values())
 assert s['fixup_reference']['catalog_memberships_compared']==61737
 counts={}
 for r in s['historical_case_boundaries']:
  assert r['historical_boundary_PC']=='0x10057a774'and int(r['historical_W8'],16)==0x19a3 and int(r['historical_W19'],16)==0x6cf4
  assert r['watched_frame_cells_unmodified_in_retained_interval']and not r['XPC_pointer_substitution_or_target_execution_performed']
  st=r['historical_raw_status_u32'];counts[st]=counts.get(st,0)+1
 assert counts=={'0x74c29d85':16,'0x74c29d69':48}
 assert all(s[k]is False for k in FLAGS);return rows

def sdk_checks():
 code='''#define OS_OBJECT_USE_OBJC 0
#include <stdint.h>
#include <stddef.h>
#include <xpc/xpc.h>
struct B72 {void *input;uint64_t length;void *peer;uint8_t audit[32];void **output;uint64_t *extent;};
struct P32 {uint64_t encoded;uint32_t tag,operation;B72 *arguments;uint32_t result,pad;};
#define A(x) static_assert((x),#x)
A(sizeof(void*)==8);A(sizeof(uint64_t)==8);A(sizeof(uint32_t)==4);A(sizeof(int64_t)==8);
A(sizeof(B72)==72);A(offsetof(B72,output)==56);A(offsetof(B72,extent)==64);
A(sizeof(P32)==32);A(offsetof(P32,result)==24);A(sizeof(xpc_object_t)==8);
A(__is_same(decltype(&xpc_dictionary_set_int64),void(*)(xpc_object_t,const char*,int64_t)));
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return {'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Compile-only installed LP64 SDK and analyst-declared recovered record projections; not native layout/reachability validation.'}

def proofs():
 qs=[('terminal_marker_partition_all32','''(declare-fun s () (_ BitVec 32))
(define-fun w8 () (_ BitVec 32) (bvor (bvadd #x00006cf4 #xffffa40e) #x000008a1))
(define-fun i () (_ BitVec 32) (bvxor (bvmul (ite (= s #x8b3dc651) #x00000001 #x00000000) (bvxor w8 #x000019b5)) (bvadd #x00006cf4 #xffffd60e)))
(assert (or (distinct w8 #x000019a3) (distinct i (ite (= s #x8b3dc651) #x00004314 #x00004302))))'''),
 ('output_byte_widths_and_result_all_values','''(declare-fun C () (_ BitVec 64)) (declare-fun s () (_ BitVec 32))
(declare-fun M () (Array (_ BitVec 64) (_ BitVec 8)))
(define-fun A () (_ BitVec 64) (bvadd C #x0000000000000408))
(define-fun B () (_ BitVec 64) (bvadd C #x00000000000006e8))
(define-fun R () (_ BitVec 64) (bvadd C #x0000000000000ea8))
'''+memory_query()),
 ('core_frame_inverse_and_guard_location','''(declare-fun E () (_ BitVec 64))
(define-fun F () (_ BitVec 64) (bvsub (bvsub E #x0000000000000080) #x0000000000010d50))
(define-fun FP () (_ BitVec 64) (bvadd (bvsub E #x0000000000000080) #x0000000000000070))
(assert (or (distinct (bvadd F #x0000000000010d50 #x0000000000000080) E)
 (distinct (bvsub FP #x0000000000000088) (bvsub E #x0000000000000098))))'''),
 ('xpc_status_and_no_data_all32','''(declare-fun s () (_ BitVec 32))
(define-fun decoded () (_ BitVec 32) (bvxor s #x8b3dc651))
(define-fun phase () (_ BitVec 32) (ite (= s #x8b3dc651) (bvshl (bvmul (bvxor #x00002dfe #x00002c5b) #x00000003) #x00000004) (bvxor #x00002dfe #x0000630e)))
(define-fun mask () (_ BitVec 32) (bvadd (bvxor phase #x0000e0c0) #x8b3d1821))
(assert (or (distinct phase #x00004ef0) (distinct ((_ sign_extend 32) (bvxor s mask)) ((_ sign_extend 32) decoded))
 (distinct (= s #x8b3dc651) (= decoded #x00000000))))'''),
 ('budget_delta_zero_condition_and_cell_epoch','''(declare-fun V () (_ BitVec 64)) (declare-fun Q () (_ BitVec 32)) (declare-fun C () (_ BitVec 64))
(define-fun d () (_ BitVec 64) (bvshl ((_ zero_extend 48) ((_ extract 15 0) (bvsub Q ((_ extract 31 0) V)))) #x0000000000000004))
(define-fun init () (_ BitVec 64) (bvsub V #x00000000000000e0))
(define-fun initial_update () (_ BitVec 64) (bvadd init #x00000000000000e0))
(assert (or (distinct initial_update V)
 (distinct (= d #x0000000000000000) (= ((_ extract 15 0) Q) ((_ extract 15 0) V)))
 (distinct (= (bvadd C #x0000000000000408) (bvadd C d #x0000000000000408)) (= d #x0000000000000000))))''')]
 out=[]
 for name,body in qs:
  q='(set-option :timeout 10000)\n(set-logic QF_AUFBV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Instruction-matched component identities; valid cells, phase/frame epoch and logical call continuity are premises. No recovered-code execution/native occurrence or hardware PAC.'})
 return out

def memory_query():
 # Exact scalar store projection. Probe every affected byte plus arbitrary outside bytes.
 expr='M';affected=[]
 for base,count in [('A',8),('B',8),('R',4)]:
  for j in range(count):
   addr=f'(bvadd {base} #x{j:016x})';val='#x00'if base!='R'else f'((_ extract {j*8+7} {j*8}) s)'
   expr=f'(store {expr} {addr} {val})';affected.append((addr,val))
 out=f'(define-fun N () (Array (_ BitVec 64) (_ BitVec 8)) {expr})\n(declare-fun probe () (_ BitVec 64))\n'
 terms=[f'(distinct (select N {a}) {v})'for a,v in affected]
 terms.append('(and '+ ' '.join(f'(distinct probe {a})'for a,v in affected)+' (distinct (select N probe) (select M probe)))')
 return out+'(assert (or '+' '.join(terms)+'))'

def models():
 rows=[]
 for raw in(0x74c29d85,0x74c29d69,0x8b3dc651):
  dec=raw^0x8b3dc651;signed=dec-(1<<32)if dec>>31 else dec
  for guard_equal in(False,True):
   for event_peer_reply in(False,True):
    for delta in(0,16,1048560):
     clear=raw!=0x8b3dc651
     rows.append({'raw_u32':hex(raw),'decoded_u32':hex(dec),'signed_i64':signed,'guard_equal':guard_equal,'event_peer_reply_present':event_peer_reply,'caller_SP_delta_bytes':delta,'outputs_cleared_at_terminal_gate':clear,'result_written_before_guard':True,'normal_guard_branch':guard_equal,'conditional_reply_after_normal_returns':guard_equal and event_peer_reply,'conditional_set_data':guard_equal and event_peer_reply and not clear,'same_output_cells_after_SP_adjustment':delta==0,'conditional_output_free_skipped_by_clear':guard_equal and clear and delta==0})
 assert len(rows)==36
 return {'terminal_component_cases':rows,'scope':'Analyst-written component predicates. Entries are not native executions or proofs that each raw value reaches this terminal gate. Post-return cell equality requires delta zero and preserved cells; no budget stability or native ownership is inferred.'}

def alterations(s):
 def ins(q,name,ea,op):next(i for i in q['fragments'][name]['instructions']if i['ea']==ea).update(operands=op)
 changes=[('clear_store_width',lambda q:ins(q,'clear_outputs','0x10057a774','wzr, [x9]')),
 ('result_store_width',lambda q:ins(q,'result_return','0x100528ddc','x6, [x8, #0x18]')),
 ('output_length_cell',lambda q:ins(q,'xpc_cells','0x100a86d0c','x9, sp, #0x6e0')),
 ('branch_target',lambda q:q['branches'][0].update(target='0x100528dd8')),
 ('authentication_modifier',lambda q:q['branches'][2].update(modifier_u16=0)),
 ('guard_call',lambda q:ins(q,'guard_failure','0x100528e24','#0x100e2aad4')),
 ('historical_status',lambda q:q['historical_case_boundaries'][0].update(historical_raw_status_u32='0x0')),
 ('native_occurrence',lambda q:q.update(native_peer_identity_proved=True))]
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
 'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'component_queries_unsat':len(pr),'terminal_component_cases':len(mm['terminal_component_cases']),'rejected_evidence_alterations':len(neg)},'all_checks_pass':True,'static_scope':SCOPE,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
