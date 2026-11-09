#!/usr/bin/env python3
"""Original coalition field/callback/gate correspondence; no native target effects."""
import copy,json,struct,subprocess
from recover_coalition_service_gate import ROOT,P,FLAGS,ROLES,PRIMARY,COMMIT,SDK,CS,sha,h,build
EXPECTED='''
current_task|fffffe000bd41ac8|mrs|x0, tpidr_el1
current_task|fffffe000bd41acc|b|#0xfffffe000bd7e9c4
thread_task|fffffe000bd7ea3c|ldr|x0, [x1, #0x28]
get_bsdtask_info|fffffe000bd7def0|subs|x1, x0, #0x7c0
get_bsdtask_info|fffffe000bd7df44|tst|w8, #1
jetsam_set_taskrole|fffffe000bce788c|ldr|x8, [x1, #0x608]
jetsam_set_taskrole|fffffe000bce7890|cmp|x8, x0
coalition_adopt|fffffe000bce8ff8|cmp|w8, #1
coalition_adopt|fffffe000bce906c|add|x21, x1, #0x600
coalition_adopt|fffffe000bce90a8|blraa|x8, x17
coalition_adopt|fffffe000bce90e4|lsl|x8, x8, #3
coalition_adopt|fffffe000bce90fc|str|x20, [x9]
coalition_adopt|fffffe000bce9134|ldr|x20, [x23, #8]
coalition_adopt|fffffe000bce91c4|blraa|x8, x17
coalition_adopt|fffffe000bce9200|lsl|x8, x8, #3
coalition_adopt|fffffe000bce9218|str|x20, [x9]
coalition_create|fffffe000bce7334|mov|x20, x2
coalition_create|fffffe000bce7338|mov|x23, x1
coalition_create|fffffe000bce735c|stp|w22, w23, [x0, #8]
coalition_create|fffffe000bce7398|blraa|x8, x17
coalition_create|fffffe000bce73cc|cmp|w21, #0
coalition_create|fffffe000bce73d0|csel|w8, wzr, w8, eq
coalition_create|fffffe000bce73d4|cmp|w20, #0
coalition_create|fffffe000bce73dc|mov|w10, #0xde
coalition_create|fffffe000bce73e4|cinc|w8, w8, ne
coalition_create|fffffe000bce73ec|strb|w8, [x19, #0x28]
coalitions_init|fffffe000bce9d88|mov|w0, #0
coalitions_init|fffffe000bce9d90|mov|w2, #1
coalitions_init|fffffe000bce9d9c|bl|#0xfffffe000bce7304
coalitions_init|fffffe000bce9db0|mov|w2, #0
coalitions_init|fffffe000bce9dbc|bl|#0xfffffe000bce7304
coalitions_init|fffffe000bce9dcc|mov|w0, #1
coalitions_init|fffffe000bce9dd4|mov|w2, #1
coalitions_init|fffffe000bce9de0|bl|#0xfffffe000bce7304
coalitions_init|fffffe000bce9df8|mov|w2, #0
coalitions_init|fffffe000bce9e04|bl|#0xfffffe000bce7304
coalition_syscall|fffffe000c309a58|ubfx|x0, x9, #4, #4
coalition_syscall|fffffe000c309a80|add|x8, x8, #0xdc0
coalition_syscall|fffffe000c309a84|ldr|x8, [x8, x0, lsl #3]
coalition_syscall|fffffe000c309a90|tbnz|w8, #0, #0xfffffe000c309aac
coalition_syscall|fffffe000c309acc|mov|w10, #-0xff4
coalition_syscall|fffffe000c309ad0|tst|w9, w10
coalition_syscall|fffffe000c309adc|ubfx|w3, w9, #1, #1
coalition_syscall|fffffe000c309ae0|lsr|w1, w9, #8
coalition_syscall|fffffe000c309ae4|and|w2, w9, #1
coalition_syscall|fffffe000c309af0|bl|#0xfffffe000bce7304
service_construct|fffffe000bce01f0|bl|#0xfffffe000bd7e9c4
service_construct|fffffe000bce01f4|ldr|x8, [x0, #0x608]
service_construct|fffffe000bce01fc|ldrb|w8, [x8, #0x28]
service_construct|fffffe000bce0200|tbz|w8, #0, #0xfffffe000bce03cc
receive_publish|fffffe000bcd5edc|bl|#0xfffffe000bd7e9c4
receive_publish|fffffe000bcd5ee0|ldr|x8, [x0, #0x608]
receive_publish|fffffe000bcd5ee8|ldrb|w8, [x8, #0x28]
receive_publish|fffffe000bcd5eec|tbz|w8, #0, #0xfffffe000bcd61f4
task_create|fffffe000bd42a1c|bl|#0xfffffe000bce8fa0
task_create|fffffe000bd42a34|bl|#0xfffffe000bce8fa0
task_create|fffffe000bd42c68|add|x0, x22, #0x600
task_create|fffffe000bd42c70|bl|#0xfffffe000bce8fa0
task_create|fffffe000bd42cb0|bl|#0xfffffe000bce8fa0
type1_adopt|fffffe000bce79e8|str|x8, [x1, #0x620]
type1_adopt|fffffe000bce79ec|str|x9, [x1, #0x628]
type1_init|fffffe000bce7b00|str|x8, [x0, #0x80]
'''
def verify(s):
 assert s['kernel_source_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'and s['kernel_version']['text']=='Darwin Kernel Version 27.2.0: Wed Oct  7 23:15:14 PDT 2026; root:xnu-13432.41.4~3/RELEASE_ARM64_T6041';records=[]
 for role,a in ROLES.items():assert s['functions'][role]['start']==hex(a)
 for line in EXPECTED.strip().splitlines():
  role,ea,mn,op=line.split('|');i=next(i for i in s['functions'][role]['instructions']if i['ea']=='0x'+ea);assert(i['mnemonic'],i['operands'])==(mn,op),(role,ea,i);records.append({'role':role,**i})
 for role,name in[('current_task','_current_task'),('get_bsdtask_info','_get_bsdtask_info')]:assert any(r['name']==name and r['entry']=='com.apple.kernel'for r in s['functions'][role]['original_nlist'])
 for row in s['type_operations']:
  typ=row['type_index'];assert struct.unpack_from('<II',bytes.fromhex(row['bytes']))==(typ,1)
  for name,p in row['pointers'].items():assert p['format']==8 and p['auth']==1 and p['target']==s['functions']['type'+str(typ)+'_'+name]['start']
 assert len(s['constructor_direct_callers'])==5 and{r['containing_start']for r in s['constructor_direct_callers']}=={s['functions'][k]['start']for k in['coalitions_init','coalition_syscall']};loc=s['immediate608_locators'];assert loc['aligned_words_scanned']==2537551 and len(loc['rows'])==70 and sum(r['mnemonic']=='str'for r in loc['rows'])==6 and all(r['site']not in['0xfffffe000bce90fc','0xfffffe000bce9218']for r in loc['rows'])
 strings=s['original_strings'];assert len(strings)==10 and all(h(bytes.fromhex(r['bytes']))==r['sha256']and bytes.fromhex(r['bytes']).decode()==r['text']for r in strings);assert strings[0]['text']=='coalition.c'and strings[1]['text']=='i_coal_jetsam_set_taskrole'and'[2^{coalition}]'in strings[-1]['text']
 primary=s['primary_context'];assert primary['commit']==COMMIT and primary['exact_target_source_equivalence']=='unknown'and{r['path']:r['sha256']for r in primary['files']}=={p:r['sha256']for p,r in PRIMARY.items()};header=next(r for r in primary['files']if r['path']=='osfmk/mach/coalition.h');assert header['numeric_constants']=={'COALITION_CREATE_FLAGS_MASK':0xff3,'COALITION_CREATE_FLAGS_PRIVILEGED':1,'COALITION_CREATE_FLAGS_EFFICIENT':2,'COALITION_CREATE_FLAGS_TYPE_MASK':0xf0,'COALITION_CREATE_FLAGS_TYPE_SHIFT':4,'COALITION_CREATE_FLAGS_ROLE_MASK':0xf00,'COALITION_CREATE_FLAGS_ROLE_SHIFT':8,'COALITION_ROLE_SYSTEM':1,'COALITION_TYPE_RESOURCE':0,'COALITION_TYPE_JETSAM':1}
 assert len(s['functions'])==16
 for r in s['functions'].values():
  raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and len(raw)==int(r['end'],16)-int(r['start'],16)==4*len(r['instructions'])
  ii=list(CS.disasm(raw,int(r['start'],16)));assert len(ii)==len(r['instructions'])
  for i,n in zip(r['instructions'],ii):assert(i['ea'],i['mnemonic'],i['operands'])==(hex(n.address),n.mnemonic,n.op_str)
 assert all(s[k]is False for k in FLAGS);return records
def sdk_checks():
 code='''#include <stdint.h>
#include <mach/mach_types.h>
#include <stddef.h>
#define A(x) static_assert((x), #x)
A(sizeof(uint64_t)==8); A(sizeof(uint32_t)==4); A(sizeof(void*)==8);
A(sizeof(natural_t)==4); A(sizeof(integer_t)==4); A(sizeof(mach_port_name_t)==4);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Installed SDK ABI widths only. Public coalition semantic constants are separately pinned source facts; installed kern/coalition.h exposes no private definitions.'}
def proofs():
 queries={
 'coalition_privilege_efficiency_byte':'''(declare-fun old () (_ BitVec 8)) (declare-fun p () (_ BitVec 32)) (declare-fun e () (_ BitVec 32))
(define-fun b () (_ BitVec 8) (bvor (bvand old #xde) (bvor (ite (= e #x00000000) #x00 #x20) (ite (= p #x00000000) #x00 #x01))))
(assert (or (distinct (= (bvand b #x01) #x01) (distinct p #x00000000)) (distinct (= (bvand b #x20) #x20) (distinct e #x00000000)) (distinct (bvand b #xde) (bvand old #xde))))''',
 'task_process_coalition_offsets64':'''(declare-fun t () (_ BitVec 64)) (declare-fun typ () (_ BitVec 32))
(assert (bvule typ #x00000001))
(define-fun taskslot () (_ BitVec 64) (bvadd t (bvadd #x0000000000000600 (bvshl ((_ zero_extend 32) typ) #x0000000000000003))))
(define-fun proc () (_ BitVec 64) (bvsub t #x00000000000007c0))
(define-fun procslot () (_ BitVec 64) (bvadd proc (bvadd #x0000000000000dc0 (bvshl ((_ zero_extend 32) typ) #x0000000000000003))))
(assert (distinct taskslot procslot))''',
 'syscall_flags32_and_role_separation':'''(declare-fun f () (_ BitVec 32))
(define-fun allowed () Bool (and (= (bvand f #xfffff00c) #x00000000) (bvule (bvand (bvlshr f #x00000004) #x0000000f) #x00000001)))
(define-fun spec () Bool (and (= (bvand f #xfffff00c) #x00000000) (= (bvand f #x000000e0) #x00000000)))
(assert (or (distinct allowed spec) (and allowed (distinct (bvlshr f #x00000008) (bvand (bvlshr f #x00000008) #x0000000f)))))'''};out=[]
 for name,body in queries.items():
  query='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr);out.append({'name':name,'query':query,'result':'unsat','scope':'Instruction-matched scalar formulas only. Excludes allocator validity, actual process/task alias epoch, privilege admission, namespace identity, lifetime and hardware authentication.'})
 return out
def scalar_bank():
 rows=[];accepted=0
 for low in range(4096):
  for high in[0,0x10000000]:
   f=low|high;typ=(f>>4)&15;ok=(f&0xfffff00c)==0 and typ<=1;role=f>>8;p=f&1;e=f>>1&1
   if ok:assert role<16;accepted+=1
   rows.append([f,typ,ok,role,p,e])
 assert accepted==128;return{'inputs_checked':len(rows),'scalar_valid_inputs':accepted,'rows_sha256':h(json.dumps(rows,separators=(',',':')).encode()),'scope':'Numeric operation1 flag predicate only, not caller privilege, native syscall acceptance or coalition creation.'}
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();records=verify(s);negative=[]
 for name,alter in[
  ('removed_constructor_caller',lambda q:q['constructor_direct_callers'].pop()),
  ('wrong_type_callback',lambda q:q['type_operations'][1]['pointers']['adopt'].__setitem__('target',q['functions']['type0_adopt']['start'])),
  ('wrong_primary_privilege_constant',lambda q:next(r for r in q['primary_context']['files']if r['path']=='osfmk/mach/coalition.h')['numeric_constants'].__setitem__('COALITION_CREATE_FLAGS_PRIVILEGED',2)),
  ('wrong_source_version_equivalence',lambda q:q['primary_context'].__setitem__('exact_target_source_equivalence','proved')),
  ('wrong_diagnostic_role_name',lambda q:q['original_strings'][1].__setitem__('text','coalition_role')),
  ('wrong_task_export',lambda q:q['functions']['current_task']['original_nlist'][0].__setitem__('name','_current_proc'))]:
  q=copy.deepcopy(s);alter(q)
  try:verify(q)
  except(AssertionError,KeyError,ValueError,StopIteration):negative.append(name)
  else:raise AssertionError('Accepted altered evidence: '+name)
 sdk=sdk_checks();pr=proofs();bank=scalar_bank();counts={**s['verified_source_counts'],'instruction_assertions':len(records),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'numeric_flags_inputs_checked':bank['inputs_checked'],'rejected_evidence_alterations':len(negative)}
 obj={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':records,'SDK_checks':sdk,'proofs':pr,'numeric_flag_bank':bank,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'rejected_alterations':negative,'verified_counts':counts,'static_scope':'Original task identity, jetsam membership indexed store, coalition privilege producer, initialization/inheritance and selected service construction/receive restore consumers. Public source naming is pinned but exact target source equivalence is unknown. Immediate-offset census is bounded; native membership/admission, object lifetime and complete writer census remain unknown.','all_checks_pass':True,**{f:False for f in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
