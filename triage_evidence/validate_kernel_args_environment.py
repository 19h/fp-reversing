#!/usr/bin/env python3
"""Static KernelArgs/environment checks and bounded, non-executable models.
No recovered instruction execution, native fixture or target message emission.
"""
import copy,itertools,json,subprocess
from recover_kernel_args_environment import ROOT,P,FLAGS,SDK,CS,NAMES,sha,h,build

PATTERNS='''
find_envp|add|x8, x0, #0x10
find_envp|ldr|x9, [x0, #8]
find_envp|mov|x1, #-1
find_envp|ldr|x11, [x8, x10, lsl #3]
find_envp|add|x1, x1, #1
find_envp|add|x9, x9, #8
find_apple|add|x8, x0, #0x10
find_apple|ldr|x10, [x0, #8]
find_apple|add|x0, x9, #0x18
find_apple|ldr|x11, [x8, x10, lsl #3]
find_apple|ldr|x10, [x8, x9, lsl #3]
config_ctor|add|x0, x0, #0x10
config_ctor|add|x0, x19, #0x150
config_ctor|add|x1, x19, #0x10
process_ctor|mov|x24, x1
process_ctor|mov|x19, x0
process_ctor|ldr|x0, [x24]
process_ctor|stp|x0, x1, [x19]
process_ctor|ldr|x9, [x24, #8]
process_ctor|str|w9, [x19, #0xa8]
process_ctor|stp|x8, x9, [x19, #0xb0]
process_ctor|stp|x11, x10, [x19, #0xc0]
process_ctor|stp|x10, x11, [x19, #0xd0]
runtime_ctor|stp|x16, x1, [x0]
header_from_mapped|mov|w8, #0xface
header_from_mapped|movk|w8, #0xfeed, lsl #16
header_from_mapped|ldr|w9, [x0]
header_from_mapped|mov|w8, #0x20
header_from_mapped|mov|w9, #0x1c
header_from_mapped|csel|x8, x9, x8, eq
header_from_mapped|ldr|w9, [x0, #0x14]
header_from_mapped|add|x1, x8, x9
security_ctor|ldrb|w8, [x19, #0x22]
security_ctor|ldrb|w8, [x19, #0x23]
security_ctor|ldrb|w8, [x19, #0x24]
prune_env|ldr|x8, [x1, #0xc8]
prune_env|ldr|x9, [x1, #0xd8]
prune_env|adds|x23, x10, #2
prune_env|ldr|x22, [x1, #0xc0]
prune_env|cmp|x26, x8
prune_env|add|w25, w25, #1
prune_env|sub|x8, x26, w25, sxtw
prune_env|str|x9, [x22, x8, lsl #3]
prune_env|sub|x8, x8, w25, sxtw
prune_env|stp|x22, x24, [x19, #0xc0]
prune_env|add|x8, x24, #1
prune_env|stp|x10, x9, [x19, #0xd0]
starts_with|ldr|x8, [x20, #8]
starts_with|cmp|x8, x0
starts_with|cset|w0, eq
simple_getenv|cmp|w9, #0x3d
simple_getenv|ldrb|w9, [x8, x21]
'''

def verify(s):
 assert s['dyld_sha256']=='3bbd2bc4d7f315fafec3cc51d6f0def403ce1149e3fb99e53b21ee19776d7401'
 assert[v['slice']['uuid']for v in s['variants']]==['3721f73b-6239-3955-9231-625bf089baa0','d038ad32-39e7-3d41-a8e7-106921edcaf0']
 rows=[]
 def need(label,rr,role,mn,op):
  hits=[i for i in rr[role]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(label,role,mn,op)
  rows.extend({'scope':label,'role':role,**i}for i in hits)
 for v in s['variants']:
  fs=v['roles'];label=v['label'];assert v['compiler_starts_reference']['all_matches']and v['compiler_starts_reference']['starts_compared']==3376
  for line in PATTERNS.strip().splitlines():role,mn,op=line.split('|');need(label,fs,role,mn,op)
  for role,name in NAMES.items():assert any(q['name']==name for q in fs[role]['original_nlist'])
  assert[q['text']for q in v['literals']]==['DYLD_','DYLD_SKIP_MAIN','DYLD_JUST_BUILD_CLOSURE','dyld_flags']
  assert all(bytes.fromhex(q['bytes'])==q['text'].encode()+b'\0'for q in v['literals'])
  for caller,target in [('config_ctor','process_ctor'),('config_ctor','security_ctor'),('process_ctor','header_from_mapped'),('prune_env','strlen'),('prune_env','starts_with'),('starts_with','strlen'),('starts_with','string_compare'),('security_ctor','prune_env'),('security_ctor','simple_getenv'),('security_ctor','header_env_iterator')]:need(label,fs,caller,'bl','#'+fs[target]['start'])
  for f in fs.values():
   raw=bytes.fromhex(f['bytes']);assert h(raw)==f['sha256']and len(raw)==int(f['end'],16)-int(f['start'],16)==4*len(f['instructions'])
   for j,i in enumerate(f['instructions']):
    pc=int(f['start'],16)+4*j;word=raw[4*j:4*j+4];cc=list(CS.disasm(word,pc));assert i['ea']==hex(pc)and i['bytes']==i['LLVM']['bytes']==word.hex()
    if cc:assert i['decoder']=='Capstone'and(i['mnemonic'],i['operands'])==(cc[0].mnemonic,cc[0].op_str)
    else:assert i['decoder']=='LLVM'and(i['mnemonic'],i['operands'])==(i['LLVM']['mnemonic'],i['LLVM']['operands'])and i['mnemonic']not in['.long','.word','<unknown>']
   assert f['extended']==[i for i in f['instructions']if i['decoder']=='LLVM']
  # These three post-iterator branches test the least significant bit of each byte.
  code=fs['security_ctor']['instructions'];p=next(j for j,i in enumerate(code)if(i['mnemonic'],i['operands'])==('ldrb','w8, [x19, #0x22]'))
  for delta,off in[(0,'0x22'),(2,'0x23'),(4,'0x24')]:
   assert code[p+delta]['operands']==f'w8, [x19, #{off}]'and code[p+delta+1]['mnemonic']=='tbnz'and code[p+delta+1]['operands'].startswith('w8, #0, ')
  assert [q['role']for q in v['prior_roles_recaptured']]==['process_ctor','header_value','runtime_ctor']
  expected_op='add'if label=='arm64e'else'addpt'
  need(label,fs,'process_ctor',expected_op,'x11, x8, x9')
  need(label,fs,'find_envp',expected_op,'x0, x8, x9')
  need(label,fs,'prune_env',expected_op,'x10, x22, x8, lsl #3')
  need(label,fs,'simple_getenv',expected_op,'x0, x8, x9')
 expected=[('header_span',0,8,0,16,16),('argc_u32',8,8,168,184,4),('argv_span',16,None,176,192,16),('environment_span',None,None,192,208,16),('apple_span',None,None,208,224,16)]
 assert[(q['meaning'],q['KernelArgs_offset'],q['KernelArgs_observed_load_width_bytes'],q['Process_offset'],q['ProcessConfig_offset'],q['Process_field_width_bytes'])for q in s['record_fields']]==expected
 d=s['daemon'];assert d['sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and d['uuid']=='204741e9-b89f-32b4-9321-51f3975c7cac'
 assert d['load_commands']==d['independent_otool']['load_commands_compared']==30 and not d['embedded_dyld_environment_commands']and d['independent_otool']['embedded_environment_commands_compared']==0
 assert all(s[k]is False for k in FLAGS);return rows

def sdk_checks():
 code='''#include <mach-o/loader.h>
#include <crt_externs.h>
#include <stdint.h>
#include <stddef.h>
#include <string_view>
#define A(x) static_assert((x), #x)
struct Span {const void* p;size_t n;};
struct ReconstructedKernelArgsPrefix {const mach_header* h;uint64_t argc_observed_word;const char* argv[1];};
struct ReconstructedProcessPrefix {Span header;char opaque[0xa8-16];uint32_t argc;uint32_t pad;Span argv;Span env;Span apple;};
A(sizeof(void*)==8);A(sizeof(size_t)==8);A(sizeof(int)==4);A(sizeof(Span)==16);A(alignof(Span)==8);
A(offsetof(ReconstructedKernelArgsPrefix,argc_observed_word)==8);A(offsetof(ReconstructedKernelArgsPrefix,argv)==16);
A(offsetof(ReconstructedProcessPrefix,argc)==0xa8);A(offsetof(ReconstructedProcessPrefix,argv)==0xb0);
A(offsetof(ReconstructedProcessPrefix,env)==0xc0);A(offsetof(ReconstructedProcessPrefix,apple)==0xd0);
A(sizeof(mach_header)==28);A(sizeof(mach_header_64)==32);A(offsetof(mach_header,sizeofcmds)==20);A(offsetof(mach_header_64,sizeofcmds)==20);
A(MH_MAGIC==0xfeedfaceU);A(MH_MAGIC_64==0xfeedfacfU);A(LC_DYLD_ENVIRONMENT==0x27);
A(std::string_view("DYLD_").starts_with("DYLD_"));A(std::string_view("DYLD_PAGEIN_LINKING=0").starts_with("DYLD_"));
A(!std::string_view("XPC_FLAGS=1").starts_with("DYLD_"));A(!std::string_view("XPC_NULL_BOOTSTRAP=1").starts_with("DYLD_"));
A(!std::string_view("XPC_SERVICES_UNAVAILABLE=1").starts_with("DYLD_"));
A(!std::string_view("DYLD").starts_with("DYLD_"));A(!std::string_view("dyld_A=1").starts_with("DYLD_"));
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++20','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'SDK Mach-O constants, header extents/offsets and C++ prefix semantics; private prefixes explicitly reconstructed, not canonical declarations.'}

def finite_models():
 # All models below are analyst-written semantics, not recovered code execution.
 prefixes=[(b'DYLD_',True),(b'DYLD_=1',True),(b'DYLD_A=1',True),(b'DYLD',False),(b'dyld_A=1',False),(b'_DYLD_A=1',False),(b'XPC_FLAGS=1',False),(b'XPC_NULL_BOOTSTRAP=1',False),(b'XPC_SERVICES_UNAVAILABLE=1',False),(b'',False)]
 for value,wanted in prefixes:assert value.startswith(b'DYLD_')==wanted
 layout=[]
 for argc,envc,applec in itertools.product(range(5),range(5),range(5)):
  argv=[('arg',i)for i in range(argc)];env=[('env',i)for i in range(envc)];apple=[('apple',i)for i in range(applec)];v=argv+[None]+env+[None]+apple+[None]
  # findEnvp's loop begins at argv[argc+1], and increments count from -1.
  i=argc;ec=-1
  while True:
   i+=1;ec+=1
   if v[i]is None:break
  envstart=argc+1
  # findApple separately rescans environment including its terminator.
  i=argc;appleat=argc+1
  while True:
   i+=1;appleat+=1
   if v[i]is None:break
  ac=-1;j=i+1
  while True:
   ac+=1
   if v[j]is None:break
   j+=1
  assert(ec,ac,appleat)==(envc,applec,argc+envc+2)
  assert v[envstart:envstart+ec]==env and v[appleat:appleat+ac]==apple
  layout.append([argc,envc,applec,envstart,appleat])
 cases=[]
 for ec in range(9):
  for mask in range(1<<ec):
   env=[(b'DYLD_'if mask>>i&1 else b'XPC_')+str(i).encode()+b'=v'for i in range(ec)]
   for ac in range(5):
    apple=[b'apple'+str(i).encode()for i in range(ac)];mem=env+[None]+apple+[None];original=list(mem);removed=0;writes=[]
    for index in range(ec+ac+2):
     if index<ec and mem[index].startswith(b'DYLD_'):removed+=1;continue
     if removed:
      dest=index-removed;assert 0<=dest<ec+ac+2
      mem[dest]=mem[index];writes.append([index,dest])
    new_ec=ec-removed;new_ap=new_ec+1;oracle=[x for x in env if not x.startswith(b'DYLD_')]
    assert mem[:new_ec]==oracle and mem[new_ec]is None and mem[new_ap:new_ap+ac]==apple and mem[new_ap+ac]is None
    assert all(dst<src for src,dst in writes)and len(mem)==len(original)
    cases.append([ec,mask,ac,removed,new_ap,h(repr(mem).encode())])
 return{'layout_cases':len(layout),'layout_digest':h(json.dumps(layout).encode()),'compaction_cases':len(cases),'compaction_digest':h(json.dumps(cases).encode()),'prefix_cases':[{'bytes':v.hex(),'removed':r}for v,r in prefixes],
  'scope':'125 normal-arm64e well-formed sentinel-layout models; all511 deletion masks for environment lengths0..8 times five apple lengths0..4 =2555 ordered compaction models. Independent filter oracle. No recovered instruction emulation, unbounded path proof, native pointer validity or x1 ADDPT semantics.'}

def proofs():
 queries={
 'normal_environment_base':'''(declare-fun k () (_ BitVec 64))
(declare-fun n () (_ BitVec 64))
(assert (distinct (bvadd (bvadd k (_ bv16 64)) (bvadd (bvshl n (_ bv3 64)) (_ bv8 64))) (bvadd k (bvshl (bvadd n (_ bv3 64)) (_ bv3 64)))))''',
 'header_length_arithmetic':'''(declare-fun magic () (_ BitVec 32))
(declare-fun sz () (_ BitVec 32))
(define-fun len () (_ BitVec 64) (bvadd (ite (= magic #xfeedface) (_ bv28 64) (_ bv32 64)) ((_ zero_extend 32) sz)))
(assert (or (bvult len (_ bv28 64)) (bvugt len (_ bv4294967327 64))))''',
 'compaction_destination_and_apple_shift':'''(declare-fun e () (_ BitVec 64))
(declare-fun a () (_ BitVec 64))
(declare-fun d () (_ BitVec 32))
(assert (bvule e (_ bv2147483647 64)))
(assert (bvule ((_ zero_extend 32) d) e))
(assert (bvule a (_ bv2147483647 64)))
(define-fun dd () (_ BitVec 64) ((_ sign_extend 32) d))
(define-fun total () (_ BitVec 64) (bvadd e a (_ bv2 64)))
(define-fun newe () (_ BitVec 64) (bvsub e dd))
(assert (or (distinct dd ((_ zero_extend 32) d)) (bvugt newe e) (bvuge (bvadd newe (_ bv1 64)) total) (distinct (bvsub (bvadd e (_ bv1 64)) dd) (bvadd newe (_ bv1 64)))))'''}
 out=[]
 for name,body in queries.items():
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Matched scalar 64-bit arithmetic under recorded bounds; excludes valid mappings, termination, full compactor/control-flow proof and x1 ADDPT behavior.'})
 return out

def alterations(s):
 changes=[('argc_input_width',lambda q:q['record_fields'][1].update(KernelArgs_observed_load_width_bytes=4)),('environment_outer_offset',lambda q:q['record_fields'][3].update(ProcessConfig_offset=192)),('pruning_prefix',lambda q:q['variants'][0]['literals'][0].update(text='XPC_')),('header_command_presence',lambda q:q['daemon']['embedded_dyld_environment_commands'].append({'text':'fake'})),('x1_environment_mnemonic',lambda q:next(i for i in q['variants'][1]['roles']['process_ctor']['instructions']if i['mnemonic']=='addpt').update(mnemonic='add')),('slice_UUID',lambda q:q['variants'][1]['slice'].update(uuid=q['variants'][0]['slice']['uuid']))]
 out=[]
 for name,change in changes:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence '+name)
 return out

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();neg=alterations(s);models=finite_models()
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':rows,'SDK_checks':sdk,'proofs':pr,'alterations':neg,'finite_models':models,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'rejected_evidence_alterations':len(neg),'layout_model_cases':models['layout_cases'],'compaction_model_cases':models['compaction_cases'],'prefix_model_cases':len(models['prefix_cases'])},'all_checks_pass':True,
  'static_scope':'KernelArgs observed loads and sentinel scans; nested ProcessConfig/header production; selected conditional DYLD_ pruning and pointer compaction; normal-arm64e bounded semantic models. x1 ADDPT semantics, effective native inputs, AMFI decisions and later mutation remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
