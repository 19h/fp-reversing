#!/usr/bin/env python3
"""Static constructor ABI checks. No recovered target execution or IPC.
O(captured bytes + compiler starts) time, O(capture) memory; fixed SMT queries.
"""
import copy,json,struct,subprocess
from recover_initializer_programvars import ROOT,P,FLAGS,SDK,CS,sha,h,build,NAMES

CACHE_PATTERNS='''
libSystem_initializer|mov|x20, x4
libSystem_initializer|mov|x21, x2
libSystem_initializer|mov|x19, x3
libSystem_initializer|mov|x1, x21
libSystem_initializer|mov|x2, x19
libSystem_initializer|mov|x3, x20
libSystem_initializer|bl|#0x2d00a0840
libc_initializer|mov|x0, x3
libc_initializer|bl|#0x1805c48a8
program_vars_init|ldp|x8, x9, [x0, #0x10]
program_vars_init|str|x8, [x10, #0xdf0]
program_vars_init|ldp|x10, x8, [x0]
program_vars_init|str|x8, [x11, #0xdc0]
program_vars_init|str|x9, [x8, #0xd98]
program_vars_init|ldr|x8, [x0, #0x20]
program_vars_init|str|x8, [x9, #0xdb8]
program_vars_init|str|x10, [x8, #0xda0]
default_program_vars|add|x8, x8, #0x118
default_program_vars|add|x9, x9, #0xf8
default_program_vars|add|x10, x10, #0x100
default_program_vars|stp|x9, x10, [x1, #8]
default_program_vars|add|x9, x9, #0x108
default_program_vars|stp|x9, x8, [x1, #0x18]
helper_version|mov|w0, #8
call_initializer|mov|x0, x1
call_initializer|mov|x1, x2
call_initializer|mov|x2, x3
call_initializer|mov|x3, x4
call_initializer|mov|x4, x5
call_initializer|blraaz|x6
__NSGetMachExecuteHeader|ldr|x0, [x8, #0xda0]
__NSGetArgc|ldr|x0, [x8, #0xdc0]
__NSGetArgv|ldr|x0, [x8, #0xdf0]
__NSGetEnviron|ldr|x0, [x8, #0xd98]
__NSGetProgname|ldr|x0, [x8, #0xdb8]
'''
DYLD_PATTERNS='''
initializer_callback|ldp|x8, x19, [x0, #0x28]
initializer_callback|ldr|x8, [x8]
initializer_callback|add|x20, x8, w1, uxtw
initializer_callback|ldr|x9, [x8, #8]
initializer_callback|ldr|w0, [x9, #0xb8]
initializer_callback|ldr|x1, [x9, #0xc0]
initializer_callback|ldr|x2, [x9, #0xd0]
initializer_callback|ldr|x3, [x9, #0xe0]
initializer_callback|add|x4, x8, #0x88
initializer_callback|blraaz|x19
initializer_callback|cmp|x0, #8
initializer_callback|ldr|w1, [x9, #0xb8]
initializer_callback|ldr|x2, [x9, #0xc0]
initializer_callback|ldr|x3, [x9, #0xd0]
initializer_callback|ldr|x4, [x9, #0xe0]
initializer_callback|ldr|x0, [x8, #0xb0]
initializer_callback|ldr|x9, [x16, #0xc8]!
initializer_callback|add|x5, x8, #0x88
initializer_callback|mov|x6, x19
initializer_callback|blraa|x9, x16
prepare|cmp|x22, #8
prepare|cmp|x0, #6
prepare|ldr|x8, [x16, #0xb0]!
prepare|add|x1, x20, #0x88
prepare|str|x0, [x20, #0x88]
prepare|ldr|x9, [x8, #0xf0]
prepare|ldr|x10, [x20, #0xa8]
prepare|str|x9, [x10]
prepare|ldr|w9, [x8, #0xb8]
prepare|ldr|x10, [x20, #0x90]
prepare|str|w9, [x10]
prepare|ldr|x9, [x8, #0xc0]
prepare|ldr|x10, [x20, #0x98]
prepare|ldr|x8, [x8, #0xd0]
prepare|ldr|x9, [x20, #0xa0]
prepare|str|x8, [x9]
runtime_ctor|stur|q0, [x0, #0x88]
runtime_ctor|stur|q0, [x0, #0x98]
runtime_ctor|stur|q0, [x0, #0xa8]
header_value|ldr|x8, [x0, #8]
header_value|cmp|x8, #0x1b
header_value|ldr|x0, [x0]
header_value|brk|#1
'''

def verify(s):
 rows=[]
 def need(scope,fs,pattern):
  for line in pattern.strip().splitlines():
   role,mn,op=line.split('|');hits=[i for i in fs[role]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)]
   assert hits,(scope,role,mn,op)
   rows.extend({'scope':scope,'role':role,**i}for i in hits)
 assert s['dyld_path']=='/usr/lib/dyld'and s['dyld_sha256']=='3bbd2bc4d7f315fafec3cc51d6f0def403ce1149e3fb99e53b21ee19776d7401'
 assert [v['slice']['uuid']for v in s['variants']]==['3721f73b-6239-3955-9231-625bf089baa0','d038ad32-39e7-3d41-a8e7-106921edcaf0']
 assert [v['slice']['sha256']for v in s['variants']]==['3ff23912245179d64ce6135d3ab230f6e1f10c5addeb7f1f3e8cf18948b14f7b','3cae66750bbbe40e4d476d8642835137cf60c84836f92a0dd5c179f12d3b85e5']
 assert s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a'
 cf=s['cache_functions'];need('cache',cf,CACHE_PATTERNS)
 def sequence(f,wanted):
  pairs=[(i['mnemonic'],i['operands'])for i in f['instructions']]
  assert any(pairs[j:j+len(wanted)]==wanted for j in range(len(pairs)-len(wanted)+1))
 sequence(cf['call_initializer'],[('mov',f'x{i}, x{i+1}')for i in range(5)]+[('blraaz','x6')])
 sequence(cf['program_vars_init'],[('ldp','x8, x9, [x0, #0x10]'),('adrp','x10, #0x1ed84e000'),('str','x8, [x10, #0xdf0]'),('ldp','x10, x8, [x0]'),('adrp','x11, #0x1ed84e000'),('str','x8, [x11, #0xdc0]'),('adrp','x8, #0x1ed84e000'),('str','x9, [x8, #0xd98]'),('ldr','x8, [x0, #0x20]'),('adrp','x9, #0x1ed84e000'),('str','x8, [x9, #0xdb8]'),('adrp','x8, #0x1ed84e000'),('str','x10, [x8, #0xda0]'),('ret','')])
 for v in s['variants']:
  need(v['label'],v['roles'],DYLD_PATTERNS)
  sequence(v['roles']['initializer_callback'],[('ldr','w0, [x9, #0xb8]'),('ldr','x1, [x9, #0xc0]'),('ldr','x2, [x9, #0xd0]'),('ldr','x3, [x9, #0xe0]'),('add','x4, x8, #0x88'),('blraaz','x19')])
  assert [q['text']for q in v['section_literals']]==['__TPRO_CONST','__dyld_apis','__DATA_CONST','__helper']
  assert all(bytes.fromhex(q['bytes'])==q['text'].encode()+b'\0'for q in v['section_literals'])
  assert v['compiler_starts_reference']['all_matches']and v['compiler_starts_reference']['starts_compared']==3376
  for role,name in NAMES.items():assert any(q['name']==name for q in v['roles'][role]['original_nlist'])
  need(v['label'],v['roles'],'prepare|bl|#'+v['roles']['header_value']['start'])
  for f in v['roles'].values():
   raw=bytes.fromhex(f['bytes']);assert h(raw)==f['sha256']and len(raw)==int(f['end'],16)-int(f['start'],16)==4*len(f['instructions'])
   for j,i in enumerate(f['instructions']):
    a=int(f['start'],16)+4*j;word=raw[j*4:j*4+4];assert i['ea']==hex(a)and i['bytes']==i['LLVM']['bytes']==word.hex()
    cc=list(CS.disasm(word,a))
    if cc:assert i['decoder']=='Capstone'and(i['mnemonic'],i['operands'])==(cc[0].mnemonic,cc[0].op_str)
    else:assert i['decoder']=='LLVM'and(i['mnemonic'],i['operands'])==(i['LLVM']['mnemonic'],i['LLVM']['operands'])and i['mnemonic']not in['.long','.word','<unknown>']
   assert f['extended']==[i for i in f['instructions']if i['decoder']=='LLVM']
 for f in cf.values():
  raw=bytes.fromhex(f['bytes']);cc=list(CS.disasm(raw,int(f['start'],16)))
  assert h(raw)==f['sha256']and len(raw)==int(f['end'],16)-int(f['start'],16)==4*len(cc)==4*len(f['instructions'])
  assert[(q['ea'],q['mnemonic'],q['operands'])for q in f['instructions']]==[(hex(i.address),i.mnemonic,i.op_str)for i in cc]
 hi=s['helper_interface'];assert hi['section']['size']==hi['APIs_section']['size']==8
 assert(hi['section']['segment'],hi['section']['name'])==('__DATA_CONST','__helper')
 assert(hi['APIs_section']['segment'],hi['APIs_section']['name'])==('__TPRO_CONST','__dyld_apis')
 assert hi['object_pointer']['target']==hi['vtable_address_point']=='0x1e2122d70'
 assert hi['object_pointer']['chain_membership_verified']and hi['object_pointer']['authenticated']
 assert[(r['offset'],r['role'])for r in hi['methods']]==[(0,'helper_version'),(176,'default_program_vars'),(200,'call_initializer')]
 for q in hi['methods']:
  p=q['pointer'];assert p['chain_membership_verified']and p['authenticated']and p['target']==cf[q['role']]['start']
  assert int(p['address'],16)==int(hi['vtable_address_point'],16)+q['offset']
 assert len(s['cache_stub_bindings'])==2
 for q in s['cache_stub_bindings']:assert q['pointer']['chain_membership_verified']and q['pointer']['target']==cf[q['role']]['start']
 expected=[(0,'0x1ed84eda0',None,'__NSGetMachExecuteHeader',8),(8,'0x1ed84edc0','0x1ed83b0f8','__NSGetArgc',4),(16,'0x1ed84edf0','0x1ed83b100','__NSGetArgv',8),(24,'0x1ed84ed98','0x1ed83b108','__NSGetEnviron',8),(32,'0x1ed84edb8','0x1ed83b118','__NSGetProgname',8)]
 assert[(r['record_offset'],r['libc_cell'],r['storage_address'],r['accessor'],r['storage_width_bytes'])for r in s['ProgramVars_fields']]==expected
 assert all(r['field_bytes']==8 and not r['native_value_observed']for r in s['ProgramVars_fields'])
 init=s['libSystem_initializer_registration'];assert init['targets']==[cf['libSystem_initializer']['start']]
 assert[hex(int(init['image_base'],16)+v[0])for v in struct.iter_unpack('<I',bytes.fromhex(init['bytes']))]==init['targets']
 d=s['daemon'];assert d['sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and d['uuid']=='204741e9-b89f-32b4-9321-51f3975c7cac'and len(d['sections'])==29
 assert d['dyld_load_commands']==[{'command_bytes':'0e000000200000000c0000002f7573722f6c69622f64796c6400000000000000','path':'/usr/lib/dyld'}]
 assert all(s[k]is False for k in FLAGS)
 return rows

def sdk_checks():
 code='''#include <crt_externs.h>
#include <mach-o/loader.h>
#include <stddef.h>
#define A(x) static_assert((x), #x)
struct ReconstructedProgramVars {mach_header_64* mh;int* argc;char*** argv;char*** env;char** name;};
A(sizeof(void*)==8);A(sizeof(int)==4);A(sizeof(ReconstructedProgramVars)==40);A(alignof(ReconstructedProgramVars)==8);
A(offsetof(ReconstructedProgramVars,mh)==0);A(offsetof(ReconstructedProgramVars,argc)==8);
A(offsetof(ReconstructedProgramVars,argv)==16);A(offsetof(ReconstructedProgramVars,env)==24);A(offsetof(ReconstructedProgramVars,name)==32);
A(__is_same(decltype(&_NSGetMachExecuteHeader),mach_header_64*(*)()));
A(__is_same(decltype(&_NSGetArgc),int*(*)()));A(__is_same(decltype(&_NSGetArgv),char*** (*)()));
A(__is_same(decltype(&_NSGetEnviron),char*** (*)()));A(__is_same(decltype(&_NSGetProgname),char** (*)()));
A(sizeof(mach_header_64)==32);A(LC_LOAD_DYLINKER==14);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-']
 r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),
  'scope':'SDK public accessor types and Mach-O constant; explicitly reconstructed private record layout. No canonical private ProgramVars declaration or native object validation.'}

def proofs():
 # MOV chain is checked against the exact selected source instructions above.
 regs={f'x{i}':f'a{i}'for i in range(7)};decl='\n'.join(f'(declare-fun a{i} () (_ BitVec 64))'for i in range(7))
 for i in range(5):regs[f'x{i}']=regs[f'x{i+1}']
 shuffle=decl+'\n(assert (or '+' '.join(f'(distinct {regs[f"x{i}"]} a{i+1})'for i in range(5))+'))'
 # Word memory, distinct record/cell locations, stable input; not a byte-alias proof.
 mem='(declare-fun m () (Array (_ BitVec 64) (_ BitVec 64)))\n'
 mem+='(declare-fun p () (_ BitVec 64))\n'
 ins=[f'(bvadd p (_ bv{o} 64))'for o in[0,8,16,24,32]];outs=[f'(_ bv{int(x,16)} 64)'for x in['1ed84eda0','1ed84edc0','1ed84edf0','1ed84ed98','1ed84edb8']]
 mem+='(assert (= (bvand p (_ bv7 64)) (_ bv0 64)))\n(assert (distinct '+' '.join(ins+outs)+'))\n'
 # Actual load/store order: input2,3; output2; input0,1; output1,3; input4; output4,0.
 vals={2:f'(select m {ins[2]})',3:f'(select m {ins[3]})'};current='m';step=0
 def store(field):
  nonlocal current,step,mem
  step+=1;name=f'm{step}';mem+=f'(define-fun {name} () (Array (_ BitVec 64) (_ BitVec 64)) (store {current} {outs[field]} {vals[field]}))\n';current=name
 store(2)
 vals[0]=f'(select {current} {ins[0]})';vals[1]=f'(select {current} {ins[1]})';store(1);store(3)
 vals[4]=f'(select {current} {ins[4]})';store(4);store(0)
 mem+='(assert (or '+' '.join(f'(distinct (select {current} {outs[i]}) (select m {ins[i]}))'for i in range(5))+'))'
 queries=[('constructor_helper_register_shuffle','QF_BV',shuffle),('initializer_offset_uxtw','QF_BV','''(declare-fun base () (_ BitVec 64))
(declare-fun lo () (_ BitVec 32))
(declare-fun hi1 () (_ BitVec 32))
(declare-fun hi2 () (_ BitVec 32))
(assert (distinct (bvadd base ((_ zero_extend 32) ((_ extract 31 0) (concat hi1 lo)))) (bvadd base ((_ zero_extend 32) ((_ extract 31 0) (concat hi2 lo))))))'''),('ProgramVars_disjoint_word_copy','QF_AUFBV',mem)]
 out=[]
 for name,logic,body in queries:
  q=f'(set-option :timeout 10000)\n(set-logic {logic})\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True)
  assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Instruction-matched register/address or aligned disjoint stable word-memory identity only; no arbitrary aliasing, native pointer validity, PAC, reachability or environment provenance proof.'})
 return out

def alterations(s):
 changes=[('record_field_offset',lambda q:q['ProgramVars_fields'][2].update(record_offset=24)),('header_cell',lambda q:q['ProgramVars_fields'][0].update(libc_cell='0x1ed84edc0')),('argc_storage_width',lambda q:q['ProgramVars_fields'][1].update(storage_width_bytes=8)),('helper_method_target',lambda q:q['helper_interface']['methods'][2]['pointer'].update(target='0x180467a28')),('daemon_loader_path',lambda q:q['daemon']['dyld_load_commands'][0].update(path='/other/dyld')),('dyld_slice_UUID',lambda q:q['variants'][1]['slice'].update(uuid=q['variants'][0]['slice']['uuid']))]
 out=[]
 for name,change in changes:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence '+name)
 return out

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();neg=alterations(s)
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':rows,'SDK_checks':sdk,'proofs':pr,'alterations':neg,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'rejected_evidence_alterations':len(neg)},'all_checks_pass':True,
  'static_scope':'Dyld constructor record producer and direct/delegated five-argument ABI; libdyld default storage and helper vtable; libSystem/libc record forwarding and public accessor cells; declared FairPlay loader. Native image/header, branch, environment, interposition and PAC remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
