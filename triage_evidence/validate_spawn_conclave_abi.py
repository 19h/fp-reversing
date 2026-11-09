#!/usr/bin/env python3
"""Verify static spawn arguments, pointer ownership frontiers and census bounds.
No original target execution, spawn, syscall or malformed-request testing.
"""
import copy,json,struct,subprocess
from recover_spawn_conclave_abi import ROOT,P,FLAGS,SDK,CS,sha,h,build,receiver_census
PATTERNS='''
launch_core|add|x1, sp, #0x38
launch_core|add|x3, sp, #0x38
launch_core|add|x2, x23, #8
launch_core|add|x0, sp, #0x1c
record_init|mov|w1, #0xb48
record_init|add|x0, x20, #8
record_cleanup|mov|x19, x0
record_cleanup|add|x0, x19, #8
attribute_prepare|ldr|x1, [x21, #0x570]
attribute_prepare|mov|x0, x20
'''
CF_PATTERNS='''
_posix_spawn|mov|w11, #0x100
_posix_spawn|stp|x11, x9, [sp]
_posix_spawn|ldr|x8, [x9, #0xf8]
_posix_spawn|mov|w9, #0x80
_posix_spawn|stp|x9, x8, [sp, #0x80]
_posix_spawn|mov|x2, x23
_posix_spawn|str|w25, [x8]
_posix_spawn|ldur|w0, [x29, #-0x44]
___posix_spawn|mov|x16, #0xf4
___posix_spawn|svc|#0x80
_posix_spawnattr_init|mov|w0, #0x100
_posix_spawnattr_init|str|x0, [x19]
_posix_spawnattr_init|stp|xzr, xzr, [x8, #0xf0]
_posix_spawnattr_destroy|ldr|x0, [x9, #0xf8]
_posix_spawnattr_destroy|str|xzr, [x9, #0xf8]
_posix_spawnattr_destroy|str|xzr, [x19]
_posix_spawnattr_set_conclave_id_np|str|x0, [x21, #0xf8]
filter|ldr|q0, [x9, #0x80]
filter|str|q0, [x19, #0xf0]
filter|add|x2, x19, #0x70
___libkernel_init_late|cmp|x8, #3
___libkernel_init_late|ldrb|w8, [x19, #0xa]
___libkernel_init_late|str|x16, [x8, #0xe68]
_posix_spawnattr_setmacpolicyinfo_np|ldr|x22, [x24, #0xd0]
_posix_spawnattr_setmacpolicyinfo_np|str|x0, [x24, #0xd0]
_posix_spawnattr_setmacpolicyinfo_np|mov|w9, #0x90
_posix_spawnattr_setmacpolicyinfo_np|mov|w2, #0x80
_posix_spawnattr_setmacpolicyinfo_np|stp|x20, x19, [x23, #0x80]
_posix_spawnattr_getmacpolicyinfo_np|ldr|x8, [x8, #0xd0]
_posix_spawnattr_getmacpolicyinfo_np|ldr|x8, [x22, #0x80]
_posix_spawnattr_getmacpolicyinfo_np|ldr|x8, [x22, #0x88]
'''
KERNEL='''
syscall|fffffe000c2a2ca4|ldr|x0, [x22, #0x10]
syscall|fffffe000c2a2cc0|mov|w2, #0x48
syscall|fffffe000c2a2cc4|bl|#0xfffffe000be76e18
syscall|fffffe000c2a2d7c|add|x1, sp, #0x250
syscall|fffffe000c2a2d80|mov|w2, #0x90
syscall|fffffe000c2a2d84|bl|#0xfffffe000be76e18
syscall|fffffe000c2a2da8|ldr|x0, [sp, #0x258]
syscall|fffffe000c2a2db4|mov|w2, #0xc8
syscall|fffffe000c2a2db8|bl|#0xfffffe000be76e18
syscall|fffffe000c2a4d44|add|x0, sp, #0x250
syscall|fffffe000c2a4d48|add|x1, x27, #0x300
syscall|fffffe000c2a4d4c|bl|#0xfffffe000c2a5450
descriptor_helper|fffffe000c2a5480|ldr|x1, [x0, #0x30]
descriptor_helper|fffffe000c2a54cc|ldp|x2, x0, [x19, #0x30]
descriptor_helper|fffffe000c2a5640|ldp|x0, x2, [x27, #0x80]
'''

def verify(s):
 assert s['source_sha256']=='1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168'and s['kernel_source_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a';rows=[]
 def need(scope,rr,role,mn,op):
  found=[i for i in rr[role]['instructions']if i['mnemonic']==mn and i['operands']==op];assert found,(scope,role,mn,op)
  rows.extend({'scope':scope,'role':role,**q}for q in found)
 for v in s['variants']:
  rr=v['roles'];assert len(rr)==4 and v['fixup_reference']['all_matches']and v['fixup_reference']['fixups_compared']==2447
  for line in PATTERNS.strip().splitlines():role,mn,op=line.split('|');need(v['label'],rr,role,mn,op)
  for a,b in[('launch_core','record_init'),('launch_core','record_cleanup'),('launch_core','attribute_prepare')]:need(v['label'],rr,a,'bl','#'+rr[b]['start'])
  for role,name in[('launch_core','_posix_spawnp'),('record_init','_posix_spawnattr_init'),('record_init','_posix_spawn_file_actions_init'),
                   ('record_cleanup','_posix_spawnattr_destroy'),('record_cleanup','_posix_spawn_file_actions_destroy'),('attribute_prepare','_posix_spawnattr_set_conclave_id_np')]:
   assert v['stubs'][name]['binding']['symbol']==name;need(v['label'],rr,role,'bl','#'+v['stubs'][name]['address'])
  for r in rr.values():
   raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and len(raw)==int(r['end'],16)-int(r['start'],16)==4*len(r['instructions'])
   for j,i in enumerate(r['instructions']):
    pc=int(r['start'],16)+4*j;b=raw[4*j:4*j+4];assert i['ea']==hex(pc)and i['bytes']==i['LLVM']['bytes']==b.hex();cc=list(CS.disasm(b,pc))
    if cc:assert(i['mnemonic'],i['operands'])==(cc[0].mnemonic,cc[0].op_str)
    else:assert i['decoder']=='LLVM'and(i['mnemonic'],i['operands'])==(i['LLVM']['mnemonic'],i['LLVM']['operands'])
 cf=s['cache_functions'];assert len(cf)==10
 for line in CF_PATTERNS.strip().splitlines():role,mn,op=line.split('|');need('cache',cf,role,mn,op)
 for a,b in[('_posix_spawn','___posix_spawn'),('_posix_spawn','filter'),('filter','___posix_spawn')]:need('cache',cf,a,'bl','#'+cf[b]['start'])
 assert s['filter_cell']['bytes']=='0000000000000000'and not s['filter_cell']['runtime_value_observed']
 assert any(q['name']=='_posix_spawn_with_filter'for q in s['filter_cell']['original_nlist'])
 assert len(s['spawnp_to_spawn_bindings'])==2
 for row in s['spawnp_to_spawn_bindings']:
  p=row['pointer'];assert p['chain_membership_verified']and p['authenticated']and p['target']==cf['_posix_spawn']['start']
  need('cache',cf,'_posix_spawnp','bl','#'+row['stub_address'])
  raw=bytes.fromhex(row['bytes']);zz=list(CS.disasm(raw,int(row['stub_address'],16)));assert len(zz)==4
  assert[(q['ea'],q['mnemonic'],q['operands'])for q in row['instructions']]==[(hex(i.address),i.mnemonic,i.op_str)for i in zz]
 k=s['kernel_functions'];assert len(k)==4
 for line in KERNEL.strip().splitlines():
  role,ea,mn,op=line.split('|');i=next(q for q in k[role]['instructions']if q['ea']=='0x'+ea);assert(i['mnemonic'],i['operands'])==(mn,op);rows.append({'scope':'kernel','role':role,**i})
 assert any(q['name']=='_copyin'and q['entry']=='com.apple.kernel'for q in k['copyin']['original_nlist'])
 assert sum(i['mnemonic']=='ushll'for i in k['syscall']['instructions'])==9
 row=s['BSD244'];assert(row['index'],row['name'],row['argument_count'],row['u32_argument_bytes'])==(244,'posix_spawn',5,20)
 raw=bytes.fromhex(s['sysent_row_bytes']);assert len(raw)==24
 assert struct.unpack_from('<Q',raw,0)[0]==int(row['handler_pointer']['raw'],16)and struct.unpack_from('<Q',raw,8)[0]==int(row['munger_pointer']['raw'],16)
 assert struct.unpack_from('<IHH',raw,16)==(row['return_type'],5,20)
 assert row['handler_pointer']['target']==k['syscall']['start']and row['munger_pointer']['target']==k['argument_munger']['start']and bytes.fromhex(s['syscall_name_bytes'])==b'posix_spawn\0'
 for r in list(cf.values())+list(k.values()):
  raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and len(raw)==int(r['end'],16)-int(r['start'],16)==4*len(r['instructions'])
  cc=list(CS.disasm(raw,int(r['start'],16)));assert len(cc)==len(r['instructions'])
  for i,q in zip(r['instructions'],cc):assert(i['ea'],i['mnemonic'],i['operands'])==(hex(q.address),q.mnemonic,q.op_str)
 assert s['receiver_census']==receiver_census(k['syscall'],k['descriptor_helper'])and not s['receiver_census']['overlapping_direct_SP_loads']
 job=s['job_declaration'];assert job['sha256']=='ca21543400f3ead9e96d2434f968184b6acd2e1e3de57322ca3da663831eae3c'and'_Conclave'not in job['relevant_plist']and not job['native_job_identity_observed']
 assert all(s[k]is False for k in FLAGS);return rows

def sdk_checks():
 code='''#include <spawn.h>
#include <mach/mach_param.h>
#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>
#define A(x) static_assert((x), #x)
struct pair64 { uint64_t size, address; }; struct pair32 { uint32_t size, address; };
struct desc64 { pair64 pairs[9]; }; struct desc32 { pair32 pairs[9]; };
struct mac_extension { char policy_name[128]; uint64_t data_address, data_size; };
A(sizeof(posix_spawnattr_t)==8); A(sizeof(posix_spawn_file_actions_t)==8); A(sizeof(pid_t)==4);
A(sizeof(void*)==8); A(MAXCONCLAVENAME==128); A(sizeof(pair64)==16); A(sizeof(pair32)==8);
A(sizeof(desc64)==144); A(sizeof(desc32)==72); A(offsetof(desc64,pairs)+8*sizeof(pair64)==128);
A(sizeof(uint64_t[5])==40); A(sizeof(uint32_t[5])==20); A(248+sizeof(void*)==256);
A(EINVAL==22); A(ENOMEM==12); A(__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__);
A(sizeof(mac_extension)==144); A(offsetof(mac_extension,data_address)==128); A(offsetof(mac_extension,data_size)==136);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-']
 r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':19,'exit_code':r.returncode,'stderr':r.stderr,
   'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),
   'scope':'Public SDK opaque-handle/constants/widths and explicitly reconstructed C descriptor/argument geometry. No canonical private struct or native request claimed.'}

def proofs():
 queries={
 'MAC_extensions_admitted_count_size64':'''(declare-fun n () (_ BitVec 32))
(assert (bvsge n #x00000000))
(define-fun z () (_ BitVec 64) ((_ zero_extend 32) n))
(define-fun a () (_ BitVec 64) (bvor (bvshl (bvadd z (bvshl z (_ bv3 64))) (_ bv4 64)) (_ bv8 64)))
(assert (distinct a (bvadd (bvmul z (_ bv144 64)) (_ bv8 64))))''',
 'file_actions_positive_count_size64':'''(declare-fun n () (_ BitVec 32))
(assert (bvsgt n #x00000000))
(define-fun z () (_ BitVec 64) ((_ zero_extend 32) n))
(define-fun a () (_ BitVec 64) (bvor (bvmul z (_ bv1040 64)) (_ bv8 64)))
(assert (distinct a (bvadd (bvmul z (_ bv1040 64)) (_ bv8 64))))''',
 'compat_descriptor_zeroextend_lanes':'''(declare-fun a () (_ BitVec 32)) (declare-fun b () (_ BitVec 32))
(define-fun q () (_ BitVec 128) (concat ((_ zero_extend 32) b) ((_ zero_extend 32) a)))
(assert (or (distinct ((_ extract 31 0) q) a) (distinct ((_ extract 95 64) q) b)
 (distinct ((_ extract 63 32) q) #x00000000) (distinct ((_ extract 127 96) q) #x00000000)))'''}
 out=[]
 for name,body in queries.items():
  query='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,capture_output=True,text=True)
  assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':query,'result':'unsat','scope':'Instruction-matched scalar/packing identities only; no pointer validity, request admission, target record mutation, kernel execution or whole-kernel non-use proof.'})
 return out

def alterations(s):
 def extent(q):next(i for i in q['cache_functions']['_posix_spawn']['instructions']if i['mnemonic']=='mov'and i['operands']=='w9, #0x80')['operands']='w9, #0x100'
 def copyin(q):next(i for i in q['kernel_functions']['syscall']['instructions']if i['ea']=='0xfffffe000c2a2d80')['operands']='w2, #0x80'
 def census(q):q['receiver_census']['Conclave_frame_interval']=[0x2c0,0x2d0]
 def binding(q):q['spawnp_to_spawn_bindings'][0]['pointer']['target']=q['cache_functions']['___posix_spawn']['start']
 def args(q):q['BSD244']['argument_count']=6
 def declaration(q):q['job_declaration']['relevant_plist']['_Conclave']='altered-evidence'
 rows=[]
 for name,mutate in[('Conclave_extent',extent),('kernel_copy_extent',copyin),('census_interval',census),('spawn_binding',binding),('syscall_argument_count',args),('job_declaration',declaration)]:
  q=copy.deepcopy(s);mutate(q)
  try:verify(q)
  except AssertionError:rows.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence: '+name)
 return rows

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();neg=alterations(s)
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,
   'instruction_assertions':rows,'SDK_checks':sdk,'proofs':pr,'alterations':neg,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
   'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':19,'SDK_compilations':1,'scalar_queries_unsat':3,'rejected_evidence_alterations':len(neg)},
   'all_checks_pass':True,'static_scope':'Launchd handle/attribute lifecycle; cache spawnp binding, normal/filter descriptor and syscall; original kernel copyin/compat path and bounded direct-read/helper census. Effective filter, native spawn, Conclave effect and whole-kernel non-use unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
