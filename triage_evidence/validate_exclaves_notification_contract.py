#!/usr/bin/env python3
"""Static interface assertions, SDK geometry and full-domain scalar proofs.
No recovered target code, request packet or native failure scenario executes.
"""
import copy,json,struct,subprocess
from recover_exclaves_notification_contract import ROOT,P,FLAGS,SDK,CS,sha,h,build
PATTERNS='''
boot|mov|w0, #0
boot|mov|w1, #0
boot|cmp|w0, #0x2e
identifier_property|mov|x0, x1
identifier_property|mov|x1, x2
identifier_setter|cmp|x0, #0x80
identifier_setter|ldr|x0, [x19, #0x570]
identifier_setter|str|xzr, [x19, #0x570]
identifier_setter|str|x0, [x19, #0x570]
notification_property|mov|w1, #8
notification_property|stp|x20, x21, [sp, #0x20]
notification_entry|ldrb|w8, [x1]
notification_entry|cmp|x0, #0x80
notification_entry|ldp|x4, x0, [x19, #0x20]
notification_entry|ldr|x8, [x0, #0x230]
notification_entry|ldr|x5, [x0, #0x258]
notification_entry|mov|x3, #0
notification_entry|blraaz|x8
notification_entry|orr|w8, w8, #0x200
notification_entry|and|w8, w8, #0xffffffef
publish|ldr|x8, [x23, #0x570]
publish|and|w8, w8, #0xfffffdff
publish|ldr|x1, [x21, #0x570]
publish|mov|x3, x0
publish|mov|w0, #0
publish|mov|x2, x20
publish|orr|w8, w8, #0x1000
remove|ldr|x8, [x20, #0x570]
remove|ldr|x1, [x20, #0x570]
remove|mov|x3, x0
remove|mov|w0, #0
remove|mov|x2, x21
remove|and|w8, w8, #0xffffefff
spawn_attributes|ldr|x1, [x21, #0x570]
spawn_attributes|mov|x0, x20
job_clone|ldr|x0, [x19, #0x570]
job_clone|str|x0, [x20, #0x570]
job_install|ldr|x8, [x19, #0x570]
job_install|mov|w1, #8
endpoint_wrapper|mov|x3, x16
endpoint_wrapper|mov|x5, x0
policy_query|mov|w9, #0x1002
policy_query|mov|w1, #0x20
'''

def verify(s):
 assert s['source_sha256']=='1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168'
 assert s['kernel_source_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a';rows=[]
 def need(scope,roles,role,mn,op):
  found=[i for i in roles[role]['instructions']if i['mnemonic']==mn and i['operands']==op];assert found,(scope,role,mn,op)
  rows.extend({'scope':scope,'role':role,**q}for q in found)
 for v in s['variants']:
  rr=v['roles'];assert len(rr)==15 and v['fixup_reference']['all_matches']and v['fixup_reference']['fixups_compared']==2447
  for line in PATTERNS.strip().splitlines():
   role,mn,op=line.split('|')
   need(v['label'],rr,role,mn,op)
  for role,prefixes in[('publish',['w8, #9,']),('remove',['w8, #5,','w8, #9,','w8, #0xc,'])]:
   for prefix in prefixes:
    found=[i for i in rr[role]['instructions']if i['mnemonic']=='tbz'and i['operands'].startswith(prefix)]
    assert found,(v['label'],role,prefix);rows.extend({'scope':v['label'],'role':role,**q}for q in found)
  need(v['label'],rr,'notification_property','bl','#'+rr['policy_query']['start'])
  for role,name in[('boot','_exclaves_boot'),('publish','_exclaves_daemon_notification_register'),('remove','_exclaves_daemon_notification_deregister'),
                  ('spawn_attributes','_posix_spawnattr_set_conclave_id_np'),('identifier_setter','_strlen'),('identifier_setter','_free'),('identifier_duplicate','_strdup'),('notification_property','_xpc_dictionary_apply')]:
   assert v['stubs'][name]['binding']['symbol']==name;need(v['label'],rr,role,'bl','#'+v['stubs'][name]['address'])
  need(v['label'],rr,'identifier_property','b','#'+rr['identifier_setter']['start'])
  need(v['label'],rr,'identifier_setter','bl','#'+rr['identifier_duplicate']['start'])
  assert len(v['field570_store_candidates'])==3 and all(len(q)==1 for q in v['import_direct_callers'].values())
  for role,key,off in[('identifier_property','_Conclave',0x38),('notification_property','DaemonNotifications',0x68)]:
   block=v['property_blocks'][key];ptrs=block['pointers'];assert ptrs[0]['symbol']=='__NSConcreteGlobalBlock'and ptrs[1]['target']==rr[role]['start']
   assert ptrs[1]['authenticated']and all(q['chain_membership_verified']for q in ptrs)
   assert any(i['mnemonic']=='add'and i['operands']=='x1, x20, #'+hex(off)for i in block['schema_neighborhood'])
  strings=[q['text']for q in v['strings']['publish']];assert any('Daemon Notification requires _Conclave key'in q for q in strings)
  assert 'DaemonNotifications requires a valid _Conclave'in[q['text']for q in v['strings']['notification_property']]
  assert v['policy_jump_table']['targets'][8]in{q['ea']for q in rr['policy_query']['instructions']}
  for r in rr.values():
   raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and len(raw)==int(r['end'],16)-int(r['start'],16)==4*len(r['instructions'])
   for j,i in enumerate(r['instructions']):
    pc=int(r['start'],16)+4*j;b=raw[4*j:4*j+4];assert i['ea']==hex(pc)and i['bytes']==i['LLVM']['bytes']==b.hex();cc=list(CS.disasm(b,pc))
    if cc:assert(i['mnemonic'],i['operands'])==(cc[0].mnemonic,cc[0].op_str)
    else:assert i['decoder']=='LLVM'and(i['mnemonic'],i['operands'])==(i['LLVM']['mnemonic'],i['LLVM']['operands'])
 cf=s['cache_functions'];assert len(cf)==8
 for role,op in[('_exclaves_daemon_notification_register',0x15000000),('_exclaves_daemon_notification_deregister',0x16000000)]:
  for mn,arg in[('sub','sp, sp, #0x160'),('cbz','x1, '+next(i['operands'].split(', ')[1]for i in cf[role]['instructions']if i['mnemonic']=='cbz'and i['operands'].startswith('x1,'))),
      ('sub','w8, w3, #1'),('cmn','w8, #3'),('mov','w1, #0x80'),('cmp','x0, #0x7f'),('mov','w2, #0x80'),
      ('str','w20, [sp, #0x100]'),('mov','x3, sp'),('mov','w1, #'+hex(op)),('mov','w4, #0x104'),('mov','x2, #0'),('mov','w0, #4')]:need('cache',cf,role,mn,arg)
  need('cache',cf,role,'bl','#'+cf['__exclaves_ctl_trap']['start'])
 for role,mn,arg in[('_exclaves_boot','mov','w1, #0x5000000'),('_exclaves_boot','mov','w2, w1'),
      ('__exclaves_ctl_trap','mov','x16, #-0x58'),('__exclaves_ctl_trap','svc','#0x80'),
      ('_posix_spawnattr_set_conclave_id_np','cmp','x0, #0x7f'),('_posix_spawnattr_set_conclave_id_np','mov','w0, #0x16'),
      ('_posix_spawnattr_set_conclave_id_np','mov','w0, #0x22'),('_posix_spawnattr_set_conclave_id_np','mov','w0, #0xc'),
      ('_posix_spawnattr_set_conclave_id_np','ldr','x0, [x21, #0xf8]'),('_posix_spawnattr_set_conclave_id_np','str','x0, [x21, #0xf8]'),
      ('___libkernel_platform_init','str','x0, [x8, #0x8c8]')]:need('cache',cf,role,mn,arg)
 tr=s['trap88'];assert(tr['index'],tr['signed_selector'],tr['argument_count'],tr['u32_words'])==(88,-88,8,14)
 reg=bytes.fromhex(s['trap_registry_bytes']);assert reg[:8]==bytes([8,14,0,0,0,0,0,0])
 assert struct.unpack_from('<Q',reg,8)[0]==int(tr['handler_pointer']['raw'],16)and struct.unpack_from('<Q',reg,16)[0]==int(tr['munger_pointer']['raw'],16)
 kf=s['kernel_functions'];assert tr['handler_pointer']['target']==kf['handler']['start']=='0xfffffe000bcf0138'
 assert[(i['mnemonic'],i['operands'])for i in kf['handler']['instructions']]==[('bti','c'),('mov','w0, #0x2e'),('ret','')]
 assert bytes.fromhex(s['trap_name_bytes'])==b'_exclaves_ctl_trap\0'
 for mn,arg in[('ldr','w8, [x0]'),('ldr','w8, [x0, #4]'),('str','x8, [x0, #8]'),('str','x8, [x0, #0x38]')]:need('kernel',kf,'argument_munger',mn,arg)
 for r in list(cf.values())+list(kf.values()):
  raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and len(raw)==int(r['end'],16)-int(r['start'],16)==4*len(r['instructions'])
  cc=list(CS.disasm(raw,int(r['start'],16)));assert len(cc)==len(r['instructions'])
  for i,q in zip(r['instructions'],cc):assert(i['ea'],i['mnemonic'],i['operands'])==(hex(q.address),q.mnemonic,q.op_str)
 table=s['string_callback_table'];assert table['cell']=='0x1ed83e8c8'and table['pointer']['chain_membership_verified']and table['offset78_raw_bytes']=='0000000000000000'
 assert bytes.fromhex(table['bytes'])[0x78:0x80]==b'\0'*8 and not table['runtime_table_observed']
 for role,off,name in[('generic_strlcpy',0x58,'__libkernel_strlcpy'),('generic_strlen',0x60,'__libkernel_strlen')]:
  assert table['pointers'][hex(off)]['target']==cf[role]['start']and any(q['name']==name for q in cf[role]['original_nlist'])
 job=s['job_declaration'];assert job['sha256']=='ca21543400f3ead9e96d2434f968184b6acd2e1e3de57322ca3da663831eae3c'
 assert '_Conclave'not in job['plist']and'DaemonNotifications'not in job['plist']and not job['effective_runtime_configuration_observed']
 assert all(s[k]is False for k in FLAGS);return rows

def sdk_checks():
 code='''#include <mach/mach.h>
#include <mach/mach_param.h>
#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>
#define A(x) static_assert((x), #x)
struct reconstructed_notification { char identifier[MAXCONCLAVENAME]; char endpoint[MAXCONCLAVENAME]; mach_port_name_t name; };
A(MAXCONCLAVENAME==128); A(sizeof(reconstructed_notification)==260);
A(offsetof(reconstructed_notification,identifier)==0); A(offsetof(reconstructed_notification,endpoint)==128);
A(offsetof(reconstructed_notification,name)==256); A(sizeof(mach_port_name_t)==4);
A(KERN_NOT_SUPPORTED==46); A(KERN_INVALID_ARGUMENT==4);
A(EINVAL==22); A(ERANGE==34); A(ENOMEM==12); A(sizeof(void*)==8); A(sizeof(uint16_t)==2);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-']
 r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':13,'exit_code':r.returncode,'stderr':r.stderr,
   'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),
   'scope':'Primary SDK constants/widths plus C geometry of an explicitly reconstructed record; no canonical private SDK struct claimed or target request constructed.'}

def proofs():
 queries={
 'Mach_name_CMN32_sentinels':'''(declare-fun n () (_ BitVec 32))
(define-fun t () (_ BitVec 32) (bvsub n #x00000001))
(define-fun sum () (_ BitVec 33) (bvadd ((_ zero_extend 1) t) (_ bv3 33)))
(define-fun hi () Bool (and (= ((_ extract 32 32) sum) #b1) (distinct ((_ extract 31 0) sum) #x00000000)))
(assert (distinct hi (or (= n #x00000000) (= n #xffffffff))))''',
 'bounded_length64_capacity128':'''(declare-fun n () (_ BitVec 64))
(assert (distinct (bvule n (_ bv127 64)) (bvult n (_ bv128 64))))''',
 'registered_flag16_set_clear':'''(declare-fun f () (_ BitVec 16))
(define-fun set32 () (_ BitVec 32) (bvor ((_ zero_extend 16) f) #x00001000))
(define-fun clear32 () (_ BitVec 32) (bvand ((_ zero_extend 16) f) #xffffefff))
(assert (or (distinct ((_ extract 15 0) set32) (bvor f #x1000))
 (distinct ((_ extract 15 0) clear32) (bvand f #xefff))))'''}
 out=[]
 for name,body in queries.items():
  query='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n'
  r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,capture_output=True,text=True)
  assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':query,'result':'unsat','scope':'Instruction-matched scalar domains only; excludes pointers, effective callback table, registration success, namespace identity and native execution.'})
 return out

def alterations(s):
 controls=[]
 def handler(q):q['kernel_functions']['handler']['instructions'][1]['operands']='w0, #0'
 def selector(q):q['trap88']['signed_selector']=-89
 def block(q):q['variants'][1]['property_blocks']['_Conclave']['pointers'][1]['target']=q['variants'][1]['roles']['boot']['start']
 def callbacks(q):q['string_callback_table']['offset78_raw_bytes']='0100000000000000'
 def extent(q):
  next(i for i in q['cache_functions']['_exclaves_daemon_notification_register']['instructions']if i['mnemonic']=='mov'and i['operands']=='w4, #0x104')['operands']='w4, #0x100'
 def declaration(q):q['job_declaration']['plist']['_Conclave']='altered-evidence'
 for name,mutate in[('handler_result',handler),('trap_selector',selector),('property_invoke',block),('default_callback',callbacks),('record_extent',extent),('declaration',declaration)]:
  q=copy.deepcopy(s);mutate(q)
  try:verify(q)
  except AssertionError:controls.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence: '+name)
 return controls

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();neg=alterations(s)
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},
   'source_recapture_match':True,'instruction_assertions':rows,'SDK_checks':sdk,'proofs':pr,'alterations':neg,
   'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
   'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':13,'SDK_compilations':1,'scalar_queries_unsat':3,'rejected_evidence_alterations':len(neg)},
   'all_checks_pass':True,'static_scope':'Original properties/identifier lifetime, endpoint registration flags, spawn attribute, callback-table premise, trap88/munger and unconditional KERN_NOT_SUPPORTED handler. Native loaded identity, initialization and FairPlay use unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
