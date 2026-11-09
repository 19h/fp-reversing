#!/usr/bin/env python3
"""Validate original spawn port-action contracts and locator boundaries.
Static bytes, SDK compilation, scalar proofs and altered-evidence rejection only.
"""
import copy,json,struct,subprocess,hashlib,re
from recover_spawn_port_actions import ROOT,P,FLAGS,SETTERS,sha,SDK,build
from recover_spawn_conclave_abi import CS,h
from analyze_spawn_port_frame import analyze
PATTERNS='''
_posix_spawn|ldr|x11, [x9, #0xc8]
port_append|ldr|x0, [x20, #0xc8]
port_append|mov|w0, #0x38
port_append|mov|w11, #0x18
port_append|str|x0, [x20, #0xc8]
port_append|str|q0, [x11]
port_append|str|x9, [x11, #0x10]
port_append|str|w9, [x0, #4]
_posix_spawnattr_setspecialport_np|stp|w1, wzr, [sp, #0x10]
_posix_spawnattr_setspecialport_np|stp|wzr, w2, [sp, #0x18]
_posix_spawnattr_setexceptionports_np|stp|w8, w1, [sp, #8]
_posix_spawnattr_setexceptionports_np|stp|w2, w3, [sp, #0x10]
_posix_spawnattr_setexceptionports_np|stp|w4, wzr, [sp, #0x18]
_posix_spawnattr_set_importancewatch_port_np|cmp|w1, #0x80
_posix_spawnattr_set_registered_ports_np|cmp|w2, #3
'''
KERNEL='''
syscall|fffffe000c2a2b74|sub|sp, sp, #0x370
syscall|fffffe000c2a2b84|add|x25, sp, #0x150
syscall|fffffe000c2a2bc0|stp|q0, q0, [x25, #0x170]
syscall|fffffe000c2a2c04|stp|q0, q0, [sp, #0xf0]
syscall|fffffe000c2a2d14|str|q0, [x25, #0x180]
syscall|fffffe000c2a3774|ldr|x0, [x25, x24, lsl #3]
syscall|fffffe000c2a377c|bl|#0xfffffe000bcd0448
syscall|fffffe000c2a4918|add|x1, sp, #0xf0
syscall|fffffe000c2a4920|bl|#0xfffffe000c2a5724
syscall|fffffe000c2a3fa4|bl|#0xfffffe000bcfa5fc
syscall|fffffe000c2a3fd0|bl|#0xfffffe000bd4ff08
syscall|fffffe000c2a508c|bl|#0xfffffe000bcfc69c
syscall|fffffe000c2a5094|str|xzr, [x25]
syscall|fffffe000c2a4d44|add|x0, sp, #0x250
syscall|fffffe000c2a4d4c|bl|#0xfffffe000c2a5450
port_prepare|fffffe000c2a5750|ldr|x24, [x0, #0x2f0]
port_prepare|fffffe000c2a581c|ldr|w8, [x19, #8]
port_prepare|fffffe000c2a5824|str|w8, [x19, #8]
port_prepare|fffffe000c2a5828|cmp|w8, #3
port_prepare|fffffe000c2a582c|b.ls|#0xfffffe000c2a57cc
port_prepare|fffffe000c2a5830|b|#0xfffffe000c2a58d8
port_prepare|fffffe000c2a584c|cmp|w8, #0xe
port_prepare|fffffe000c2a5880|cmp|w8, #0x80
port_prepare|fffffe000c2a5928|add|x8, x19, #0x20
port_prepare|fffffe000c2a59ac|mov|w2, #0x13
port_prepare|fffffe000c2a59b0|mov|w3, #1
port_prepare|fffffe000c2a59b4|mov|w4, #7
port_prepare|fffffe000c2a59bc|bl|#0xfffffe000bcc9658
port_prepare|fffffe000c2a59f0|str|x8, [x9, w21, sxtw #3]
port_prepare|fffffe000c2a5a18|bl|#0xfffffe000c25a0ec
port_prepare|fffffe000c2a5a38|str|x8, [x19, #0x38]
port_prepare|fffffe000c2a5a48|str|x8, [x9, w27, sxtw #3]
port_prepare|fffffe000c2a5a74|str|x25, [x11, #8]
port_prepare|fffffe000c2a5a80|str|x8, [x9, x10]
port_prepare|fffffe000c2a58d8|mov|w8, #0x16
port_prepare|fffffe000c2a593c|bl|#0xfffffe000bcd0448
port_prepare|fffffe000c2a5a9c|bl|#0xfffffe000bcfa548
special_front|fffffe000bcfa5dc|b|#0xfffffe000bcfa334
special_store|fffffe000bcfa39c|cmp|w1, #4
special_store|fffffe000bcfa408|add|x9, x0, #0x2d8
special_store|fffffe000bcfa4a0|str|x17, [x9]
special_store|fffffe000bcfa4d4|bl|#0xfffffe000bcd0448
registered_store|fffffe000bcfa6f0|add|x8, x9, #0x2f8
registered_store|fffffe000bcfa72c|str|x17, [x9, #0x2f8]
registered_store|fffffe000bcfa76c|str|x17, [x9, #0x300]
registered_store|fffffe000bcfa7ac|str|x17, [x9, #0x308]
registered_store|fffffe000bcfa7d0|bl|#0xfffffe000bcd0448
registered_store|fffffe000bcfa7d8|bl|#0xfffffe000bcd0448
registered_store|fffffe000bcfa7e0|bl|#0xfffffe000bcd0448
'''

def verify(s):
 assert s['source_sha256']=='1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168'
 assert s['kernel_source_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a';rows=[]
 def need(scope,rr,role,mn,op):
  hits=[i for i in rr[role]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(role,mn,op)
  rows.extend({'scope':scope,'role':role,**i}for i in hits)
 for v in s['variants']:
  assert v['fixup_reference']['all_matches']and v['fixup_reference']['fixups_compared']==2447
  rr=v['roles']
  for role,name in [('launch_core','_posix_spawnattr_set_registered_ports_np'),('attribute_prepare','_posix_spawnattr_set_importancewatch_port_np')]:
   assert v['stubs'][name]['binding']['symbol']==name;need(v['label'],rr,role,'bl','#'+v['stubs'][name]['address'])
  for role,mn,op in [('launch_core','mov','w2, #2'),('launch_core','stp','w9, w8, [x29, #-0x98]'),
    ('launch_core','ldr','w8, [x19, #0x2ec]'),('attribute_prepare','mov','x1, x23'),('attribute_prepare','mov','x2, x22')]:need(v['label'],rr,role,mn,op)
  for r in rr.values():
   raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and len(raw)==4*len(r['instructions'])==int(r['end'],16)-int(r['start'],16)
   for j,i in enumerate(r['instructions']):
    b=raw[j*4:j*4+4];pc=int(r['start'],16)+4*j;assert i['ea']==hex(pc)and i['bytes']==i['LLVM']['bytes']==b.hex();cc=list(CS.disasm(b,pc))
    if cc:assert(i['mnemonic'],i['operands'])==(cc[0].mnemonic,cc[0].op_str)
    else:assert i['decoder']=='LLVM'and(i['mnemonic'],i['operands'])==(i['LLVM']['mnemonic'],i['LLVM']['operands'])
 shared=s['shared_cell_interfaces'];assert len(shared)==8
 assert {q['role']for q in shared}=={'registered_input','notification_destination','fixed_host22','fixed_host16'}
 for q in shared:
  raw=bytes.fromhex(q['bytes']);cc=list(CS.disasm(raw,int(q['start'],16)));assert len(raw)==8 and len(cc)==2 and h(raw)==q['sha256']
  assert q['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in cc]
  assert cc[0].mnemonic=='adrp'and cc[0].op_str.endswith('#0x10008a000')
  assert cc[1].mnemonic=='ldr'and cc[1].op_str.endswith('#0xf20]')and q['global_cell']=='0x10008af20'
  rows.extend({'scope':q['label'],'role':q['role'],**i}for i in q['instructions'])
 cf=s['cache_functions'];k=s['kernel_functions'];assert len(cf)==9 and len(k)==13
 for line in PATTERNS.strip().splitlines():role,mn,op=line.split('|');need('cache',cf,role,mn,op)
 for name in SETTERS:
  assert any(q['name']==name for q in cf[name]['original_nlist']);need('cache',cf,name,'bl','#'+cf['port_append']['start'])
 for n,off in [('_posix_spawnattr_setauditsessionport_np',0x328),('_posix_spawnattr_set_importancewatch_port_np',0x330),
  ('_posix_spawnattr_set_registered_ports_np',0x338),('_posix_spawnattr_set_ptrauth_task_port_np',0x340),('_posix_spawnattr_set_virtual_env_np',0x348)]:
  need('cache',cf,n,'adrp','x8, #0x18057d000');need('cache',cf,n,'ldr',('d8'if'importance'in n or'registered'in n else'd0')+', [x8, #'+hex(off)+']')
 for line in KERNEL.strip().splitlines():
  role,ea,mn,op=line.split('|');i=next(q for q in k[role]['instructions']if q['ea']=='0x'+ea);assert(i['mnemonic'],i['operands'])==(mn,op);rows.append({'scope':'kernel','role':role,**i})
 for r in list(cf.values())+list(k.values()):
  raw=bytes.fromhex(r['bytes']);cc=list(CS.disasm(raw,int(r['start'],16)))
  assert h(raw)==r['sha256']and len(raw)==4*len(cc)==4*len(r['instructions'])==int(r['end'],16)-int(r['start'],16)
  assert [(i['ea'],i['mnemonic'],i['operands'])for i in r['instructions']]==[(hex(i.address),i.mnemonic,i.op_str)for i in cc]
 assert any(q['name']=='_ipc_port_release_send'for q in k['send_release']['original_nlist'])
 assert [r['u32_words']for r in s['kind_literals']]==[[i,0]for i in range(2,7)]
 assert all(list(struct.unpack('<II',bytes.fromhex(r['bytes'])))==r['u32_words']for r in s['kind_literals'])
 a=s['frame_alias_analysis'];assert a==analyze(k['syscall'])
 assert a['counts']['CFG_reachable_instructions']==2556 and a['counts']['unsupported_frame_operations']==0
 assert a['counts']['resolved_memory_sites']==362 and a['counts']['dynamic_memory_sites']==1
 assert a['counts']['frame_argument_call_sites']==19 and a['counts']['frame_pointer_escape_stores']==3
 assert [q['ea']for q in a['Conclave_overlapping_accesses']]==['0xfffffe000c2a2bc0','0xfffffe000c2a2d14']
 assert a['counts']['Conclave_overlapping_resolved_loads']==0
 assert a['states']['0xfffffe000c2a2d14']['x25']==[0x150]
 assert a['states']['0xfffffe000c2a3774']['x25']==[0x110]
 assert a['dynamic_accesses'][0]['ea']=='0xfffffe000c2a3774'
 descriptor_calls=[q for q in a['calls']if any(0x250 in z for z in q['args'].values())]
 assert [q['ea']for q in descriptor_calls]==['0xfffffe000c2a2d84','0xfffffe000c2a4d4c']
 assert [(q['instruction'],list(q['stored_frame_offsets'].values()))for q in a['escapes']]==[
  ('str x8, [x27, #0x2a8]',[[0x2e8]]),('str x22, [x27, #0x2e0]',[[0x150]]),('str x8, [x26, #0x798]',[[0x150]])]
 g=s['record_geometry'];assert(g['action_stride_bytes'],g['temporary_registered_error_max'],g['temporary_registered_admitted_max'],g['temporary_base_SP'])==(24,4,3,0xf0)
 assert g['temporary_registered_ports_offset']==0x20 and g['temporary_bytes']==64
 assert s['BSD244']['handler_pointer']['target']==k['syscall']['start']and s['BSD244']['argument_count']==5
 assert all(s[f]is False for f in FLAGS);return rows

def reference_frame_checks(s):
 # Independent literal SP/FP geometry certificate from the verified prologue/epilogue.
 # Cold blocks after RETAB retain the normal frame through CFG branches.
 a=s['kernel_functions']['syscall']['instructions'];by={r['ea']:r for r in s['frame_alias_analysis']['accesses']};rows=[]
 for j,i in enumerate(a):
  m=re.search(r'\[(sp|x29)(?:, #(-?(?:0x)?[0-9a-f]+))?\]',i['operands'])
  if not m:continue
  assert i['mnemonic']in ['ldr','ldp','ldrh','ldrb','ldrsh','ldur','str','stp','stur'],i
  if m[1]=='sp':base=0x3f0 if j<=1 else 0x370 if 2<=j<=10 or 1214<=j<=1221 else 0
  else:base=0x3e0
  off=int(m[2],0)if m[2]else 0
  reg=i['operands'].split(',')[0];mn=i['mnemonic']
  lane=1 if mn=='ldrb'else 2 if mn in ['ldrh','ldrsh']else {'x':8,'w':4,'q':16,'d':8,'s':4}[reg[0]]
  width=lane*(2 if mn in ['ldp','stp']else 1)
  r=by[i['ea']];assert r['frame_offsets']==[base+off]and r['size_bytes']==width,(i,r,base,off,width)
  rows.append({'ea':i['ea'],'base_register':m[1],'offset_bytes':base+off,'size_bytes':width})
 assert rows;return rows

def sdk_checks():
 code='''#include <spawn.h>
#include <mach/message.h>
#include <mach/task_special_ports.h>
#include <mach/exception_types.h>
#include <mach/kern_return.h>
#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>
#define A(x) static_assert((x), #x)
struct action {uint32_t kind,mask,port,behavior,flavor,selector;};
struct prefix {uint32_t capacity,count;};
struct temporary {uint32_t exception_count,importance_count,registered_count,reserved;uint64_t exceptions,importance,registered[3],virtual_environment;};
A(sizeof(posix_spawnattr_t)==8);A(sizeof(mach_port_t)==4);A(sizeof(exception_mask_t)==4);
A(sizeof(exception_behavior_t)==4);A(sizeof(thread_state_flavor_t)==4);
A(MACH_MSG_TYPE_COPY_SEND==19);A(TASK_BOOTSTRAP_PORT==4);A(EXC_TYPES_COUNT==14);
A(sizeof(action)==24);A(offsetof(action,mask)==4);A(offsetof(action,port)==8);
A(offsetof(action,behavior)==12);A(offsetof(action,flavor)==16);A(offsetof(action,selector)==20);
A(sizeof(prefix)==8);A(offsetof(prefix,count)==4);A(sizeof(temporary)==64);
A(offsetof(temporary,registered)==32);A(offsetof(temporary,virtual_environment)==56);
A(EINVAL==22);A(ENOMEM==12);A(KERN_INVALID_ARGUMENT==4);A(KERN_INVALID_RIGHT==17);
A(__is_same(decltype(&posix_spawnattr_setspecialport_np),int(*)(posix_spawnattr_t*,mach_port_t,int)));
A(__is_same(decltype(&posix_spawnattr_setexceptionports_np),int(*)(posix_spawnattr_t*,exception_mask_t,mach_port_t,exception_behavior_t,thread_state_flavor_t)));
A(__is_same(decltype(&posix_spawnattr_setauditsessionport_np),int(*)(posix_spawnattr_t*,mach_port_t)));
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-']
 r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,
  'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'exit_code':r.returncode,'stderr':r.stderr,
  'scope':'Primary SDK public widths/constants/prototypes; explicitly reconstructed private action/prefix/temporary geometry. No canonical private type or native execution claim.'}

def proofs():
 queries={
 'registered_count_step_bound':'''(declare-fun c () (_ BitVec 32))
(assert (bvule c (_ bv3 32)))
(define-fun n () (_ BitVec 32) (bvadd c (_ bv1 32)))
(assert (or (bvugt n (_ bv4 32)) (and (not (bvule n (_ bv3 32))) (distinct n (_ bv4 32)))))''',
 'bounded_cleanup_is_disjoint_from_Conclave_pair':'''(declare-fun i () (_ BitVec 64))
(assert (bvult i (_ bv4 64)))
(define-fun a () (_ BitVec 64) (bvadd (_ bv272 64) (bvshl i (_ bv3 64))))
(assert (and (bvult a (_ bv736 64)) (bvugt (bvadd a (_ bv8 64)) (_ bv720 64))))''',
 'admitted_port_array_size':'''(declare-fun n () (_ BitVec 32))
(assert (bvsge n (_ bv0 32)))
(define-fun z () (_ BitVec 64) ((_ zero_extend 32) n))
(define-fun a () (_ BitVec 64) (bvadd (bvshl (bvadd z (bvshl z (_ bv1 64))) (_ bv3 64)) (_ bv8 64)))
(assert (distinct a (bvadd (bvmul z (_ bv24 64)) (_ bv8 64))))'''}
 out=[]
 for name,body in queries.items():
  query='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,capture_output=True,text=True)
  assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':query,'result':'unsat','scope':'Instruction-matched scalar invariant/offset identity, conditional on initialization, selected branches and no external record mutation. Not an end-to-end alias, admission, ownership or native-effect proof.'})
 return out

def alterations(s):
 def literal(q):q['kind_literals'][2]['u32_words'][0]=3
 def census(q):q['frame_alias_analysis']['counts']['frame_argument_call_sites']=18
 def cap(q):q['record_geometry']['temporary_registered_error_max']=3
 def import_kind(q):next(i for i in q['kernel_functions']['port_prepare']['instructions']if i['ea']=='0xfffffe000c2a59ac')['operands']='w2, #0x11'
 def launch(q):next(i for i in q['variants'][0]['roles']['launch_core']['instructions']if i['ea']=='0x10001f774')['operands']='w2, #3'
 def identity(q):q['kernel_source_sha256']='0'*64
 out=[]
 for name,change in [('kind_literal',literal),('frame_call_census',census),('partial_error_count_bound',cap),('port_disposition',import_kind),('launchd_registered_count',launch),('kernel_identity',identity)]:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence: '+name)
 return out

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);ref=reference_frame_checks(s);sdk=sdk_checks();pr=proofs();neg=alterations(s)
 c={'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['recover_'+P+'.py','analyze_spawn_port_frame.py']},
  'source_recapture_match':True,'reference_frame_checks':ref,'instruction_assertions':rows,'SDK_checks':sdk,'proofs':pr,'alterations':neg,
  'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],
   'direct_SP_FP_accesses_checked':len(ref),'SDK_compilations':1,'scalar_queries_unsat':len(pr),'rejected_evidence_alterations':len(neg)},
  'all_checks_pass':True,'static_scope':'Spawn port-action producers/import/apply/cleanup, explicit frame-origin locator and bounded dynamic cleanup. Opaque loads/calls, escaped objects, native admission/identity/right balance, Conclave consumption and whole-kernel non-use remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
