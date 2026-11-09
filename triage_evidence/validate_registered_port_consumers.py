#!/usr/bin/env python3
"""Static initialization, registered-port, bootstrap and daemon-link checks.
No target execution, native requests, fork, policy experiment or IDB mutation.
"""
import copy,json,struct,subprocess
from pathlib import Path
from recover_registered_port_consumers import ROOT,P,FLAGS,KP,XP,BP,MP,CP,SDK,sha,h,CS,build
PATTERNS='''
__kernelrpc_mach_ports_register3|bl|#0x18055a894
__kernelrpc_mach_ports_lookup3|bl|#0x18055a894
_task_get_special_port|bl|#0x18055a894
register_legacy|bl|#0x18055a894
lookup_legacy|bl|#0x18055a894
_mach_ports_lookup|mov|w2, #0xc
_mach_ports_lookup|add|x2, x23, #4
_mach_ports_lookup|add|x3, x23, #8
_mach_ports_lookup|mov|w8, #3
_mach_ports_lookup|str|x23, [x20]
_mach_ports_lookup|str|w8, [x19]
_mach_ports_register|cmp|w2, #3
_mach_ports_register|mov|w0, #4
_mach_ports_register|cmn|w0, #0x130
_mach_ports_register|mov|w1, #0
lookup_legacy|cmp|w8, #1
lookup_legacy|ldur|x19, [sp, #0x24]
lookup_legacy|str|x19, [x21]
lookup_legacy|str|w8, [x20]
__kernelrpc_mach_ports_lookup3|mov|x4, #0xd4c00000000
__kernelrpc_mach_ports_lookup3|mov|w6, #0x48
__kernelrpc_mach_ports_lookup3|cmp|w9, #3
__kernelrpc_mach_ports_lookup3|cmp|w8, #0x40
__kernelrpc_mach_ports_lookup3|cmp|w8, #0xdb0
__kernelrpc_mach_ports_lookup3|str|w8, [x21]
__kernelrpc_mach_ports_lookup3|str|w9, [x20]
__kernelrpc_mach_ports_lookup3|str|w8, [x19]
__kernelrpc_mach_ports_register3|mov|w20, #3
__kernelrpc_mach_ports_register3|mov|x4, #0xd4b00000000
__kernelrpc_mach_ports_register3|mov|w6, #0x2c
_task_get_special_port|mov|x4, #0xd5100000000
_task_get_special_port|mov|w6, #0x30
_task_get_special_port|cmp|w8, #0x28
_task_get_special_port|str|w8, [x19]
__libxpc_initializer|ldr|w9, [x0]
__libxpc_initializer|str|w9, [x20, #0x10]
__libxpc_initializer|str|w9, [x20, #0x14]
__libxpc_initializer|mov|w1, #4
__libxpc_initializer|str|w1, [x8]
__libxpc_initializer|mov|w2, #0
__libxpc_initializer|mov|w3, #1
__libxpc_initializer|str|w24, [x0, #0x18]
bootstrap_pipe|ldr|w1, [x19, #0x10]
bootstrap_pipe|mov|w2, #4
bootstrap_pipe|str|x0, [x19, #0x18]
_xpc_atfork_prepare|stur|w8, [x29, #-4]
_xpc_atfork_prepare|mov|w2, #1
_xpc_atfork_prepare|sub|x1, x29, #4
__NSGetMachExecuteHeader|ldr|x0, [x8, #0xda0]
'''
KERNEL='''
MIG3404|fffffe000bd9734c|str|x17, [x10]
MIG3404|fffffe000bd97364|str|x17, [x9]
MIG3404|fffffe000bd9737c|stur|x17, [x8, #0x44]
MIG3409|fffffe000bd96f10|stur|x17, [x19, #0x24]
registered_lookup|fffffe000bcfa8a0|ldr|x16, [x19, #0x2f8]
registered_lookup|fffffe000bcfa8e0|ldr|x16, [x19, #0x300]
registered_lookup|fffffe000bcfa908|ldr|x16, [x19, #0x308]
registered_lookup|fffffe000bcfa8dc|str|x0, [x24]
registered_lookup|fffffe000bcfa904|str|x0, [x23]
registered_lookup|fffffe000bcfa934|str|x8, [x22]
copy_send|fffffe000bcd002c|ldr|w8, [x0, #0x88]
copy_send|fffffe000bcd0038|str|w8, [x0, #0x88]
copy_send|fffffe000bcd004c|ldadd|w9, w9, [x8]
special_core|fffffe000bcf98d0|cmp|w1, #4
special_core|fffffe000bcf98d8|ldr|x16, [x0, #0x2d8]
special_core|fffffe000bcf98e8|add|x17, x0, #0x2d8
MIG3403|fffffe000bd973bc|cmp|w8, #3
MIG3403|fffffe000bd973c8|cmp|w8, #0x54
MIG3404|fffffe000bd97274|cmp|w8, #0x20
MIG3404|fffffe000bd97388|mov|w10, #0x54
MIG3404|fffffe000bd97390|mov|w9, #3
MIG3409|fffffe000bd96e8c|cmp|w8, #0x2c
'''

def verify(s):
 assert s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a'and s['kernel_source_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 cf=s['cache_functions'];kf=s['kernel_functions'];rows=[]
 def need(scope,rr,role,mn,op):
  hits=[i for i in rr[role]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(role,mn,op)
  rows.extend({'scope':scope,'role':role,**i}for i in hits)
 for line in PATTERNS.strip().splitlines():role,mn,op=line.split('|');need('cache',cf,role,mn,op)
 for line in KERNEL.strip().splitlines():
  role,ea,mn,op=line.split('|');i=next(q for q in kf[role]['instructions']if q['ea']=='0x'+ea);assert(i['mnemonic'],i['operands'])==(mn,op);rows.append({'scope':'kernel','role':role,**i})
 for scope,rr in [('cache',cf),('kernel',kf)]:
  for role,f in rr.items():
   raw=bytes.fromhex(f['bytes']);cc=list(CS.disasm(raw,int(f['start'],16)))
   assert h(raw)==f['sha256']and len(raw)==int(f['end'],16)-int(f['start'],16)==4*len(cc)==4*len(f['instructions'])
   assert [(q['ea'],q['mnemonic'],q['operands'])for q in f['instructions']]==[(hex(q.address),q.mnemonic,q.op_str)for q in cc]
 bindings={0x188087980:'_mach_ports_lookup',0x188087990:'_mach_ports_register',0x1880879b0:'_mig_deallocate',
  0x188087cc0:'_task_get_special_port',0x1880878d0:'_getsectbyname',0x2d00b4d20:'__NSGetMachExecuteHeader'}
 assert len(s['cache_stubs'])==8
 for r in s['cache_stubs'].values():
  b=r['symbol_binding'];assert r['pointer']['chain_membership_verified']and r['pointer']['authenticated']and r['pointer']['target']==b['address']
  assert s['cache_libraries'][b['library']]==b['library_uuid']and any(q['name']==b['exact_export']for q in b['original_nlist'])
  zz=list(CS.disasm(bytes.fromhex(r['bytes']),int(r['address'],16)));assert len(zz)==4 and r['instructions']==[{'ea':hex(q.address),'mnemonic':q.mnemonic,'operands':q.op_str}for q in zz]
  assert[q.mnemonic for q in zz]==['adrp','add','ldr','braa']
 for a,role in bindings.items():
  r=s['cache_stubs'][hex(a)];p=r['pointer'];assert p['chain_membership_verified']and p['authenticated']and p['target']==cf[role]['start']
  bb=bytes.fromhex(r['bytes']);cc=list(CS.disasm(bb,a));assert len(cc)==4 and r['instructions']==[{'ea':hex(q.address),'mnemonic':q.mnemonic,'operands':q.op_str}for q in cc]
  assert[q.mnemonic for q in cc]==['adrp','add','ldr','braa']
 for caller,target in [('_mach_ports_lookup','__kernelrpc_mach_ports_lookup3'),('_mach_ports_lookup','lookup_legacy'),
  ('_mach_ports_register','__kernelrpc_mach_ports_register3'),('_mach_ports_register','register_legacy'),('bootstrap_pipe','pipe_create')]:
  need('cache',cf,caller,'b'if target=='register_legacy'else'bl','#'+cf[target]['start'])
 for role,target in [('registered_lookup','copy_send'),('MIG3403','registered_store'),('MIG3404','registered_lookup'),('MIG3409','special_front'),('special_front','special_core')]:
  need('kernel',kf,role,'bl','#'+kf[target]['start'])
 for role,stub in [('__libxpc_initializer',0x188087980),('__libxpc_initializer',0x188087cc0),('bootstrap_pipe',0x18806cf50),('_xpc_atfork_prepare',0x188087990)]:need('cache',cf,role,'bl','#'+hex(stub))
 for mid,maximum in [(3403,44),(3404,84),(3409,52)]:
  q=s['MIG_bindings'][str(mid)];assert q['reply_size_word1c']==maximum and q['stub']['target']==kf['MIG'+str(mid)]['start']
 init=s['initializer_registration'];assert init['targets']==[cf['libSystem_initializer']['start']]
 assert [hex(int(init['library_base'],16)+v[0])for v in struct.iter_unpack('<I',bytes.fromhex(init['bytes']))]==init['targets']
 assert [q['role']for q in s['initializer_edges']]==['___libkernel_init','__libxpc_initializer']
 for q in s['initializer_edges']:assert q['pointer']['target']==cf[q['role']]['start']and q['pointer']['chain_membership_verified']
 assert {q['path']for q in s['libSystem_reexports']} >= {KP,XP}
 ptrs={q['pointer']['address']:q for q in s['cache_pointer_bindings']}
 for slot,target,name in [('0x1e01c8b30','0x1ed83e960','_mach_task_self_'),('0x1e01c8ad0','0x1ed83e95c','_bootstrap_port'),('0x1e01c8ac8','0x1eb065e20','__os_xbs_chrooted')]:
  q=ptrs[slot];assert q['pointer']['target']==target and any(r['name']==name for r in q['original_nlist'])
 assert bytes.fromhex(s['file_default_cells'][0]['bytes'])==b'\0'and all(not q['native_value_observed']for q in s['file_default_cells'])
 d=s['daemon'];assert d['sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 assert d['imports_reference']['entries_compared']==len(d['imports'])==243
 assert d['sections_reference']['sections_compared']==len(d['sections'])==29
 names={r['symbol']for r in d['imports']};assert '_mach_ports_lookup'not in names and '_mach_ports_register'not in names
 assert {'_bootstrap_port','_bootstrap_check_in'}<=names
 assert not {'__launchd','__xpcproxy','__launchctl'}&{r['section']for r in d['sections']if r['segment']=='__TEXT'}
 b=d['bootstrap_binding'];assert b['import']['ordinal']==19 and b['import']['symbol']=='_bootstrap_port'and b['import']['library']==BP
 assert b['import']['addend']==0x7da61013 and b['pointer_addend']==0 and not b['authenticated']
 assert int.from_bytes(bytes.fromhex(b['bytes']),'little')==int(b['word'],16)==0x4008000000000013
 bank=d['bootstrap_bank'];l,r=[bytes.fromhex(q['bytes'])for q in bank['tables']]
 assert len(l)==len(r)==256 and set(i^r[l[i]^0x6c]for i in range(256))=={0x87}
 assert int(bank['pool'],16)+8*(0x87+0x29c)==int(bank['slot'],16)==int(b['slot'],16)
 for f in d['fragments']:
  raw=bytes.fromhex(f['bytes']);cc=list(CS.disasm(raw,int(f['start'],16)));assert h(raw)==f['sha256']and len(raw)==4*len(cc)
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in cc]
 need('daemon',{f['role']:f for f in d['fragments']},'bootstrap_data_forward','ldr','w0, [x11]')
 need('daemon',{f['role']:f for f in d['fragments']},'bootstrap_data_forward','mov','x12, #-0x1013')
 need('daemon',{f['role']:f for f in d['fragments']},'bootstrap_data_forward','movk','x12, #0x8259, lsl #16')
 need('daemon',{f['role']:f for f in d['fragments']},'checkin_call','blraa','x8, x17')
 job=s['job_declaration'];assert job['sha256']=='ca21543400f3ead9e96d2434f968184b6acd2e1e3de57322ca3da663831eae3c'
 assert job['relevant_plist'].get('EnvironmentVariables')=={'DYLD_PAGEIN_LINKING':'0'}
 assert all(s[k]is False for k in FLAGS);return rows

def sdk_checks():
 user='''#define __MigPackStructs 1
#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/message.h>
#include <mach/task_special_ports.h>
#include <mach/mig_errors.h>
#include <stddef.h>
#define A(x) static_assert((x), #x)
#pragma pack(push,4)
struct fixed3 {mach_msg_header_t head;mach_msg_body_t body;mach_msg_port_descriptor_t ports[3];};
struct special_reply {mach_msg_header_t head;mach_msg_body_t body;mach_msg_port_descriptor_t port;};
#pragma pack(pop)
A(sizeof(mach_msg_header_t)==24);A(sizeof(mach_msg_port_descriptor_t)==12);A(sizeof(mach_port_t)==4);
A(sizeof(fixed3)==64);A(offsetof(fixed3,ports)==28);A(sizeof(special_reply)==40);
A(sizeof(__Request__mach_ports_lookup_t)==24);A(sizeof(__Request__mach_ports_register_t)==56);
A(sizeof(__Reply__mach_ports_lookup_t)==56);A(sizeof(__Reply__mach_ports_register_t)==36);
A(sizeof(__Request__task_get_special_port_t)==36);A(sizeof(__Reply__task_get_special_port_t)==40);
A(MACH_MSG_TYPE_COPY_SEND==19);A(MACH_MSG_TYPE_MOVE_SEND==17);A(MACH_MSG_TYPE_MAKE_SEND_ONCE==21);
A(MACH_MSGH_BITS_COMPLEX==0x80000000U);A(TASK_BOOTSTRAP_PORT==4);A(MACH_PORT_RIGHT_SEND==0);
A(MACH_PORTS_SLOTS_USED==3);A(MIG_BAD_ID==-303);A(MIG_TYPE_ERROR==-300);A(MIG_BAD_ARGUMENTS==-304);
A(__is_same(decltype(&mach_ports_lookup),kern_return_t(*)(task_t,mach_port_array_t*,mach_msg_type_number_t*)));
'''
 kernel='''#include <mach/message.h>
#include <mach/ndr.h>
#include <stddef.h>
#define A(x) static_assert((x), #x)
#pragma pack(push,4)
struct fixed3 {mach_msg_header_t head;mach_msg_body_t body;mach_msg_port_descriptor_t ports[3];};
struct special_reply {mach_msg_header_t head;mach_msg_body_t body;mach_msg_port_descriptor_t port;};
struct error_reply {mach_msg_header_t head;NDR_record_t ndr;int status;};
#pragma pack(pop)
A(sizeof(mach_msg_header_t)==32);A(sizeof(mach_msg_port_descriptor_t)==16);
A(sizeof(fixed3)==84);A(offsetof(fixed3,ports)==36);A(sizeof(special_reply)==52);A(sizeof(error_reply)==44);
A(32+4+3*16==84);A(24+4+3*12==64);A((32-24)+3*(16-12)==20);
'''
 out=[];kh=SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers'
 for label,code in [('user',user),('kernel',kernel)]:
  cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-']
  if label=='kernel':cmd[1:1]=['-I',str(kh),'-DKERNEL','-fapple-kext','-fno-exceptions','-fno-rtti']
  r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
  out.append({'mode':label,'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr})
 return{'compilations':out,'assertions':sum(q['assertions']for q in out),'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),
  'scope':'Primary user/Kernel SDK header, descriptor, generated legacy types, constants and prototype checks; fixed-three-port aggregates are explicitly reconstructed. No request serialization or target execution.'}

def proofs():
 queries={
 'u32_name_domain':'''(declare-fun n () (_ BitVec 32))
(assert (distinct (bvugt (bvadd n (_ bv1 32)) (_ bv1 32))
 (and (distinct n (_ bv0 32)) (distinct n #xffffffff))))''',
 'three_port_header_descriptor_growth':'''(declare-fun n () (_ BitVec 32))
(assert (bvule n (_ bv3 32)))
(define-fun u () (_ BitVec 64) (bvadd (_ bv28 64) (bvmul ((_ zero_extend 32) n) (_ bv12 64))))
(define-fun k () (_ BitVec 64) (bvadd (_ bv36 64) (bvmul ((_ zero_extend 32) n) (_ bv16 64))))
(assert (distinct (bvsub k u) (bvadd (_ bv8 64) (bvmul ((_ zero_extend 32) n) (_ bv4 64)))))''',
 'daemon_bootstrap_import_addend_cancellation':'''(declare-fun base () (_ BitVec 64))
(assert (distinct (bvadd (bvadd base #x000000007da61013) #xffffffff8259efed) base))'''}
 out=[]
 for name,body in queries.items():
  query='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,capture_output=True,text=True)
  assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':query,'result':'unsat','scope':'Instruction-matched scalar name/size/address identity only. No source reachability, pointer validity, byte continuity, native initialization, namespace or ownership proof.'})
 return out

def alterations(s):
 def order(q):q['initializer_edges'].reverse()
 def marker(q):q['daemon']['sections'][0]['section']='__xpcproxy'
 def extent(q):q['MIG_bindings']['3404']['reply_size_word1c']=72
 def alias(q):q['cache_pointer_bindings'][1]['pointer']['target']='0x1ed83e960'
 def addend(q):q['daemon']['bootstrap_binding']['import']['addend']=0
 def bank(q):
  a=q['daemon']['bootstrap_bank']['tables'][0];b=bytearray.fromhex(a['bytes']);b[0]^=1;a['bytes']=b.hex()
 out=[]
 for name,change in [('initializer_order',order),('daemon_role_marker',marker),('kernel_descriptor_extent',extent),('bootstrap_data_alias',alias),('daemon_import_addend',addend),('selector_bank_byte',bank)]:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence: '+name)
 return out

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();neg=alterations(s)
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,
  'instruction_assertions':rows,'SDK_checks':sdk,'proofs':pr,'alterations':neg,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],
   'SDK_compilations':2,'scalar_queries_unsat':len(pr),'rejected_evidence_alterations':len(neg)},
  'all_checks_pass':True,'static_scope':'Registered-port lookup/register, libSystem/libkernel/libxpc initialization, role/configuration gates, bootstrap data/pipes, atfork stash, fixed-three-port client/kernel geometry and FairPlay import forwarding. Native image/header/role, namespace identity, right balance and bootstrap value remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
