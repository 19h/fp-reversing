#!/usr/bin/env python3
"""Instruction, layout, byte-footprint and full-domain scalar checks.
O(B+F+I) static recapture; finite store footprint is 256 B. No target effects.
"""
import copy,json,re,struct,subprocess
from recover_launchd_service_endpoint import ROOT,P,FLAGS,ROLES,SDK,sha,h,CS,build
def verify(s):
 assert s['launchd_source_sha256']=='1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168'and s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a'and s['kernel_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 records=[];footprints=[]
 for j,v in enumerate(s['variants']):
  r=v['roles'];assert set(r)==set(ROLES[j])and all(int(r[name]['start'],16)==a for name,a in ROLES[j].items());assert v['fixup_reference']['all_matches']and v['fixup_reference']['fixups_compared']==2447
  def at(role,off,mn,op=None):
   ea=int(r[role]['start'],16)+off;i=next(i for i in r[role]['instructions']if int(i['ea'],16)==ea);assert i['mnemonic']==mn and(op is None or i['operands']==op),(v['label'],role,hex(off),i,mn,op);records.append({'scope':v['label'],'role':role,**i});return i
  def call(role,off,name):return at(role,off,'bl','#'+v['stubs'][name]['address'])
  def local(role,off,dest):return at(role,off,'bl','#'+r[dest]['start'])
  # Fast cache, creation mode and exact scalar selection from caller-owned fields.
  for off,mn,op in[(0x1c,'ldr','x8, [x0, #0x68]'),(0x24,'and','w8, w1, #7'),(0x28,'cmp','w8, #1'),(0x54,'ldrh','w8, [x19, #0xa0]'),(0x58,'tbnz',None),(0x5c,'tbnz',None),(0x60,'tbnz',None),(0x68,'ldr','x20, [x9, #0xa38]'),(0x6c,'add','x10, x20, #1'),(0x70,'str','x10, [x9, #0xa38]'),(0x74,'tbnz',None),(0x7c,'ldrb','w8, [x0, #0x583]'),(0x84,'mov','w1, #4'),(0x90,'mov','w21, #0x37'),(0xb0,'mov','w21, #0x2037'),(0xb8,'ldr','x0, [x8, #0xf8]'),(0xc4,'add','x2, x19, #0xa8'),(0xcc,'mov','w1, #6'),(0xd0,'mov','x4, x20'),(0xd8,'str','x20, [x19, #0x70]'),(0xdc,'mov','w1, #0x11'),(0xe8,'str','x0, [x19, #0x68]'),(0xf0,'and','w8, w9, w8'),(0xf4,'cmp','w8, #2')]:at('send_object',off,mn,op)
  local('send_object',0xbc,'domain');local('send_object',0xd4,'factory');call('send_object',0xe0,'_xpc_mach_send_create_with_disposition');local('send_object',0x100,'receive_source')
  for off,mn,prefix,dest in[(0x58,'tbnz','w8, #3, #',0x11c),(0x5c,'tbnz','w8, #0, #',0x12c),(0x60,'tbnz','w8, #5, #',0x98),(0x74,'tbnz','w8, #0xd, #',0xb0),(0x80,'tbnz','w8, #6, #',0xb0),(0x8c,'tbz','w0, #0, #',0xb0)]:at('send_object',off,mn,prefix+hex(int(r['send_object']['start'],16)+dest))
  # Complete options and info record production, retaining the one-byte overlap.
  for off,mn,op in[(0x1c,'mov','x19, x4'),(0x20,'mov','x20, x2'),(0x24,'mov','x21, x0'),(0x28,'add','x22, sp, #0x20'),(0x3c,'str','w1, [sp, #0xc]'),(0x40,'str','xzr, [sp, #0x18]'),(0x44,'movi','v0.2d, #0000000000000000'),(0x6c,'strb','w3, [sp, #0x11f]'),(0x80,'cmp','x0, #0xfe'),(0x84,'csel','x1, x8, x20, hi'),(0x88,'add','x0, sp, #0x20'),(0x8c,'mov','w2, #0xff'),(0x90,'mov','w3, #0xff'),(0x98,'orr','w8, w21, #0x400'),(0x9c,'str','w8, [sp, #8]'),(0xa0,'str','x22, [sp, #0x10]'),(0xa4,'add','x0, sp, #8'),(0xa8,'mov','x1, x19')]:at('factory',off,mn,op)
  call('factory',0x74,'_strlen');call('factory',0x94,'___strlcpy_chk');local('factory',0xac,'construct_or_crash')
  stores=v['info_zero_stores'];assert[(q['offset_bytes'],q['size_bytes'])for q in stores]==[(239,16),(208,32),(176,32),(144,32),(112,32),(80,32),(48,32),(16,32),(0,16)];coverage=[0]*256
  for row in stores:
   assert row['instruction']in r['factory']['instructions']
   for x in range(row['offset_bytes'],row['offset_bytes']+row['size_bytes']):coverage[x]+=1
  assert coverage[:239]==[1]*239 and coverage[239]==2 and coverage[240:255]==[1]*15 and coverage[255]==0;footprints.append({'variant':v['label'],'zero_store_count':len(stores),'unique_zeroed_bytes':255,'zero_store_bytes_including_overlap':sum(coverage),'overlap_offsets':[239],'domain_byte_offset':255})
  at('construct_or_crash',0x10,'stur','wzr, [x29, #-4]');local('construct_or_crash',0x18,'construct_status');at('construct_or_crash',0x1c,'cbnz');at('construct_or_crash',0x20,'ldur','w0, [x29, #-4]');at('construct_or_crash',0x54,'brk','#1')
  for off,mn,op in[(0xc,'mov','x3, x2'),(0x10,'mov','x2, x1'),(0x14,'mov','x1, x0'),(0x20,'ldr','w0, [x8]'),(0x28,'cmp','w0, #6'),(0x2c,'ccmp','w0, #3, #4, ne')]:at('construct_status',off,mn,op)
  call('construct_status',0x24,'_mach_port_construct');assert[q['symbol']for q in v['data_bindings']]==['__dispatch_source_type_mach_recv','_mach_task_self_']
  for off,mn,op in[(0x8,'ldr','x8, [x0, #0x68]'),(0x3c,'mov','w0, #2'),(0x44,'mov','w0, #1'),(0x5c,'mov','w0, #5')]:at('domain',off,mn,op)
  # Callback/cookie capture -> event call ABI; receive setup and cancellation edges.
  at('constructor',0x30,'mov','x22, x5');at('constructor',0x38,'mov','x23, x3');at('constructor',0x84,'stp','x23, x22, [x0, #0x90]')
  for off,mn,op in[(0x20,'ldr','x21, [x0, #0x68]'),(0x2c,'mov','w1, w0'),(0x40,'mov','w2, #0x8000'),(0x4c,'mov','x1, x19'),(0xa0,'str','x20, [sp, #0x58]'),(0xec,'stp','x20, x21, [sp, #0x28]'),(0x11c,'str','x20, [x19, #0x80]')]:at('receive_source',off,mn,op)
  for off,name in[(0x28,'_xpc_mach_send_get_right'),(0x44,'_dispatch_source_create'),(0x50+0x0,'_dispatch_set_context'),(0x58,'_xpc_retain'),(0xac,'_dispatch_source_set_event_handler'),(0xf8,'_dispatch_source_set_cancel_handler'),(0x100,'_dispatch_activate'),(0x110,'_objc_retain')]:
   # Context setter is at +0x50; its preceding MOV is at +0x4c.
   call('receive_source',off,name)
  at('event',0xc,'ldr','x0, [x0, #0x20]');call('event',0x10,'_dispatch_get_context');at('event',0x14,'ldp','x3, x2, [x0, #0x90]');at('event',0x18,'mov','w1, #0');assert r['event']['instructions'][-1]['mnemonic']=='braaz'and r['event']['instructions'][-1]['operands']=='x3'
  for off,dest in[(0x88,'event'),(0xd4,'cancel')]:
   addr=int(r[dest]['start'],16);at('receive_source',off,'adrp','x16, #'+hex(addr&~4095));at('receive_source',off+4,'add','x16, x16, #'+hex(addr&4095))
  call('cancel',0x18,'_dispatch_get_context');local('cancel',0x20,'live_assert');call('cancel',0x28,'_objc_release');call('cancel',0x30,'_xpc_release');assert r['cancel']['instructions'][-1]['operands']=='#'+v['stubs']['_dispatch_release']['address']
  assert v['strings'][0]['text']=='<endpoint name too long>'
 # All selected spans must decode completely and their byte hashes must match.
 bodies=[r for v in s['variants']for r in v['roles'].values()]+s['cache_functions']+s['kernel_functions'];assert len(bodies)==38
 for r in bodies:
  raw=bytes.fromhex(r['bytes']);assert len(raw)==int(r['end'],16)-int(r['start'],16)==4*len(r['instructions'])and h(raw)==r['sha256']
  for j,i in enumerate(r['instructions']):
   assert int(i['ea'],16)==int(r['start'],16)+4*j;cc=list(CS.disasm(raw[4*j:4*j+4],int(i['ea'],16)))
   if cc:assert(i['mnemonic'],i['operands'])==(cc[0].mnemonic,cc[0].op_str)
   else:assert i['decoder']=='LLVM'and i['bytes']==i['LLVM']['bytes']==raw[4*j:4*j+4].hex()and i['mnemonic']==i['LLVM']['mnemonic']and i['operands']==i['LLVM']['operands']
 rows={int(i['ea'],16):i for r in s['cache_functions']+s['kernel_functions']for i in r['instructions']}
 def check(ea,mn,op):
  i=rows[ea];assert(i['mnemonic'],i['operands'])==(mn,op),(hex(ea),i,mn,op);records.append({'scope':'cache_or_kernel',**i})
 expected='''
184b737d8|mov|w1, #0x13
184b737f4|sub|w8, w0, #1
184b737f8|cmn|w8, #3
184b737fc|ccmp|w1, #0x11, #4, ls
184b73800|b.eq|#0x184b73864
184b73804|cmp|w1, #0x13
184b7380c|cmp|w1, #0x14
184b73828|mov|w3, #0x14
184b7382c|bl|#0x18806d270
184b73848|mov|w2, #0
184b7384c|mov|w3, #1
184b73850|bl|#0x18806cf50
184b7386c|mov|w1, #0x20
184b73870|bl|#0x188087440
184b73880|str|w19, [x0, #0x18]
184b74298|ldr|w0, [x19, #0x18]
184b7429c|cmn|w0, #2
184b742c4|mov|w9, #-1
184b742c8|swp|w9, w1, [x8]
184b742d0|cmn|w8, #4
184b742f0|bl|#0x18806cf40
184b773ac|mov|w9, #-2
184b773b0|swp|w9, w0, [x8]
184b7f80c|bl|#0x18806cf50
180548ec0|bl|#0x180547b10
180548ec4|mov|w8, #3
180548ec8|movk|w8, #0x1000, lsl #16
180548ed0|b.ne|#0x180548f04
180548f00|b|#0x18056df38
180547b10|mov|x16, #-0x18
180547b14|svc|#0x80
18056df5c|str|w21, [sp, #0x18]
18056df60|stur|x1, [sp, #0x1c]
18056df7c|stur|x2, [sp, #0x34]
18056dfb0|movk|x2, #0x3c, lsl #32
18056dfc0|mov|x4, #0xc9f00000000
18056dfcc|bl|#0x18055a894
18056e008|cmp|w8, #0xd03
18056e01c|cmp|w8, #0x28
18056e098|ldr|w8, [sp, #0x24]
18056e09c|str|w8, [x19]
fffffe000bcdbde4|mov|w2, #0x18
fffffe000bcdbde8|bl|#0xfffffe000be76e18
fffffe000bcdbe30|bl|#0xfffffe000bce00b8
fffffe000bcdbe40|mov|w2, #4
fffffe000bd87838|cmp|w8, #0x44
fffffe000bd87844|cmp|w8, #1
fffffe000bd87850|cmp|w8, #0x18
fffffe000bd87894|mov|x1, x16
fffffe000bd878d0|ldr|x2, [x22, #8]
fffffe000bd878dc|bl|#0xfffffe000bce00b8
fffffe000bd87940|mov|w8, #0x30
fffffe000bce055c|mov|w2, #0x100
fffffe000bce0560|bl|#0xfffffe000be76e18
fffffe000bce05c0|mov|w1, #0xff
fffffe000bce05c4|bl|#0xfffffe000bc9dac0
fffffe000bce05c8|cmp|x0, #0xfe
fffffe000bce05d4|mov|w8, #0x21
fffffe000bce05e0|cmp|w10, #1
fffffe000bce05ec|ldrb|w10, [sp, #0x11f]
fffffe000bce0414|ubfx|w3, w24, #4, #1
fffffe000bce04d8|ubfx|w3, w8, #5, #1
fffffe000bcd6c28|add|x1, x22, #1
fffffe000bcd6c38|str|x0, [x20, #0x18]
fffffe000bcd6c3c|add|x2, x22, #1
fffffe000bcd6c48|ldrb|w8, [x21, #0xff]
fffffe000bcd6c4c|strb|w8, [x20, #0x15]
'''
 for line in expected.strip().splitlines():a,mn,op=line.split('|');check(int(a,16),mn,op)
 assert s['MIG3231']['id']==3231 and s['MIG3231']['stub']['target']=='0xfffffe000bd87808'
 assert[bytes.fromhex(r['bytes'])for r in s['cache_constants']]==[bytes.fromhex(v)for v in['0001000118000000','131500803c000000','000000009f0c0000']]
 assert[r['exact_exports'][0]for r in s['cache_imports']]==['_mach_port_insert_right','_mach_port_mod_refs','_mach_port_deallocate','__os_object_alloc_realized','_object_getClass','__os_assumes_log']
 assert s['cache_type_links'][0]['target']=='0x1ed891ec0'and s['cache_type_links'][1]['target']=='0x184b742c0'and all(p['chain_membership_verified']for p in s['cache_type_links'])
 assert all(s[k]is False for k in FLAGS)
 return records,footprints
def proofs():
 queries={
 'create_name_compare_unsigned32':'''(declare-fun n () (_ BitVec 32))
(define-fun t () (_ BitVec 32) (bvsub n #x00000001))
(define-fun c () Bool (bvuge (bvadd ((_ zero_extend 1) t) (_ bv3 33)) (_ bv4294967296 33)))
(define-fun z () Bool (= (bvadd t #x00000003) #x00000000))
(assert (distinct (or (not c) z) (and (bvuge n #x00000001) (bvule n #xfffffffe))))''',
 'create_direct_allocation_ccmp32':'''(declare-fun n () (_ BitVec 32)) (declare-fun d () (_ BitVec 32))
(define-fun t () (_ BitVec 32) (bvsub n #x00000001))
(define-fun c () Bool (bvuge (bvadd ((_ zero_extend 1) t) (_ bv3 33)) (_ bv4294967296 33)))
(define-fun z () Bool (= (bvadd t #x00000003) #x00000000))
(define-fun branch () Bool (ite (or (not c) z) (= d #x00000011) true))
(assert (distinct branch (or (= n #x00000000) (= n #xffffffff) (= d #x00000011))))''',
 'dispose_deallocation_domain32':'''(declare-fun n () (_ BitVec 32))
(define-fun t () (_ BitVec 32) (bvsub n #x00000001))
(define-fun c () Bool (bvuge (bvadd ((_ zero_extend 1) t) (_ bv4 33)) (_ bv4294967296 33)))
(define-fun z () Bool (= (bvadd t #x00000004) #x00000000))
(assert (distinct (not (and c (not z))) (and (bvuge n #x00000001) (bvule n #xfffffffd))))''',
 'receive_source_gate32':'''(declare-fun f () (_ BitVec 32))
(assert (distinct (= (bvand f #x00000402) #x00000002) (and (= (bvand f #x00000002) #x00000002) (= (bvand f #x00000400) #x00000000))))'''}
 out=[]
 for name,body in queries.items():
  query='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr;out.append({'name':name,'query':query,'result':'unsat','scope':'Full stated scalar domain of instruction-matched manual formulas; excludes reachability, native object validity and concurrency.'})
 return out
def sdk_checks():
 user='''#include <mach/port.h>
#include <mach/message.h>
#include <mach/mach_port.h>
#include <dispatch/dispatch.h>
#include <stddef.h>
#define A(x) static_assert((x), #x)
A(sizeof(mach_port_options_t)==24); A(offsetof(mach_port_options_t,flags)==0);
A(offsetof(mach_port_options_t,mpl)==4); A(offsetof(mach_port_options_t,service_port_info)==8);
A(sizeof(mach_service_port_info_data_t)==256); A(offsetof(mach_service_port_info_data_t,mspi_domain_type)==255);
A(MACH_SERVICE_PORT_INFO_STRING_NAME_MAX_BUF_LEN==255); A(sizeof(mach_port_name_t)==4);
A(sizeof(mach_port_context_t)==8); A(MPO_CONTEXT_AS_GUARD==1); A(MPO_QLIMIT==2);
A(MPO_INSERT_SEND_RIGHT==16); A(MPO_STRICT==32); A(MPO_SERVICE_PORT==0x400);
A(MPO_ENFORCE_REPLY_PORT_SEMANTICS==0x2000); A(MACH_MSG_TYPE_MOVE_SEND==17);
A(MACH_MSG_TYPE_COPY_SEND==19); A(MACH_MSG_TYPE_MAKE_SEND==20); A(MACH_PORT_RIGHT_SEND==0);
A(MACH_SEND_INVALID_DEST==0x10000003); A(MACH_MSG_OOL_DESCRIPTOR==1); A(MACH_MSG_VIRTUAL_COPY==1);
A(sizeof(__Request__mach_port_construct_t)==60); A(offsetof(__Request__mach_port_construct_t,options)==28);
A(offsetof(__Request__mach_port_construct_t,NDR)==44); A(offsetof(__Request__mach_port_construct_t,context)==52);
A(sizeof(__Reply__mach_port_construct_t)==40); A(offsetof(__Reply__mach_port_construct_t,RetCode)==32);
A(offsetof(__Reply__mach_port_construct_t,name)==36);
'''
 kernel='''#include <mach/message.h>
#include <mach/ndr.h>
#include <stddef.h>
#pragma pack(push,4)
struct req {mach_msg_header_t h;mach_msg_body_t b;mach_msg_ool_descriptor_t o;NDR_record_t n;unsigned long long context;};
struct rep {mach_msg_header_t h;NDR_record_t n;int result;unsigned name;};
#pragma pack(pop)
#define A(x) static_assert((x), #x)
A(sizeof(req)==68); A(offsetof(req,o)==36); A(offsetof(req,n)==52); A(offsetof(req,context)==60);
A(sizeof(rep)==48); A(offsetof(rep,result)==40); A(offsetof(rep,name)==44);
'''
 out=[]
 for code,kh in[(user,False),(kernel,True)]:
  cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-']
  if kh:cmd[1:1]=['-I'+str(SDK/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers')]
  r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr;out.append({'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang')})
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();checks,footprints=verify(s);negative=[]
 for name,alter in[
  ('missing_info_store',lambda q:q['variants'][0]['info_zero_stores'].pop()),
  ('changed_info_extent',lambda q:q['variants'][1]['info_zero_stores'][0].__setitem__('size_bytes',15)),
  ('wrong_role_entry',lambda q:q['variants'][1]['roles']['factory'].__setitem__('start','0x10000ce68')),
  ('wrong_disposition_record',lambda q:q['variants'][0]['roles']['send_object']['instructions'][55].__setitem__('operands','w1, #0x13')),
  ('missing_MIG_route',lambda q:q['MIG3231'].__setitem__('id',3232)),
  ('changed_descriptor_extent',lambda q:q['cache_constants'][0].__setitem__('bytes','0001000110000000')),
  ('changed_dispose_target',lambda q:q['cache_type_links'][1].__setitem__('target','0x0')),
  ('changed_port_api_binding',lambda q:q['cache_imports'][1].__setitem__('exact_exports',['_mach_port_allocate']))]:
  q=copy.deepcopy(s);alter(q)
  try:verify(q)
  except(AssertionError,KeyError,ValueError,StopIteration):negative.append(name)
  else:raise AssertionError('Accepted alteration: '+name)
 sdk=sdk_checks();pr=proofs();counts={**s['verified_source_counts'],'instruction_assertions':len(checks),'SDK_assertions':sum(r['assertions']for r in sdk),'SDK_compilations':len(sdk),'scalar_queries_unsat':len(pr),'rejected_evidence_alterations':len(negative),'info_zero_footprints':len(footprints)}
 obj={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':checks,'info_zero_footprints':footprints,'SDK_checks':sdk,'proofs':pr,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'rejected_alterations':negative,'verified_counts':counts,'static_scope':'Both original launchd slices; selected service endpoint factory, construct trap/MIG3231 and kernel service-info copy, receive-source callbacks and XPC right access/copy/disposal. Static contracts and scalar formulas only; native endpoint identity, policy decisions, callbacks, reference balance and RPC700 receiver unknown.','all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
