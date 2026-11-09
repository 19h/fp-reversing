#!/usr/bin/env python3
"""Validate original notification-registration/return instructions and SDK ABI.
O(captured instructions+finite scalar bank) time/space; no target effects.
"""
import copy,json,struct,subprocess
from recover_port_destroyed_return import ROOT,P,FLAGS,SDK,CS,sha,h,build
PATTERNS='''
record_allocator|mov|w0, #1
record_allocator|mov|x1, x0
notify_setup|cmp|w1, #0x45
notify_setup|mov|w0, #0x30
notify_setup|str|w21, [x0, #0x10]
notify_setup|strb|w8, [x0, #0x28]
notify_setup|mov|w3, #0x14
notify_setup|ldr|w4, [x8, #0xf20]
notify_setup|mov|w8, #0x15
notify_setup|mov|w9, #0x12
notify_setup|csel|w5, w9, w8, eq
notify_setup|mov|w2, #0x45
notify_setup|mov|w3, #0
notify_setup|str|x20, [x19, #0x18]
notification_init|str|x16, [x0]
notification_init|stp|x9, x0, [x8]
notification_init|mov|w9, #0x28
notification_demux|sub|w9, w8, #0x49
notification_demux|cmn|w9, #9
notification_demux|mov|w9, #0x28
notification_demux|umull|x8, w8, w9
notification_demux|sub|x8, x8, #0x9f8
notification_demux|blraaz|x8
id69_stub|ldr|w8, [x0, #0x18]
id69_stub|cmp|w8, #1
id69_stub|cmp|w8, #0x28
id69_stub|ldrh|w8, [x0, #0x26]
id69_stub|cmp|w8, #0x100, lsl #12
id69_stub|ldr|w8, [x0, #0xc]
id69_stub|ldr|w1, [x0, #0x1c]
id69_handler|ldr|w8, [x8, #0x41c]
id69_handler|mov|w0, #5
id69_handler|mov|x0, x1
id69_handler|mov|w1, #1
id69_handler|mov|w1, #0x45
record_lookup|mov|w8, #0x1505
record_lookup|mov|w10, #4
record_lookup|ldrb|w11, [x9], #1
record_lookup|add|x8, x8, x8, lsl #5
record_lookup|add|x8, x8, x11
record_lookup|umulh|x9, x8, x9
record_lookup|add|x9, x9, x10, lsr #1
record_lookup|lsr|x9, x9, #5
record_lookup|mov|w10, #0x35
record_lookup|msub|x8, x9, x10, x8
record_lookup|ldrb|w9, [x8, #0x28]
record_lookup|cmp|w9, w1
record_lookup|ldr|w9, [x8, #0x10]
record_lookup|cmp|w9, w0
record_insert|msub|x9, x9, x10, x8
record_insert|str|x0, [x8]
record_insert|str|x8, [x0, #8]
event_callback|ldr|x21, [x0, #0x28]
event_callback|cmp|x21, x8
event_callback|ldr|x0, [x19, #0x20]
event_callback|blraa|x9, x8
cancel_callback|ldrb|w8, [x0, #0x29]
cancel_callback|ldr|w1, [x0, #0x10]
explicit_cancel|ldrb|w8, [x19, #0x29]
explicit_cancel|orr|w8, w8, #1
explicit_cancel|strb|w8, [x19, #0x29]
endpoint_cancel|orr|w9, w8, #0x20
endpoint_cancel|orr|w8, w8, #0x80
endpoint_reset|ldr|x1, [x19, #0x70]
endpoint_reset|mov|w2, #4
endpoint_reset|mov|x3, #0
endpoint_reset|mov|w4, #0
endpoint_reset|and|w9, w8, #0xfffffffe
endpoint_reset|orr|w9, w9, #0x40
endpoint_reset|and|w8, w8, #0xfffffeff
endpoint_reset|ldp|x3, x2, [x19, #0x90]
endpoint_reset|mov|w1, #1
endpoint_reset|braaz|x3
guard_assert|str|x1, [sp, #8]
guard_assert|mov|w2, #8
guard_assert|mov|w4, #2
guard_assert|brk|#1
receive_drain|mov|w22, #0x14
receive_drain|mov|w1, #0x102
receive_drain|mov|w2, #0
receive_drain|mov|w3, #0x20
receive_drain|mov|x4, x20
receive_drain|mov|w5, #0
receive_drain|mov|w6, #0
receive_drain|subs|w22, w22, #1
'''
CALLS=[('record_allocator','_malloc_type_calloc'),('notify_setup','_mach_port_insert_right'),('notify_setup','_mach_port_request_notification'),('notify_setup','_mach_port_deallocate'),('id69_handler','_dispatch_source_merge_data'),('event_callback','_dispatch_get_context'),('event_callback','_dispatch_source_cancel'),('cancel_callback','_mach_port_deallocate'),('cancel_callback','_dispatch_release'),('cancel_callback','_free'),('explicit_cancel','_dispatch_source_cancel'),('endpoint_reset','_mach_port_set_attributes'),('guard_assert','_mach_port_assert_attributes'),('receive_drain','_mach_msg'),('receive_drain','_mach_msg_destroy')]
def verify(s):
 assert s['launchd_source_sha256']=='1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168'and s['kernel_source_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'and s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a';records=[]
 def need(scope,role,r,mn,op):
  ii=[i for i in r['instructions']if i['mnemonic']==mn and i['operands']==op];assert ii,(scope,role,mn,op)
  records.extend({'scope':scope,'role':role,**i}for i in ii);return ii
 for v in s['variants']:
  roles=v['roles'];scope=v['label'];assert len(roles)==21 and v['fixup_reference']['fixups_compared']==2447 and v['fixup_reference']['all_matches'];assert v['data_add_type_binding']['symbol']=='__dispatch_source_type_data_add'
  for line in PATTERNS.strip().splitlines():role,mn,op=line.split('|');need(scope,role,roles[role],mn,op)
  for role,name in CALLS:
   assert v['stubs'][name]['binding']['symbol']==name;a=v['stubs'][name]['address'];ii=[i for i in roles[role]['instructions']if i['mnemonic']in['b','bl']and i['operands']=='#'+a];assert ii,(scope,role,name);records.extend({'scope':scope,'role':role,'API':name,**i}for i in ii)
  for caller,callee in[('id69_stub','id69_handler'),('id69_handler','record_lookup'),('explicit_cancel','record_lookup'),('endpoint_cancel','explicit_cancel'),('endpoint_reset','guard_assert'),('endpoint_reset','receive_drain'),('endpoint_reset','async_reset')]:need(scope,caller,roles[caller],'bl','#'+roles[callee]['start'])
  need(scope,'event_callback',roles['event_callback'],'b','#'+roles['record_unlink']['start']);need(scope,'explicit_cancel',roles['explicit_cancel'],'b','#'+roles['record_unlink']['start']);reg=v['notification_registry'];assert reg['address']=='0x1000835c0'and struct.unpack_from('<III',bytes.fromhex(reg['bytes']),8)==(64,73,36);assert[bool(r['stub'])for r in reg['routines']]==[False,True,False,False,False,True,True,True,True];assert reg['routines'][5]['id']==69 and reg['routines'][5]['stub']['target']==roles['id69_stub']['start']and reg['selector']['target']==roles['notification_lookup']['start'];assert len(v['explicit_cancel_byte29_writer_candidates'])==1 and v['explicit_cancel_byte29_writer_candidates'][0]['containing_start']==roles['explicit_cancel']['start']and len(v['explicit_cancel_direct_callers'])==1
  # Control-flow predicates independently tie input checks to the intended branch.
  rr=roles['id69_handler'];ii=rr['instructions'];assert ii[2]['mnemonic']=='cbz'and ii[2]['operands']=='w8, #'+hex(int(rr['start'],16)+20)and ii[3]['operands']=='w0, #5';records.append({'scope':scope,'role':'PID_gate_control_flow',**ii[2]})
 kernel=s['kernel_functions'];cache=s['cache_functions']
 expected='''
request_trap|fffffe000bcdc128|bl|#0xfffffe000bcdf1ec
request_MIG|fffffe000bd88900|cmp|w8, #0x48
request_MIG|fffffe000bd8891c|cmp|w8, #0x12
request_MIG|fffffe000bd88920|ccmp|w9, #0x15, #4, ne
request_MIG|fffffe000bd889bc|bl|#0xfffffe000bcdf1ec
request_core|fffffe000bcdf25c|cmp|w4, #0x45
request_core|fffffe000bcdf264|cbnz|w23, #0xfffffe000bcdf2c0
request_core|fffffe000bcdf288|bl|#0xfffffe000bccbe54
request_core|fffffe000bcdf434|bl|#0xfffffe000bccc064
request_core|fffffe000bcdf450|add|x8, x20, #0x60
request_core|fffffe000bcdf458|tbnz|w9, #1, #0xfffffe000bcdf474
request_core|fffffe000bcdf460|movk|x16, #0x78bc, lsl #48
request_core|fffffe000bcdf46c|str|x17, [x8]
request_core|fffffe000bcdf498|str|x17, [x8, #0x10]
backup_admission|fffffe000bccbfd8|cbz|x16, #0xfffffe000bccc018
backup_admission|fffffe000bccbfec|mov|w0, #5
port_destroy|fffffe000bccdc64|ldr|x16, [x8, #0x60]!
port_destroy|fffffe000bcce154|mov|w8, #0x12
port_destroy|fffffe000bcce174|mov|w1, #0x34
port_destroy|fffffe000bcce188|bl|#0xfffffe000bcf55dc
'''
 for line in expected.strip().splitlines():
  role,ea,mn,op=line.split('|');ii=need('kernel',role,kernel[role],mn,op);assert any(i['ea']=='0x'+ea for i in ii)
 need('cache','request_trap',cache['request_trap'],'mov','x16, #-0x4d');need('cache','request_trap',cache['request_trap'],'svc','#0x80');need('cache','request_wrapper',cache['request_wrapper'],'bl','#0x180547ccc');need('cache','request_wrapper',cache['request_wrapper'],'b','#0x18054bd00');need('cache','request_MIG',cache['request_MIG'],'mov','x4, #0xc8d00000000');assert cache['request_wrapper']['exact_exports']==['_mach_port_request_notification'];assert s['kernel_notification_constant']['bytes']=='4500000001000000';assert[r['bytes']for r in s['cache_MIG_constants']]==['131500803c000000','000000008d0c0000'];kr=s['kernel_request_registration'];assert kr['routine']['id']==3213 and kr['routine']['stub']['target']==kernel['request_MIG']['start']and kr['trap']['index']==77 and kr['trap']['handler_pointer']['target']==kernel['request_trap']['start']
 bodies=[r for v in s['variants']for r in v['roles'].values()]+list(kernel.values())+list(cache.values());assert len(bodies)==51
 for r in bodies:
  raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and len(raw)==int(r['end'],16)-int(r['start'],16)==4*len(r['instructions'])
  for j,i in enumerate(r['instructions']):
   ea=int(r['start'],16)+4*j;assert int(i['ea'],16)==ea;decoded=list(CS.disasm(raw[4*j:4*j+4],ea))
   if decoded:assert(i['mnemonic'],i['operands'])==(decoded[0].mnemonic,decoded[0].op_str)
   else:assert i['decoder']=='LLVM'and i['LLVM']['bytes']==raw[4*j:4*j+4].hex()
 assert all(s[k]is False for k in FLAGS);return records
def sdk_checks():
 code='''#define __MigPackStructs 1
#include <mach/mach_port.h>
#include <mach/notify.h>
#include <stddef.h>
#define A(x) static_assert((x), #x)
A(sizeof(mach_msg_header_t)==24); A(sizeof(mach_msg_port_descriptor_t)==12);
A(MACH_NOTIFY_PORT_DESTROYED==69); A(MACH_MSG_TYPE_MOVE_RECEIVE==16);
A(MACH_MSG_TYPE_MOVE_SEND_ONCE==18); A(MACH_MSG_TYPE_MAKE_SEND_ONCE==21);
A(MACH_MSG_TYPE_MAKE_SEND==20); A(MACH_MSG_PORT_DESCRIPTOR==0);
A(MACH_PORT_TEMPOWNER==4); A(MACH_PORT_GUARD_INFO==8); A(MACH_PORT_GUARD_INFO_COUNT==2);
A(sizeof(mach_port_guard_info_t)==8); A(sizeof(mach_port_name_t)==4);
A(offsetof(mach_port_destroyed_notification_t,not_body)==24);
A(offsetof(mach_port_destroyed_notification_t,not_port)==28);
A(offsetof(mach_port_destroyed_notification_t,trailer)==40);
A(sizeof(__Request__mach_port_request_notification_t)==60);
A(offsetof(__Request__mach_port_request_notification_t,notify)==28);
A(offsetof(__Request__mach_port_request_notification_t,NDR)==40);
A(offsetof(__Request__mach_port_request_notification_t,name)==48);
A(offsetof(__Request__mach_port_request_notification_t,msgid)==52);
A(offsetof(__Request__mach_port_request_notification_t,sync)==56);
A(sizeof(__Reply__mach_port_request_notification_t)==40);
A(MACH_RCV_MSG==2); A(MACH_RCV_TIMEOUT==0x100); A((MACH_RCV_MSG|MACH_RCV_TIMEOUT)==0x102);
A(MACH_RCV_TIMED_OUT==0x10004003); A(MACH_MSGH_BITS_COMPLEX==0x80000000);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Installed SDK compile-time ABI checks only. No recovered API or target invoked.'}
def proofs():
 queries={
 'notification_demux_u32_range_and_slot':'''(declare-fun n () (_ BitVec 32))
(define-fun accepts () Bool (bvuge (bvsub n #x00000049) #xfffffff7))
(define-fun spec () Bool (and (bvuge n #x00000040) (bvule n #x00000048)))
(define-fun slot () (_ BitVec 64) (bvsub (bvmul ((_ zero_extend 32) n) #x0000000000000028) #x00000000000009f8))
(assert (or (distinct accepts spec) (and accepts (distinct slot (bvadd #x0000000000000008 (bvmul (bvsub ((_ zero_extend 32) n) #x0000000000000040) #x0000000000000028))))))''',
 'endpoint_suffix_flags16':'''(declare-fun f () (_ BitVec 16))
(define-fun out () (_ BitVec 16) (bvand (bvor (bvand f #xfffe) #x0040) #xfeff))
(assert (or (distinct (bvand out #x0040) #x0040) (distinct (bvand out #x0101) #x0000) (distinct (bvand out #xfebe) (bvand f #xfebe))))'''};out=[]
 for name,body in queries.items():
  query='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr);out.append({'name':name,'query':query,'result':'unsat','scope':'Instruction-matched scalar formulas only. Flags proof assumes no intervening callback/helper flag writes; table contents, names, ownership and native delivery excluded.'})
 return out
def hash_certificate():
 maximum=5381
 for _ in range(4):maximum=maximum*33+255
 m=0x3521cfb2b78c1353;epsilon=(2**64+m)*53-64*2**64;assert 0<=epsilon<53 and maximum*epsilon<64*2**64
 rows=[]
 for name in list(range(65536))+[0x10000,0x1010101,0xff00ffff,0xffffffff,0x01000101,0xffffff00,0x01010100]:
  value=5381
  for b in name.to_bytes(4,'little'):
   if b==0:break
   value=value*33+b
  hi=value*m>>64;q=(hi+((value-hi)>>1))>>5;assert q==value//53 and value-q*53==value%53;rows.append([name,value,value-q*53])
 return{'maximum_hash':maximum,'magic_u64':hex(m),'epsilon':epsilon,'error_bound_numerator':maximum*epsilon,'error_bound_denominator':64*2**64,'certificate':'q=floor((h+floor(h*m/2^64))/64)=floor(h*(2^64+m)/(64*2^64)). Epsilon makes the rational excess strictly less than 1/53 throughout the bounded four-byte hash domain; integer remainders cannot cross the next multiple. Therefore remainder=h mod53.','finite_inputs_checked':len(rows),'rows_sha256':h(json.dumps(rows,separators=(',',':')).encode()),'scope':'Name-number hash arithmetic only. Early zero terminates before that byte; exact u32 name and kind comparisons remain necessary; no IPC-space identity proof.'}
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();records=verify(s);negative=[]
 for name,alter in[
  ('wrong_ID69_table_entry',lambda q:q['variants'][0]['notification_registry']['routines'][5].__setitem__('id',70)),
  ('wrong_data_source_type',lambda q:q['variants'][1]['data_add_type_binding'].__setitem__('symbol','__dispatch_source_type_mach_recv')),
  ('changed_explicit_cancel_flag',lambda q:q['variants'][0]['roles']['explicit_cancel']['instructions'][12].__setitem__('operands','w8, [x19, #0x28]')),
  ('changed_notification_ID_constant',lambda q:q['kernel_notification_constant'].__setitem__('bytes','4600000001000000')),
  ('wrong_trap_binding',lambda q:q['kernel_request_registration']['trap'].__setitem__('index',78)),
  ('wrong_MIG_extent_constant',lambda q:q['cache_MIG_constants'][0].__setitem__('bytes','1315008040000000'))]:
  q=copy.deepcopy(s);alter(q)
  try:verify(q)
  except(AssertionError,KeyError,ValueError,StopIteration):negative.append(name)
  else:raise AssertionError('Accepted altered evidence: '+name)
 sdk=sdk_checks();pr=proofs();cert=hash_certificate();counts={**s['verified_source_counts'],'instruction_assertions':len(records),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'name_hash_finite_inputs_checked':cert['finite_inputs_checked'],'rejected_evidence_alterations':len(negative)}
 obj={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':records,'SDK_checks':sdk,'proofs':pr,'name_hash_certificate':cert,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'rejected_alterations':negative,'verified_counts':counts,'static_scope':'Selected trap/MIG registration, kernel backup storage/emission, both launchd notification tables and PID gate, record dispatch/cancellation, guard assertion and bounded receive drain. No native delivery/name identity/ownership/guard restoration, exhaustive producer/writer census, async endpoint job body or x1 ISA equivalence.','all_checks_pass':True,**{f:False for f in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
