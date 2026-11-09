#!/usr/bin/env python3
"""Validate original check-in contracts and ten observed flat XPC packets.
O(B+F+I+T) recapture/checking; finite parser sensitivity cases emit no packets.
"""
import copy,json,struct,subprocess
from recover_bootstrap_checkin_handoff import ROOT,P,FLAGS,SDK,CS,sha,h,build,flat_dictionary
STARTS=[{'init':0x10002d3a8,'register':0x100045930,'dispatcher':0x10002e16c,'domain_context':0x10002eb50,'domain_decode':0x10005b1dc,'handler':0x100038158,'core':0x100059640,'status_map':0x100059a64,'activate':0x100046e3c,'getter':0x100047360,'notify_setup':0x100045bec,'send_object':0x10005cb6c,'send_name':0x100046c28},{'init':0x10002ca6c,'register':0x100044c60,'dispatcher':0x10002d830,'domain_context':0x10002e1d8,'domain_decode':0x10005a200,'handler':0x100037690,'core':0x1000586a0,'status_map':0x100058ac4,'activate':0x100046100,'getter':0x100046624,'notify_setup':0x100044f10,'send_object':0x10005bb3c,'send_name':0x100045ef8}]
def verify(s):
 assert s['launchd_source_sha256']=='1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168'and s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a';assert len(s['variants'])==2
 checks=[]
 for j,v in enumerate(s['variants']):
  roles=v['roles'];assert set(roles)==set(STARTS[j])and all(int(roles[k]['start'],16)==a for k,a in STARTS[j].items());assert v['fixup_reference']['fixups_compared']==2447 and v['fixup_reference']['all_matches']
  def at(role,off,mn,op=None):
   ea=int(roles[role]['start'],16)+off;i=next(i for i in roles[role]['instructions']if int(i['ea'],16)==ea);assert i['mnemonic']==mn and(op is None or i['operands']==op),(v['label'],role,hex(off),i,mn,op);checks.append({'scope':v['label'],'role':role,**i});return i
  def local(role,off,dest):return at(role,off,'bl','#'+roles[dest]['start'])
  def call(role,off,name):return at(role,off,'bl','#'+v['stubs'][name]['address'])
  # Registration binds interface5 to the 200..211 dispatcher; no numeric address delta.
  ii=roles['init']['instructions'];k=next(k for k,i in enumerate(ii)if i['mnemonic']=='mov'and i['operands']=='w0, #5');assert ii[k+1]['operands']=='#'+roles['register']['start'];target=int(ii[k-4]['operands'].split('#')[1],0)+int(ii[k-3]['operands'].split('#')[1],0);assert target==int(roles['dispatcher']['start'],16)
  at('register',0xa0,'str','x20, [x9, x8, lsl #3]');at('register',0xa4,'str','w19, [x0, x8, lsl #2]')
  at('dispatcher',0xa8,'sub','w16, w22, #0xc8');at('dispatcher',0xac,'cmp','w16, #0xb');at('dispatcher',0xb0,'b.hi');jt=v['routine_table'];targets=[hex(int(jt['relative_base'],16)+w)for w in struct.unpack('<12i',bytes.fromhex(jt['bytes']))];assert targets==jt['targets'];hit=v['routine206_handler_call'];assert int(targets[6],16)<=int(hit['ea'],16)<int(targets[6],16)+24 and hit['operands']=='#'+roles['handler']['start']and hit in roles['dispatcher']['instructions']
  call('domain_context',0x34,'_xpc_dictionary_get_audit_token');local('domain_context',0x50,'domain_decode')
  call('handler',0x30,'_xpc_dictionary_expects_reply');call('handler',0x44,'_xpc_dictionary_get_string');call('handler',0x5c,'_xpc_dictionary_get_uint64')
  for off,mn,op in[(0x60,'ubfiz','x8, x0, #1, #1'),(0x64,'bfxil','x8, x0, #6, #1'),(0x68,'str','xzr, [sp, #8]'),(0x6c,'eor','x3, x8, #1'),(0x70,'add','x5, sp, #8'),(0x80,'mov','x4, #0'),(0x84,'mov','x6, #0')]:at('handler',off,mn,op)
  local('handler',0x88,'core');local('handler',0x8c,'status_map');at('handler',0x94,'cbnz');call('handler',0x9c,'_xpc_dictionary_create_reply');at('handler',0xa4,'ldr','x22, [sp, #8]');call('handler',0xac,'_xpc_mach_send_get_right');at('handler',0xb0,'mov','x2, x0');call('handler',0xc0,'_xpc_dictionary_set_mach_recv');call('handler',0xc8,'_xpc_release');at('handler',0xcc,'str','x20, [x19]')
  # Existing endpoint path, activation, checked-in state and retained output object.
  local('core',0x3c4,'activate');at('core',0x3c8,'cmp','w0, #3');at('core',0x3d4,'cbnz');at('core',0x3dc,'orr','w8, w8, #0x2000');at('core',0x3e0,'strh','w8, [x20, #0x180]');at('core',0x3ec,'orr','w8, w8, #4');at('core',0x3f0,'strh','w8, [x9, #0x58]');at('core',0x3fc,'mov','w1, #4');local('core',0x400,'getter');call('core',0x404,'_xpc_retain');at('core',0x408,'str','x0, [x24]')
  at('activate',0x40,'mov','w1, #1');local('activate',0x44,'send_name');at('activate',0x98,'mov','w1, #0x45');local('activate',0x9c,'notify_setup');at('activate',0xa0,'cbnz');at('activate',0xa4,'ldr','x2, [x19, #0x70]');call('activate',0xb8,'_mach_port_unguard');at('activate',0xbc,'b','#'+hex(int(roles['activate']['start'],16)+0x1c4));at('activate',0x1c4,'mov','w0, #0');at('activate',0x1cc,'orr','w8, w8, #1');at('activate',0x1d0,'strh','w8, [x19, #0xa0]')
  at('getter',0x8,'ldrh','w8, [x0, #0xa0]');at('getter',0xc,'mov','w9, #5');at('getter',0x10,'and','w8, w8, w9');at('getter',0x14,'cmp','w8, #4');assert any(i['mnemonic']=='b'and i['operands']=='#'+roles['send_object']['start']for i in roles['getter']['instructions'])
  at('notify_setup',0x18,'cmp','w1, #0x45');at('notify_setup',0x13c,'mov','w3, #0x14');call('notify_setup',0x140,'_mach_port_insert_right');at('notify_setup',0x150,'ldr','w4, [x8, #0xf20]');at('notify_setup',0x154,'mov','w8, #0x15');at('notify_setup',0x158,'mov','w9, #0x12');at('notify_setup',0x15c,'cmp','w4, #0');at('notify_setup',0x160,'csel','w5, w9, w8, eq');at('notify_setup',0x170,'mov','w2, #0x45');at('notify_setup',0x174,'mov','w3, #0');call('notify_setup',0x178,'_mach_port_request_notification')
  # Every instruction of the pure status mapper anchors the full-width proof.
  mapping=[('cmp','w0, #0x37'),('b.gt',0x20),('cmp','w0, #2'),('b.gt',0x3c),('cbz',0x78),('cmp','w0, #1'),('b.eq',0x64),('b',0x7c),('cmp','w0, #0x96'),('b.gt',0x54),('cmp','w0, #0x38'),('b.eq',0x74),('cmp','w0, #0x91'),('b.eq',0x6c),('b',0x7c),('cmp','w0, #3'),('b.eq',0x6c),('cmp','w0, #0x25'),('b.ne',0x7c),('mov','w0, #0x44f'),('ret',''),('cmp','w0, #0x97'),('b.eq',0x78),('cmp','w0, #0x9f'),('b.ne',0x7c),('mov','w0, #0x44c'),('ret',''),('mov','w0, #0x44e'),('ret',''),('mov','w0, #0x44d'),('ret',''),('mov','w0, #0x451'),('ret','')]
  for k,(mn,op)in enumerate(mapping):
   if isinstance(op,int):op=('w0, #'if mn=='cbz'else'#')+hex(int(roles['status_map']['start'],16)+op)
   at('status_map',4*k,mn,op)
 # Complete original byte/decoder checks for every selected span.
 bodies=[r for v in s['variants']for r in v['roles'].values()]+s['cache_functions'];assert len(bodies)==46
 for r in bodies:
  raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and len(raw)==int(r['end'],16)-int(r['start'],16)==4*len(r['instructions'])
  for j,i in enumerate(r['instructions']):
   ea=int(r['start'],16)+4*j;assert int(i['ea'],16)==ea;b=raw[4*j:4*j+4];ii=list(CS.disasm(b,ea))
   if ii:assert(i['mnemonic'],i['operands'])==(ii[0].mnemonic,ii[0].op_str)
   else:assert i['decoder']=='LLVM'and i['bytes']==i['LLVM']['bytes']==b.hex()and(i['mnemonic'],i['operands'])==(i['LLVM']['mnemonic'],i['LLVM']['operands'])
 rows={i['ea']:i for r in s['cache_functions']for i in r['instructions']}
 def check(ea,mn,op):
  i=rows[ea];assert(i['mnemonic'],i['operands'])==(mn,op),(ea,i,mn,op);checks.append({'scope':'cache',**i})
 expected='''
184b7f8a4|add|x3, sp, #8
184b7f8a8|mov|x4, #0
184b7f8ac|bl|#0x184b7f8d8
184b7f924|cmp|w8, #1
184b7f928|b.ne|#0x184b7f99c
184b7f99c|bl|#0x184b736a0
184b7f9b0|bl|#0x184b6d250
184b7f9c4|bl|#0x184b70674
184b7f9d0|mov|w0, #5
184b7f9d4|mov|w1, #0xce
184b7f9dc|mov|w4, #0
184b7f9e0|mov|w5, #1
184b7f9e4|bl|#0x184b706f0
184b7fa08|add|x16, x16, #0xcc8
184b7fa18|bl|#0x184b9fbf8
184b7fa1c|str|w0, [x20]
184b7fa2c|bl|#0x184b7fbe4
184b7fa38|str|q0, [x19]
184b736e4|mov|w2, #7
184b736e8|bl|#0x184b70674
184b736f8|mov|x2, #0
184b736fc|bl|#0x184b70674
184b7370c|mov|x2, x19
184b73710|bl|#0x184b73724
184b73760|mov|w1, #0x13
184b73764|bl|#0x184b737e0
184b70784|bl|#0x184b8a790
184b707e4|bl|#0x184ba24d8
184b70b98|mov|w8, #0x40000000
184b70b9c|mov|w9, #0x10000000
184b70bb4|mov|w24, #0x20000000
184b70bc0|orr|w24, w26, w24
184ba2598|bl|#0x184b70b0c
184ba2678|bl|#0x184ba325c
184ba3290|bl|#0x18806d230
184b89188|stp|w21, w21, [x22, #0x18]
184b89268|swp|w10, w4, [x9]
184b8926c|cmn|w4, #1
184b8927c|mov|w9, #0x5000
184b89280|movk|w9, #1, lsl #16
184b89294|mov|w5, #0x10
184b89298|bl|#0x184b73bfc
184b73c74|lsl|w8, w20, #0x10
184b73c78|stp|w19, wzr, [x10]
184b73c7c|str|w8, [x10, #8]
184b7cc58|mov|w1, #0x10
184b7cc5c|bl|#0x184b740b0
184b7cc84|stp|w19, w19, [x0, #0x18]
184b7ccfc|mov|w9, #-1
184b7cd00|swp|w9, w0, [x8]
184b7cd04|cmn|w0, #1
184b7cd30|add|x8, x0, #0x18
184b7cd34|swp|wzr, w1, [x8]
184b7cd64|bl|#0x18806d260
184b7faa8|mov|w2, #0xa8
184b7faac|mov|w3, #0x48
184b7fab8|bl|#0x18806d230
184b7fb04|cmp|w8, #0x1f6
184b7fb64|cmp|w8, #0x40
184b7fb8c|str|w8, [x20]
'''
 for line in expected.strip().splitlines():ea,mn,op=line.split('|');check('0x'+ea,mn,op)
 assert[r['exact_exports'][0]for r in s['cache_stubs']]==['_mach_msg','_mach_port_destruct','_object_getClass','__os_object_alloc_realized','_task_get_special_port']
 assert s['cache_constants'][0]['bytes']=='0000000092010000';assert[r['text']for r in s['cache_strings']]==['name','flags','port','instance','type','handle','domain-port','error','subsystem','routine']
 trace=s['trace'];assert trace['sha256']=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'and trace['printed_message_headers']==44 and len(trace['pairs'])==5;old=json.loads((ROOT/'zut_trace_decoded.json').read_text());old_by_line={r['line']:r for r in old['events']}
 names=['com.apple.unfreed','com.apple.fairplayd','com.apple.fpsd','com.apple.arcade.fpsd','com.apple.fpsd.sim'];ports=['0xe03','0x1303','0x1403','0x1503','0x1603'];lines=[1500,1541,1575,1609,1643]
 for j,pair in enumerate(trace['pairs']):
  q,r=pair['request'],pair['reply'];assert q['line']==lines[j]and r['line']==q['line']+16 and q['id']==0x400000ce and r['id']==0x20000000 and q['remote']=='0x707'and q['local']==r['local']=='0xb03'
  assert pair['request_dictionary']==flat_dictionary(q)and pair['reply_dictionary']==flat_dictionary(r)
  a={e['key']:e for e in pair['request_dictionary']['entries']};b={e['key']:e for e in pair['reply_dictionary']['entries']};assert set(a)=={'handle','flags','name','type','domain-port'}and set(b)=={'port'};assert a['handle']['value']==a['flags']['value']==0 and a['name']['value']==names[j]and a['type']['value']==7;assert a['domain-port']['value']['name']=='0x707'and a['domain-port']['value']['disposition']==19 and b['port']['value']['name']==ports[j]and b['port']['value']['disposition']==16
  for msg in[q,r]:assert old_by_line[msg['line']]['message_hex']==msg['message_hex']and old_by_line[msg['line']]['trailer_hex']==msg['trailer_hex']
 assert all(s[k]is False for k in FLAGS)
 return checks
def proofs():
 queries={
 'routine_window_unsigned32':'''(declare-fun r () (_ BitVec 32))
(assert (distinct (bvule (bvsub r #x000000c8) #x0000000b) (and (bvuge r #x000000c8) (bvule r #x000000d3))))''',
 'handler_flags64':'''(declare-fun f () (_ BitVec 64))
(define-fun native () (_ BitVec 64) (bvxor (bvor (bvshl (bvand f #x0000000000000001) #x0000000000000001) (bvand (bvlshr f #x0000000000000006) #x0000000000000001)) #x0000000000000001))
(define-fun spec () (_ BitVec 64) ((_ zero_extend 62) (concat ((_ extract 0 0) f) (bvnot ((_ extract 6 6) f)))))
(assert (distinct native spec))''',
 'getter_null_gate16':'''(declare-fun f () (_ BitVec 16))
(assert (distinct (= (bvand f #x0005) #x0004) (and (= ((_ extract 2 2) f) #b1) (= ((_ extract 0 0) f) #b0))))''',
 'status_mapping_signed32':'''(declare-fun v () (_ BitVec 32))
(define-fun a () (_ BitVec 32) (ite (bvsgt v #x00000096) (ite (= v #x00000097) v (ite (= v #x0000009f) #x0000044c #x00000451)) (ite (= v #x00000038) #x0000044d (ite (= v #x00000091) #x0000044e #x00000451))))
(define-fun b () (_ BitVec 32) (ite (bvsgt v #x00000002) (ite (= v #x00000003) #x0000044e (ite (= v #x00000025) #x0000044f #x00000451)) (ite (= v #x00000000) v (ite (= v #x00000001) #x0000044c #x00000451))))
(define-fun native () (_ BitVec 32) (ite (bvsgt v #x00000037) a b))
(define-fun spec () (_ BitVec 32) (ite (or (= v #x00000000) (= v #x00000097)) v (ite (or (= v #x00000001) (= v #x0000009f)) #x0000044c (ite (or (= v #x00000003) (= v #x00000091)) #x0000044e (ite (= v #x00000025) #x0000044f (ite (= v #x00000038) #x0000044d #x00000451))))))
(assert (distinct native spec))'''}
 out=[]
 for name,body in queries.items():
  query='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr;out.append({'name':name,'query':query,'result':'unsat','scope':'Complete stated scalar domain of instruction-matched manual formulas; excludes native reachability, caller admission, objects and concurrency.'})
 return out
def sdk_checks():
 code='''#include <mach/message.h>
#include <mach/notify.h>
#include <mach/ndr.h>
#include <servers/bootstrap.h>
#include <uuid/uuid.h>
#include <stddef.h>
#pragma pack(push,4)
struct legacy_req {mach_msg_header_t h;NDR_record_t n;name_t name;unsigned long long flags;};
struct legacy_rep {mach_msg_header_t h;mach_msg_body_t b;mach_msg_port_descriptor_t p;NDR_record_t n;uuid_t instance;};
#pragma pack(pop)
#define A(x) static_assert((x), #x)
A(sizeof(mach_port_name_t)==4); A(sizeof(mach_msg_header_t)==24); A(sizeof(mach_msg_port_descriptor_t)==12);
A(sizeof(audit_token_t)==32); A(sizeof(uuid_t)==16); A(sizeof(name_t)==128);
A(BOOTSTRAP_MAX_NAME_LEN==128); A(MACH_MSG_TYPE_MOVE_RECEIVE==16); A(MACH_MSG_TYPE_COPY_SEND==19);
A(MACH_MSG_TYPE_MAKE_SEND==20); A(MACH_MSG_TYPE_MOVE_SEND_ONCE==18); A(MACH_MSG_TYPE_MAKE_SEND_ONCE==21);
A(MACH_NOTIFY_PORT_DESTROYED==69); A(BOOTSTRAP_SUCCESS==0); A(BOOTSTRAP_NOT_PRIVILEGED==1100);
A(BOOTSTRAP_NAME_IN_USE==1101); A(BOOTSTRAP_UNKNOWN_SERVICE==1102); A(BOOTSTRAP_SERVICE_ACTIVE==1103);
A(BOOTSTRAP_NO_MEMORY==1105); A(sizeof(legacy_req)==168); A(offsetof(legacy_req,name)==32);
A(offsetof(legacy_req,flags)==160); A(sizeof(legacy_rep)==64); A(offsetof(legacy_rep,p)==28);
A(offsetof(legacy_rep,n)==40); A(offsetof(legacy_rep,instance)==48);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return {'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Public SDK types and explicitly derived legacy client layouts; no message emission.'}
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();checks=verify(s);negative=[]
 for name,alter in[
  ('wrong_handler_entry',lambda q:q['variants'][1]['roles']['handler'].__setitem__('start','0x100038158')),
  ('changed_routine_destination',lambda q:q['variants'][1]['routine_table']['targets'].__setitem__(6,'0x0')),
  ('changed_receive_disposition',lambda q:q['trace']['pairs'][0]['reply']['descriptors'][0].__setitem__('disposition',17)),
  ('changed_trace_field',lambda q:q['trace']['pairs'][0]['request_dictionary']['entries'][0].__setitem__('value',1)),
  ('changed_legacy_ID',lambda q:q['cache_constants'][0].__setitem__('bytes','0000000093010000')),
  ('changed_api_binding',lambda q:q['cache_stubs'][1].__setitem__('exact_exports',['_mach_port_deallocate']))]:
  q=copy.deepcopy(s);alter(q)
  try:verify(q)
  except(AssertionError,KeyError,ValueError,StopIteration):negative.append(name)
  else:raise AssertionError('Accepted evidence alteration: '+name)
 for name,off,replacement in[('changed_wire_magic',40,b'XXXX'),('changed_root_count',56,struct.pack('<I',2)),('changed_dictionary_extent',52,struct.pack('<I',112)),('unknown_type_tag',68,struct.pack('<I',0x99000))]:
  msg=copy.deepcopy(s['trace']['pairs'][0]['request']);raw=bytearray.fromhex(msg['message_hex']);raw[off:off+len(replacement)]=replacement;msg['message_hex']=raw.hex()
  try:flat_dictionary(msg)
  except(AssertionError,KeyError,ValueError,struct.error,UnicodeDecodeError):negative.append(name)
  else:raise AssertionError('Accepted parser alteration: '+name)
 sdk=sdk_checks();pr=proofs();counts={**s['verified_source_counts'],'instruction_assertions':len(checks),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'rejected_evidence_or_parser_alterations':len(negative)}
 obj={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':checks,'SDK_checks':sdk,'proofs':pr,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'rejected_alterations':negative,'verified_counts':counts,'static_scope':'Two launchd slices, cached bootstrap/XPC check-in/receive-wrapper contracts and five historical trace pairs. Bounded flat packet decoding only. No native check-in/handoff, sender admission, right balance, complete notification lifetime, slot34/RPC700 receiver or successful FairPlay processing proof.','all_checks_pass':True,**{f:False for f in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
