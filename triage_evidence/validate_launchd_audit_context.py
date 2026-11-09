#!/usr/bin/env python3
"""Static token provenance, SDK layouts and scalar routing checks. No target effects."""
import copy,json,struct,subprocess
from recover_launchd_audit_context import ROOT,P,FLAGS,ROLES,TOKEN,SDK,CS,sha,h,build
def verify(s):
 assert s['audit_token_global']==hex(TOKEN)and s['launchd_source_sha256']=='1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168'and s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a';checks=[]
 for j,v in enumerate(s['variants']):
  roles=v['roles'];assert set(roles)==set(ROLES[j])and all(int(roles[k]['start'],16)==a for k,a in ROLES[j].items());assert v['fixup_reference']['fixups_compared']==2447 and v['fixup_reference']['all_matches'];assert len(v['token_address_references'])==89
  def at(role,off,mn,op=None):
   ea=int(roles[role]['start'],16)+off;i=next(i for i in roles[role]['instructions']if int(i['ea'],16)==ea);assert i['mnemonic']==mn and(op is None or i['operands']==op),(v['label'],role,hex(off),i,mn,op);checks.append({'scope':v['label'],'role':role,**i});return i
  def call(role,off,name):return at(role,off,'bl','#'+v['stubs'][name]['address'])
  def local(role,off,dest):return at(role,off,'bl','#'+roles[dest]['start'])
  # Actual Mach-message producer, class/routine separation and current dictionary epoch.
  at('mach_event',0x18,'cmp','x1, #8');at('mach_event',0x24,'cmp','x1, #7');at('mach_event',0x2c,'cmp','x1, #2');local('mach_event',0x48,'mach_entry');at('mach_event',0x4c,'str','xzr, [x19, #0x428]')
  call('mach_entry',0x3c,'_dispatch_mach_msg_get_msg');at('mach_entry',0x48,'cmp','x8, #0x17');at('mach_entry',0x54,'ldr','w22, [x0, #0x14]');at('mach_entry',0x58,'and','w8, w22, #0xff000000');at('mach_entry',0x5c,'mov','w9, #0x40000000');at('mach_entry',0x64,'mov','w9, #0x10000000');at('mach_entry',0x70,'str','w8, [x20, #0x14]');call('mach_entry',0x88,'_xpc_receive_mach_msg');local('mach_entry',0x94,'current_dictionary');at('mach_entry',0x9c,'and','w1, w22, #0xffffff');local('mach_entry',0xa4,'xpc_dispatch');call('mach_entry',0xac,'_xpc_release');at('mach_entry',0xb0,'mov','x0, #0');local('mach_entry',0xb4,'current_dictionary')
  # Embedded raw carrier and raw audit-trailer copy. No outer/inner identity equivalence claim.
  call('dictionary_entry',0x64,'_xpc_dictionary_get_value');call('dictionary_entry',0x88,'_xpc_data_get_bytes_ptr');call('dictionary_entry',0x94,'_xpc_data_get_length');at('dictionary_entry',0x98,'cmp','x0, #0x17');call('dictionary_entry',0x100,'__xpc_pipe_handle_mig');local('dictionary_entry',0x120,'xpc_dispatch')
  for off,mn,op in[(0x30,'ldr','w8, [x0, #4]'),(0x34,'add','x8, x8, #3'),(0x38,'and','x8, x8, #0x1fffffffc'),(0x3c,'add'if j==0 else'addpt','x21, x0, x8'),(0x40,'ldur','q0, [x21, #0x14]'),(0x44,'ldur','q1, [x21, #0x24]'),(0x4c,'add','x8, x8, #0x408'),(0x50,'stp','q0, q1, [x8]'),(0x88,'blraaz','x8')]:at('raw_dispatch',off,mn,op)
  # XPC token copied before group matching and authenticated callback; ordinary suffix clears busy only.
  for off,mn,op in[(0x34,'cmp','w8, #1'),(0x48,'mov','w8, #1'),(0x4c,'strb','w8, [x23, #0x9e0]'),(0x74,'stp','q0, q0, [sp, #0x20]'),(0x78,'add','x1, sp, #0x20'),(0x88,'add','x8, x8, #0x408'),(0x8c,'ldp','q0, q1, [sp, #0x20]'),(0x90,'stp','q0, q1, [x8]'),(0x98,'cmp','w21, #0x577'),(0x9c,'b.hi',None),(0xa0,'ubfx','w8, w21, #2, #0xe'),(0xa4,'mov','w9, #0x147b'),(0xa8,'mul','w8, w8, w9'),(0xac,'lsr','w8, w8, #0x11'),(0xb8,'mov','w10, #0x861'),(0xcc,'ldr','w22, [x9, w8, uxtw #2]'),(0x14c,'ldr','w11, [x10, x9, lsl #2]'),(0x150,'cmp','w11, w22'),(0x21c,'strb','wzr, [x23, #0x9e0]'),(0x258,'add','x8, x8, x9, lsl #3'),(0x260,'add','x3, sp, #0x18'),(0x264,'mov','x0, x20'),(0x268,'mov','x1, x21'),(0x26c,'mov','x2, x19'),(0x270,'blraaz','x8')]:at('xpc_dispatch',off,mn,op)
  call('xpc_dispatch',0x80,'_xpc_dictionary_get_audit_token');call('xpc_dispatch',0x31c,'_xpc_pipe_routine_reply')
  # Consumer receives the exact same global address and passes the audit record through unchanged.
  at('checkin_dispatcher',0x174,'adrp','x1, #0x10008b000');at('checkin_dispatcher',0x178,'add','x1, x1, #0x408');local('checkin_dispatcher',0x188,'checkin_handler');at('checkin_handler',0x24,'mov','x21, x1');at('checkin_handler',0x78,'mov','x1, x21');local('checkin_handler',0x88,'checkin_core');at('checkin_core',0x38,'mov','x23, x1');at('checkin_core',0x40,'ldr','w1, [x1, #0x14]')
  table=v['routine_group_table'];assert bytes.fromhex(table['bytes'])==struct.pack('<14i',*table['signed32_values'])and table['signed32_values']==[0,7,5,6,4,0,0,2,3,8,10,0,11,12];assert v['strings'][0]['text']=='mig-request';assert len(v['producer_callers']['xpc_dispatch'])==2 and len(v['producer_callers']['raw_dispatch_literals'])==2 and len(v['producer_callers']['mach_entry'])==1
 bodies=[r for v in s['variants']for r in v['roles'].values()]+s['cache_functions'];assert len(bodies)==35
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
184b7213c|bl|#0x184b89370
184b72140|tbz|w0, #0, #0x184b722b4
184b721ac|add|x8, x9, #3
184b721b0|and|x8, x8, #0x1fffffffc
184b721b8|ldur|q0, [x9, #0x14]
184b721bc|ldur|q1, [x9, #0x24]
184b721c0|stp|q0, q1, [sp, #0x30]
184b72300|bl|#0x184b725f4
184b7233c|str|x21, [x20]
184b7285c|orr|w8, w8, #1
184b72860|str|w8, [x0, #0x1c]
184b72900|ldp|q0, q1, [x19, #0x20]
184b72904|stur|q0, [x20, #0x78]
184b72908|stur|q1, [x20, #0x88]
184b72b94|ldr|w8, [x20, #0x1c]
184b72b98|and|w8, w8, #3
184b72ba8|ldur|q0, [x20, #0x78]
184b72bac|ldur|q1, [x20, #0x88]
184b72bbc|ldur|q0, [x20, #0x58]
184b72bc0|ldur|q1, [x20, #0x68]
184b72bc4|stp|q0, q1, [x19]
184b72bcc|movi|v0.2d, #0xffffffffffffffff
184b72bd0|stp|q0, q0, [x19]
184b72bd4|str|wzr, [x19, #0x14]
184b89370|mov|w8, #-0x10000000
184b89378|add|w8, w9, w8
184b8937c|ror|w8, w8, #0x1c
184b89380|cmp|w8, #2
184b89398|and|w8, w8, #0x1f
184b893a4|ccmp|w8, #0x12, #4, ne
184b893b8|cbz|w8, #0x184b893ac
184ba241c|blraaz|x2
184ba2484|bl|#0x18806d230
184ba2b18|bl|#0x184b70b0c
'''
 for line in expected.strip().splitlines():ea,mn,op=line.split('|');check('0x'+ea,mn,op)
 assert len(s['audit_fields'])==8
 for j,f in enumerate(s['audit_fields']):
  assert f['index']==j and f['offset_bytes']==4*j and f['width_bytes']==4 and f['global_address']==hex(TOKEN+4*j);r=next(r for r in s['cache_functions']if r.get('exact_export')==f['export']);op='w0, [x0]'if j==0 else'w0, [x0, #'+(str(j*4)if j*4<10 else hex(j*4))+']';check(r['start'],'ldr',op);check(hex(int(r['start'],16)+4),'ret','')
 assert[r['exact_exports'][0]for r in s['cache_stubs']]==['_object_getClass','_dispatch_mach_msg_get_msg','_mach_msg','_mach_msg_destroy'];assert all(s[k]is False for k in FLAGS)
 return checks
def proofs():
 queries={
 'audit_trailer_alignment_u32':'''(declare-fun s () (_ BitVec 32))
(define-fun v () (_ BitVec 64) ((_ zero_extend 32) s))
(define-fun aligned () (_ BitVec 64) (bvand (bvadd v #x0000000000000003) #x00000001fffffffc))
(assert (or (not (= (bvand aligned #x0000000000000003) #x0000000000000000)) (bvult aligned v) (bvuge (bvsub aligned v) #x0000000000000004)))''',
 'numeric_routine_group_index':'''(declare-fun r () (_ BitVec 32))
(assert (bvule r #x00000577))
(define-fun v () (_ BitVec 32) (bvlshr (bvmul (bvand (bvlshr r #x00000002) #x00003fff) #x0000147b) #x00000011))
(assert (distinct v (bvudiv r #x00000064)))''',
 'canonical_header_predicate32':'''(declare-fun n () (_ BitVec 32)) (declare-fun bits () (_ BitVec 32)) (declare-fun remote () (_ BitVec 32))
(define-fun r () (_ BitVec 32) ((_ rotate_right 28) (bvsub n #x10000000)))
(define-fun req () Bool (ite (distinct remote #x00000000) (= (bvand bits #x0000001f) #x00000012) true))
(define-fun native () Bool (or (and (or (bvult r #x00000002) (= r #x00000003)) req) (and (= r #x00000002) (= remote #x00000000))))
(define-fun spec () Bool (or (and (or (= n #x10000000) (= n #x20000000) (= n #x40000000)) (or (= remote #x00000000) (= (bvand bits #x0000001f) #x00000012))) (and (= n #x30000000) (= remote #x00000000))))
(assert (distinct native spec))'''};out=[]
 for name,body in queries.items():
  query='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr;out.append({'name':name,'query':query,'result':'unsat','scope':'Complete stated scalar domain of instruction-matched manual formulas; address bounds, trailer validity, ADDPT semantics, sender authenticity and native admission excluded.'})
 return out
def routing_bank(s):
 table=s['variants'][0]['routine_group_table']['signed32_values'];rows=[];hist={}
 for r in range(1400):
  q=(((r>>2)&0x3fff)*0x147b)&0xffffffff;q>>=17;assert q==r//100;accepted=r!=0 and not((1<<q)&0x861);group=table[q]if accepted else None;rows.append([r,q,accepted,group])
  if accepted:hist[group]=hist.get(group,0)+1
 assert sum(hist.values())==1000 and rows[206]==[206,2,True,5]
 return {'inputs_checked':len(rows),'range_inclusive':[0,1399],'accepted_numeric_inputs':1000,'accepted_group_histogram':{str(k):v for k,v in sorted(hist.items())},'routine206':rows[206],'rows_sha256':h(json.dumps(rows,separators=(',',':')).encode()),'scope':'Numeric classifier only; excludes busy/context gates, registry contents, callback policy and native execution.'}
def sdk_checks():
 code='''#include <mach/message.h>
#include <bsm/libbsm.h>
#include <sys/types.h>
#include <stddef.h>
#include <limits.h>
#define A(x) static_assert((x), #x)
A(sizeof(audit_token_t)==32); A(sizeof(audit_token_t::val[0])==4);
A(sizeof(security_token_t)==8); A(sizeof(mach_msg_header_t)==24);
A(sizeof(mach_msg_audit_trailer_t)==52); A(offsetof(mach_msg_audit_trailer_t,msgh_seqno)==8);
A(offsetof(mach_msg_audit_trailer_t,msgh_sender)==12); A(offsetof(mach_msg_audit_trailer_t,msgh_audit)==20);
A(sizeof(uid_t)==4); A(sizeof(gid_t)==4); A(sizeof(pid_t)==4); A(sizeof(au_asid_t)==4);
A(MACH_MSG_TYPE_MOVE_SEND_ONCE==18); A(sizeof(audit_token_t::val)/sizeof(unsigned int)==8);
constexpr audit_token_t invalid = INVALID_AUDIT_TOKEN_VALUE;
A(invalid.val[0]==UINT_MAX); A(invalid.val[1]==UINT_MAX); A(invalid.val[2]==UINT_MAX); A(invalid.val[3]==UINT_MAX);
A(invalid.val[4]==UINT_MAX); A(invalid.val[5]==UINT_MAX); A(invalid.val[6]==UINT_MAX); A(invalid.val[7]==UINT_MAX);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return {'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Installed primary SDK layout/types and all-ones invalid-token initializer; no framework or target invocation.'}
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();records=verify(s);negative=[]
 for name,alter in[
  ('wrong_global',lambda q:q.__setitem__('audit_token_global','0x10008b400')),
  ('changed_group_map',lambda q:q['variants'][1]['routine_group_table']['signed32_values'].__setitem__(2,6)),
  ('missing_raw_producer_literal',lambda q:q['variants'][1]['producer_callers']['raw_dispatch_literals'].pop()),
  ('wrong_PID_offset',lambda q:q['audit_fields'][5].__setitem__('offset_bytes',16)),
  ('wrong_PID_accessor',lambda q:q['audit_fields'][5].__setitem__('export','_audit_token_to_euid')),
  ('changed_XPC_token_store',lambda q:q['variants'][0]['roles']['xpc_dispatch']['instructions'][36].__setitem__('operands','q0, q1, [x9]')),
  ('changed_API_binding',lambda q:q['cache_stubs'][1].__setitem__('exact_exports',['_mach_msg']))]:
  q=copy.deepcopy(s);alter(q)
  try:verify(q)
  except(AssertionError,KeyError,ValueError,StopIteration):negative.append(name)
  else:raise AssertionError('Accepted alteration: '+name)
 sdk=sdk_checks();pr=proofs();bank=routing_bank(s);fallback=struct.pack('<8I',*[0xffffffff if j!=5 else 0 for j in range(8)]).hex();counts={**s['verified_source_counts'],'instruction_assertions':len(records),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'numeric_routing_inputs_checked':bank['inputs_checked'],'rejected_evidence_alterations':len(negative)}
 obj={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':records,'SDK_checks':sdk,'proofs':pr,'numeric_routing_bank':bank,'getter_fallback_pattern32_hex':fallback,'getter_fallback_is_SDK_all_ones_invalid':False,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'rejected_alterations':negative,'verified_counts':counts,'static_scope':'Identified XPC/raw token producers and selected check-in consumer in both launchd slices; ordinary libxpc trailer/metadata path and original libbsm field accessors. Exact-address locators are not an exhaustive writer census. No native sender/admission proof, cross-path serialization, full ADDPT semantics or carrier authenticity proof.','all_checks_pass':True,**{f:False for f in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
