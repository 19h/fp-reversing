#!/usr/bin/env python3
"""Static namespace/guard ABI checks; O(instructions+scalar bank), no target effects."""
import copy,json,struct,subprocess
from recover_receive_name_guard import ROOT,P,FLAGS,KERNEL_ROLES,SDK,CS,sha,h,build
EXPECTED='''
construct|fffffe000bce0500|str|w8, [x23, #0x10]
construct|fffffe000bce0504|str|x19, [x23, #8]
guard_install|fffffe000bce0630|str|x2, [x1, #0x78]
guard_install|fffffe000bce063c|bfi|w8, w3, #0xb, #1
guard_install|fffffe000bce0640|orr|w8, w8, #0x400
unguard|fffffe000bce08dc|tbz|w9, #0xa, #0xfffffe000bce0960
unguard|fffffe000bce08e4|cmp|x1, x21
unguard|fffffe000bce08f0|str|xzr, [x20, #0x78]
unguard|fffffe000bce08f4|and|w9, w9, #0xfffff3ff
unguard|fffffe000bce08f8|str|w9, [x20, #0x10]
port_destroy|fffffe000bcce054|and|w8, w8, #0xfffff3ff
port_destroy|fffffe000bcce05c|str|xzr, [x20, #0x78]
port_destroy|fffffe000bcce090|orr|w8, w8, #0x400
port_destroy|fffffe000bcce0ac|str|x17, [x20, #8]
kernel_copyin|fffffe000bcc6f6c|bl|#0xfffffe000bcc9718
kernel_copyin|fffffe000bcc6f80|cmp|w24, #0x10
kernel_copyin|fffffe000bcc6f84|ccmp|x8, x9, #4, eq
kernel_copyin|fffffe000bcc7020|bl|#0xfffffe000bcc08ec
kernel_right_copyin|fffffe000bcc9798|cmp|w1, #0x10
kernel_right_copyin|fffffe000bcc98e8|sub|w8, w8, #3
kernel_right_copyin|fffffe000bcc98ec|cmp|w8, #2
kernel_right_copyin|fffffe000bcc98fc|strb|wzr, [x19, #2]
link_walk|fffffe000bcc0b78|bl|#0xfffffe000bcccf0c
set_destination|fffffe000bcccf3c|ubfx|x11, x10, #8, #3
set_destination|fffffe000bcccf40|sub|w9, w11, #3
set_destination|fffffe000bcccf44|cmp|w9, #2
set_destination|fffffe000bcccf78|str|x17, [x0, #0x48]
set_destination|fffffe000bcccf8c|cmp|w11, #3
set_destination|fffffe000bcccf90|mov|w11, #5
set_destination|fffffe000bcccf94|cinc|w11, w11, ne
set_destination|fffffe000bcccfa4|str|w9, [x0]
set_destination|fffffe000bcccfc0|str|x17, [x0, #8]
descriptor_copyout|fffffe000bcc57bc|ubfx|w2, w21, #0x10, #8
descriptor_copyout|fffffe000bcc57cc|mov|w3, #2
descriptor_copyout|fffffe000bcc57d0|mov|x4, #0
descriptor_copyout|fffffe000bcc57d4|bl|#0xfffffe000bcc9c1c
right_copyout|fffffe000bcc9ce4|bl|#0xfffffe000bccc258
right_copyout|fffffe000bcc9dd0|b.eq|#0xfffffe000bcc9dec
right_copyout|fffffe000bcc9de4|bl|#0xfffffe000bcd308c
right_copyout|fffffe000bcc9dfc|bl|#0xfffffe000bcbc0f0
right_copyout|fffffe000bcc9e00|cmp|w20, #0x10
right_copyout|fffffe000bcc9e20|bl|#0xfffffe000bcd5e24
right_copyout|fffffe000bcc9e8c|str|w24, [x22]
entry_reuse|fffffe000bcd30a4|ands|w8, w8, #7
entry_reuse|fffffe000bcd30ac|cmp|w8, #2
entry_reuse|fffffe000bcd30c8|cmp|x16, x0
entry_reuse|fffffe000bcd30d0|bl|#0xfffffe000bcbdf9c
entry_reuse|fffffe000bcd30e4|ldr|w19, [x1, #0x34]
entry_reuse|fffffe000bcd30f4|bl|#0xfffffe000bcbbf50
entry_reuse|fffffe000bcd30f8|str|w19, [x21]
reverse_lookup|fffffe000bcbe104|b|#0xfffffe000bcbe068
reverse_lookup|fffffe000bcbe068|cmp|x16, x1
reverse_lookup|fffffe000bcbe110|str|x8, [x3]
reverse_lookup|fffffe000bcbe118|extr|w8, w15, w8, #0x18
reverse_lookup|fffffe000bcbe11c|orr|w8, w8, #3
reverse_lookup|fffffe000bcbe120|str|w8, [x2]
entry_lookup|fffffe000bcbbf9c|lsr|w10, w1, #8
entry_lookup|fffffe000bcbbfcc|and|w8, w8, #0xfc000000
entry_lookup|fffffe000bcbbfd0|orr|w8, w8, #0x3000000
entry_lookup|fffffe000bcbbfd4|lsl|w9, w1, #0x18
entry_lookup|fffffe000bcbbfd8|cmp|w8, w9
receive_publish|fffffe000bcd5ea4|cmp|w22, #4
receive_publish|fffffe000bcd5ea8|ccmp|w22, #2, #4, ne
receive_publish|fffffe000bcd5eb8|cmp|w8, #6
receive_publish|fffffe000bcd5ed8|ldr|x26, [x2, #8]
receive_publish|fffffe000bcd5edc|bl|#0xfffffe000bd7e9c4
receive_publish|fffffe000bcd5ee0|ldr|x8, [x0, #0x608]
receive_publish|fffffe000bcd5eec|tbz|w8, #0, #0xfffffe000bcd61f4
receive_publish|fffffe000bcd5ef0|ldr|w8, [x26, #0x10]
receive_publish|fffffe000bcd5f10|cmp|w3, w8
receive_publish|fffffe000bcd5f14|b.ne|#0xfffffe000bcd6210
receive_publish|fffffe000bcd5f1c|orr|w8, w8, #0xc00
receive_publish|fffffe000bcd5f24|ldr|x8, [x26, #8]
receive_publish|fffffe000bcd5f28|str|x8, [x20, #0x78]
receive_publish|fffffe000bcd5fc0|stur|w3, [x8, #-0x14]
receive_publish|fffffe000bcd5fd4|pacda|x17, x16
receive_publish|fffffe000bcd5fe0|str|x17, [x8]
receive_publish|fffffe000bcd6060|orr|w8, w25, #0x20000
receive_publish|fffffe000bcd6064|str|w8, [x4, #8]
assert_attributes|fffffe000bce0f60|cmp|w2, #8
assert_attributes|fffffe000bce0f68|cmp|w4, #2
assert_attributes|fffffe000bce0fac|tbz|w9, #0xa, #0xfffffe000bce1004
assert_attributes|fffffe000bce0fb4|tbz|w9, #0xb, #0xfffffe000bce0fe4
assert_attributes|fffffe000bce0fb8|ldr|x9, [x21]
assert_attributes|fffffe000bce0fbc|cmp|x20, x9
MIG3234|fffffe000bd875cc|cmp|w8, #0x34
MIG3234|fffffe000bd875f8|bl|#0xfffffe000bce0894
MIG3242|fffffe000bd86ea0|cmn|w9, #0x45
MIG3242|fffffe000bd86eac|cmp|w9, #0x11
MIG3242|fffffe000bd86eb4|sub|w10, w8, #0x34
MIG3242|fffffe000bd86eb8|cmp|w9, w10, lsr #2
MIG3242|fffffe000bd86ec0|add|w9, w9, #0x34
MIG3242|fffffe000bd86ec4|ccmp|w8, w9, #0, ls
MIG3242|fffffe000bd86f18|bl|#0xfffffe000bce0f44
unguard_trap|fffffe000bcdbfb8|b|#0xfffffe000bce0894
'''
def verify(s):
 assert s['launchd_source_sha256']=='1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168'and s['kernel_source_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'and s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a';records=[]
 def need(scope,role,r,mn,op,ea=None):
  ii=[i for i in r['instructions']if i['mnemonic']==mn and i['operands']==op and(ea is None or i['ea']==ea)];assert ii,(scope,role,ea,mn,op);records.extend({'scope':scope,'role':role,**i}for i in ii)
 for v in s['variants']:
  rr=v['roles'];assert len(rr)==5 and v['fixup_reference']['fixups_compared']==2447 and v['fixup_reference']['all_matches']
  for role,mn,op in[('send_object','str','x20, [x19, #0x70]'),('factory','str','x22, [sp, #0x10]'),('guard_assert','str','x1, [sp, #8]'),('guard_assert','mov','w2, #8'),('guard_assert','mov','w4, #2'),('endpoint_reset','ldr','x1, [x19, #0x70]')]:need(v['label'],role,rr[role],mn,op)
  for role,name in[('activate','_mach_port_unguard'),('guard_assert','_mach_port_assert_attributes')]:assert v['stubs'][name]['binding']['symbol']==name;need(v['label'],role,rr[role],'bl','#'+v['stubs'][name]['address'])
  need(v['label'],'endpoint_reset',rr['endpoint_reset'],'bl','#'+rr['guard_assert']['start'])
 for role,a in KERNEL_ROLES.items():assert s['kernel_functions'][role]['start']==hex(a)
 for line in EXPECTED.strip().splitlines():role,ea,mn,op=line.split('|');need('kernel',role,s['kernel_functions'][role],mn,op,'0x'+ea)
 cf=s['cache_functions'];need('cache','unguard_wrapper',cf['_mach_port_unguard'],'bl','#'+cf['__kernelrpc_mach_port_unguard_trap']['start']);need('cache','unguard_wrapper',cf['_mach_port_unguard'],'b','#'+cf['__kernelrpc_mach_port_unguard']['start']);need('cache','unguard_trap',cf['__kernelrpc_mach_port_unguard_trap'],'mov','x16, #-0x2a');need('cache','assert_export',cf['_mach_port_assert_attributes'],'b','#'+cf['assert_attributes_MIG']['start']);need('cache','assert_MIG',cf['assert_attributes_MIG'],'cmp','w4, #0x11');need('cache','assert_MIG',cf['assert_attributes_MIG'],'mov','x4, #0xcaa00000000')
 for mid in[3234,3242]:assert s['MIG_bindings'][str(mid)]['id']==mid and s['MIG_bindings'][str(mid)]['stub']['target']==s['kernel_functions']['MIG'+str(mid)]['start']
 assert s['unguard_trap']['index']==42 and s['unguard_trap']['handler_pointer']['target']==s['kernel_functions']['unguard_trap']['start'];assert[(r['index'],struct.unpack_from('<H',bytes.fromhex(r['bytes']),8)[0])for r in s['kernel_policy_rows']]==[(0,0),(2,0x3f8),(4,0x2fc),(11,0x40)]
 bodies=[r for v in s['variants']for r in v['roles'].values()]+list(s['kernel_functions'].values())+list(cf.values());assert len(bodies)==36
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
#include <mach/message.h>
#include <stddef.h>
#define A(x) static_assert((x), #x)
A(sizeof(mach_port_context_t)==8); A(sizeof(mach_port_name_t)==4); A(sizeof(natural_t)==4);
A(MACH_PORT_GUARD_INFO==8); A(MACH_PORT_GUARD_INFO_COUNT==2); A(sizeof(mach_port_guard_info_t)==8);
A(MPO_CONTEXT_AS_GUARD==1); A(MPO_STRICT==0x20); A(MPO_INSERT_SEND_RIGHT==0x10);
A(MACH_PORT_TYPE_SEND==0x10000); A(MACH_PORT_TYPE_RECEIVE==0x20000);
A(MACH_MSG_TYPE_MOVE_RECEIVE==16); A(MACH_MSG_TYPE_MOVE_SEND_ONCE==18);
A(sizeof(__Request__mach_port_unguard_t)==44);
A(offsetof(__Request__mach_port_unguard_t,name)==32);
A(offsetof(__Request__mach_port_unguard_t,guard)==36);
A(sizeof(__Reply__mach_port_unguard_t)==36);
A(sizeof(__Request__mach_port_assert_attributes_t)==112);
A(offsetof(__Request__mach_port_assert_attributes_t,name)==32);
A(offsetof(__Request__mach_port_assert_attributes_t,flavor)==36);
A(offsetof(__Request__mach_port_assert_attributes_t,infoCnt)==40);
A(offsetof(__Request__mach_port_assert_attributes_t,info)==44);
A(sizeof(__Request__mach_port_assert_attributes_t::info)==68);
A(sizeof(__Reply__mach_port_assert_attributes_t)==36);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Compile-time installed SDK names/layouts only; no guard or port API called.'}
def proofs():
 queries={
 'receiver_state_3_4_to_5_6':'''(declare-fun w () (_ BitVec 32))
(define-fun k () (_ BitVec 32) (bvand (bvlshr w #x00000008) #x00000007))
(assert (or (= k #x00000003) (= k #x00000004)))
(define-fun b () (_ BitVec 32) (bvor (bvand (bvlshr w #x00000008) #x000000f8) (ite (= k #x00000003) #x00000005 #x00000006)))
(define-fun out () (_ BitVec 32) (bvor (bvand w #xffff00ff) (bvshl b #x00000008)))
(assert (distinct out (bvor (bvand w #xfffff8ff) (bvshl (bvadd k #x00000002) #x00000008))))''',
 'reverse_name_generation_consistency32':'''(declare-fun i () (_ BitVec 32)) (declare-fun e () (_ BitVec 32))
(define-fun n () (_ BitVec 32) (bvor (bvor (bvshl i #x00000008) (bvlshr e #x00000018)) #x00000003))
(assert (distinct (bvshl n #x00000018) (bvor (bvand e #xfc000000) #x03000000)))''',
 'strict_guard_restore_then_assert64':'''(declare-fun f () (_ BitVec 32)) (declare-fun saved () (_ BitVec 64)) (declare-fun expected () (_ BitVec 64))
(define-fun restored () (_ BitVec 32) (bvor f #x00000c00))
(define-fun accepts () Bool (and (distinct (bvand restored #x00000400) #x00000000) (distinct (bvand restored #x00000800) #x00000000) (= saved expected)))
(assert (distinct accepts (= saved expected)))''',
 'MIG3242_extent_and_count32':'''(declare-fun s () (_ BitVec 32)) (declare-fun n () (_ BitVec 32))
(define-fun range () Bool (bvuge (bvsub s #x00000079) #xffffffbb))
(define-fun accept () Bool (and range (bvule n #x00000011) (bvule n (bvlshr (bvsub s #x00000034) #x00000002)) (= s (bvadd #x00000034 (bvshl n #x00000002)))))
(assert (distinct accept (and (bvule n #x00000011) (= s (bvadd #x00000034 (bvshl n #x00000002))))))'''};out=[]
 for name,body in queries.items():
  query='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr);out.append({'name':name,'query':query,'result':'unsat','scope':'Instruction-matched scalar formulas under stated path premises only. No native name/entry identity, task metadata admission, guard reachability, interleaving or PAC semantics.'})
 return out
def guard_bank():
 rows=[]
 for low in range(16):
  for high in[0,0x5a5a0000,0xffff0000]:
   flags=high|(low<<8)
   for context in[0,1,0x0123456789abcdef,0xffffffffffffffff]:
    for expected in[context,context^1]:
     before=bool(flags&0x400)and bool(flags&0x800)and context==expected;after=bool((flags|0xc00)&0x400)and bool((flags|0xc00)&0x800)and context==expected;assert after==(context==expected);rows.append([flags,context,expected,before,after])
 return{'inputs_checked':len(rows),'rows_sha256':h(json.dumps(rows,separators=(',',':')).encode()),'scope':'Pure scalar guard/context formulas; no port, token, IPC request or native failure constructed.'}
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();records=verify(s);negative=[]
 for name,alter in[
  ('wrong_unguard_trap',lambda q:q['unguard_trap'].__setitem__('index',41)),
  ('wrong_assert_MIG_ID',lambda q:q['MIG_bindings']['3242'].__setitem__('id',3241)),
  ('changed_reverse_name_generation',lambda q:q['kernel_functions']['reverse_lookup']['instructions'][-4].__setitem__('operands','w8, w8, #1')),
  ('changed_policy_row',lambda q:q['kernel_policy_rows'][1].__setitem__('index',3)),
  ('wrong_assert_export_target',lambda q:q['cache_functions']['_mach_port_assert_attributes']['instructions'][0].__setitem__('operands','#0x18056e2e0')),
  ('changed_live_guard_store',lambda q:q['kernel_functions']['guard_install']['instructions'][3].__setitem__('operands','x2, [x1, #0x70]'))]:
  q=copy.deepcopy(s);alter(q)
  try:verify(q)
  except(AssertionError,KeyError,ValueError,StopIteration):negative.append(name)
  else:raise AssertionError('Accepted altered evidence: '+name)
 sdk=sdk_checks();pr=proofs();bank=guard_bank();counts={**s['verified_source_counts'],'instruction_assertions':len(records),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'finite_guard_inputs_checked':bank['inputs_checked'],'rejected_evidence_alterations':len(negative)}
 obj={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':records,'SDK_checks':sdk,'proofs':pr,'guard_scalar_bank':bank,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'rejected_alterations':negative,'verified_counts':counts,'static_scope':'Selected original constructor/unguard/destruction/copyin/link/copyout/service restore/assert interfaces. Name reuse and context restoration are conditional on one object/label/entry epoch, admission, reverse-map membership and receiver metadata. Native identity, guard state, ownership, scheduling, complete fallback allocation and hardware authentication remain unknown.','all_checks_pass':True,**{f:False for f in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
