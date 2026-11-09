#!/usr/bin/env python3
"""Verify endpoint/job callback, scalar lifetime and destruct ABI; no target effects."""
import copy,json,subprocess
from recover_endpoint_job_lifecycle import ROOT,P,FLAGS,SDK,CS,sha,h,build
PATTERNS='''
wrapper|mov|x3, x16
wrapper|mov|x5, x0
constructor|str|x24, [x0, #0x60]
constructor|stp|x23, x22, [x0, #0x90]
callback|mov|x19, x2
callback|cmp|w1, #1
callback|tst|w8, #8
callback|csinc|w1, w8, wzr, ne
callback|and|w8, w0, #0xfffffffe
callback|cmp|w8, #0x24
callback|csel|w8, wzr, w0, eq
callback|ldr|x21, [x19, #0xf8]
callback|and|w8, w8, #0xfffffffb
deactivate|ldr|x8, [x1, #0xf8]
deactivate|ldrsh|w9, [x20, #0x12c]
deactivate|strh|w10, [x20, #0x12c]
deactivate|cinc|w10, w10, ne
deactivate|cmp|w10, w9
deactivate|strh|wzr, [x20, #0x12c]
deactivate|ldr|w9, [x19, #0x410]
deactivate|ldrh|w8, [x19, #0xb0]
deactivate|ldr|w8, [x20, #0x120]
pending_restart|ldr|w1, [x0, #0x120]
pending_restart|str|wzr, [x0, #0x120]
pending_writer|ldrh|w10, [x20, #0x12c]
pending_writer|str|w19, [x20, #0x120]
pending_writer|mov|w0, #0x24
rearm_all|ldr|x20, [x0, #0x98]
rearm_all|ldr|x20, [x19, #0xb0]
rearm_all|ldr|x20, [x19, #0xb8]
endpoint_rearm|mov|w9, #0xffbd
endpoint_rearm|orr|w8, w9, #2
endpoint_rearm|mov|w8, #0x402
base_init|add|x19, x22, #0x218
base_init|ldp|q0, q1, [x21, #0x20]
base_init|stp|q0, q1, [x19, #0x20]
base_init|ldp|q0, q1, [x21]
base_init|stp|q0, q1, [x19]
base_init|ldr|x9, [x21, #0x40]
base_init|str|x9, [x22, #0x258]
factory_bridge|mov|x23, x5
factory_bridge|mov|x5, x23
factory_clone|mov|x25, x5
factory_clone|mov|x4, x25
async_prepare|ldr|x20, [x19, #0x68]
async_prepare|ldr|x21, [x19, #0x70]
async_prepare|str|xzr, [x19, #0x68]
async_prepare|stp|x20, x21, [sp, #0x28]
async_block|ldr|x0, [x0, #0x20]
async_block|ldr|x3, [x19, #0x28]
async_block|mov|w2, #0
launch_core|ldr|x8, [x0, #0x220]
launch_core|ldr|x2, [x0, #0x258]
launch_core|blraaz|x8
'''
def verify(s):
 assert s['launchd_source_sha256']=='1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168'and s['kernel_source_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'and s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a';records=[]
 def need(scope,role,r,mn,op):
  ii=[i for i in r['instructions']if i['mnemonic']==mn and i['operands']==op];assert ii,(scope,role,mn,op);records.extend({'scope':scope,'role':role,**i}for i in ii)
 for v in s['variants']:
  rr=v['roles'];assert len(rr)==21 and v['fixup_reference']['fixups_compared']==2447 and v['fixup_reference']['all_matches'];assert len(v['constructor_direct_callers'])==1 and len(v['wrapper_address_references'])==8 and len(v['pending_writer_address_references'])==8 and len(v['pending120_immediate_store_candidates'])==3
  for line in PATTERNS.strip().splitlines():role,mn,op=line.split('|');need(v['label'],role,rr[role],mn,op)
  for role,name in[('launch_core','_posix_spawnp'),('async_prepare','_dispatch_async'),('async_block','_xpc_mach_send_get_right'),('async_block','_mach_port_destruct'),('async_block','_xpc_release')]:assert v['stubs'][name]['binding']['symbol']==name;need(v['label'],role,rr[role],'bl','#'+v['stubs'][name]['address'])
  for a,b,mn in[('wrapper','constructor','bl'),('callback','start_gate','bl'),('callback','deactivate','b'),('pending_restart','start_gate','b'),('deactivate','pending_restart','b'),('deactivate','rearm_all','bl'),('deactivate','job_remove','b'),('start_gate','launch_core','b'),('selected_factory','factory_bridge','bl'),('factory_bridge','factory_clone','bl'),('factory_clone','base_init','bl')]:need(v['label'],a,rr[a],mn,'#'+rr[b]['start'])
  tt=v['callback_table_contract'];assert len(tt)==8 and tt[1]['target']==rr['pending_writer']['start']and tt[3]['target']==rr['wrapper']['start']and all(r['index']==j and r['table_offset_bytes']==8*j and r['job_field_offset_bytes']==0x218+8*j for j,r in enumerate(tt));strings=[r['text']for r in v['strings']];assert 'Deactivated abandoned endpoint: %s'in strings and 'service inactive: %s%s'in strings and 'removing inactive unmanaged service: %s'in strings and 'endpoint event received for running service'in strings
 k=s['kernel_functions']
 for role,mn,op in[('destruct_MIG','cmp','w8, #0x38'),('destruct_MIG','bl','#0xfffffe000bce0714'),('destruct_core','bl','#0xfffffe000bcd2f34'),('destruct_core','b','#0xfffffe000bcd4ab0'),('right_destruct','tbnz','w26, #0x11, #0xfffffe000bcd4af0'),('right_destruct','cmp','w23, #1'),('right_destruct','cbz','w23, #0xfffffe000bcd4ba4'),('right_destruct','tbz','w8, #2, #0xfffffe000bcd4b54'),('right_destruct','cmp','x24, x25'),('right_destruct','bl','#0xfffffe000bccdbb4')]:need('kernel',role,k[role],mn,op)
 assert s['MIG3232']['id']==3232 and s['MIG3232']['stub']['target']==k['destruct_MIG']['start']and s['trap25']['index']==25 and s['trap25']['handler_pointer']['target']==k['destruct_trap']['start'];cf=s['cache_functions'];need('cache','wrapper',cf['_mach_port_destruct'],'bl','#'+cf['__kernelrpc_mach_port_destruct_trap']['start']);need('cache','wrapper',cf['_mach_port_destruct'],'b','#'+cf['__kernelrpc_mach_port_destruct']['start']);need('cache','trap',cf['__kernelrpc_mach_port_destruct_trap'],'mov','x16, #-0x19')
 bodies=[r for v in s['variants']for r in v['roles'].values()]+list(k.values())+list(cf.values());assert len(bodies)==51
 for r in bodies:
  raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and len(raw)==int(r['end'],16)-int(r['start'],16)==4*len(r['instructions'])
  for j,i in enumerate(r['instructions']):
   ea=int(r['start'],16)+4*j;assert i['ea']==hex(ea);ii=list(CS.disasm(raw[4*j:4*j+4],ea))
   if ii:assert(i['mnemonic'],i['operands'])==(ii[0].mnemonic,ii[0].op_str)
   else:assert i['decoder']=='LLVM'and i['LLVM']['bytes']==raw[4*j:4*j+4].hex()and(i['mnemonic'],i['operands'])==(i['LLVM']['mnemonic'],i['LLVM']['operands'])
 assert all(s[k]is False for k in FLAGS);return records
def sdk_checks():
 code='''#define __MigPackStructs 1
#include <mach/mach_port.h>
#include <spawn.h>
#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>
#define A(x) static_assert((x), #x)
A(sizeof(pid_t)==4); A(sizeof(posix_spawnattr_t)==8); A(sizeof(posix_spawn_file_actions_t)==8);
A(sizeof(mach_port_context_t)==8); A(sizeof(mach_port_delta_t)==4); A(sizeof(mach_port_name_t)==4);
A(sizeof(__Request__mach_port_destruct_t)==48);
A(offsetof(__Request__mach_port_destruct_t,name)==32);
A(offsetof(__Request__mach_port_destruct_t,srdelta)==36);
A(offsetof(__Request__mach_port_destruct_t,guard)==40);
A(sizeof(__Reply__mach_port_destruct_t)==36);
A(EINPROGRESS==36); A(EALREADY==37); A(sizeof(int16_t)==2); A(sizeof(uint16_t)==2);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Installed SDK compile-time ABI/constants only; no spawn, port destruct, service API or target invoked.'}
def proofs():
 queries={
 'callback_reason_selector16':'''(declare-fun f () (_ BitVec 16))
(define-fun r () (_ BitVec 32) (ite (distinct (bvand f #x0008) #x0000) #x00000008 #x00000001))
(assert (or (and (= (bvand f #x0008) #x0000) (distinct r #x00000001)) (and (distinct (bvand f #x0008) #x0000) (distinct r #x00000008))))''',
 'callback_status_normalization32':'''(declare-fun s () (_ BitVec 32))
(define-fun n () (_ BitVec 32) (ite (= (bvand s #xfffffffe) #x00000024) #x00000000 s))
(assert (or (distinct n (ite (or (= s #x00000024) (= s #x00000025)) #x00000000 s)) (= n #x00000025)))''',
 'activation_decrement_domain16':'''(declare-fun c () (_ BitVec 16)) (declare-fun m () (_ BitVec 32))
(define-fun n () (_ BitVec 32) ((_ sign_extend 16) c))
(define-fun bad () Bool (or (bvult (bvsub n #x00008001) #xffff0000) (bvsle n #x00000000)))
(define-fun threshold () (_ BitVec 32) (ite (= m #x00000000) #x00000001 #x00000002))
(define-fun cleanup () Bool (and (not bad) (bvsge threshold n)))
(assert (or (distinct bad (bvsle n #x00000000)) (distinct cleanup (or (= c #x0001) (and (distinct m #x00000000) (= c #x0002))))))''',
 'endpoint_rearm_flags16':'''(declare-fun f () (_ BitVec 16)) (declare-fun t () (_ BitVec 32))
(define-fun o () (_ BitVec 16) (bvor (bvor (bvand f #xffbd) #x0002) (ite (bvuge t #x00000002) #x0400 #x0000)))
(assert (or (distinct (bvand o #x0042) #x0002) (and (bvuge t #x00000002) (distinct (bvand o #x0400) #x0400)) (distinct (bvand o #xfbbd) (bvand f #xfbbd))))'''};out=[]
 for name,body in queries.items():
  query='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr);out.append({'name':name,'query':query,'result':'unsat','scope':'Instruction-matched scalar formulas only; flag formula begins after optional helper/reread. Excludes object validity, policy callbacks, scheduling, native launch and PAC semantics.'})
 return out
def count_bank():
 rows=[];hist={'bad':0,'cleanup':0,'return':0}
 for raw in range(65536):
  n=raw if raw<32768 else raw-65536
  for discriminator in[0,1]:
   overflow=((n-0x8001)&0xffffffff)<0xffff0000;bad=overflow or n<=0;cleanup=not bad and n<=1+discriminator;klass='bad'if bad else'cleanup'if cleanup else'return';hist[klass]+=1;assert bad==(n<=0);assert cleanup==(n==1 or(discriminator!=0 and n==2));rows.append([raw,discriminator,(raw-1)&0xffff,klass])
 assert hist=={'bad':65538,'cleanup':3,'return':65531};return{'inputs_checked':len(rows),'class_histogram':hist,'rows_sha256':h(json.dumps(rows,separators=(',',':')).encode()),'scope':'Every signed16 activation-count pattern and zero/nonzero discriminator class. Diagnostic prefixes and precheck wrapping stores are arithmetic observations; no target record or native failure is constructed.'}
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();records=verify(s);negative=[]
 for name,alter in[
  ('changed_callback_copy',lambda q:next(i for i in q['variants'][0]['roles']['base_init']['instructions']if i['mnemonic']=='stp'and i['operands']=='q0, q1, [x19]').__setitem__('operands','q0, q1, [x20]')),
  ('wrong_pending_callback_slot',lambda q:q['variants'][0]['callback_table_contract'][1].__setitem__('target',q['variants'][0]['roles']['wrapper']['start'])),
  ('missing_wrapper_literal',lambda q:q['variants'][1]['wrapper_address_references'].pop()),
  ('wrong_destruct_binding',lambda q:q['trap25'].__setitem__('index',24)),
  ('wrong_destruct_MIG_ID',lambda q:q['MIG3232'].__setitem__('id',3233)),
  ('changed_callback_ABI',lambda q:q['variants'][0]['roles']['wrapper']['instructions'][11].__setitem__('operands','x5, x1')),
  ('changed_LLVM_mnemonic',lambda q:q['variants'][1]['roles']['base_init']['instructions'].__setitem__(0,{**q['variants'][1]['roles']['base_init']['instructions'][0],'mnemonic':'nop','operands':''}))]:
  q=copy.deepcopy(s);alter(q)
  try:verify(q)
  except(AssertionError,KeyError,ValueError,StopIteration):negative.append(name)
  else:raise AssertionError('Accepted altered evidence: '+name)
 sdk=sdk_checks();pr=proofs();bank=count_bank();counts={**s['verified_source_counts'],'instruction_assertions':len(records),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'activation_count_inputs_checked':bank['inputs_checked'],'rejected_evidence_alterations':len(negative)}
 obj={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':records,'SDK_checks':sdk,'proofs':pr,'activation_count_bank':bank,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'rejected_alterations':negative,'verified_counts':counts,'static_scope':'Selected factory/callback installation and reason0/1, pending launch producer/consumer, deactivation/rearm/remove and conditional spawnp API frontier, asynchronous destruct trap/MIG/core. Native callback/launch/guard effects, full policy/allocator/process epochs and complete right balance remain unknown.','all_checks_pass':True,**{f:False for f in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
