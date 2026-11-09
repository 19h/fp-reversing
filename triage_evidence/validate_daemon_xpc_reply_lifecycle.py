#!/usr/bin/env python3
"""Static reply/status/free-order contracts; no native transport or CPU execution."""
import copy,json,struct,subprocess
from recover_daemon_xpc_reply_lifecycle import ROOT,P,FLAGS,SDK,CS,sha,h,build,SPECS,FRAGMENTS,BRANCHES
PATTERNS='''
post_core|cmp|x13, #0
post_core|ldr|x8, [sp, #0xc0]
post_core|ccmp|x8, #0, #4, ne
create_reply|ldr|x21, [sp, #0x408]
create_reply|ldr|x22, [sp, #0x6e8]
create_reply|mov|x0, x13
create_reply|cmp|x0, #0
status_gate|cmp|w20, w8
set_data|add|x1, x9, x10
set_data|mov|x23, x0
set_data|mov|x2, x21
set_data|mov|x3, x22
set_data|mov|x0, x23
send_reply|eor|w8, w8, w20
send_reply|sxtw|x2, w8
send_reply|add|x1, x8, x9
send_reply|mov|x21, x0
send_reply|ldr|x0, [sp, #0xc0]
send_reply|mov|x1, x21
send_reply|mov|x0, x21
cleanup_output|ldr|x0, [sp, #0x408]
free_output|str|xzr, [sp, #0x408]
cleanup_input|ldr|x0, [sp, #0x820]
free_input|str|xzr, [sp, #0x820]
collection_prepare|add|x20, sp, #0x898
collection_slot|str|x8, [sp, #0x838]
collection_slot|cmp|x20, #0
collection_object|ldr|x22, [x20]
head|str|x22, [sp, #0x240]
head|ldr|x22, [x22]
head|mov|x19, x28
node|ldr|x26, [x22]
node|ldr|x0, [x22, #0x18]
free_node_buffer|str|xzr, [x22, #0x18]
free_node|mov|x0, x22
free_node|cmp|x26, #0
free_node|mov|x22, x26
free_collection|ldr|x0, [sp, #0x240]
free_collection|str|xzr, [x20]
free_collection|ldr|x8, [sp, #0x838]
free_collection|mov|x28, x19
epilogue|ldur|x8, [x29, #-0x60]
epilogue|cmp|x9, x8
epilogue|b.ne|#0x100c577f0
epilogue|add|sp, sp, #0xee0
epilogue|ldp|x29, x30, [sp, #0x50]
epilogue|ldp|x20, x19, [sp, #0x40]
epilogue|ldp|x22, x21, [sp, #0x30]
epilogue|ldp|x24, x23, [sp, #0x20]
epilogue|ldp|x26, x25, [sp, #0x10]
epilogue|ldp|x28, x27, [sp], #0x60
guard_stub|adrp|x17, #0x1010b1000
guard_stub|add|x17, x17, #0xd00
guard_stub|ldr|x16, [x17]
'''
EXPECTED={'create_reply':'_xpc_dictionary_create_reply','set_data':'_xpc_dictionary_set_data','set_status':'_xpc_dictionary_set_int64','send_reply':'_xpc_connection_send_message','release_reply':'_xpc_release','free_output':'_free','free_input':'_free','free_node_buffer':'_free','free_node':'_free','free_collection':'_free'}
def verify(s):
 assert s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 rows=[]
 for name,a in FRAGMENTS.items():
  f=s['fragments'][name];bb=bytes.fromhex(f['bytes']);ii=list(CS.disasm(bb,a));assert f['start']==hex(a)and h(bb)==f['sha256']and len(bb)==int(f['end'],16)-a==4*len(ii)
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]
  assert ii[-1].mnemonic in('braa','retab')
 for line in PATTERNS.strip().splitlines():
  name,mn,op=line.split('|');hits=[i for i in s['fragments'][name]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(name,mn,op);rows.extend({'role':name,**i}for i in hits)
 for name,pair,key,add,base,bias in SPECS:
  r=s['banks'][name];l,rr=bytes.fromhex(r['left_bytes']),bytes.fromhex(r['right_bytes']);outputs=[i^rr[l[i]^key]for i in range(256)]
  assert len(l)==len(rr)==256 and outputs==r['results_256']and set(outputs)=={int(r['constant'],16)}
  assert(r['left'],r['right'],int(r['key'],16),int(r['additive'],16))==(hex(pair[0]),hex(pair[1]),key,add)
  assert int(r['slot'],16)==base+8*(add+outputs[0])and int(r['bias'],16)==bias
 for r in s['calls']:
  b=s['banks'][r['role']];w=int(r['pointer_word'],16);ii=list(CS.disasm(bytes.fromhex(r['bytes']),int(r['site'],16)-4))
  assert r['target']==b['target']=='libSystem/'+EXPECTED[r['role']]and r['slot']==b['slot']
  assert w>>63 and(w>>32&65535)==r['modifier_u16']and not(w>>48&1)and not(w>>49&3)
  assert ii[0].op_str==f'x17, #{hex(r["modifier_u16"])}'and ii[1].mnemonic=='blraa'
 assert [(r['role'],r['source'],int(r['index'],16),int(r['target'],16))for r in s['branches']]==BRANCHES
 for r in s['branches']:
  w=int(r['pointer_word'],16);assert w>>63 and(w>>32&65535)==r['modifier_u16']and int(r['slot'],16)==0x101039ef0+8*int(r['index'],16)
 assert s['key_literals']=={'data':{'address':'0x100e86130','bytes':b'data\0'.hex()},'status':{'address':'0x100f18410','bytes':b'status\0'.hex()}}
 g=s['guard_failure'];ii=list(CS.disasm(bytes.fromhex(g['call_bytes']),int(g['call_site'],16)));assert len(ii)==1 and ii[0].mnemonic=='bl'and ii[0].op_str=='#0x100e2aad0'
 assert g['target']=='libSystem/___stack_chk_fail'and g['slot']=='0x1010b1d00'
 w=int.from_bytes(bytes.fromhex(g['pointer_word']),'little');assert w>>63 and(w>>32&65535)==0 and(w>>48&1)==1 and not(w>>49&3)
 imports={r['symbol']:r for r in s['imports']};assert '___stack_chk_guard'in imports and imports['___stack_chk_guard']['total_addend']==0
 assert s['inherited_entry_match']['bytes_checked']==1360 and s['fixup_reference']['catalog_memberships_compared']==61737
 assert all(s[k]is False for k in FLAGS);return rows

def sdk_checks():
 code='''#define OS_OBJECT_USE_OBJC 0
#include <xpc/xpc.h>
#include <xpc/connection.h>
#include <stdlib.h>
#include <stdint.h>
#define A(x) static_assert((x),#x)
A(sizeof(void*)==8);A(sizeof(size_t)==8);A(sizeof(mach_port_t)==4);A(sizeof(int64_t)==8);A(sizeof(xpc_connection_t)==8);
A(__is_same(decltype(&xpc_dictionary_create_reply),xpc_object_t(*)(xpc_object_t)));
A(__is_same(decltype(&xpc_dictionary_set_data),void(*)(xpc_object_t,const char*,const void*,size_t)));
A(__is_same(decltype(&xpc_dictionary_set_int64),void(*)(xpc_object_t,const char*,int64_t)));
A(__is_same(decltype(&xpc_connection_send_message),void(*)(xpc_connection_t,xpc_object_t)));
A(__is_same(decltype(&xpc_release),void(*)(xpc_object_t)));A(__is_same(decltype(&free),void(*)(void*)));
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return {'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang')}

def proofs():
 qs=[('signed_status_all32_and_success_path_join','''(declare-fun s () (_ BitVec 32))
(define-fun zero () Bool (= s #x8b3dc651))
(define-fun successful_phase () (_ BitVec 32) (bvshl (bvmul (bvxor #x00002dfe #x00002c5b) #x00000003) #x00000004))
(define-fun phase () (_ BitVec 32) (ite zero successful_phase (bvxor #x00002dfe #x0000630e)))
(define-fun mask () (_ BitVec 32) (bvadd (bvxor phase #x0000e0c0) #x8b3d1821))
(define-fun decoded () (_ BitVec 32) (bvxor s mask))
(assert (or (distinct phase #x00004ef0) (distinct ((_ sign_extend 32) decoded) ((_ sign_extend 32) (bvxor s #x8b3dc651)))
 (distinct zero (= decoded #x00000000))))'''),
 ('event_peer_guard_partition','''(declare-fun event () (_ BitVec 64)) (declare-fun peer () (_ BitVec 64))
(define-fun Z () Bool (ite (distinct event #x0000000000000000) (= peer #x0000000000000000) true))
(define-fun index () (_ BitVec 32) (bvxor #x0000a236 (bvmul (ite Z #x00000001 #x00000000) #x0000006d)))
(assert (or (distinct Z (or (= event #x0000000000000000) (= peer #x0000000000000000)))
 (distinct index (ite Z #x0000a25b #x0000a236))))'''),
 ('node_and_buffer_branch_indices','''(declare-fun empty () Bool) (declare-fun absent () Bool) (declare-fun next () Bool)
(define-fun head_mask () (_ BitVec 32) (bvand #x00000001 (bvnot (bvxor #x0000fb92 (ite empty #x00000001 #x00000000)))))
(define-fun head_index () (_ BitVec 32) (bvxor #x00006d36 (bvmul head_mask #x0000000b)))
(define-fun buffer_mask () (_ BitVec 32) (bvand #x00000001 (bvnot (bvxor #x00003142 (ite absent #x00000001 #x00000000)))))
(define-fun buffer_index () (_ BitVec 32) (bvxor #x0000c492 (bvmul buffer_mask #x00000057)))
(define-fun next_index () (_ BitVec 32) (bvxor #x00006d36 (bvmul (ite next #x00000001 #x00000000) #x0000000b)))
(assert (or (distinct head_index (ite empty #x00006d36 #x00006d3d))
 (distinct buffer_index (ite absent #x0000c492 #x0000c4c5)) (distinct next_index (ite next #x00006d3d #x00006d36))))'''),
 ('entry_exit_stack_equation','''(declare-fun entry () (_ BitVec 64))
(define-fun S () (_ BitVec 64) (bvsub (bvsub entry #x0000000000000060) #x0000000000000ee0))
(assert (distinct (bvadd S #x0000000000000ee0 #x0000000000000060) entry))''')]
 out=[]
 for name,body in qs:
  q='(set-option :timeout 10000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Instruction-matched scalar/frame identities; no native delivery, heap validity, alias/ownership proof, guard value, hardware PAC or recovered-code execution.'})
 return out

def models():
 replies=[]
 for event in[False,True]:
  for peer in[False,True]:
   for reply in[False,True]:
    for success in[False,True]:
     seq=[]
     if event and peer:
      seq.append('create_reply')
      if reply:seq+=(['set_data']if success else[])+['set_status','send_reply','release_reply']
     seq+=['cleanup_output','cleanup_input','cleanup_collection']
     assert ('send_reply'in seq)==(event and peer and reply)
     assert ('set_data'in seq)==(event and peer and reply and success)
     replies.append({'event_present':event,'peer_present':peer,'reply_present':reply,'status_marker':success,'operations':seq})
 chains=[]
 for count in range(9):
  for present in range(1<<count):
   events=[]
   for node in range(count):
    events.append(['save_next',node])
    if present>>node&1:events.append(['free_buffer',node])
    events.append(['free_node',node])
   events+= [['free_Q',None],['clear_owner_slot',None]]
   assert sum(e[0]=='free_node'for e in events)==count and sum(e[0]=='free_buffer'for e in events)==present.bit_count()
   chains.append([count,present,events])
 status=[]
 for x in[0,1,0x7fffffff,0x80000000,0xffffffff]:
  raw=x^0x8b3dc651;signed=x-(1<<32)if x>>31 else x;status.append({'raw_u32':hex(raw),'decoded_u32':hex(x),'status_i64':signed})
 assert len(chains)==511
 # Local constants through both reply and ownership-cleanup paths.
 assert(0xa236-0x21da)==0x805c and(0x805c^0x2e6c)==0xae30
 assert ((0x805c-0x57a2)|0x544)==0x2dfe
 assert(0x4ef0^0xe0c0)==0xae30 and(0xae30^0x2ad3)==0x84e3
 assert ((0x84e3+0x3b818a9c)&0xc47dfbe6)==0xb66
 assert ((0xb66-0x6d31)+(0xb66+0x74e8))==0x1e83
 assert (((0x58e1+0x3c6b1ec4)&0xc394fffa)-0xa6a)==0x6d36
 assert(0x6d36+0x534a)|0x412==0xc492
 assert(0xc492-0x9350)==0x3142 and(0xc492-0x575c)==0x6d36
 assert ((0x6d36-0x4a26)|0x1802)==0x3b12 and((0x6d36+0xc433675d)&0x3bcceffe)==0xc492
 return {'reply_cases':replies,'cleanup_chain_cases':len(chains),'cleanup_chain_models_sha256':h(json.dumps(chains,separators=(',',':')).encode()),'status_cases':status,'scope':'Analyst-written Boolean and finite disjoint-chain event models. These are call-order intents, not executed target requests, actual frees or proof of unique native heap ownership.'}

def alterations(s):
 def instruction(q,name,ea,op):next(i for i in q['fragments'][name]['instructions']if i['ea']==ea).update(operands=op)
 def bank(q):
  r=q['banks']['send_reply'];b=bytearray.fromhex(r['left_bytes']);b[0]^=1;r['left_bytes']=b.hex()
 changes=[('bank_byte',bank),('send_peer',lambda q:instruction(q,'send_reply','0x100bb4cfc','x0, [sp, #0x408]')),
 ('status_signedness',lambda q:instruction(q,'send_reply','0x100bb4c10','x2, w8, uxtw')),
 ('output_length_width',lambda q:instruction(q,'create_reply','0x100a85ce0','w22, [sp, #0x6e8]')),
 ('next_link_offset',lambda q:instruction(q,'node','0x100d25fcc','x26, [x22, #8]')),
 ('reply_release_target',lambda q:q['banks']['release_reply'].update(target='libSystem/_free')),
 ('status_key_literal',lambda q:q['key_literals']['status'].update(bytes=b'Status\0'.hex())),('native_delivery',lambda q:q.update(native_peer_identity_proved=True))]
 out=[]
 for name,change in changes:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence '+name)
 return out
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();pr=proofs();mm=models();neg=alterations(s)
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':rows,'SDK_checks':sdk,'proofs':pr,'models':mm,'alterations':neg,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
 'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'reply_model_cases':len(mm['reply_cases']),'cleanup_chain_model_cases':mm['cleanup_chain_cases'],'status_model_cases':len(mm['status_cases']),'rejected_evidence_alterations':len(neg)},'all_checks_pass':True,
 'static_scope':'Conditional post-A70 reply creation, data/status setters, saved-peer send and reply release; returned/input-buffer frees, finite-chain node/Q destruction, owner clearing and guarded frame epilogue. Native transport names/delivery, actual output schema/ownership, libxpc copy/retention implementation, authorization and complete daemon-kext exchange remain unknown.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
