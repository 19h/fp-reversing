#!/usr/bin/env python3
"""Static ABI/call-edge assertions and two finite-width algebra proofs.
No target execution/emulation or protocol transmission. O(I+E), O(I+E);
solver cost is separate from instruction/call-edge processing.
"""
import json,re,struct,subprocess
from recover_kernel_membership_removal import *
def analyze(s):
 fs=s['kernel_functions']+s['cache_functions'];ins={int(i['ea'],16):i for f in fs for i in f['instructions']};checks=[]
 def check(a,m,o,role):
  i=ins[a];assert(i['mnemonic'],i['operands'])==(m,o),(hex(a),i);checks.append({'address':hex(a),'mnemonic':m,'operands':o,'meaning':role})
 for a,m,o,role in[
  (0xfffffe000bcdbd48,'ldr','w0, [x0]','extract task u32 in slot0'),
  (0xfffffe000bcdbd8c,'ldr','w1, [x19, #8]','extract member u32 in slot1'),
  (0xfffffe000bcdbd90,'ldr','w2, [x19, #0x10]','extract set u32 in slot2'),
  (0xfffffe000bcdbda0,'b','#0xfffffe000bcdffd8','fast path tail-call to extraction core'),
  (0xfffffe000bcdbd74,'mov','w0, #3','task-conversion failure low fallback status'),
  (0xfffffe000bcdbd78,'movk','w0, #0x1000, lsl #16','task-conversion failure high fallback status'),
  (0xfffffe000bf08718,'ldr','w8, [x0, #8]','third packed u32 load'),
  (0xfffffe000bf0871c,'str','x8, [x0, #0x10]','third zero-extended slot store'),
  (0xfffffe000bf08720,'ldr','w8, [x0, #4]','second packed u32 load'),
  (0xfffffe000bf08724,'str','x8, [x0, #8]','second zero-extended slot store'),
  (0xfffffe000bf08728,'ldr','w8, [x0]','first packed u32 load'),
  (0xfffffe000bf0872c,'str','x8, [x0]','first zero-extended slot store'),
  (0xfffffe000bce0000,'mov','w0, #0x11','extraction sentinel-name continuation value17'),
  (0xfffffe000bce0028,'bl','#0xfffffe000bcc936c','pair lookup/type admission'),
  (0xfffffe000bcc93b8,'tbnz','w24, #0x11, #0xfffffe000bcc93d0','member receive-right bit17'),
  (0xfffffe000bcc93d8,'tbz','w24, #0x13, #0xfffffe000bcc94b8','set right bit19'),
  (0xfffffe000bcc9490,'mov','w0, #0xf','pair inactive/name continuation value15'),
  (0xfffffe000bcc94d0,'mov','w0, #0x11','pair type diagnostic continuation value17'),
  (0xfffffe000bce003c,'bl','#0xfffffe000bd6d9c0','unlink selected membership'),
  (0xfffffe000bce0050,'bl','#0xfffffe000bd0ab18','first object unlock'),
  (0xfffffe000bce0060,'bl','#0xfffffe000bd0ab18','second object unlock'),
  (0xfffffe000bce0074,'bl','#0xfffffe000bd7a4b8','free returned membership link'),
  (0xfffffe000bce0078,'mov','w0, #0','link-found success continuation'),
  (0xfffffe000bce0080,'mov','w0, #0x10','null-space result16'),
  (0xfffffe000bce0098,'mov','w0, #0xc','no matching link result12'),
  (0xfffffe000bcdff08,'adrp','x0, #0xfffffe0007e43000','insertion link allocator class page'),
  (0xfffffe000bcdff0c,'add','x0, x0, #0x358','insertion link allocator class offset'),
  (0xfffffe000bce0068,'adrp','x0, #0xfffffe0007e43000','extraction link free class page'),
  (0xfffffe000bce006c,'add','x0, x0, #0x358','extraction link free class offset'),
  (0xfffffe000bcde558,'sub','w8, w1, #1','deallocation name guard input'),
  (0xfffffe000bcde55c,'cmn','w8, #3','deallocation sentinel arithmetic'),
  (0xfffffe000bcde560,'b.hi','#0xfffffe000bcde5a4','deallocation sentinel no-op branch'),
  (0xfffffe000bcde70c,'sub','w8, w1, #1','mod_refs name guard input'),
  (0xfffffe000bcde710,'cmn','w8, #2','mod_refs sentinel arithmetic'),
  (0xfffffe000bcde714,'b.hs','#0xfffffe000bcde764','mod_refs sentinel branch'),
  (0xfffffe000bcde764,'mov','w8, #5','mod_refs sentinel right mask'),
  (0xfffffe000bcde768,'tst','w2, w8','mod_refs tests selected right kind'),
  (0xfffffe000bcde76c,'mov','w8, #0xf','mod_refs nonzero selected kind result15'),
  (0xfffffe000bcde770,'csel','w0, wzr, w8, eq','mod_refs right-kind-dependent sentinel result'),
  (0xfffffe000bcde598,'b','#0xfffffe000bcd3cfc','deallocation has a different right-dispatch frontier'),
  (0xfffffe000bcde5a4,'mov','w0, #0','deallocate sentinel-name no-op result0'),
  (0xfffffe000bcde760,'b','#0xfffffe000bcd4250','mod_refs has a different right-dispatch frontier'),
  (0xfffffe000bcfb638,'cmp','x19, x21','ordinary fast conversion compares resolved and thread-derived task candidates'),
  (0xfffffe000bcfb63c,'csel','x0, x19, xzr, eq','fast conversion returns null for unequal task candidates'),
  (0x184779334,'ldr','w2, [x22, #0x88]','CF set-name u32 argument'),
  (0x184779340,'ldr','w0, [x8]','CF task-name u32 argument'),
  (0x18477934c,'ldr','x0, [x22, #0x60]','CF overwrites extraction return before subsequent set removal'),
  (0x18054b380,'bl','#0x180547b04','library fast extract trap call'),
  (0x18054b388,'movk','w8, #0x1000, lsl #16','library fallback compare high status'),
  (0x18054b390,'b.ne','#0x18054b3c0','other fast results return directly'),
  (0x18054b3bc,'b','#0x18056dcb0','library extraction fallback client'),
  (0x180547b04,'mov','x16, #-0x17','extract signed selector -23'),
  (0x180547b08,'svc','#0x80','static extract SVC site'),
  (0x18056dcd0,'stp','w2, wzr, [sp, #0x24]','inline set at36 and zero outside40-byte send'),
  (0x18056dcd8,'str','w1, [sp, #0x20]','inline member at32'),
  (0x18056dd14,'movk','x2, #0x28, lsl #32','40-byte extraction send size'),
  (0x18056dd24,'bl','#0x18055a894','fallback transport emission call'),
  (0x18056dd64,'cmp','w8, #0xcff','expected reply3327'),
  (0x18056dd7c,'cmp','w8, #0x24','36-byte simple status reply'),
  (0xfffffe000bd87b88,'cmp','w8, #0x30','48-byte kernel-form request guard'),
  (0xfffffe000bd87bac,'ldp','w1, w2, [x21, #8]','MIG body contains two packed u32 names'),
  (0xfffffe000bd87bb0,'bl','#0xfffffe000bcdffd8','MIG and fast paths converge on same core')]:check(a,m,o,role)
 assert {r['index']:r['argument_count']for r in s['original_trap_bindings']}=={18:2,19:4,22:3,23:3}
 trap=next(r for r in s['original_trap_bindings']if r['index']==23);assert trap['handler_pointer']['target']==hex(EXTRACT_HANDLER)and trap['munger_pointer']['target']=='0xfffffe000bf08714'
 assert s['MIG_subsystem']['start']==3200 and s['MIG_subsystem']['end']==3243 and s['MIG_routine_3227']['index']==27 and s['MIG_routine_3227']['stub']['target']==hex(RPC_STUB)
 constants={int(r['address'],16):struct.unpack('<II',bytes.fromhex(r['bytes8_hex']))for r in s['cache_constants']};assert constants=={0x18057d380:(0x1513,40),0x18057d6c0:(0,3227),0x1eb065de0:(0,1)}
 assert s['kernel_NDR8_hex']=='0000000001000000'and s['task_self_static_binding']['target']=='0x1ed83e960'
 for a,m,o in[(0xfffffe000bcdfffc,'sub','w9, w1, #1'),(0xfffffe000bce0004,'cmn','w9, #3'),(0xfffffe000bce0008,'b.hi','#0xfffffe000bce0084'),(0xfffffe000bce0010,'sub','w9, w2, #1'),(0xfffffe000bce0014,'cmn','w9, #3'),(0xfffffe000bce0018,'b.hi','#0xfffffe000bce0084')]:check(a,m,o,'matched u32 sentinel-name guard expression')
 proofs=[]
 def prove(name,body,assumptions):
  text='(set-logic QF_BV)\n'+body+'\n(check-sat)\n';cmd=['/opt/homebrew/bin/z3','-in','-smt2'];r=subprocess.run(cmd,input=text,text=True,capture_output=True,timeout=15);assert r.returncode==0 and r.stdout.strip()=='unsat',(name,r.stdout,r.stderr);proofs.append({'name':name,'negated_equivalence_SMT2':text,'result':r.stdout.strip(),'command':cmd,'assumptions':assumptions})
 body='(declare-fun name () (_ BitVec 32))\n(define-fun y () (_ BitVec 32) (bvsub name #x00000001))\n(define-fun wide () (_ BitVec 33) (bvadd ((_ zero_extend 1) y) (_ bv3 33)))\n(define-fun wide2 () (_ BitVec 33) (bvadd ((_ zero_extend 1) y) (_ bv2 33)))\n(define-fun hi () Bool (and (= ((_ extract 32 32) wide) #b1) (not (= ((_ extract 31 0) wide) #x00000000))))\n(define-fun hs () Bool (= ((_ extract 32 32) wide2) #b1))\n(assert (not (and (= hi (or (= name #x00000000) (= name #xffffffff))) (= hs (or (= name #x00000000) (= name #xffffffff))))))'
 prove('matched_BHI_and_BHS_sentinel_guards',body,'u32 SUB/CMN carry and zero semantics; supplied nonnull IPC space; no namespace/right admission claim')
 def ext(mem,lo,n):return '((_ extract '+str(lo+n-1)+' '+str(lo)+') '+mem+')'
 def concat(parts):
  v=parts[0]
  for p in parts[1:]:v='(concat '+v+' '+p+')'
  return v
 def store64(mem,offset,value):
  lo=offset*8;parts=[]
  if lo+64<192:parts.append(ext(mem,lo+64,192-lo-64))
  parts.append(value)
  if lo:parts.append(ext(mem,0,lo))
  return concat(parts)
 lines=['(declare-fun initial () (_ BitVec 192))'];mem='initial'
 for j,(read,write)in enumerate([(8,16),(4,8),(0,0)]):
  value='((_ zero_extend 32) '+ext(mem,read*8,32)+')';after='m'+str(j);lines.append('(define-fun '+after+' () (_ BitVec 192) '+store64(mem,write,value)+')');mem=after
 ideal=concat(['((_ zero_extend 32) '+ext('initial',i*32,32)+')'for i in(2,1,0)]);lines.append('(assert (not (= '+mem+' '+ideal+')))')
 prove('reverse_three_u32_to_three_u64_expansion','\n'.join(lines),'mathematical 24-byte bitvector storage; matched fixed LDR W/STR X sequence; no target-memory validity or invocation proof')
 edges=[];indirect=[]
 for f in fs:
  start,end=int(f['start'],16),int(f['end'],16)
  for i in f['instructions']:
   if i['mnemonic']in('b','bl')and i['operands'].startswith('#'):
    target=int(i['operands'][1:],16)
    if i['mnemonic']=='bl'or not start<=target<end:edges.append({'caller':f['start'],'site':i['ea'],'kind':'call'if i['mnemonic']=='bl'else'tail_branch','target':hex(target)})
   elif i['mnemonic']in('blr','blraa','blraaz','braa','braaz'):indirect.append({'caller':f['start'],'site':i['ea'],'mnemonic':i['mnemonic'],'operands':i['operands']})
 core_calls={int(e['target'],16)for e in edges if e['caller']==hex(CORE)};assert core_calls=={PAIR,UNLINK,0xfffffe000bd0ab18,0xfffffe000bd7a4b8}
 assert not any(e['target']in('0xfffffe000bcd3cfc','0xfffffe000bcd4250')and e['caller']in(hex(CORE),hex(UNLINK))for e in edges)
 apis=[]
 for name,start,selector,argc in[('extract_member',0x18056dcb0,-23,3),('deallocate',0x18056c8a4,-18,2),('mod_refs',0x18056c9c0,-19,4)]:
  f=next(f for f in s['cache_functions']if int(f['start'],16)==start);x4=next(i for i in f['instructions']if i['mnemonic']=='mov'and i['operands'].startswith('x4, #'));mid=int(x4['operands'].split('#')[1],16)>>32;size=next(int(re.search(r'#(0x[0-9a-f]+)',i['operands']).group(1),16)for i in f['instructions']if i['mnemonic']=='movk'and i['operands'].startswith('x2, #'));apis.append({'operation':name,'signed_fast_selector':selector,'u32_argument_count':argc,'fallback_client':hex(start),'request_id':mid,'expected_reply_id':mid+100,'user_request_bytes':size,'expected_simple_user_reply_bytes':36,'receive_capacity_bytes':44})
 assert[(e['request_id'],e['user_request_bytes'])for e in apis]==[(3227,40),(3206,36),(3208,44)]
 return{'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3'),'version':subprocess.check_output(['/opt/homebrew/bin/z3','--version'],text=True).strip()},'instruction_assertions':checks,'direct_call_edges':edges,'unresolved_indirect_sites':indirect,'proofs':proofs,'operation_comparison':apis,'bounded_core_direct_callee_set':[hex(v)for v in sorted(core_calls)],'role_inferences_are_not_recovered_symbols':True,'native_observations_added':False}
if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());r=analyze(s);out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','recover_'+P+'.py']},**r,**{k:False for k in FLAGS}};(ROOT/(P+'_contracts.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'instruction_assertions':len(r['instruction_assertions']),'direct_edges':len(r['direct_call_edges']),'proofs':len(r['proofs'])}),flush=True)
