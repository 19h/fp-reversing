#!/usr/bin/env python3
"""Prove the caller's fixed32-byte reduction and conditional parser/retry joins."""
import copy,json,re,shutil,subprocess,hashlib
from recover_daemon_mode_one_output_verification import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_result_publication import PublicationSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq,low
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
BASELINE=0x155e2952
C={0:0xa30a9645cc89fd48,3:0xf7229b2be77ef1d2,4:0x6710477b9e467850,5:0x3a0cf7eba1ac099a,6:0x261a633a5b5d4bfb,7:0xe2f9840a2f29fb32,8:0xf6b43dbb8042ac13,11:0x2b3f,19:0x4d17ddb26a9cc592,20:0x324a764c67af2e0e,21:0x90c6356e6b233489,22:0x5cf569ba337602b7,23:0x41b5,24:0xbbfcee0d92832507,25:0x6f39ca9194dccb76,26:0xa2,27:(-0x6cf6)&((1<<64)-1),28:0x1dd3a2cc9b1a2a60,30:0x37788aa17c73e700}
class ConsumerSSA(PublicationSSA):
 def compare(self,a,b,w,cmn=False):
  super().compare(a,b,w,cmn)
  if not cmn:self.flags['hs']=f'(bvuge {a} {b})'
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   p=split(i['operands']);m=i['mnemonic']
   if m=='strh':
    self.stores.append({'site':i['ea'],'address':self.address(p[1]),'value':self.get(p[0],16),'width_bits':16});self.sites.append(i['ea']);continue
   if m=='ldrb':
    a=re.fullmatch(r'\[(x\d+)(?:, #(0x[0-9a-f]+))?\]',p[1])
    if a and a[1]in self.aliases:
     off=self.aliases[a[1]]+(int(a[2],0)if a[2]else 0);self.alias_records.append({'site':i['ea'],'original_address':self.address(p[1]),'frame_offset':off,'mnemonic':m});i={**i,'operands':p[0]+', [sp, #'+hex(off)+']'}
   super().run({'instructions':[i]},pc+4)
  return self

def chain(old,name,loads=None):
 g=ConsumerSSA(name,old.r,loads=loads);g.defs=list(old.defs);g.decl=dict(old.decl);g.byte_cells=dict(old.byte_cells);g.loaded=old.loaded;g.aliases=dict(old.aliases);return g

def compact_stream(address,namespace='mask'):
 """Independent compact u64 equations; ROR counts and all arithmetic are explicit."""
 defs=[]
 def put(expr):
  n=namespace+'_'+str(len(defs));defs.append(f'(define-fun {n} () (_ BitVec 64) {expr})');return n
 def op(name,a,b):return put('('+name+' '+a+' '+b+')')
 def rot(a,n):return put(f'((_ rotate_right {n}) {a})')
 def const(j):return bv(C[j])
 a=rot(op('bvand',address,bv(-8)),8)
 s=op('bvsub',op('bvsub',bv(0x6cf4^C[27]),op('bvor',op('bvadd',a,bv(0x622c5d3364e5d59f)),const(25))),op('bvor',op('bvsub',const(28),a),const(21)))
 t=op('bvxor',op('bvadd',rot(op('bvxor',s,const(30)),8),op('bvxor',s,const(6))),const(20));s=op('bvxor',s,const(6))
 def step(t,s):
  s=op('bvxor',t,rot(s,61));t=op('bvadd',rot(t,8),s);return t,s
 t,s=step(t,s)
 t=op('bvxor',op('bvadd',op('bvsub',op('bvor',t,const(22)),op('bvor',t,const(0))),const(0)),const(24));t,s=step(t,s)
 t=op('bvxor',op('bvadd',op('bvsub',t,op('bvand',bv(0xee453657cefde3a4),op('bvshl',t,bv(1)))),const(3)),const(4));t,s=step(t,s)
 t=op('bvxor',op('bvadd',op('bvsub',op('bvand',const(5),op('bvshl',t,bv(1))),t),const(7)),const(8));t,s=step(t,s)
 t=op('bvxor',op('bvadd',op('bvsub',op('bvand',const(19),op('bvshl',t,bv(1))),t),bv(0xd9741126cab19d36)),bv(0x32fa49a750392206));t,s=step(t,s)
 t=op('bvxor',t,bv(0x7faaf81a732f68b4));t,s=step(t,s)
 out=op('bvxor',t,bv(0x9e48c154c17c4731))
 return '\n'.join(defs)+'\n',out

def certificates(s):
 pp=[];mm={};fs=s['fragments'];replays=[]
 def solve(name,g=None,terms=(),cc=(),result='unsat',extra='',body='',values=None):
  q='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL+extra
  if g is not None:
   gs=g if isinstance(g,list)else[g];decl={};defs=[]
   for x in gs:
    for n,w in x.decl.items():assert n not in decl or decl[n]==w;decl[n]=w
    defs+=x.defs
   q+=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in decl.items())+'\n'.join(dict.fromkeys(defs))+'\n'
  q+=body+''.join('(assert '+v+')\n'for v in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n'
  if values is not None:q+='(get-value ('+' '.join(values)+'))\n'
  r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr,(name,r.returncode,r.stdout[:1800],r.stderr)
  row={'name':name,'query':q,'result':result,'scope':SCOPE}
  if values is None:assert r.stdout.strip()==result,(name,r.stdout[:1800])
  else:
   from daemon_mode_one_handoff_tools import parse
   assert result=='sat'and r.stdout.startswith('sat\n');vs=parse(r.stdout[4:]);assert len(vs)==len(values);row['model_value_hex']=[v[-1]for v in vs];assert all(re.fullmatch('#x[0-9a-f]+',v)for v in row['model_value_hex'])
  pp.append(row);print(name,result,flush=True);return row
 def replay(name,names):
  c=json.loads(read(ROOT/(name+'_checks.json')));rows=[p for p in c['proofs']if p['name']in names];assert{p['name']for p in rows}==set(names)
  for p in rows:
   original=p['query'];q=original.replace('(set-option :timeout 15000)','(set-option :timeout 45000)');r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat',(name,p['name'],r.stdout[:500],r.stderr);pp.append({**p,'name':'replayed_'+name+'_'+p['name'],'query':q,'original_query_sha256':hashlib.sha256(original.encode()).hexdigest(),'historical_timeout_raised_to45000_ms':q!=original,'replayed_query':True})
  replays.append({'checks':name+'_checks.json','sha256':sha(ROOT/(name+'_checks.json')),'selected_propositions':names,'all_historical_queries_replayed':False});print('replayed',name,len(rows),flush=True)
 replay('daemon_mode_one_adapter',['actual_mode_one_object_local_and_entry_phase','caller_result_uses_saved_base_continuation_uses_adjusted_SP','same_saved_continuation_address_requires_zero_delta','relay_uses_loaded_continuation_without_redecoding_result','delta_zero_returns_to_outer_status_dispatch'])
 replay('daemon_mode_one_result_publication',['all32_original_LOCAL_output_byte_addresses','all_eight_original_BIG_ENDIAN_LOCAL_word_pair_identities','LOCAL_serializer_result_code_and_status_target','status_prefix_stores_raw_result_code_to_REQUEST0'])
 replay('daemon_outer_first_key',['first_span_stages_borrowed_pointer_extent_end_and_mode','first_key_miss_flag_not25_direct_option_ABI'])
 replay('daemon_reader_outer_lifecycle',['outer_arguments_and_local32_reservation','raw_result_saved_before_success_cleanup_split'])
 def run(g,name):
  f=fs[name];g.run(f,int(f['instructions'][-1]['ea'],16)if f['instructions'][-1]['mnemonic']=='braa'else int(f['end'],16));mm[name]=g;return g
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 def frame_cert(name,g):
  rows={r['site']:r for r in g.reads+g.stores};terms=[neq(rows[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_reads+g.frame_writes]+[neq(r['original_address'],frame(r['frame_offset']))for r in g.alias_records];solve(name+'_all_frame_and_original_alias_addresses',g,terms or['false'])
 PH='(concat PHHI #x00006cf4)';presets={0x9d8:('TABLE',64),0x9d0:(PH,64),0x2290:('LOCAL',64),0x58a0:('SPAN',64),0xf7c:('ENCLEN',32),0x1ae8:('OBJ',64)}
 g=ConsumerSSA('setup',{19:'OBJ',20:'LOCAL',21:bv(0x2486),24:bv(0x15db),9:bv(0xd1a433c1)},presets=presets,loads={'0x100901530':('ENTRYFN',64)});g.decl.update(PHHI=32,OBJ=64,LOCAL=64,SPAN=64,ENCLEN=32,ENTRYFN=64);run(g,'setup');frame_cert('setup',g)
 words={0x990:0xb9a,0x9a0:0x8b3dc671,0x988:0xaa40,0x998:0xe2f6,0x980:0x8b3dc651,0x978:0x7b31,0x970:0xc0b}
 solve('setup_all_seven_saved_control_words_and_seed_registers',g,[neq(g.loadframe(o,32),bv(v,32))for o,v in words.items()]+[neq(g.get('x'+str(k)),bv(C[k]))for k in[0,21,23,25,26,27,28,30]if k!=23]+[neq(rd(g,0x100901530)['address'],at(0x2486))])
 ps=chain(g,'preserve_seed');run(ps,'preserve_seed');solve('wrapper_saves_original_X21_and_X30_in_callee_preserved_pairs',ps,[neq(ps.get('x27'),bv(C[21])),neq(ps.get('x23'),bv(C[30]))])
 # Ordinary AAPCS callee preservation is a premise,not execution of the adapter.
 rr={j:'HR'+str(j)for j in list(range(19))+[30]};rr.update({j:ps.get('x'+str(j))for j in range(19,30)});rr.update({19:frame(0xb000),20:bv(0x6358),22:'TABLE',24:frame(0x10000)})
 rs=chain(ps,'restore_seed',{'0x1009bb564':('DELTA',64)});rs.r.update(rr);rs.decl.update({n:64 for n in rr.values()if re.fullmatch('HR[0-9]+',n)});rs.decl['DELTA']=64;run(rs,'restore_seed');frame_cert('restore_seed',rs)
 solve('normal_return_restores_all_comparison_inherited_seeds',rs,[neq(rs.get('x'+str(k)),bv(C[k]))for k in[0,21,23,25,26,27,28,30]]+[neq(rd(rs,0x1009bb564)['address'],frame(0xbe28))])
 cr=chain(rs,'caller_return',{'0x100912004':('CALLERFN',64)});cr.r[6]=z('RESULT');cr.decl.update(RESULT=32,CALLERFN=64);run(cr,'caller_return');frame_cert('caller_return',cr)
 solve('raw_result_marker_routes_to_verifier_and_other_results_to_staging',cr,[neq(rd(cr,0x100912004)['address'],'(ite (= RESULT #x8b3dc651) '+at(0xa1da)+' '+at(0xb9a)+')')])
 lg=chain(cr,'length_gate',{'0x10084fbfc':('LENFN',64)});lg.decl['LENFN']=64;run(lg,'length_gate');frame_cert('length_gate',lg)
 solve('encoded_span_length32_selects_comparison_seed',lg,[neq(rd(lg,0x10084fbfc)['address'],'(ite (= ENCLEN #x8b3dc671) '+at(0x865d)+' '+at(0x8653)+')')]);solve('encoded_length_equality_is_exact_decoded_length32',terms=[neq('(= (bvxor PLEN #x8b3dc651) #x8b3dc671)','(= PLEN #x00000020)')],extra='(declare-fun PLEN () (_ BitVec 32))\n')
 selected=['(= ENCLEN #x8b3dc671)'];seed=chain(lg,'first_seed',{'0x1006cb9d4':('SEEDFN',64)});seed.decl['SEEDFN']=64;run(seed,'first_seed');frame_cert('first_seed',seed)
 solve('equal_length_seed_supplies_shared_compare_entry_phase',seed,[neq(rd(seed,0x1006cb9d4)['address'],at(0x7dc8)),neq(seed.get('w8'),bv(0x7b9,32)),neq(seed.get('w12'),bv(0x6cf4,32))],cc=selected)
 ce=chain(seed,'compare_entry',{'0x10093ced0':('CONT0',64),'0x10093cf10':('STARTFN',64)});ce.decl.update(CONT0=64,STARTFN=64);run(ce,'compare_entry');frame_cert('compare_entry',ce)
 terms=[neq(ce.get('x'+str(k)),bv(v))for k,v in C.items()]+[neq(ce.get('x2'),frame(0x8000)),neq(ce.get('x9'),'LOCAL'),neq(ce.get('x10'),'SPAN'),neq(ce.get('w12'),bv(BASELINE,32)),neq(ce.loadframe(0x9bf0,64),bv(0)),neq(ce.loadframe(0x9b8,64),'CONT0'),neq(rd(ce,0x10093ced0)['address'],at(0x7b9)),neq(rd(ce,0x10093cf10)['address'],at(0x5619))]
 solve('actual_first_compare_entry_count32_roots_all_live_seeds_and_continuation',ce,terms,cc=selected)
 # One source iteration with unrestricted byte operands and counter.
 lp=ConsumerSSA('compare_loop',{**{j:bv(v)for j,v in C.items()},2:frame(0x8000),9:'LOCAL',10:'SPAN',12:z('ACC')},presets={0x9d8:('TABLE',64),0x9bf0:('INDEX',64)},loads={'0x100bade40':('SB',8),'0x100bade78':('LB',8),'0x100badf80':('LOOPFN',64)})
 lp.aliases['x2']=0x8000;lp.decl.update(LOCAL=64,SPAN=64,ACC=32,INDEX=64,SB=8,LB=8,LOOPFN=64);mask_word=mask_shifted=None
 for i in fs['compare_loop']['instructions'][:-1]:
  if i['ea']=='0x100badf20':mask_word=lp.get('x15')
  if i['ea']=='0x100badf28':mask_shifted=lp.get('x14')
  lp.run({'instructions':[i]},int(i['ea'],16)+4)
 mm['compare_loop']=lp;frame_cert('compare_loop',lp);assert len(lp.sites)==110 and len(lp.reads)==8 and len(lp.stores)==len(lp.frame_writes)==1
 addr='(bvadd SPAN INDEX)';shift='(bvshl (bvand '+addr+' #x0000000000000007) #x0000000000000003)';mask_byte='((_ extract 7 0) '+mask_shifted+')';diff='(bvxor (bvxor (bvxor LB #xd1) SB) '+mask_byte+')'
 next_acc='(bvor (bvand ACC (bvnot ((_ zero_extend 24) '+diff+'))) (bvand #x000000ad ((_ zero_extend 24) '+diff+')))'
 compact_body,compact_value=compact_stream(addr)
 solve('independent_compact_address_stream_equals_original_u64_mask',lp,[neq(mask_word,compact_value)],body=compact_body)
 solve('source_loop_reads_exact_span_and_LOCAL_bytes_and_selects_lane',lp,[neq(rd(lp,0x100bade40)['address'],addr),neq(rd(lp,0x100bade78)['address'],'(bvadd LOCAL INDEX)'),neq(mask_shifted,'(bvlshr '+mask_word+' '+shift+')')])
 solve('source_loop_exact_address_bound_byte_difference_and_accumulator',lp,[neq(lp.get('w12'),next_acc)])
 solve('loop_advances_counter_and_only_count_controls_repeat_exit',lp,[neq(lp.loadframe(0x9bf0,64),'(bvadd INDEX #x0000000000000001)'),neq(rd(lp,0x100badf80)['address'],'(ite (bvugt (bvadd INDEX #x0000000000000001) #x000000000000001f) '+at(0x2b4b)+' '+at(0x2b3f)+')'),neq(lp.get('w13'),bv(0x6cf4,32))])
 solve('all_loop_invariant_live_registers_preserved_or_restored',lp,[neq(lp.get('x'+str(k)),bv(v))for k,v in C.items()]+[neq(lp.get('x2'),frame(0x8000)),neq(lp.get('x9'),'LOCAL'),neq(lp.get('x10'),'SPAN')])
 # Finite chronology uses the universal source iteration theorem above.
 ledger=[{'iteration':j,'counter_before':j,'counter_after':j+1,'SPAN_offset':j,'LOCAL_offset':j,'original_SPAN_byte_read_PC':'0x100bade40','original_LOCAL_byte_read_PC':'0x100bade78','terminal_slot':'0x2b4b'if j==31 else'0x2b3f'}for j in range(32)]
 solve('bounded_counter32_has_exactly31_repeats_then_exit',terms=[neq('(bvugt (bvadd I32 #x0000000000000001) #x000000000000001f)','(= I32 #x000000000000001f)')],cc=['(bvult I32 #x0000000000000020)'],extra='(declare-fun I32 () (_ BitVec 64))\n')
 dd=''.join(f'(declare-fun D{j} () (_ BitVec 8))\n'for j in range(32));defs=[];acc=bv(BASELINE,32);fold=bv(0,8)
 for j in range(32):
  d='((_ zero_extend 24) D'+str(j)+')';n='A'+str(j);defs.append(f'(define-fun {n} () (_ BitVec 32) (bvor (bvand {acc} (bvnot {d})) (bvand #x000000ad {d})))');acc=n;fold='(bvor '+fold+' D'+str(j)+')'
 body='\n'.join(defs)+'\n';solve('full32_byte_reduction_is_baseline_XOR_OR_differences',terms=[neq(acc,'(bvxor #x155e2952 ((_ zero_extend 24) '+fold+'))')],extra=dd,body=body)
 solve('full32_byte_result_equal_iff_every_address_decoded_byte_equal',terms=[neq('(= '+acc+' #x155e2952)','(and '+' '.join('(= D'+str(j)+' #x00)'for j in range(32))+')')],extra=dd,body=body)
 finish=ConsumerSSA('compare_finish',{12:z('ACC'),13:bv(0x6cf4)},presets={0x9d8:('TABLE',64),0x9b8:('CMPRET',64)},loads={'0x1006d5480':('FINFN',64)});finish.decl.update(ACC=32,CMPRET=64,FINFN=64);run(finish,'compare_finish');frame_cert('compare_finish',finish)
 solve('comparison_exit_decodes_accumulator_to_boolean',finish,[neq(finish.get('w13'),'(ite (= ACC #x155e2952) #x00000001 #x00000000)'),neq(rd(finish,0x1006d5480)['address'],at(0x5667))])
 relay=chain(finish,'compare_relay');run(relay,'compare_relay');frame_cert('compare_relay',relay);solve('shared_compare_relay_uses_saved_code_pointer_and_boolean',relay,[neq(relay.get('x8'),'CMPRET'),neq(relay.get('w13'),finish.get('w13')),neq(relay.get('x17'),bv(0x7af9))])
 # The same control contracts are evaluated for each boolean,not sampled bytes.
 controls=[]
 for b in [0,1]:
  nm='first_result_'+str(b);q=ConsumerSSA(nm,{13:bv(b)},presets={**presets,0x998:(bv(words[0x998],32),32)},loads={'0x1006a9f90':(nm+'FN',64)});q.decl.update(PHHI=32,LOCAL=64,SPAN=64,ENCLEN=32,OBJ=64,**{nm+'FN':64});run(q,'first_result');mm[nm]=mm.pop('first_result');frame_cert(nm,q)
  solve(nm+'_stores_boolean_and_selects_option_or_fallback',q,[neq(q.loadframe(0x4e17,8),bv(b,8)),neq(q.get('w8'),bv(0x3c37,32)),neq(q.get('w9'),bv(1,32)),neq(rd(q,0x1006a9f90)['address'],at(0x96b9 if b else 0x744f))]);controls.append(q)
 length_bad=ConsumerSSA('length_reject',presets={0x9a0:(bv(words[0x9a0],32),32),0x9d8:('TABLE',64)},loads={'0x100901ee8':('BADLENFN',64)});length_bad.decl['BADLENFN']=64;run(length_bad,'length_reject');frame_cert('length_reject',length_bad);solve('unequal_span_length_sets_false_flag_without_reading_payload',length_bad,[neq(length_bad.loadframe(0x4e17,8),bv(0,8)),neq(length_bad.get('w22'),bv(0x6cf4,32)),neq(rd(length_bad,0x100901ee8)['address'],at(0x744f))])
 fb=ConsumerSSA('fallback_gate',{22:bv(0x6cf4)},presets=presets,loads={'0x10075b304':('ALT_LEN',32),'0x10075b330':('FALLFN',64)});fb.decl.update(PHHI=32,LOCAL=64,SPAN=64,ENCLEN=32,OBJ=64,ALT_LEN=32,FALLFN=64);run(fb,'fallback_gate');frame_cert('fallback_gate',fb);solve('fallback_tests_alternate_object_count_and_selects_zero_or_retry',fb,[neq(rd(fb,0x10075b304)['address'],'(bvadd OBJ #x000000000000005c)'),neq(fb.get('w24'),bv(0x15cc,32)),neq(fb.get('w6'),bv(0x74c29d77,32)),neq(rd(fb,0x10075b330)['address'],'(ite (= ALT_LEN #x00000000) '+at(0x4382)+' '+at(0x43c1)+')')])
 retry=chain(fb,'retry',{'0x100686a5c':('RETRYFN',64)});retry.decl['RETRYFN']=64;run(retry,'retry');frame_cert('retry',retry);solve('retry_zeros_LOCAL32_and_changes_object_source_and_count_cell',retry,[neq(retry.get('x11'),'(bvadd OBJ #x0000000000000038)'),neq(retry.get('x12'),'(bvadd OBJ #x000000000000005c)'),neq(retry.get('x20'),'LOCAL'),neq(retry.get('w9'),bv(0xd1a433c1,32)),neq(retry.get('w24'),bv(0x15cc,32)),neq(rd(retry,0x100686a5c)['address'],at(0x2486))]+[neq(r['address'],'(bvadd LOCAL '+bv(2*j)+')')for j,r in enumerate(retry.stores)]+[neq(r['value'],bv(0,16))for r in retry.stores]);assert len(retry.stores)==16 and not retry.frame_writes
 entry=chain(retry,'helper_entry',{'0x100729930':('RETRY_LEN',32),'0x100729934':('COLL',64),'0x10072993c':('RETRYCONT',64),'0x10072995c':('HELPFN',64)});entry.decl.update(RETRY_LEN=32,COLL=64,RETRYCONT=64,HELPFN=64);run(entry,'helper_entry');frame_cert('helper_entry',entry)
 solve('retry_reuses_private_wrapper_with_alternate_source_and_return_selector',entry,[neq(rd(entry,0x100729930)['address'],'(bvadd OBJ #x000000000000005c)'),neq(rd(entry,0x100729934)['address'],'OBJ'),neq(rd(entry,0x10072993c)['address'],at(0x15cc)),neq(entry.loadframe(0x2300,64),'RETRYCONT'),neq(entry.get('x11'),'(bvadd OBJ #x0000000000000038)'),neq(rd(entry,0x10072995c)['address'],'(ite (= COLL #x0000000000000000) '+at(0x9d0d)+' '+at(0x9d05)+')')])
 rr=ConsumerSSA('retry_return',{6:z('RESULT')},presets={**presets,0x980:(bv(words[0x980],32),32)},loads={'0x100708184':('RETFN',64)});rr.decl.update(PHHI=32,LOCAL=64,SPAN=64,ENCLEN=32,OBJ=64,RESULT=32,RETFN=64);run(rr,'retry_return');frame_cert('retry_return',rr);solve('retry_marker_result_selects_second_length_gate',rr,[neq(rd(rr,0x100708184)['address'],'(ite (= RESULT #x8b3dc651) '+at(0x5c9d)+' '+at(0xb9a)+')')])
 rl=ConsumerSSA('retry_length',presets={**presets,0x970:(bv(words[0x970],32),32),0x978:(bv(words[0x978],32),32),0x4e17:('FIRSTFLAG',8)},loads={'0x1009b19f0':('RLFN',64)});rl.decl.update(PHHI=32,LOCAL=64,SPAN=64,ENCLEN=32,OBJ=64,FIRSTFLAG=8,RLFN=64);run(rl,'retry_length');frame_cert('retry_length',rl);solve('retry_length_gate_retains_first_flag_and_reuses_expected32',rl,[neq(rl.get('w8'),bv(0x3c37,32)),neq(rl.get('w12'),bv(0x6cf4,32)),neq(rl.get('w9'),'((_ zero_extend 24) FIRSTFLAG)'),neq(rd(rl,0x1009b19f0)['address'],'(ite (= ENCLEN #x8b3dc671) '+at(0x87a3)+' '+at(0x7b31)+')')])
 rseed=chain(rl,'retry_seed',{'0x1008f0bb8':('RSFN',64)});rseed.decl['RSFN']=64;run(rseed,'retry_seed');frame_cert('retry_seed',rseed);solve('retry_seed_uses_same_comparator_with_distinct_saved_return_selector',rseed,[neq(rseed.get('w8'),bv(0x7b7,32)),neq(rd(rseed,0x1008f0bb8)['address'],at(0x7dc8))])
 # Re-establish comparator inputs after the second normal helper return.
 retry_ce=chain(ce,'second_compare_entry',{'0x10093ced0':('CONT1',64),'0x10093cf10':('RESTARTFN',64)});retry_ce.r.update({8:bv(0x7b7),12:bv(0x6cf4)});retry_ce.decl.update(CONT1=64,RESTARTFN=64);run(retry_ce,'compare_entry');mm['second_compare_entry']=mm.pop('compare_entry');mm['compare_entry']=ce
 solve('second_comparator_uses_same_live_seeds_roots_count_and_alternate_return',retry_ce,[neq(retry_ce.get('x'+str(k)),bv(v))for k,v in C.items()]+[neq(retry_ce.get('x9'),'LOCAL'),neq(retry_ce.get('x10'),'SPAN'),neq(retry_ce.get('w12'),bv(BASELINE,32)),neq(retry_ce.loadframe(0x9bf0,64),bv(0)),neq(rd(retry_ce,0x10093ced0)['address'],at(0x7b7)),neq(rd(retry_ce,0x10093cf10)['address'],at(0x5619))],cc=selected)
 rb=ConsumerSSA('retry_result',{13:z('BOOL2')},presets={**presets,0x4e17:('FIRSTFLAG',8)},loads={'0x10068abbc':('RBFN',64)});rb.decl.update(PHHI=32,LOCAL=64,SPAN=64,ENCLEN=32,OBJ=64,BOOL2=32,FIRSTFLAG=8,RBFN=64);run(rb,'retry_result');frame_cert('retry_result',rb);solve('second_comparison_true_rejoins_option_call_false_rechecks_first_flag',rb,[neq(rb.get('w10'),bv(0x935,32)),neq(rb.get('w8'),bv(0x3c37,32)),neq(rb.get('w9'),'((_ zero_extend 24) FIRSTFLAG)'),neq(rd(rb,0x10068abbc)['address'],'(ite (= BOOL2 #x00000001) '+at(0x7b40)+' '+at(0x7b31)+')')],cc=['(or (= BOOL2 #x00000000) (= BOOL2 #x00000001))'])
 og=ConsumerSSA('option_gate',{8:bv(0x3c37),9:z('FLAG')},presets={0x9d8:('TABLE',64)},loads={'0x1009aab98':('OGFN',64)});og.decl.update(FLAG=32,OGFN=64);run(og,'option_gate');frame_cert('option_gate',og);solve('shared_flag_gate_accepts_exact_flag1_and_restores_option_phase',og,[neq(og.get('w10'),bv(0x935,32)),neq(og.get('w22'),bv(0x6cf4,32)),neq(og.get('w6'),bv(0x74c29d77,32)),neq(rd(og,0x1009aab98)['address'],'(ite (= FLAG #x00000001) '+at(0xab4b)+' '+at(0x3c37)+')')])
 oc=chain(og,'option_call',{'0x1008b35c0':('OPTFN',64)});oc.decl.update(OBJ=64,OPTFN=64);oc.save(0x1ae8,'OBJ',64,'preserved outer object premise');run(oc,'option_call');frame_cert('option_call',oc);solve('verified_output_rejoins_known_option_key_and_borrowed_F_cell',oc,[neq(oc.get('w22'),bv(0x6cf4,32)),neq(oc.get('x8'),'OBJ'),neq(oc.get('w9'),bv(0xf24be74b,32)),neq(oc.get('x11'),frame(0x53ac)),neq(rd(oc,0x1008b35c0)['address'],at(0x3b01))])
 er=ConsumerSSA('error',{22:bv(0x6cf4),6:bv(0x74c29d77)},presets={0x9d8:('TABLE',64)},loads={'0x100941a90':('ERRORFN',64)});er.decl['ERRORFN']=64;run(er,'error');frame_cert('error',er);solve('verification_failure_stages_raw_code_and_selects_existing_cleanup',er,[neq(er.loadframe(0x5f60,32),bv(0x74c29d77,32)),neq(rd(er,0x100941a90)['address'],at(0xc04f))])
 st=ConsumerSSA('staging',{22:bv(0x6cf4),6:z('RESULT')},presets={0x9d8:('TABLE',64)},loads={'0x100975d8c':('STAGEFN',64)});st.decl.update(RESULT=32,STAGEFN=64);run(st,'staging');frame_cert('staging',st);solve('nonmarker_core_result_saved_before_common_marker_reset',st,[neq(st.loadframe(0x5f60,32),'RESULT'),neq(st.get('w6'),bv(0x8b3dc651,32)),neq(rd(st,0x100975d8c)['address'],'(ite (= RESULT #x8b3dc651) '+at(0xc022)+' '+at(0xc04f)+')')])
 wr=ConsumerSSA('wrapper_relay',{13:'WCONT',6:z('RESULT')});wr.decl.update(WCONT=64,RESULT=32);run(wr,'wrapper_relay');solve('wrapper_relay_preserves_result_and_loaded_continuation',wr,[neq(wr.get('x13'),'WCONT'),neq(wr.get('w6'),'RESULT'),neq(wr.get('x17'),bv(0x3275))])
 # Compose the retry's seed-preserving path,including both wrapper pair saves.
 def step(old,n,label,loads=None):
  q=chain(old,label,loads);f=fs[n];q.run(f,int(f['instructions'][-1]['ea'],16)if f['instructions'][-1]['mnemonic']=='braa'else int(f['end'],16));mm[label]=q;return q
 cy=chain(lp,'retry_cycle_first_result',{'0x1006a9f90':('CY0FN',64)});cy.r[13]=bv(0);cy.decl.update(PHHI=32,OBJ=64,ENCLEN=32,CY0FN=64)
 for off,pair in presets.items():cy.save(off,*pair,'preserved outer-frame contract')
 for off,value in words.items():cy.save(off,bv(value,32),32,'source-proved setup control word')
 cy.run(fs['first_result'],int(fs['first_result']['instructions'][-1]['ea'],16));mm['retry_cycle_first_result']=cy
 cy.decl.update(CY_ALT_LEN=32,CYFALLFN=64,CYRETRYFN=64,CYCOLL=64,CYRETCONT=64,CYHELPFN=64)
 cy=step(cy,'fallback_gate','retry_cycle_fallback',{'0x10075b304':('CY_ALT_LEN',32),'0x10075b330':('CYFALLFN',64)})
 cy=step(cy,'retry','retry_cycle_zero_and_arguments',{'0x100686a5c':('CYRETRYFN',64)})
 cy=step(cy,'helper_entry','retry_cycle_helper_entry',{'0x100729930':('CY_ALT_LEN',32),'0x100729934':('CYCOLL',64),'0x10072993c':('CYRETCONT',64),'0x10072995c':('CYHELPFN',64)})
 # The recaptured97-instruction wrapper prefix writes none of these five seeds.
 assert s['wrapper_prefix_seed_preservation']['instructions']==97
 cy=step(cy,'preserve_seed','retry_cycle_preserve_pairs')
 rr={j:'CYHR'+str(j)for j in list(range(19))+[30]};rr.update({j:cy.get('x'+str(j))for j in range(19,30)});rr.update({19:frame(0xb000),20:bv(0x6358),22:'TABLE',24:frame(0x10000)})
 cy.r.update(rr);cy.decl.update({n:64 for n in rr.values()if re.fullmatch('CYHR[0-9]+',n)});cy.decl.update(CYDELTA=64,CYRESULT=32,CYRETFN=64,CYLENFN=64,CYSEEDFN=64,CYCONT=64,CYSTARTFN=64)
 cy=step(cy,'restore_seed','retry_cycle_restore_pairs',{'0x1009bb564':('CYDELTA',64)});cy.r[6]=z('CYRESULT')
 cy=step(cy,'retry_return','retry_cycle_result_gate',{'0x100708184':('CYRETFN',64)})
 cy=step(cy,'retry_length','retry_cycle_length_gate',{'0x1009b19f0':('CYLENFN',64)})
 cy=step(cy,'retry_seed','retry_cycle_seed',{'0x1008f0bb8':('CYSEEDFN',64)})
 cy=step(cy,'compare_entry','retry_cycle_comparator_entry',{'0x10093ced0':('CYCONT',64),'0x10093cf10':('CYSTARTFN',64)})
 solve('actual_retry_cycle_preserves_all_comparator_seeds_and_selects_second_return',cy,[neq(cy.get('x'+str(k)),bv(v))for k,v in C.items()]+[neq(cy.get('x9'),'LOCAL'),neq(cy.get('x10'),'SPAN'),neq(cy.get('w12'),bv(BASELINE,32)),neq(cy.loadframe(0x9bf0,64),bv(0)),neq(rd(cy,0x10093ced0)['address'],at(0x7b7)),neq(rd(cy,0x10093cf10)['address'],at(0x5619))],cc=['(= ENCLEN #x8b3dc671)'])
 # A plain byte-equality interpretation is refuted in an abstract component.
 mask0=solve('address_stream_word_at_abstract_aligned_address0',lp,cc=['(= INDEX #x0000000000000000)','(= SPAN #x0000000000000000)'],result='sat',values=[mask_word])
 mask8=solve('address_stream_word_at_abstract_aligned_address8',lp,cc=['(= INDEX #x0000000000000000)','(= SPAN #x0000000000000008)'],result='sat',values=[mask_word])
 assert mask0['model_value_hex']!=mask8['model_value_hex']
 sample=solve('plain_span_LOCAL_byte_equality_is_not_the_source_predicate',lp,cc=['(= INDEX #x0000000000000000)','(= SPAN #x0000000000000000)','(= SB #x00)','(= LB #x00)','(= ACC #x155e2952)',neq(lp.get('w12'),bv(BASELINE,32))],result='sat',values=[mask_word,mask_byte,diff,lp.get('w12')])
 # The source census,not a recurrence assumption,establishes no data-dependent branch.
 expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};actual={pc for q in mm.values()for pc in q.sites};assert actual==expected,(expected-actual,actual-expected)
 effects={n:{'nonbranch_sites':len(q.sites),'loads':len(q.reads),'stores':len(q.stores),'read_bytes':sum(r['width_bits']//8 for r in q.reads),'store_effect_bytes':sum(r['width_bits']//8 for r in q.stores),'frame_stores':len(q.frame_writes)}for n,q in mm.items()}
 sem={'source_models':{n:g.record_full()for n,g in mm.items()},'predecessor_replays':replays,'source_nonbranch_sites_translated':len(actual),'saved_control_words':{hex(k):hex(v)for k,v in words.items()},'comparison_entry_registers':{str(k):hex(v)for k,v in C.items()},'comparison_iterations':32,'SPAN_bytes_read':32,'LOCAL_bytes_read':32,'comparison_byte_ledger':ledger,'comparison_counter_cell':'K+0x9bf0/u64','comparison_saved_continuation_cell':'K+0x9b8/u64;new epoch replaces earlier context role','mask_word_source_expression':mask_word,'mask_shifted_source_expression':mask_shifted,'mask_byte_source_expression':mask_byte,'difference_source_expression':diff,'exact_accumulator_step':next_acc,'accumulator_initial':hex(BASELINE),'accumulator_after32':'0x155e2952 XOR zero_extend32(OR of all32 byte differences)','comparison_predicate':'Every j in[0,32):LOCAL[j] == SPAN[j] XOR0xd1 XOR lane8(mask_word(align_down8(SPAN+j)),(SPAN+j)&7)','independent_compact_stream_SMT':compact_body,'independent_compact_stream_result':compact_value,'mask_is_address_dependent':True,'abstract_address_stream_values':[{'aligned_address':'0x0','word':mask0['model_value_hex'][0]},{'aligned_address':'0x8','word':mask8['model_value_hex'][0]}],'plain_comparison_refutation':sample['model_value_hex'],'no_data_dependent_early_exit_in_comparison':True,'LOCAL_bytes_written_by_comparator':0,'retry_LOCAL_zero_halfword_stores':16,'retry_LOCAL_bytes_zeroed':32,'first_source':'OBJ+0x18;count u32[OBJ+0x58]','retry_source':'OBJ+0x38;count u32[OBJ+0x5c]','retry_saved_return_selector':'0x15cc','first_saved_return_selector':'0x15db','option_join_key':'0xf24be74b','option_join_output_cell':'K+0x53ac','raw_verification_failure_code':'0x74c29d77','result_marker_private_interpretation':'0x8b3dc651 admits comparison,not unconditional outer success','effect_counts':effects,'normal_callee_return_and_zero_wrapper_delta_are_premises':True,'actual_retry_cycle_seed_preservation_proved':True,'wrapper_prefix_seed_preservation':s['wrapper_prefix_seed_preservation'],'complete_processing_budget_history_proved':False,'native_comparison_observed':False,'native_owner_extent_alias_policy_proved':False,'whole_algorithm_identified':False,'native_output_serialization_proved':False,'daemon_kext_pairing_proved':False,'Mach_port_emissions':0,'new_IDA_access':False,'source_value_cuts':0,'coherence_boundary':'Stable mapped nonwrapping roots and disjoint scratch/control/source owners are premises. Counter forwarding is coherent;byte loads are unrestricted component inputs. The32-step theorem applies the universal original iteration plus proved live-register invariants. Native normal return/zero delta and intervening frame/root preservation remain explicit. No native input or target transaction is constructed.','excluded_exploration':'The base PostSSA helper rejected EON;the already source-checked PublicationSSA lowering is reused. An early private solver probe redeclared FN and was rejected;only strict zero-exit/no-stderr/query-exact outputs enter evidence. No sampled mask constant or plain memcmp claim is accepted.'}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('source_byte',lambda t:t['fragments']['compare_loop'].__setitem__('bytes','00'+t['fragments']['compare_loop']['bytes'][2:])),('wrong_counter_bound',lambda t:next(i for i in t['fragments']['compare_loop']['instructions']if i['ea']=='0x100badf6c').__setitem__('operands','x14, #0x20')),('wrong_retry_source',lambda t:next(i for i in t['fragments']['retry']['instructions']if i['ea']=='0x100686a40').__setitem__('operands','x11, x8, #0x18')),('wrong_exit_target',lambda t:t['branch_edges'][0].__setitem__('target','0x0')),('wrong_shift_mask',lambda t:next(i for i in t['ISA_decode_checks']if i['kind']=='register_lsr').__setitem__('shift_mask',31)),('wrong_return_selector',lambda t:t['saved_continuations'][1].__setitem__('index','0x15db')),('wrong_lineage',lambda t:t['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda t:t.__setitem__('native_target_executed',True))];out=[]
 for name,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'comparison_iterations':32,'SPAN_byte_reads':32,'LOCAL_byte_reads':32,'retry_LOCAL_halfword_zero_stores':16,'retry_LOCAL_bytes_zeroed':32,'source_value_cuts':0,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'mode_one_caller_output_verification_and_retry_interfaces_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
