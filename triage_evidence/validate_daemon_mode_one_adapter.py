#!/usr/bin/env python3
"""Source-pinned selected SSA spans and fixed-frame assertions;no target execution."""
import copy,json,subprocess
from recover_daemon_mode_one_adapter import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_reader_outer_lifecycle import Engine as Parent
from validate_daemon_reader_container_origins import lut
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix,split
SOLVER='/opt/homebrew/bin/z3';PH='(concat ((_ extract 63 32) Z30) #x00006cf4)'
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in [('OBJ',64),('COLL',64),('LOCAL',64),('SRC',64),('R',64),('J',64),('BP',64),('VSEED',64),('DOUT',64),('DELTA',64),('LEN',32),('Q',32),('RESULT',32),('GUARD',64),('LIVE',64)])
class Engine(Parent):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='adrp':p=split(i['operands']);self.put(p[0],bv(int(p[1][1:],0)));self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def certificates(s):
 pp=[];tr={};fs=s['fragments'];frame=lambda o:f'(bvadd K {bv(o)})';at=lambda ix:f'(bvadd TABLE {bv(ix*8)})';R=frame(0x10cb8);F=0x4fabe741
 def solve(n,body,result='unsat',note='',extra=''):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+extra+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE+' '+note,'reused_lemma':False});print(n,result,flush=True)
 def part(n,label=None,r=None,loads=None,chain=None,a=None,end=None):
  label=label or n;f=fs[n];a=a or int(f['start'],16);end=end or int(f['instructions'][-1]['ea'],16);ii=[i for i in f['instructions']if a<=int(i['ea'],16)<end];ll={};dd=[]
  for i in ii:
   if i['mnemonic']in('ldr','ldrb','ldrh','ldrsh','ldur'):
    w=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']in('ldrh','ldrsh')else 32 if i['operands'].startswith('w')else 64;v='TABLE'if i['operands'].endswith('[sp, #0x9d8]')else PH if i['operands'].endswith('[sp, #0x9d0]')else None
    if v is None:v=label+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {w}))')
    ll[i['ea']]=(v,w)
  ll.update(loads or{});rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K'
  if chain:rr.update({j:chain[-1].get('x'+str(j))for j in range(31)});rr['sp']=chain[-1].get('sp')
  rr.update(r or{});g=Engine(rr,ll,namespace=label+'_');g.run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';tr[label]=g.record();return(chain or[])+[g]
 def add(n,gs,tt,cc=(),note=''):solve(n,prefix(*gs)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(tt)+'))',note=note)
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def st(g,pc):return next(q for q in g.stores if q['site']==hex(pc))
 def store(g,pc,a,v):q=st(g,pc);return[neq(q['address'],a),neq(q['value'],v)]
 for b in s['banks']:
  ld=lut('L',bytes.fromhex(b['left_bytes']))+lut('R',bytes.fromhex(b['right_bytes']))
  solve('bank_'+b['role'],f'(assert (distinct (bvxor B0 (LUT_R (bvxor (LUT_L B0) {bv(b["key_u8"],8)}))) {bv(b["results_256"][0],8)}))',extra=ld,note='All256 byte inputs over exact original banks;native mutable roots/controller contents remain premises.')
 mo=part('mode_one',r={9:bv(0x419a),19:'OBJ'},loads={'0x1005b04b4':('LOCAL',64)});setup=part('setup',chain=mo);g=setup[-1]
 add('actual_mode_one_object_local_and_entry_phase',setup,[neq(g.get('x8'),'OBJ'),neq(g.get('w9'),'#xd1a433c1'),neq(g.get('x11'),f'(bvadd OBJ {bv(0x18)})'),neq(g.get('x12'),f'(bvadd OBJ {bv(0x58)})'),neq(g.get('w10'),'#x00009d05'),neq(g.get('w24'),'#x000015db'),neq(g.get('x20'),'LOCAL'),neq(rd(g,0x100901530)['address'],at(0x2486))])
 ent=part('entry',chain=setup,loads={'0x100729930':('LEN',32),'0x100729934':('COLL',64),'0x10072993c':('CONT',64)});g=ent[-1]
 add('entry_reads_object_C0_length_and_saves_continuation',ent,[neq(rd(g,0x100729930)['address'],f'(bvadd OBJ {bv(0x58)})'),neq(rd(g,0x100729934)['address'],'OBJ'),neq(rd(g,0x10072993c)['address'],at(0x15db)),neq(rd(g,0x10072995c)['address'],f'(ite (= COLL {bv(0)}) {at(0x9d0d)} {at(0x9d05)})'),neq(g.get('w6'),'#x74c29d88')]+store(g,0x100729940,frame(0x2300),'CONT'))
 wr=part('wrapper','request',chain=ent,end=0x1009bb468);g=wr[-1];cookie=g.get('w10');fields={0x24:st(g,0x1009bb460)['value'],0x2c:st(g,0x1009bb448)['value']}
 tt=[]
 for pc,off,v in [(0x1009bb3b4,8,'COLL'),(0x1009bb3e8,16,f'(bvadd OBJ {bv(0x18)})'),(0x1009bb3b8,24,'LOCAL'),(0x1009bb464,32,f'(bvadd {cookie} #xd1a433c1)'),(0x1009bb460,36,f'(bvadd {cookie} #x00004923)'),(0x1009bb44c,40,f'(bvadd {cookie} #x3e060fa6)'),(0x1009bb448,44,f'(bvadd {cookie} (bvadd (bvmul LEN {bv(F,32)}) #x1d89a59c))')]:tt+=store(g,pc,f'(bvadd {R} {bv(off)})',v)
 add('private48_record_fields_and_address_cookie',wr,tt+[neq(g.get('w20'),'#x00006358')],note='Accessed extent48 B;result/u32 at+0 is written by the core,not initialized here. Offset+4 padding has no source definition.')
 cd=part('core','decode',r={0:R,'sp':'J'},a=0x100cf02fc,end=0x100cf038c,loads={'0x100cf0370':(fields[0x24],32),'0x100cf0378':(f'(bvadd OBJ {bv(0x18)})',64),'0x100cf0380':(fields[0x2c],32)});g=cd[-1];aligned=f'(= (bvand K {bv(3)}) {bv(0)})'
 add('aligned_request_decodes_mode4923_and_length_operand',wr+cd,[neq(g.get('w19'),'#x00004923'),neq(g.get('w20'),f'(bvadd (bvmul LEN {bv(F,32)}) #x1d89a59c)'),neq(g.get('x25'),f'(bvadd OBJ {bv(0x18)})'),neq('((_ extract 31 0) '+st(g,0x100cf0384)['value']+')',cookie)],[aligned],note='4 B aligned request premise is explicit;ordinary16 B stack alignment implies it. Unaligned full-width cookies are not identified.')
 norm=part('core','normalize',r={20:z(f'(bvadd (bvmul LEN {bv(F,32)}) #x1d89a59c)')},a=0x100cf0430,end=0x100cf0444);g=norm[-1]
 add('decoded_length_normalization_cancels_odd_multipliers',norm,[neq(g.get('w8'),'(bvadd LEN #x16f293c0)')],note='Independent source cut uses the preceding proved decoded W20;F*7aa4a8c1=1 modulo2^32.')
 pred=part('core','predicate',r={8:z('VALUE'),19:bv(0x4923),25:'SRC',21:'TABLE'},a=0x100cf0444,end=0x100cf04ec,loads={'0x100cf04dc':('FN',64)});g=pred[-1];eq='(= VALUE #x16f293e0)'
 add('mixed_predicate_has_exact_comparison_preimage',pred,[neq('(= '+g.get('w13')+' #x16f293e0)',eq)],note='Arbitrary32-bit normalized input;the monolithic wrapper-through-predicate query timed out and is excluded. Source lemma composition replaces that failed diagnostic.')
 add('core_null_or_size_predicate_selects_original_paths',pred,[neq(rd(g,0x100cf04dc)['address'],f'(ite (or (= SRC {bv(0)}) {eq}) {at(0x8ed9)} {at(0x4923)})'),neq(g.get('w9'),'#x74c29dee')])
 add('normalized_predicate_is_exact_LEN32',[],[neq('(= (bvadd LEN #x16f293c0) #x16f293e0)','(= LEN #x00000020)')])
 seed=part('adapter','lcg',r={19:'DOUT'},a=0x100d03458,end=0x100d0346c,loads={'0x100d03458':('VSEED',64)});g=seed[-1];LCG='(bvadd (bvmul VSEED #x0000000000002ea5) #x0000000000000001)'
 add('adapter_seed_and_LCG_value',seed,[neq(g.get('x21'),'VSEED'),neq(g.get('x16'),LCG)])
 reserve=part('adapter','reserve',r={16:LCG,21:'VSEED','sp':'A'},a=0x100d034c8,end=0x100d034ec);g=reserve[-1];amt=f'(bvshl (bvadd (bvlshr {LCG} {bv(60)}) {bv(1)}) {bv(4)})';bp=f'(bvsub A {amt})'
 add('adapter_reserve_and_budget_minus144',reserve,[neq(g.get('x20'),bp),neq(g.get('sp'),bp)]+store(g,0x100d034e8,bp,f'(bvsub VSEED {bv(0x90)})'))
 add('adapter_reservation_range_and_alignment',[],[f'(bvult {amt} {bv(16)})',f'(bvugt {amt} {bv(256)})',neq(f'(bvand {amt} {bv(15)})',bv(0))])
 bu=part('core','budget',r={1:'BP'},a=0x100cf02f0,end=0x100cf02fc,loads={'0x100cf02f0':(f'(bvsub VSEED {bv(0x90)})',64)});g=bu[-1]
 add('core_budget_add144_cancels_adapter_entry_bias',bu,store(g,0x100cf02f8,'BP','VSEED'))
 ar=part('adapter','delta_return',r={20:'BP',21:'VSEED',19:'DOUT'},a=0x100d03584,end=0x100d03594,loads={'0x100d03584':('Q',32)});g=ar[-1];delta='(bvshl ((_ zero_extend 32) (bvand (bvsub Q ((_ extract 31 0) VSEED)) #x0000ffff)) #x0000000000000004)'
 add('adapter_returns_low16_budget_difference_times16',ar,store(g,0x100d03590,'DOUT',delta)+[neq(rd(g,0x100d03584)['address'],'BP')])
 add('returned_delta_bounds_alignment_and_zero_criterion',[],[f'(bvugt {delta} {bv(0xffff0)})',neq(f'(bvand {delta} {bv(15)})',bv(0)),neq(f'(= {delta} {bv(0)})','(= ((_ extract 15 0) Q) ((_ extract 15 0) VSEED))')])
 post=part('wrapper','after_call',r={19:frame(0xb000),24:frame(0x10000),20:bv(0x6358),22:'TABLE'},a=0x1009bb544,end=0x1009bb584,loads={'0x1009bb564':('DELTA',64),'0x1009bb574':('RESULT',32),'0x1009bb578':('CONT',64)});g=post[-1]
 add('caller_result_uses_saved_base_continuation_uses_adjusted_SP',post,[neq(rd(g,0x1009bb564)['address'],frame(0xbe28)),neq(g.get('sp'),'(bvadd K DELTA)'),neq(rd(g,0x1009bb574)['address'],R),neq(g.get('w6'),'RESULT'),neq(rd(g,0x1009bb578)['address'],f'(bvadd K DELTA {bv(0x2300)})'),neq(rd(g,0x1009bb57c)['address'],at(0x6358)),neq(g.get('x13'),'CONT')],note='Normal imported call preserves saved bases X19/X24/X20/X22. The continuation cell differs after nonzero delta even though result reload stays anchored at the original request.')
 add('same_saved_continuation_address_requires_zero_delta',[],[neq(f'(= (bvadd K DELTA {bv(0x2300)}) {frame(0x2300)})',f'(= DELTA {bv(0)})')])
 relay=part('relay',r={13:'CONT',6:z('RESULT')});g=relay[-1];add('relay_uses_loaded_continuation_without_redecoding_result',relay,[neq(g.get('x17'),bv(0x3275)),neq(g.get('x13'),'CONT'),neq(g.get('w6'),'RESULT')])
 rej=part('reject','reject_prefix',r={9:bv(0x74c29dee),29:'U','sp':'J'},a=0x100d7cc50,end=0x100d7cc6c,loads={'0x100d7cc50':(R,64),'0x100d7cc58':('GUARD',64),'0x100d7cc60':('CELL',64),'0x100d7cc64':('LIVE',64)});g=rej[-1]
 add('immediate_rejection_publishes_raw_result_before_guard',rej,store(g,0x100d7cc54,R,'#x74c29dee')+[neq(g.flags['eq'],'(= LIVE GUARD)')])
 add('adapter_fixed_frame_restore_algebra',[],[neq('(bvadd (bvsub (bvadd (bvsub K #x0000000000000030) #x0000000000000020) #x0000000000000020) #x0000000000000030)','K')],note='Source assertions identify preindex-30,FP=SP+20 and finalpostindex+30;dynamic reservation is discarded by FP-based restoration. Saved-register contents/PAC/normal return remain premises.')
 add('core_fixed_frame_restore_algebra',[],[neq('(bvadd (bvadd (bvsub BP #x0000000000001210) #x00000000000011b0) #x0000000000000060)','BP')],note='Source assertions identify96 B saves plus4528 B locals=4624 B total;equal-guard epilogue restores the same extent.')
 add('core_fill296_does_not_overlap_budget_word',[],['(= (bvadd (bvsub BP #x0000000000001210) #x0000000000000768 O) (bvadd BP U))'],['(bvult O #x0000000000000128)','(bvult U #x0000000000000008)'],note='Exact296 B destination offsets versus eight budget bytes;does not assert arbitrary native buffer validity or absence of other callee effects.')
 add('ordinary_stack_alignment_supplies_request_cookie_premise',[],[neq('(bvand (bvadd K #x0000000000010cb8) #x0000000000000003)',bv(0))],['(= (bvand K #x000000000000000f) #x0000000000000000)'])
 add('immediate_return_budget_implies_zero_delta',[],[neq(delta,bv(0))],['(= Q ((_ extract 31 0) (bvadd (bvsub VSEED #x0000000000000090) #x0000000000000090)))'],note='On the immediate return path only;normal source-bounded fill,nonaliasing global/stack owners and equal guard are prerequisites. Full32 B processing budget effects remain unproved.')
 setupg=setup[-1];values={int(q['site'],16):q['value']for q in setupg.stores}
 cr=part('caller_return',r={6:z('RESULT')},loads={'0x100911ff0':(values[0x10090156c],32),'0x100911ff8':(values[0x100901558],32)});g=cr[-1]
 add('delta_zero_returns_to_outer_status_dispatch',setup+cr,[neq(rd(g,0x100912004)['address'],f'(ite (= RESULT #x8b3dc651) {at(0xa1da)} {at(0xb9a)})')],note='Requires original saved continuation and frame constants,so a zero-delta/stable-frame join. The immediate raw74c29dee result takes b9a/common error.')
 solve('unaligned_cookie_identity_is_not_universal',prefix(*wr,*cd)+'(assert (not '+aligned+'))\n(assert '+neq(cd[-1].get('w19'),'#x00004923')+')','sat',note='Abstract source interpretation counterexample,not a native state or target input. Ordinary aligned stacks are the stated domain.')
 return pp,tr,[]
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_record_extent',lambda t:t['fragments']['wrapper']['instructions'][0].__setitem__('operands','x24, sp, #0xf, lsl #12')),('wrong_budget_bias',lambda t:t['fragments']['adapter']['instructions'][101].__setitem__('operands','x16, x21, #0xe0')),('missing_SP_adjustment',lambda t:t['fragments']['wrapper']['instructions'][112].__setitem__('operands','sp, sp')),('wrong_bank',lambda t:t['banks'][0].__setitem__('key_u8',0)),('wrong_core_target',lambda t:t['calls'][1].__setitem__('target','0x0')),('invent_native',lambda t:t.__setitem__('native_target_executed',True))];out=[]
 for n,op in ops:t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,_=certificates(s);aa=alterations(s);sites={pc for q in tr.values()for pc in q['source_sites']}
 counts={**s['verified_source_counts'],'new_queries_unsat':sum(q['result']=='unsat'for q in pp),'reused_queries_unsat':0,'counterexamples_sat':sum(q['result']=='sat'for q in pp),'selected_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_outer_lifecycle.py':sha(ROOT/'validate_daemon_reader_outer_lifecycle.py')},'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'source_recapture_match':True,'all_checks_pass':True,'mode_one_record_adapter_and_frame_contracts_proved':True,'complete_parser_proved':False,'coverage':'Selected SSA spans;full wrapper/adapter/core-prefix bytes retained. Prologues,epilogues,remaining controller side effects and32 B processing are not claimed universally translated.',**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
