#!/usr/bin/env python3
"""Static option/default control and frame-memory composition certificates."""
import copy,json,re,subprocess
from recover_daemon_reader_option_default import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import sha,read
from validate_daemon_reader_outer_lifecycle import Engine
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
SOLVER='/opt/homebrew/bin/z3';PH='(concat ((_ extract 63 32) Z30) #x00006cf4)';DEFAULT=0x1d45dafb
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in [('OBJ',64),('COLL',64),('RESULT',32),('FIRST_RESULT',32),('M',32),('MODE',32),('FLAG',8),('RFLAG',8)])
def certificates(s):
 pp=[];tr={};fs=s['fragments'];frame=lambda off:f'(bvadd K {bv(off)})';at=lambda ix:f'(bvadd TABLE {bv(ix*8)})'
 def solve(n,body,result='unsat',note='',arrays=False):
  q='(set-option :timeout 15000)\n(set-logic '+('QF_AUFBV'if arrays else'QF_BV')+')\n'+DECL+EXTRA+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE+' '+note,'reused_lemma':False});print(n,result,flush=True)
 def part(n,label=None,r=None,loads=None,chain=None):
  label=label or n;f=fs[n];ii=f['instructions'][:-1];ll={};dd=[]
  for i in ii:
   if i['mnemonic']in('ldr','ldrb','ldrh','ldrsh','ldur'):
    w=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']in('ldrh','ldrsh')else 32 if i['operands'].startswith('w')else 64;v='TABLE'if i['operands'].endswith('[sp, #0x9d8]')else PH if i['operands'].endswith('[sp, #0x9d0]')else None
    if v is None:v=label+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {w}))')
    ll[i['ea']]=(v,w)
  ll.update(loads or{});rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K'
  if chain:rr.update({j:chain[-1].get('x'+str(j))for j in range(31)})
  rr.update(r or{});g=Engine(rr,ll,namespace=label+'_');g.run({'instructions':ii},int(f['instructions'][-1]['ea'],16));g.declarations='\n'.join(dd)+'\n';tr[label]=g.record();return(chain or[])+[g]
 def add(n,gs,tt,cc=(),note=''):solve(n,prefix(*gs)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(tt)+'))',note=note)
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def store(g,pc,a,v):q=next(q for q in g.stores if q['site']==hex(pc));return[neq(q['address'],a),neq(q['value'],v)]
 first=part('outer_missing',r={8:bv(0xb9a),6:z('FIRST_RESULT')});g=first[-1]
 add('antecedent_missing_marker_selects_context_flag_gate',first,[neq(g.get('w9'),'#x00007b40'),neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x100781048)['address'],f'(ite (= FIRST_RESULT #x74c29ded) {at(0x43ec)} {at(0xb9a)})')],note='Incoming W8=b9a is the bounded antecedent-phase premise; no upstream request/peer attribution is inferred.')
 fg=part('outer_flag',chain=first,loads={'0x10086197c':('OBJ',64),'0x100861980':('FLAG',8)});g=fg[-1]
 add('antecedent_flag_gate_produces_accessor_return_selector',fg,[neq(g.get('w10'),'#x00000935'),neq(rd(g,0x100861980)['address'],f'(bvadd OBJ {bv(0x61)})'),neq(rd(g,0x1008619a4)['address'],f'(ite (= FLAG #x25) {at(0xbb19)} {at(0x7b40)})')],['(= FIRST_RESULT #x74c29ded)'])
 f25=part('flag25',chain=fg,loads={'0x100864a70':('MODE',32)});g=f25[-1]
 add('flag25_mode_zero_also_reaches_same_accessor',f25,[neq(g.get('w10'),'#x00000935'),neq(rd(g,0x100864a70)['address'],f'(bvadd OBJ {bv(0x14)})'),neq(rd(g,0x100864a94)['address'],f'(ite (= MODE #x00000000) {at(0xa656)} {at(0x62f8)})'),neq(g.get('w6'),'#x74c29d72')],['(= FIRST_RESULT #x74c29ded)','(= FLAG #x25)'])
 call=part('caller',r={10:bv(0x935)},loads={'0x1008b35a8':('OBJ',64)});g=call[-1]
 add('option_accessor_key_cell_output_and_return',call,[neq(g.get('x8'),'OBJ'),neq(g.get('w9'),'#xf24be74b'),neq(g.get('w10'),'#x00000935'),neq(g.get('x11'),frame(0x53ac)),neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x1008b35c0)['address'],at(0x3b01))],note='The two captured predecessor arms both produce935. Another original incoming caller edge remains unjoined; no global caller exhaustiveness is claimed.')
 ent=part('entry',chain=call,loads={'0x10084799c':('COLL',64),'0x1008479a4':('CONT',64)});g=ent[-1]
 add('option_accessor_snapshots_first_child_and_borrowed_F_cell',ent,[neq(rd(g,0x10084799c)['address'],'OBJ'),neq(rd(g,0x1008479a4)['address'],at(0x935)),neq(rd(g,0x1008479f4)['address'],f'(ite (= COLL {bv(0)}) {at(0x3cc0)} {at(0x3d4f)})')]+store(g,0x1008479a8,frame(0x7af0),'CONT')+store(g,0x1008479ac,frame(0x4ca0),frame(0x53ac))+store(g,0x1008479b0,frame(0x59b0),bv(0)),note='Replayed accessor/lookup/reader contracts distinguish null collection,miss,typed u32 success and errors. Saving OUT does not itself initialize F.')
 pub=part('publish',r={8:bv(0x3cc0)},loads={'0x100506a18':('(bvxor VALUE #x8b3dc651)',32),'0x100506a1c':(frame(0x53ac),64)});g=pub[-1]
 add('typed_u32_success_writes_decoded_option_to_F',pub,store(g,0x100506a30,frame(0x53ac),'VALUE')+[neq(rd(g,0x100506a1c)['address'],frame(0x4ca0)),neq(rd(g,0x100506a38)['address'],at(0x3cc0)),neq(g.get('w6'),'#x8b3dc651')],note='The complete prior scalar grammar requires wire tag9777 and payload extent4 B under fit/owner premises. VALUE is the decoded BE32 payload, not its XOR representation.')
 rel=part('relay',r={6:z('RESULT')},loads={'0x1006f76a8':('CONT',64)});g=rel[-1]
 add('saved_accessor_return_preserves_raw_status',rel,[neq(rd(g,0x1006f76a8)['address'],frame(0x7af0)),neq(g.get('x8'),'CONT'),neq(g.get('x6'),z('RESULT')),neq(g.get('x17'),bv(0x90ec))])
 ret=part('returned',chain=rel);g=ret[-1];add('actual_return_derives_status_partition_phase',ret,[neq(g.get('w10'),'#x00004ee7'),neq(rd(g,0x100736154)['address'],at(0x84ca))],note='Original slot935 names this continuation. W10=4ee7 is derived from the frame phase, not supplied as an isolated assumption.')
 pt=part('partition',chain=ret);g=pt[-1];low='(bvslt RESULT #x74c29ded)';add('raw_status_signed_partition_and_carried_phases',pt,[neq(g.get('w8'),'#x0000445a'),neq(g.get('w9'),'#x0000445a'),neq(rd(g,0x1006c4634)['address'],f'(ite {low} {at(0x4f26)} {at(0x4ee7)})')])
 ok=part('success',chain=pt);g=ok[-1];add('only_exact_success_preserves_the_option_value',ok,[neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x10093c464)['address'],f'(ite (= RESULT #x8b3dc651) {at(0xb17d)} {at(0x445a)})')],[low]);assert not g.stores
 miss=part('missing',chain=pt);g=miss[-1];add('only_exact_missing_marker_selects_context_default',miss,[neq(g.get('w9'),'#x00002122'),neq(g.get('w22'),'#x00006cf4'),neq(rd(g,0x1006a9ed8)['address'],f'(ite (= RESULT #x74c29ded) {at(0x4979)} {at(0x445a)})')],['(not '+low+')']);assert not g.stores
 keep=part('preserve',chain=ok,loads={'0x1008cf6d4':('OBJ',64)});g=keep[-1];add('successful_option_reaches_child_lookup_without_default_store',keep,[neq(g.get('x8'),'OBJ'),neq(rd(g,0x1008cf6dc)['address'],at(0x2122))],['(= RESULT #x8b3dc651)']);assert not g.stores
 df=part('default',chain=miss,loads={'0x1006bf438':('OBJ',64),'0x1006bf43c':('M',32)});g=df[-1];fdefault='(bvsub M #x1d45dafb)'
 add('missing_option_writes_context_word_default',df,store(g,0x1006bf458,frame(0x53ac),fdefault)+[neq(rd(g,0x1006bf460)['address'],at(0x2122)),neq(g.get('x8'),'OBJ')],['(= RESULT #x74c29ded)'],note='This derives the prior nested-input report entry phase2122 from the actual accessor status route.')
 for label,path,cond in [('success',keep,'(= RESULT #x8b3dc651)'),('missing',df,'(= RESULT #x74c29ded)')]:
  hd=part('head',label+'_head',chain=path,loads={'0x1006ab920':('COLL',64)});g=hd[-1];add(label+'_joins_same_nested_record_lookup',hd,[neq(rd(g,0x1006ab920)['address'],'OBJ'),neq(rd(g,0x1006ab950)['address'],f'(ite (= COLL {bv(0)}) {at(0x8754)} {at(0x8755)})')],[cond])
 add('composed_raw_result_route_partition',[],[neq(f'(ite {low} (ite (= RESULT #x8b3dc651) #x01 #x00) (ite (= RESULT #x74c29ded) #x02 #x00))','(ite (= RESULT #x8b3dc651) #x01 (ite (= RESULT #x74c29ded) #x02 #x00))')],note='Classes1=preserve published option,2=write context default,0=common error; raw codes are not assigned public error names.')
 # Byte-memory composition of the proved source F store and later head setup.
 a=frame(0x53ac);mem='MEM0'
 for j in range(4):mem=f'(store {mem} (bvadd {a} {bv(j)}) ((_ extract {8*j+7} {8*j}) VALUE))'
 def le32(m):return '(concat '+' '.join(f'(select {m} (bvadd {a} {bv(j)}))'for j in range(3,-1,-1))+')'
 writes=[]
 for off,val in[(0x3be0,0),(0x4890,0x4ce73660a8625cd3)]:
  for j in range(8):mem=f'(store {mem} {frame(off+j)} {bv((val>>(8*j))&255,8)})';writes.append(off+j)
 solve('published_u32_F_survives_exact_child_setup_stores','(declare-fun MEM0 () (Array (_ BitVec 64) (_ BitVec 8)))\n(assert '+neq(le32(mem),'VALUE')+')',arrays=True,note='Exact4 B little-endian option store followed by the two source head-setup u64 stores at different K offsets. Native frame mapping and other intervening writes remain premises.')
 chosen=f'(ite (= RESULT #x8b3dc651) VALUE {fdefault})';active='(or (= RESULT #x8b3dc651) (= RESULT #x74c29ded))';pred=f'(and (distinct {chosen} #x00000000) (= (bvand RFLAG #x01) #x01))'
 stage=part('stage',r={8:f'(bvadd {bv(0x4ce73660a8625cd3)} {z("PL")} {bv(10)})',9:bv(10),4:z('(bvxor PL #x8b3dc651)'),12:bv(0x4b1d)},loads={'0x100609e4c':('BUF',64),'0x100609e64':('OBJ',64),'0x100609e6c':(chosen,32),'0x100609e78':('RFLAG',8)});g=stage[-1]
 add('nested_stage_reads_selected_option_or_default',stage,[neq(rd(g,0x100609e6c)['address'],frame(0x53ac)),neq(rd(g,0x100609e94)['address'],f'(ite {pred} {at(0x4b59)} {at(0x4b1d)})')],[active],note='Prior nested-input certificates supply actual span pointer/extent/phase and stable F reaching definitions. This component changes only the source of that named F value.')
 se=part('select',chain=stage);g=se[-1];nestedzero='(= '+chosen+' #x00000000)';add('selected_scalar_or_default_zero_admits_N19',se,[neq(rd(g,0x1008017ac)['address'],f'(ite {nestedzero} {at(0x344e)} {at(0x342d)})')],[active,'(not '+pred+')'])
 add('full_two_gate_option_default_admission_rule',[],[neq(f'(and {active} {nestedzero})','(or (and (= RESULT #x8b3dc651) (= VALUE #x00000000)) (and (= RESULT #x74c29ded) (= M #x1d45dafb)))')],note='The flag affects which alternate frontier receives a nonzero selected F, not whether the selected F is zero.')
 nc=part('nested_caller',chain=se);g=nc[-1];add('admitted_option_default_path_supplies_same_parent_plus_eight',nc,[neq(g.get('x8'),f'(bvadd OBJ {bv(8)})'),neq(rd(g,0x1004e1fc0)['address'],at(0x3884))],[active,nestedzero])
 er=part('error',chain=ok);g=er[-1];add('other_accessor_results_stage_error_and_skip_object_publication',er,store(g,0x100975d5c,frame(0x5f60),'RESULT')+[neq(rd(g,0x100975d8c)['address'],at(0xc04f))],['(distinct RESULT #x8b3dc651)','(distinct RESULT #x74c29ded)'],note='Both status-tree nonmatching arms reach this same source component with phase6cf4; complete cleanup and final external result remain unproved.')
 solve('reject_global_header_equality_as_N19_requirement',prefix(*se)+'(assert (= RESULT #x8b3dc651))\n(assert (= VALUE #x00000000))\n(assert (distinct M #x1d45dafb))\n(assert (= '+rd(se[-1],0x1008017ac)['address']+' '+at(0x344e)+'))','sat',note='Abstract source interpretation counterexample under a successful typed accessor: an explicit zero option selects N19 for a nondefault context word. No target packet or execution is constructed.')
 reused=[];old=json.loads(read(ROOT/'daemon_existing_scalar_reader_checks.json'));reused +=[(q,'daemon_existing_scalar_reader_checks.json')for q in old['proofs']]
 names={f'byte{i}_{p}'for i in range(4)for p in ['seed']+['round'+str(j)for j in range(1,8)]}|{'decoder_merge_and_four_addresses','lookup_entry_snapshot_partition','next_link_and_miss_state','candidate_decoder_interface','identifier_comparison_and_first_match','lookup_result_publication'};old=json.loads(read(ROOT/'daemon_constructor_lookup_checks.json'));reused +=[(q,'daemon_constructor_lookup_checks.json')for q in old['proofs']if q['name']in names]
 names={'existing_lookup_node_cell_and_return_interface','lookup_success_enters_record_reader_other_statuses_relay','accessor_saved_return_and_raw_status','found_node_buffer_extent_and_null_guard','record_header_extent_gate_and_cursor_snapshot','found_header_first_word_decoder_interface'};old=json.loads(read(ROOT/'daemon_scalar_field_population_checks.json'));reused +=[(q,'daemon_scalar_field_population_checks.json')for q in old['proofs']if q['name']in names]
 old=json.loads(read(ROOT/'daemon_reader_nested_input_checks.json'));reused +=[(q,'daemon_reader_nested_input_checks.json')for q in old['proofs']if not q['reused_lemma']and q['result']=='unsat'];assert len(reused)==107
 for q,fn in reused:
  assert q['result']=='unsat';v=subprocess.run([SOLVER,'-in'],input=q['query'],text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()=='unsat';pp.append({**q,'name':'replay_'+fn.removesuffix('_checks.json')+'_'+q['name'],'reused_lemma':True,'source_certificate':fn})
 return pp,tr,[]
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_option_key',lambda t:t['fragments']['caller']['instructions'][8].__setitem__('operands','w9, #0')),('wrong_status_split',lambda t:t['fragments']['partition']['instructions'][7].__setitem__('operands','w11, gt')),('missing_preserve_arm',lambda t:t['fragments'].pop('preserve')),('wrong_default_word',lambda t:t['fragments']['default']['instructions'][4].__setitem__('operands','w12, #0')),('invent_global_header_requirement',lambda t:t.__setitem__('header_equality_always_required',True)),('omit_OUT_locator',lambda t:t['OUT_address_locator']['sites'].clear())];out=[]
 for n,op in ops:t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,_=certificates(s);sites={pc for q in tr.values()for pc in q['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions'][:-1]};assert sites==expected,(expected-sites,sites-expected)
 aa=alterations(s);counts={**s['verified_source_counts'],'new_queries_unsat':sum(p['result']=='unsat'and not p['reused_lemma']for p in pp),'reused_queries_unsat':sum(p['result']=='unsat'and p['reused_lemma']for p in pp),'counterexamples_sat':sum(p['result']=='sat'for p in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_outer_lifecycle.py':sha(ROOT/'validate_daemon_reader_outer_lifecycle.py')},'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'source_recapture_match':True,'all_checks_pass':True,'option_default_rule_proved':True,'global_header_equality_required':False,'complete_parser_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
