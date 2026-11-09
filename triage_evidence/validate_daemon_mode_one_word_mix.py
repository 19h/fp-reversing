#!/usr/bin/env python3
"""Universal source identities and compact word-mix composition;no CPU execution."""
import copy,json,subprocess,shutil
from recover_daemon_mode_one_word_mix import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_bank_combine import fresh,add,xo,sub
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
from validate_daemon_mode_one_inverse_tables import frame,at
SOLVER=shutil.which('z3');assert SOLVER
REGS=[0,1,2,4,5,11,12,14,19]
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec 32))\n'for n in ['A'+str(j)for j in range(4)]+['S'+str(j)for j in range(4)]+['I'+str(j)for j in REGS]+['I_LEN'])
def mapped(x,a,b,c=0):
 out=add(xo(x,bv(a,32)),bv(b,32));return xo(out,bv(c,32))if c else out
def U0(x):return mapped(x,0x08156cbf,0x5bc9af7e)
def U1(x):return mapped(x,0x7ffffffe,0x22a5c65a,0x5d5a39a4)
def U2(x):return mapped(x,2,0xb80debcc,0x47f21436)
def U3(x):return mapped(x,0x1aa82d93,0xc9cad8d0,0x7ffffffd)
def U4(x):return mapped(x,0xe557d26e,0xbefcbfd6)
def certificates(s):
 pp=[];tr={};cuts=[];fs=s['fragments'];live=[]
 def solve(n,body,cc=(),result='unsat'):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+body+'\n'+''.join('(assert '+c+')\n'for c in cc)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-word-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.stdout,r.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,cc=()):solve(n,prefix(g)+'(assert (or '+' '.join(terms)+'))',cc)
 def run(n,r=None,loads=None,a=None,end=None,label=None):
  f=fs[n];label=label or n;a=a or int(f['start'],16);end=end or(int(f['instructions'][-1]['ea'],16)if f['instructions'][-1]['mnemonic']=='braa'else int(f['end'],16));g=fresh(label,r,loads);g.run({'instructions':[i for i in f['instructions']if a<=int(i['ea'],16)<end]},end);tr[label]=g.record();return g
 phase=run('phase_seed',{8:bv(1),20:bv(0x4cdb)},{'0x100bdbcac':('TABLE',64),'0x100bdbcb0':('FN',64)})
 cert('predecessor_supplies_fixed_next_selector',phase,[neq(phase.get('w16'),'#x000017d8'),neq(next(v for v in phase.reads if v['site']=='0x100bdbcb0')['address'],at(0x4cf9)),neq(phase.get('x17'),bv(0x74b2))])
 size=run('size_word',{15:bv(0x4923),2:bv(0x16f293e0)})
 cert('LEN32_initializer_supplies_size_mix_word',size,[neq(size.stores[0]['address'],frame(0x434)),neq(size.stores[0]['value'],'#xec2864b6')])
 term=lambda x:add(xo(x,'#xe89a2bc2'),'#x5097c00a')
 specs=[('U0_entry',0x100dab3d0,0x100dab42c,{1:z('VALUE'),16:bv(0x17d8)},10,U0('VALUE'),{}),('U0_later',0x100dab568,0x100dab5b8,{1:z('VALUE')},10,U0('VALUE'),{}),('U0_parallel',0x100dab5f0,0x100dab640,{1:z('VALUE')},14,U0('VALUE'),{}),('U1_bank',0x100dab42c,0x100dab4bc,{5:z('VALUE')},13,U1('VALUE'),{'0x100dab480':('SIZE',32)}),('U2_five_term',0x100dab4bc,0x100dab518,{10:z('VALUE'),13:z('A0'),15:z(term('VALUE'))},13,xo('A0',U2('VALUE')),{}),('U3_middle',0x100dab518,0x100dab568,{13:z('VALUE')},15,U3('VALUE'),{}),('U4_final',0x100dab674,0x100dab6c4,{1:z('VALUE')},17,U4('VALUE'),{})]
 for name,a,b,rr,out,want,ll in specs:
  g=run('mix',rr,ll,a,b,name);cert(name+'_universal_source_identity',g,[neq(g.get('w'+str(out)),want)])
 rr={j:z('I'+str(j))for j in REGS};rr.update({16:bv(0x17d8),21:frame(0x8348)})
 g=fresh('full_word_mix',rr,{'0x100dab480':('I_LEN',32),'0x100dab704':('TABLE',64),'0x100dab708':('FN',64)});before={};mix_input=None;mix_seed=None
 starts={0x100dab3d0:('U0_entry','w1'),0x100dab42c:('U1_bank','w5'),0x100dab518:('U3_middle','w13'),0x100dab568:('U0_later','w1'),0x100dab5f0:('U0_parallel','w1'),0x100dab674:('U4_final','w1')}
 ends={0x100dab428:('U0_entry','w10',U0),0x100dab4b8:('U1_bank','w13',U1),0x100dab564:('U3_middle','w15',U3),0x100dab5b4:('U0_later','w10',U0),0x100dab63c:('U0_parallel','w14',U0),0x100dab6c0:('U4_final','w17',U4)}
 for i in fs['mix']['instructions'][:-1]:
  pc=int(i['ea'],16)
  if pc in starts:
   name,reg=starts[pc];before[name]=g.get(reg)
  if pc==0x100dab4bc:
   mix_input=g.get('w10');mix_seed=g.get('w13');cert('five_term_live_seed_matches_source',g,[neq(g.get('w15'),term(mix_input))]);live.append({'site':i['ea'],'word15':g.get('w15'),'expected_word15':term(mix_input),'lemma':'five_term_live_seed_matches_source'})
  g.run({'instructions':[i]},pc+4)
  if pc in ends:
   name,reg,fn=ends[pc];v=before[name];replacement=fn(v);cuts.append({'site':i['ea'],'register':reg,'original_value':g.get(reg),'replacement':replacement,'universal_lemma':name+'_universal_source_identity','input_binding':{'VALUE':v}});g.put(reg,replacement)
  if pc==0x100dab514:
   assert mix_input and mix_seed;replacement=xo(mix_seed,U2(mix_input));cuts.append({'site':i['ea'],'register':'w13','original_value':g.get('w13'),'replacement':replacement,'universal_lemma':'U2_five_term_universal_source_identity','input_binding':{'VALUE':mix_input,'A0':mix_seed},'required_live_seed':'five_term_live_seed_matches_source'});g.put('w13',replacement)
 tr['mix_full_source']=g.record()
 v=U0('I1');x=add(v,'I_LEN');j=xo(U1('I5'),U2(x));k=xo(j,add(v,'#xb8ae898b'));a=xo('I0','I14');b=add('I4','#x315be61c');delta=sub('I2','I19');diff=sub('I11','I12')
 outputs={10:add(v,'#xb8ae898b',xo('I12','#xfdb8ea3a')),13:xo(a,b),0:add(xo('I19','#xfdb8ea3a'),b),14:add(delta,'#x6fbf8128'),2:add(delta,a,'#x0931a58b'),1:add(diff,'#x8d7f1dd4',U3(j)),15:add(U4(k),'#xee7664b2'),11:add(diff,'#x916e0de3'),19:xo('I19','#x0000005f'),20:xo('I12','#x44cba52e'),3:add(xo(k,'#x2d97c0f7'),'#x763cad4d'),4:'#xca7a0e68',5:'#xfdb8ea3a',8:'#x00003146',16:'#x000017d8'}
 for reg,want in outputs.items():cert('compact_word_output_W'+str(reg),g,[neq(g.get('w'+str(reg)),want)])
 rd=lambda pc:next(v for v in g.reads if v['site']==hex(pc))
 cert('word_input_saved_view_and_private_continuation',g,[neq(rd(0x100dab480)['address'],frame(0x434)),neq(rd(0x100dab704)['address'],frame(0x740)),neq(rd(0x100dab708)['address'],at(0x17d8)),neq(g.get('x12'),'FN'),neq(g.get('x17'),bv(0x9c42)),neq(g.get('x21'),frame(0x8348))])
 solve('arbitrary_word_inputs_domain_nonempty','',result='sat');assert not g.stores and len(g.reads)==3
 parent=json.loads(read(ROOT/'daemon_mode_one_bank_combine_checks.json'));assert parent['all_checks_pass']and parent['local_two_bank_combination_proved']and not parent['complete_operation_proved']
 from recover_daemon_mode_one_bank_combine import build as parent_source
 assert parent_source()==json.loads(read(ROOT/'daemon_mode_one_bank_combine_source.json'))
 wanted={'compact_output_W'+str(r)for r in REGS}|{'initializer_binds_combine_constants_and_bank_coordinates','parallel_carry_circuit_is_add_then_xor','masked_boolean_sum_is_two_encoded_operands_added'};replayed=[]
 for proof in parent['proofs']:
  if proof['name']not in wanted:continue
  r=subprocess.run([SOLVER,'-in'],input=proof['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**proof,'name':'replayed_parent_'+proof['name'],'replayed_query':True});replayed.append(proof['name']);print('replayed_parent_'+proof['name'],'unsat',flush=True)
 assert set(replayed)==wanted
 incoming=parent['semantics']['compact_outputs_SMT']['1'];decoded=add(sub('A2','A0'),xo('A3','A1'),'#x7015ef30');mixed=add(sub('A2','A0'),xo('A3','A1'),'#x5c3e53e6')
 solve('predecessor_composition_decodes_first_mixed_word','(assert (or '+neq(U0(incoming),decoded)+' '+neq(add(U0(incoming),'#xec2864b6'),mixed)+'))')
 sem={'arithmetic':'u32 wrapping and bitwise XOR','unary_maps_SMT':{'U'+str(i):fn('VALUE')for i,fn in enumerate([U0,U1,U2,U3,U4])},'unary_source_identities':len(specs),'live_source_cuts':cuts,'live_seed_certificates':live,'compact_outputs_SMT':{str(k):v for k,v in outputs.items()},'compact_intermediates_SMT':{'v':v,'x':x,'j':j,'k':k,'a':a,'b':b,'delta':delta,'diff':diff},'input_registers':{'I'+str(r):'W'+str(r)for r in REGS},'predecessor_input_bindings_SMT':{'I'+str(r):parent['semantics']['compact_outputs_SMT'][str(r)]for r in REGS},'size_word':{'input':'I_LEN','source_cell':'F+0x434','selected_LEN32_value':'0xec2864b6','producer':'0x100dda880'},'composition':'Current formulas are universal for nine independent incoming words and I_LEN;substituting the12 replayed predecessor certificates binds actual selected bank values. The fresh size producer binds I_LEN for LEN32.','projection_only_unary_fitting_accepted':False,'full_source_universal_certificates_required':True,'new_memory_stores':0,'new_data_reads':1,'saved_view':'X21=F+0x8348,unchanged and not dereferenced','W12_at_exit':'FN selected branch pointer,not the incoming arithmetic word','W17_at_exit':'0x9c42 authenticated-branch modifier','scratch_cells_preserved':816,'next_target':'0x100bf3160','native_claim':False}
 return pp,tr,sem
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_source_byte',lambda q:q['fragments']['mix'].__setitem__('bytes','00'+q['fragments']['mix']['bytes'][2:])),('wrong_size_producer',lambda q:q['fragments']['size_word']['instructions'][0].__setitem__('operands','w20, w15, #0x3b9')),('wrong_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];rows=[]
 for name,fn in ops:
  q=copy.deepcopy(s);fn(q);assert not verify(q);rows.append({'name':name,'rejected_by_fresh_original_source_comparison':True})
 return rows
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,sem=certificates(s);aa=alterations(s);actual={pc for v in tr.values()for pc in v['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 counts={**s['verified_source_counts'],'distinct_nonbranch_sites_translated':len(actual),'new_nonbranch_sites_translated':len(tr['mix_full_source']['source_sites']),'untranslated_source_sites':len(expected-actual),'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'replayed_queries_unsat':sum(p.get('replayed_query',False)for p in pp),'unary_maps':5,'universal_unary_source_certificates':sem['unary_source_identities'],'proved_live_cuts':len(sem['live_source_cuts']),'compact_register_outputs':len(sem['compact_outputs_SMT']),'scratch_cells_preserved':816,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_bank_combine.py','recover_daemon_mode_one_bank_combine.py','validate_daemon_mode_one_carry_table.py','validate_daemon_mode_one_inverse_tables.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','daemon_mode_one_bank_combine_checks.json','daemon_mode_one_bank_combine_source.json']
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'translations':tr,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_compact_word_mix_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
