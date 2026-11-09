#!/usr/bin/env python3
"""Original SSA,three universal address cuts and exact frame-state ABI."""
import copy,json,subprocess,shutil,re,functools
from recover_daemon_mode_one_state_materialization import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_bank_combine import Engine as Parent,add,sub,xo
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
from validate_daemon_mode_one_inverse_tables import frame,at
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
INPUTS=[0,1,2,10,11,13,14,15,19,20]
EXTRA=''.join(f'(declare-fun J{j} () (_ BitVec 32))\n'for j in INPUTS)
DYNAMIC={0x100c9d7dc:529,0x100c9dba4:946,0x100c9dd48:673}
class Engine(Parent):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='orn':
    p=split(i['operands']);w=32 if p[0].startswith('w')else 64;self.put(p[0],f'(bvor {self.get(p[1],w)} (bvnot {self.operand(p[2],w,p[3]if len(p)>3 else None)}))');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def fresh(label,r=None,loads=None):
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=Engine(rr,loads,namespace=label+'_');g.declarations='';return g
def frame_layout(f):
 """Infer only constant frame aliases;all dynamic cases require certificates."""
 aliases={'sp':0};rows=[]
 for i in f['instructions']:
  p=split(i['operands']);m=i['mnemonic'];dst=p[0];pc=int(i['ea'],16)
  if m in['str','strb']:
   assert len(p)==2;w=1 if m=='strb'else 4 if dst.startswith('w')else 8
   if pc in DYNAMIC:off=0xd00+DYNAMIC[pc]
   else:
    q=split(p[1].strip('[]'));assert q[0]in aliases and(len(q)==1 or q[1].startswith('#')),(i,aliases);off=aliases[q[0]]+(int(q[1][1:],0)if len(q)>1 else 0)
   rows.append({'site':i['ea'],'frame_offset':off,'width_bytes':w,'address_kind':'source-certified computed index'if pc in DYNAMIC else'constant frame alias'})
  elif m=='add'and dst.startswith('x')and p[1]in aliases and p[2].startswith('#'):
   v=int(p[2][1:],0);v<<=int(p[3].split('#')[1],0)if len(p)>3 else 0;aliases[dst]=aliases[p[1]]+v
  elif m=='mov'and dst.startswith('x')and p[1]in aliases:aliases[dst]=aliases[p[1]]
  elif m=='ldr'and dst=='x16'and p[1]=='[sp, #0x738]':aliases[dst]=0xd00
  elif m not in['cmp','braa']:aliases.pop('x'+dst[1:]if dst.startswith('w')else dst,None)
 return rows
def certificates(s):
 pp=[];tr={};cuts=[];fs=s['fragments']
 def solve(n,body,cc=(),result='unsat'):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+body+'\n'+''.join('(assert '+c+')\n'for c in cc)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-state-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.stdout,r.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,cc=()):solve(n,prefix(g)+'(assert (or '+' '.join(terms)+'))',cc)
 def run(n,r=None,loads=None,a=None,end=None,label=None):
  f=fs[n];label=label or n;a=a or int(f['start'],16);end=end or(int(f['instructions'][-1]['ea'],16)if f['instructions'][-1]['mnemonic']=='braa'else int(f['end'],16));g=fresh(label,r,loads);g.run({'instructions':[i for i in f['instructions']if a<=int(i['ea'],16)<end]},end);tr[label]=g.record();return g
 phase=run('phase_seed',{16:bv(0x17d8)});cert('predecessor_register8_phase',phase,[neq(phase.get('w8'),'#x00003146')])
 init=run('initializer',{15:bv(0x4923),2:bv(0x16f293e0)},{'0x100dda8e0':('TABLE',64),'0x100dda8e4':('FN',64)})
 cert('LEN32_context_and_initial_byte_encoding',init,[neq(init.get('w24'),'#x3874e8e9'),neq(init.get('w27'),'#x00000034'),neq(init.get('w28'),'#x000000d4'),neq(init.get('x21'),frame(0x8348))])
 specs=[('index529',0x100c9d734,0x100c9d7c8,{0:z('VALUE')},'x0',529,0x100c9d7c4),('index946',0x100c9db10,0x100c9db88,{},'x13',946,0x100c9db84),('index673',0x100c9dc34,0x100c9dcd0,{5:z('VALUE')},'w14',673,0x100c9dccc)]
 for name,a,b,rr,out,value,_ in specs:
  g=run('bytes',rr,a=a,end=b,label=name);cert(name+'_universal_source_address',g,[neq(g.get(out),bv(value,32 if out.startswith('w')else 64))])
 rr={j:z('J'+str(j))for j in INPUTS};rr.update({8:bv(0x3146),24:z('SIZE'),27:bv(0x34),28:bv(0xd4),21:frame(0x8348)})
 spills=run('spills',rr,{'0x100bf336c':('TABLE',64),'0x100bf3370':('FN',64)})
 slayout=frame_layout(fs['spills']);assert len(slayout)==20
 rd=lambda g,pc:next(v for v in g.reads if v['site']==hex(pc))
 cert('spilled_word_addresses_and_control_seed',spills,[neq(row['address'],frame(item['frame_offset']))for row,item in zip(spills.stores,slayout)]+[neq(rd(spills,0x100bf3370)['address'],at(0x3146)),neq(spills.get('w22'),'#x0000bce7'),neq(spills.get('w2'),'#x3874e8c9'),neq(spills.get('w4'),'#x528cdb78'),neq(spills.get('w24'),'SIZE'),neq(spills.get('w27'),'#x00000034'),neq(spills.get('w28'),'#x000000d4')])
 compact_defs=[]
 def temp(n,e):
  compact_defs.append(f'(define-fun SM_{n} () (_ BitVec 32) {e})');return'SM_'+n
 v=temp('v',add('J10','J1','#x59156063'));q=temp('q',xo(v,'J11'));t=temp('t',add('J0','#xf09eaeb1'));u=temp('u',add(t,'J2','#x0000bce7','#x814a0789'));zz=temp('z',xo(u,'J14'));ww=temp('w',add(u,zz));ss=temp('s',add(ww,t));rrr=temp('r',xo(ss,zz));v2=temp('v2',add(q,v));a1=temp('a1',add('J10',v2));hh=temp('H',sub('J15','J10'));b1=temp('b1',add(a1,'#xf09eaeb1'));q1=temp('q1',xo(b1,q));m1=temp('m1',xo(q1,'#xead63300'));dd=temp('D',sub(sub(v2,q1),m1));delta=temp('delta',sub(hh,dd));xx=temp('X',sub('J13',t))
 fields={0x464:'#x00000000',0x510:sub('#x73576316','J0'),0x514:add('J10','#xe883a007'),0x50c:add('J2','#x302c2b9d'),0x550:sub('#x53d90af6','J1'),0x548:sub('#xeda438e4','J11'),0x558:sub('#x55ab6027','J13'),0x540:sub('#x6f33df6f',ww),0x560:add(ss,'#x0931b687'),0x534:sub('#x8a2b031a',hh),0x51c:add(q1,'#xc35d6b23'),0x508:add(v2,'#xe2827773'),0x538:sub('#x0bd0911f',rrr),0x52c:sub('#x7dba1bd4',a1),0x444:ss,0x520:add('J14','#x4ecaba8e'),0x530:add(xx,'#xaeec38ab'),0x518:add('J15','#xb84929d6'),0x504:'#x0dc87a81',0x460:'#x00000034'}
 compact=copy.copy(spills);compact.declarations='\n'.join(compact_defs)+'\n'
 for row,item in zip(spills.stores,slayout):cert('compact_spilled_word_'+hex(item['frame_offset']),compact,[neq(row['value'],fields[item['frame_offset']])])
 g=fresh('byte_state',spills.r,{'0x100c9d7d8':(frame(0xd00),64),'0x100c9e718':('TABLE',64),'0x100c9e71c':('CONT',64),'0x100c9e750':('BUF',64),'0x100c9e754':(bv(0x100f715a0),64)});g.defs=list(spills.defs)
 ends={b:(name,out,v,a)for name,a,_,_,out,v,b in specs};starts={a:(name,rr)for name,a,_,rr,_,_,_ in specs};bindings={}
 for i in fs['bytes']['instructions'][:-1]:
  pc=int(i['ea'],16)
  if pc in starts:
   name,rr=starts[pc];bindings[name]={str(k):g.get('w'+str(k))for k in rr}
  g.run({'instructions':[i]},pc+4)
  if pc in ends:
   name,out,v,a=ends[pc];bits=32 if out.startswith('w')else 64;replacement=bv(v,bits);cuts.append({'site':i['ea'],'register':out,'original_value':g.get(out),'replacement':replacement,'universal_lemma':name+'_universal_source_address','source_start':hex(a),'input_binding':bindings[name]});g.put(out,replacement)
 tr['bytes_full_source']=g.record();blayout=frame_layout(fs['bytes']);assert len(blayout)==140
 cert('all_byte_and_word_materialization_addresses',g,[neq(row['address'],frame(item['frame_offset']))for row,item in zip(g.stores,blayout)])
 c730=((0xbce7+0x150a0c4c)&0xffffffff)&0xeaf57fef
 store=lambda pc:next(v for v in g.stores if v['site']==hex(pc))
 cert('phase_cell_epochs_and_conditional_continuation',g,[neq(store(0x100c9d2fc)['value'],bv(c730,32)),neq(store(0x100c9d33c)['value'],'#x00004923'),neq(rd(g,0x100c9d7d8)['address'],frame(0x738)),neq(rd(g,0x100c9e71c)['address'],f'(ite (= SIZE #x3874e8c9) {at(0xbce7)} {at(0xbcff)})'),neq(rd(g,0x100c9e750)['address'],frame(0x458)),neq(rd(g,0x100c9e754)['address'],frame(0x450)),neq(g.get('x26'),frame(0xd00)),neq(g.get('x25'),'BUF'),neq(g.get('x23'),bv(0x100f715a0)),neq(g.get('x10'),'CONT'),neq(g.get('x17'),bv(0x41f7)),neq(g.get('w24'),'SIZE')])
 constants={8:0xeb,9:0x77453be2,27:0x6ada6bd2,28:527,30:0xba9559f3,16:757,4:0x440dd2cf,20:963,0:0xd693a272}
 cert('next_stage_restores_pointer_roots_and_stride_constants',g,[neq(g.get('w'+str(k)),bv(v,32))for k,v in constants.items()])
 # Every source store contributes an exact value in the retained SSA DAG.
 ledger=[]
 for name,model,layout in [('spills',spills,slayout),('bytes',g,blayout)]:
  assert len(model.stores)==len(layout)
  for row,item in zip(model.stores,layout):
   assert row['site']==item['site']and row['width_bits']//8==item['width_bytes'];ledger.append({'fragment':name,**item,'value_SMT':row['value']})
 byte_rows=[r for r in ledger if r['width_bytes']==1];word_rows=[r for r in ledger if r['width_bytes']==4]
 assert len(byte_rows)==128 and len(word_rows)==32
 offsets={r['frame_offset']-0xd00 for r in byte_rows};logical=set(range(40,104))|set(range(112,176));expected={757*t%963 for t in logical};assert offsets==expected and len(offsets)==128
 prior=json.loads(read(ROOT/'daemon_mode_one_digit_maps_checks.json'))['semantics']['region_offsets'];overlap={n:sorted(set(v)&offsets)for n,v in prior.items()};assert len(overlap['A'])==16 and all(not v for n,v in overlap.items()if n!='A')
 live_tables={x for n,v in prior.items()if n!='A'for x in v};assert len(live_tables)==800 and len(live_tables|offsets)==928
 written=[r['frame_offset']+j for r in ledger for j in range(r['width_bytes'])];assert len(written)==len(set(written))==256
 protected=set(range(0x438,0x440))|set(range(0x450,0x460))|set(range(0x568,0x588))|set(range(0x738,0x748))|set(range(0x1210,0x1218));assert not set(written)&protected
 assert not {0xd00+x for x in live_tables}&set(written)
 parent=json.loads(read(ROOT/'daemon_mode_one_word_mix_checks.json'));assert parent['all_checks_pass']and parent['local_compact_word_mix_proved']
 from recover_daemon_mode_one_word_mix import build as parent_source
 assert parent_source()==json.loads(read(ROOT/'daemon_mode_one_word_mix_source.json'))
 definitions={}
 for line in g.defs:
  m=re.fullmatch(r'\(define-fun (\S+) \(\) \(_ BitVec \d+\) (.*)\)',line);assert m;definitions[m[1]]=m[2]
 symbols={'J'+str(j)for j in INPUTS}|{'SIZE','K','BUF','TABLE','FN','CONT'}|{'Z'+str(j)for j in range(31)}
 @functools.lru_cache(None)
 def dependencies(expr):
  out=set()
  for token in re.findall(r'[A-Za-z_][A-Za-z0-9_]*',expr):
   if token in definitions:out.update(dependencies(definitions[token]))
   elif token in symbols:out.add(token)
  return frozenset(out)
 allowed={0:{'J1','J10','J11','J15','J20'},1:{'J0','J2','J13','J14','J19'}};dependency_rows=[]
 for row in byte_rows:
  index=(row['frame_offset']-0xd00)*388%963;plane=0 if index in range(40,104)else 1;dep=dependencies(row['value_SMT']);assert dep<=allowed[plane]
  dependency_rows.append({'site':row['site'],'logical_index':index,'plane':plane,'source_word_dependencies':sorted(dep)})
 bank_dependencies={}
 for j in INPUTS:
  e=parent['semantics']['compact_outputs_SMT'][str(j)];expanded=re.sub(r'\bI[0-9]+\b',lambda m:parent['semantics']['predecessor_input_bindings_SMT'][m[0]],e);atoms=set(re.findall(r'\b(?:A[0-3]|S[0-3]|I_LEN)\b',expanded));plane=0 if'J'+str(j)in allowed[0]else 1
  assert atoms<=({'A'+str(k)for k in range(4)}|{'I_LEN'}if plane==0 else{'S'+str(k)for k in range(4)})
  bank_dependencies['J'+str(j)]=sorted(atoms)
 for proof in parent['proofs']:
  if proof['result']!='unsat':continue
  r=subprocess.run([SOLVER,'-in'],input=proof['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**proof,'name':'replayed_word_'+proof['name'],'replayed_query':True});print('replayed_word_'+proof['name'],'unsat',flush=True)
 solve('materializer_input_domain_nonempty','',result='sat')
 sem={'entry_word_inputs':{'J'+str(j):'W'+str(j)for j in INPUTS},'predecessor_input_bindings_SMT':{'J'+str(j):parent['semantics']['compact_outputs_SMT'][str(j)]for j in INPUTS},'selected_context_register24':'0x3874e8e9','context_register24_generic_input':'SIZE','computed_address_cuts':cuts,'source_store_ledger':ledger,'source_value_SSA':{'spills':spills.prefix(),'bytes_with_spill_definitions':g.prefix()},'byte_planes':{'S0':{'logical_start':40,'cells':64},'S1':{'logical_start':112,'cells':64}},'physical_byte_offsets':sorted(offsets),'physical_rule':'T+(757*i mod963),T=F+0xd00','old_region_write_intersections':overlap,'raw_A_epoch':'All16 raw-permutation cells are overwritten by S1. B,U,C,D,Q are preserved.','live_arithmetic_table_cells_preserved':800,'identified_live_scratch_cells_after':928,'new_word_stores':32,'new_byte_stores':128,'new_unique_bytes_written':256,'protected_frame_offsets':sorted(protected),'frame_cell_epochs':{'0x730':hex(c730),'0x750':'0x4923,previous saved size encoding retired','0x748':'new materialized state word,previous private phase retired'},'saved_view_epoch':{'saved_cell':'F+0x568 unchanged','X21_first_repurposed':'0x100c9d47c','saved_view_dereferenced':False},'next_stage_roots':{'X26':'T','X25':'SRC from F+0x458','X23':'image-data base from F+0x450'},'next_stage_u32_constants':{str(k):hex(v)for k,v in constants.items()},'branch_partition':{'SIZE_equals_3874e8c9':'0x100a763d4','SIZE_other':'0x100c21d7c','selected_LEN32_target':'0x100c21d7c','zero_length_reachability_proved':False},'compact_full_128_byte_expansion_proved':False,'native_claim':False}
 sem['compact_spill_temporaries_SMT']=compact_defs;sem['compact_spilled_words_SMT']={hex(k):v for k,v in fields.items()};sem['byte_dependency_certificates']=sorted(dependency_rows,key=lambda r:r['logical_index']);sem['plane_input_word_families']={str(k):sorted(v)for k,v in allowed.items()};sem['word_family_predecessor_bank_dependencies']=bank_dependencies;sem['direct_SIZE_dependency_in_byte_values']=False;sem['dependency_scope']='Exact source-SSA free-variable absence;upstream words may depend on earlier size context. This proves local separation,not native scheduling or a standard algorithm.'
 return pp,tr,sem
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_byte_store',lambda q:q['fragments']['bytes']['instructions'][12].__setitem__('operands','w14, [sp, #0xd29]')),('wrong_spill_byte',lambda q:q['fragments']['spills'].__setitem__('bytes','00'+q['fragments']['spills']['bytes'][2:])),('wrong_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];rows=[]
 for n,fn in ops:
  q=copy.deepcopy(s);fn(q);assert not verify(q);rows.append({'name':n,'rejected_by_fresh_original_source_comparison':True})
 return rows
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,sem=certificates(s);aa=alterations(s);actual={pc for v in tr.values()for pc in v['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 counts={**s['verified_source_counts'],'distinct_nonbranch_sites_translated':len(actual),'new_nonbranch_sites_translated':len(tr['spills']['source_sites'])+len(tr['bytes_full_source']['source_sites']),'untranslated_source_sites':len(expected-actual),'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'replayed_queries_unsat':sum(p.get('replayed_query',False)for p in pp),'source_proved_computed_indices':len(sem['computed_address_cuts']),'new_byte_cells':128,'byte_dependency_certificates':len(sem['byte_dependency_certificates']),'new_word_stores':32,'unique_new_bytes_written':256,'retired_raw_A_cells':16,'live_arithmetic_cells_preserved':800,'identified_live_scratch_cells_after':928,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_bank_combine.py','validate_daemon_mode_one_carry_table.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','recover_daemon_mode_one_word_mix.py','daemon_mode_one_word_mix_checks.json','daemon_mode_one_digit_maps_checks.json']
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'translations':tr,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_state_materialization_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
