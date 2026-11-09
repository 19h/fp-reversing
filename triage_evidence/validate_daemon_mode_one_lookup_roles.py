#!/usr/bin/env python3
"""Proof-carrying table-family induction over original word-loop byte reads."""
import copy,json,hashlib,subprocess,shutil,collections,re
from recover_daemon_mode_one_lookup_roles import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_word_lookup_algebra import DAG,parse,children,expression,literal,typ,BOOL
from daemon_word_lookup_role_models import REGIONS,INV757,E_FACT,H_FACT,SIZE_FACT,Optimizer,unary,emit_cut,leaves
SOLVER=shutil.which('z3');assert SOLVER
def facts(expr,w,f):
 lo,hi,zr,on=f;assert 0<=lo<=hi<2**w and not zr&on
 out=[]
 if lo:out.append(f'(bvuge {expr} {literal(lo,w)})')
 if hi<2**w-1:out.append(f'(bvule {expr} {literal(hi,w)})')
 if zr:out.append(f'(= (bvand {expr} {literal(zr,w)}) {literal(0,w)})')
 if on:out.append(f'(= (bvand {expr} {literal(on,w)}) {literal(on,w)})')
 return out
def certificates(s):
 pp=[]
 def solve(name,body,logic='QF_BV',result='unsat'):
  name=str(len(pp))+'_'+name;q='(set-option :timeout 15000)\n(set-logic '+logic+')\n'+body+'\n(check-sat)\n'
  r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-roles-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr)
  pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});return name
 from validate_daemon_mode_one_lookup_bounds import certificates as parent_certificates,classify
 from validate_daemon_mode_one_digit_maps import certificates as map_certificates
 from recover_daemon_mode_one_lookup_bounds import build as parent_build
 parent=json.loads(read(ROOT/DEPS[1]));parent_source=parent_build();assert parent_source==json.loads(read(ROOT/DEPS[0]))
 bp,bs=parent_certificates(parent_source);assert bp==parent['proofs']and json.loads(json.dumps(bs))==parent['semantics']
 producer=json.loads(read(ROOT/DEPS[3]));mp,mt,ms=map_certificates(s['producer_source']);assert mp==producer['proofs']and mt==producer['translations']and json.loads(json.dumps(ms))==producer['semantics']
 for kind,proofs in[('bounds',bp),('producer',mp)]:
  for p in proofs:pp.append({**p,'name':'replayed_'+kind+'_'+p['name'],'replayed_query':True,'replay_source':kind})
 # Verify retained frame chronology without claiming to rerun every predecessor.
 chronology={}
 for name in DEPS[5:]:
  c=json.loads(read(ROOT/name));assert c['all_checks_pass']and not c['complete_operation_proved'];sem=c['semantics'];chronology[name]={'sha256':sha(ROOT/name),'all_checks_pass':True,'fresh_full_proof_replay':name==DEPS[-1]}
  if 'scratch_bytes_preserved'in sem:assert sem['scratch_bytes_preserved']==963
  if 'live_arithmetic_cells_preserved'in sem:assert sem['live_arithmetic_cells_preserved']==800
  if 'live_arithmetic_table_cells_preserved'in sem:assert sem['live_arithmetic_table_cells_preserved']==800
 original=json.loads(read(ROOT/DEPS[-1]));sem=original['semantics'];assert sem['phase_cell_F6d8']=='Saved map-B[0] byte shifted left4;retained,not a loop counter'and sem['iterations']==48
 d=DAG();d.defs(sem['source_SSA']);source_aliases=dict(d.alias);reads=sem['byte_read_address_expressions'];rows=classify(d,reads)
 assert len(rows)==69 and all(r['input']=='B'+str(j)for j,r in enumerate(reads))
 for row,prior in zip(rows,bs['source_access_certificates']):
  for key in['site','original_index_node','remainder_node','numerator_node']:assert row[key]==prior[key]
 for name,(lo,hi)in REGIONS.items():assert ms['region_offsets'][name]==[(757*j)%963 for j in range(lo,hi+1)]
 # Universal helper laws justify reassociation,constant collection and XOR pairs.
 algebra=[]
 for w in sorted({w for _,w in d.nodes if w>1}):
  decl=''.join(f'(declare-fun {v} () (_ BitVec {w}))\n'for v in['A','B','C']);z=literal(0,w)
  for op in['bvadd','bvxor']:
   algebra.append(solve('assoc_'+op+'_'+str(w),decl+f'(assert (or (distinct ({op} ({op} A B) C) ({op} A ({op} B C))) (distinct ({op} A B) ({op} B A)) (distinct ({op} A {z}) A)))'))
  algebra.append(solve('xor_pair_'+str(w),decl+f'(assert (distinct (bvxor A A) {z}))'))
 coordinate_law=solve('coordinate_ring_inverse','(declare-fun G () (_ BitVec 32))\n(declare-fun C () (_ BitVec 32))\n(assert (distinct (bvadd (bvmul G #x000002f5) C) (bvmul (bvadd G (bvmul C #x91c1195d)) #x000002f5)))')
 no_wrap=solve('coordinate_no_wrap','(declare-fun J () Int)\n(assert (and (<= 0 J) (<= J 962)))\n(assert (or (< (* 757 J) 0) (>= (* 757 J) 4294967296)))','QF_LIA')
 phase=solve('phase_E_byte_shift4','(declare-fun X () (_ BitVec 8))\n(assert (and (bvuge X #xd0) (bvule X #xdf)))\n(define-fun Y () (_ BitVec 32) (bvshl ((_ zero_extend 24) X) #x00000004))\n(assert (not (and '+' '.join(facts('Y',32,SIZE_FACT))+')))')
 codomain_certificates={}
 for name,expr,ff in[('E','(bvxor #xd4 X)',E_FACT),('H','(bvxor #xd4 (bvshl X #x04))',H_FACT)]:
  codomain_certificates[name]=solve(name+'_encoding_codomain','(declare-fun X () (_ BitVec 8))\n(assert (bvule X #x0f))\n(define-fun Y () (_ BitVec 8) '+expr+')\n(assert (not (and '+' '.join(facts('Y',8,ff))+')))')
 domains={'SIZE':SIZE_FACT};known={};ledger=[];transfers=[];range_cache={};current=[-1]
 bounds={r['remainder_node']:{'site':r['site'],'parent_certificate_index':j,'parent_checks_sha256':sha(ROOT/DEPS[1])}for j,r in enumerate(bs['source_access_certificates'])}
 def prove_range(x,opt):
  k,w=d.nodes[x];ff=opt.abstract(x);leaf=sorted(leaves(d,x));assert all(not re.fullmatch('B[0-9]+',n)or int(n[1:])<current[0]for n in leaf),(current[0],leaf)
  key=(x,ff,tuple((n,tuple(domains[n]))for n in leaf if n in domains))
  if key in range_cache:return range_cache[key]
  if x in opt.nodefacts:
   row={'node':x,'facts':ff,'kind':'replayed_source_remainder_bound','origin':opt.origins[x]};transfers.append(row);range_cache[key]=len(transfers)-1;return len(transfers)-1
  if k[0]in['const','sym']or not facts('X',w,ff):
   origin={'kind':'constant_or_full_width'}
   if k[0]=='sym'and k[1]in domains:
    n=k[1];origin={'kind':'producer_codomain'if n!='SIZE'else'phase_seed','symbol':n,'certificate':phase if n=='SIZE'else known[n]['role_certificate'],'prior_read_index':None if n=='SIZE'else int(n[1:])}
   row={'node':x,'facts':ff,**origin};transfers.append(row);range_cache[key]=len(transfers)-1;return len(transfers)-1
  cs=children(d,x);preids=[prove_range(v,opt)for v in cs];refs=[literal(d.const(v),d.nodes[v][1])if d.const(v)is not None else'A'+str(j)for j,v in enumerate(cs)]
  decl=''.join(f'(declare-fun {n} () {typ(d,v)})\n'for n,v in zip(refs,cs)if d.const(v)is None);pre=[f for n,v in zip(refs,cs)if d.const(v)is None and d.nodes[v][0][0]not in BOOL for f in facts(n,d.nodes[v][1],opt.abstract(v))];out=expression(d,x,refs)
  cert=solve('typed_transfer_'+str(x),decl+''.join('(assert '+f+')\n'for f in pre)+'(assert (not (and '+' '.join(facts(out,w,ff))+')))')
  row={'node':x,'facts':ff,'parents':cs,'parent_records':preids,'certificate':cert,'kind':'checked_local_transfer'};transfers.append(row);range_cache[key]=len(transfers)-1;return len(transfers)-1
 opt=Optimizer(d,domains,bounds,solve,prove_range);opt.special_numerator=next(r['numerator_node']for r in rows if r['site']=='0x100bdd994')
 for index,row in enumerate(rows):
  current[0]=index;symbol='B'+str(index);j=opt.coordinate(row['numerator_node']);assert j is not None,(row['site'],'no coordinate')
  abstract=opt.abstract(j);lo,hi,_,_=abstract;match=[n for n,(l,h)in REGIONS.items()if l<=lo<=hi<=h];method='checked_interval';parameters=None
  if match:
   range_record=prove_range(j,opt);name=match[0];cert=transfers[range_record].get('certificate','range_record_'+str(range_record))
  else:
   pattern=unary(d,j);assert pattern is not None,(row['site'],'no unary',abstract)
   x,parameters,offset=pattern;ff=opt.abstract(x);ll,hh,zr,on=ff;assert hh-ll<=65536,(row['site'],ff)
   # Finite arithmetic proposes the region;only the universal SMT result accepts it.
   values=[]
   for v in range(ll,hh+1):
    if v&zr or v&on!=on:continue
    value=0
    for c0,c1 in parameters:value^=((v^c0)+c1)&0xffffffff
    values.append((value+offset)&0xffffffff)
   assert values;mn,mx=min(values),max(values);match=[n for n,(l,h)in REGIONS.items()if l<=mn<=mx<=h];assert len(match)==1,(row['site'],ff,(mn,mx));name=match[0];lb,ub=REGIONS[name]
   range_record=prove_range(x,opt);expr=emit_cut(d,j,{x:'X'});assert leaves_expression(expr)=={'X'},(row['site'],leaves_expression(expr))
   cert=solve('unary_role_'+row['site'],'(declare-fun X () (_ BitVec 32))\n'+''.join('(assert '+f+')\n'for f in facts('X',32,ff))+f'(assert (or (bvult {expr} {literal(lb,32)}) (bvugt {expr} {literal(ub,32)})))');method='universal_unary_function'
   parameters={'input_node':x,'input_facts':ff,'xor_add_pairs':parameters,'offset':offset,'finite_candidate_minmax':[mn,mx],'candidate_values_count':len(values)}
  needed=sorted(leaves(d,j));assert all(not re.fullmatch('B[0-9]+',n)or int(n[1:])<index for n in needed)
  dependencies=[{'symbol':n,'read_index':int(n[1:]),'family':known[n]['family'],'role_certificate':known[n]['role_certificate']}for n in needed if n in domains and n!='SIZE']
  rr={**row,'read_index':index,'symbol':symbol,'simplified_numerator_node':opt.memo[row['numerator_node']],'logical_node':j,'logical_domain':REGIONS[name],'family':name,'range_method':method,'range_record':range_record,'role_certificate':cert,'unary_parameters':parameters,'typed_prior_read_dependencies':dependencies,'source_free_inputs':needed,'return_codomain':H_FACT if name=='D'else E_FACT,'return_codomain_certificate':codomain_certificates['H'if name=='D'else'E'],'producer_contract':{'B':'B[j]=E(R(j));logical17+j','U':'U[t]=E(R_inverse(t))','C':'C[R(a)+16R(b)]=E(R((a+b) mod16))','D':'D[R(a)+16R(b)]=H(R(floor((a+b)/16)))','Q':'Q[R(a)+16R(b)]=E(R(a XOR b))'}[name]}
  ledger.append(rr);known[symbol]=rr;domains[symbol]=H_FACT if name=='D'else E_FACT;opt.abstract.cache_clear()
  print('role',index,row['site'],name,method,flush=True)
 counts=dict(collections.Counter(r['family']for r in ledger));assert counts=={'B':16,'U':8,'C':23,'D':14,'Q':8},counts
 assert len(ledger)==69 and len({r['site']for r in ledger})==69
 # Check every canonicalizer rewrite generated by source parsing and role algebra.
 rules={};closed=[]
 for event in d.rewrites:
  key=(event['declarations'],event['lhs'],event['rhs'])
  if event['rule']=='constant_fold':closed.append(event);continue
  if key not in rules:rules[key]=solve('normalization_rule_'+str(len(rules)),key[0]+'\n(assert (distinct '+key[1]+' '+key[2]+'))')
  event['certificate']=rules[key]
 closed_cert=solve('closed_constant_folds','(assert (or '+' '.join('(distinct '+r['lhs']+' '+r['rhs']+')'for r in closed)+'))')
 for event in closed:event['certificate']=closed_cert
 # Distinguishing controls and nonempty-domain checks are mathematical only.
 solve('wrong_B_upper31_counterexample','(declare-fun X () (_ BitVec 32))\n(assert (bvule X #x0000000f))\n(assert (bvugt (bvadd X #x00000011) #x0000001f))',result='sat')
 solve('wrong_carry_E_codomain_counterexample','(declare-fun X () (_ BitVec 8))\n(assert (bvule X #x0f))\n(assert (bvult (bvxor #xd4 (bvshl X #x04)) #xd0))',result='sat')
 solve('typed_E_H_domains_nonempty','(declare-fun E () (_ BitVec 8))\n(declare-fun H () (_ BitVec 8))\n'+''.join('(assert '+f+')\n'for f in facts('E',8,E_FACT)+facts('H',8,H_FACT)),result='sat')
 cells=set()
 for lo,hi in REGIONS.values():
  for v in range(lo,hi+1):cells.add((757*v)%963)
 assert len(cells)==800 and not cells&{(757*v)%963 for v in list(range(40,104))+list(range(112,176))}
 semantics={'source_SSA_sha256':hashlib.sha256(sem['source_SSA'].encode()).hexdigest(),'source_SSA_bindings':source_aliases,'canonical_nodes':d.nodes,'normalization_rewrite_ledger':d.rewrites,'algebra_laws':algebra,'coordinate_ring_law':coordinate_law,'coordinate_no_wrap':no_wrap,'phase_certificate':phase,'optimizer_transformations':opt.transformations,'optimizer_events':opt.events,'range_ledger':transfers,'lookup_role_ledger':ledger,'region_domains':REGIONS,'role_counts':counts,'role_reads_over48_iterations':{n:v*48 for n,v in counts.items()},'arithmetic_sites':45,'conversion_sites':24,'arithmetic_reads':2160,'conversion_reads':1152,'total_reads':3312,'table_cells_in_union':800,'scratch_cells':963,'plane_cells_excluded':128,'other_scratch_cells_excluded':35,'scratch_physical_offsets':sorted(cells),'retained_chronology':chronology,'producer_composition':ms['composition'],'producer_natural_labels':ms['natural_labels'],'producer_label_rank':ms['label_rank'],'producer_R_is_unknown_permutation':True,'all69_families_classified':True,'codomains_are_overapproximations':True,'all_concrete_lookup_values_recovered':False,'full_word_recurrence_proved':False,'algorithm_identified':False,'new_Mach_ports_or_emissions':0,'native_claim':False,'scope_boundary':SCOPE}
 return pp,semantics
def leaves_expression(expr):return set(re.findall(r'(?<![A-Za-z0-9_])(?:B[0-9]+|WORD[0-9]+|SIZE|Z[0-9]+|K|X|V)(?![A-Za-z0-9_])',expr))
def verify(s):return s==build()
def alterations(s):
 cases=[('wrong_loop_source',lambda q:q['fragments']['loop'].__setitem__('bytes','00'+q['fragments']['loop']['bytes'][2:])),('wrong_producer_byte',lambda q:q['producer_source']['operation_data'].__setitem__('bytes','00'*944)),('wrong_exit_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for n,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'bounds_queries_replayed':sum(p.get('replay_source')=='bounds'for p in pp),'producer_queries_replayed':sum(p.get('replay_source')=='producer'for p in pp),'range_records':len(sem['range_ledger']),'checked_range_transfers':sum(r['kind']=='checked_local_transfer'for r in sem['range_ledger']),'unary_role_certificates':sum(r['range_method']=='universal_unary_function'for r in sem['lookup_role_ledger']),'classified_lookup_sites':69,'role_counts':sem['role_counts'],'optimizer_events':len(sem['optimizer_events']),'normalization_rewrite_instances':len(sem['normalization_rewrite_ledger']),'source_nonbranch_sites_replayed':2024,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','daemon_word_lookup_role_models.py','daemon_word_lookup_algebra.py','validate_daemon_mode_one_lookup_bounds.py','validate_daemon_mode_one_digit_maps.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'all_lookup_families_classified':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
