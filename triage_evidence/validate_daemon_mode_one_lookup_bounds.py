#!/usr/bin/env python3
"""Proof-carrying normalization/ranges and all69 original byte-address bounds."""
import copy,json,subprocess,shutil,functools,hashlib
from recover_daemon_mode_one_lookup_bounds import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_word_lookup_algebra import DAG,parse,range_engine,BOOL,literal,typ,ref,expression,children
SOLVER=shutil.which('z3');assert SOLVER
DIV1='(bvxor (bvand (bvxor (bvand V #x000003c3) #x700966ca) (bvxor (bvand V #x000003c3) #x716d7788)) (bvxor (bvand V #x00000281) #x7009654b))'
DIV2='(bvand (bvxor (bvadd V #x000827aa) (bvsub #x00000055 V)) #x000003c3)'
def classify(d,reads):
 rows=[]
 def kind(x):return d.nodes[x][0][0]
 for r in reads:
  original=d.index(r['address']);idx=original;short=kind(idx)=='extract'
  if short:assert d.nodes[idx][0][2:]==(15,0);idx=d.nodes[idx][0][1]
  k,w=d.nodes[idx];assert k[0]=='bvsub'and w==32;n,product=k[1:];kp,_=d.nodes[product];assert kp[0]=='bvmul'
  mask16=False;divisor_binding=None
  if any(d.const(x)==963 for x in kp[1:]):
   q=next(x for x in kp[1:]if d.const(x)!=963)
   if kind(q)=='extract':assert d.nodes[q][0][2:]==(31,0);q=d.nodes[q][0][1]
   kq,_=d.nodes[q];assert kq[0]=='bvlshr';prod,shift=kq[1:];shift=d.const(shift);km,width=d.nodes[prod];assert km[0]=='bvmul'
   constants=[x for x in km[1:]if d.const(x)is not None];assert len(constants)==1;coef=d.const(constants[0]);arg=next(x for x in km[1:]if x!=constants[0])
   if kind(arg)=='zext':assert width==64 and d.nodes[d.nodes[arg][0][1]][1]==32;arg=d.nodes[arg][0][1]
   if coef==0x649eb3:
    nn=d.nodes[n][0];assert nn[0]=='bvmul'and any(d.const(x)==757 for x in nn[1:]);target=next(x for x in nn[1:]if d.const(x)!=757);assert arg==target
   elif arg!=n:
    kn=d.nodes[arg][0];assert kn[0]=='bvand'and n in kn[1:]and any(d.const(v)==65535 for v in kn[1:]);mask16=True
   assert(coef,shift,width)in[(0x2207,23,32),(0x649eb3,23,32),(0x440dd3,32,64),(0x440dd2cf,40,64)]
   family=hex(coef)+':'+str(shift)
  else:
   qs=[x for x in kp[1:]if kind(x)=='ite'];assert len(qs)==1;q=qs[0];divisor=next(x for x in kp[1:]if x!=q);kq,_=d.nodes[q];condition,zero,quotient=kq[1:];assert d.const(zero)==0
   kc,_=d.nodes[condition];assert kc[0]=='='and divisor in kc[1:]and any(d.const(x)==0 for x in kc[1:]);assert d.nodes[quotient][0]==('bvudiv',n,divisor)
   seen=set()
   def walk(x):
    if x in seen:return
    seen.add(x)
    if kind(x)not in['const','sym']:
     for a in children(d,x):walk(a)
   walk(divisor);matches=[]
   for x in sorted(seen):
    kk,_=d.nodes[x]
    if kk[0]=='bvand'and any(d.const(v)==0x281 for v in kk[1:]):
     v=next(v for v in kk[1:]if d.const(v)!=0x281);d.alias['V']=v
     if d.get(parse(DIV1))==divisor:matches.append(('universal_divisor1',v))
    if kk[0]=='bvsub'and d.const(kk[1])==0x55:
     v=kk[2];d.alias['V']=v
     if d.get(parse(DIV2))==divisor and d.get(parse('(bvadd V #x000827aa)'))==n:matches.append(('universal_divisor2',v))
   assert len(set(matches))==1,(r['site'],matches);divisor_binding={'lemma':matches[0][0],'V_node':matches[0][1],'divisor_node':divisor};family='UDIV';coef=shift=arg=None;width=32
  rows.append({'site':r['site'],'original_index_node':original,'remainder_node':idx,'numerator_node':n,'argument_node':arg,'coefficient':coef,'shift':shift,'product_width':width,'family':family,'extract_low16':short,'quotient_numerator_mask16':mask16,'divisor_binding':divisor_binding})
 return rows
def certificates(s):
 pp=[]
 def solve(name,body,logic='QF_BV',result='unsat'):
  q='(set-option :timeout 15000)\n(set-logic '+logic+')\n'+body+'\n(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-lookup-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});return name
 parent=json.loads(read(ROOT/'daemon_mode_one_word_schedule_checks.json'));assert parent['all_checks_pass']and parent['local_word_schedule_interface_proved']
 from recover_daemon_mode_one_word_schedule import build as original_build
 from validate_daemon_mode_one_word_schedule import certificates as original_certificates
 source=original_build();assert source==json.loads(read(ROOT/'daemon_mode_one_word_schedule_source.json'))
 proofs,tr,sem=original_certificates(source);assert proofs==parent['proofs']and tr==parent['translations']and json.loads(json.dumps(sem))==parent['semantics']
 actual={pc for v in tr.values()for pc in v['source_sites']};expected={i['ea']for f in source['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==2024
 for proof in proofs:pp.append({**proof,'name':'replayed_'+proof['name'],'replayed_query':True})
 d=DAG();d.defs(parent['semantics']['source_SSA']);source_aliases=dict(d.alias);reads=parent['semantics']['byte_read_address_expressions'];assert len(reads)==69;rows=classify(d,reads);abstract=range_engine(d)
 # All address roots must be the actual source-proved T,not merely an arbitrary
 # other operand of a syntactically similar addition.
 t=d.get(parse('(bvadd K #x0000000000000d00)'))
 for r in reads:
  root=d.nodes[d.get(parse(r['address']))][0];assert root[0]=='bvadd'and t in root[1:]
 rules={};closed=[]
 for event in d.rewrites:
  key=(event['declarations'],event['lhs'],event['rhs'])
  if event['rule']=='constant_fold':closed.append(event);continue
  if key not in rules:rules[key]=solve('normalization_rule_'+str(len(rules)),key[0]+'\n(assert (distinct '+key[1]+' '+key[2]+'))')
  event['certificate']=rules[key]
 assert closed
 closed_name=solve('all_closed_constant_folds','(assert (or '+' '.join('(distinct '+r['lhs']+' '+r['rhs']+')'for r in closed)+'))')
 for event in closed:event['certificate']=closed_name
 # Every nontrivial interval/known-bit transfer is checked independently with
 # fresh operands,under only the certified facts about its immediate parents.
 def facts(expr,x):
  if d.nodes[x][0][0]in BOOL:return[]
  lo,hi,zr,on=abstract(x);w=d.nodes[x][1];out=[];assert not zr&on
  if lo:out.append(f'(bvuge {expr} {literal(lo,w)})')
  if hi<2**w-1:out.append(f'(bvule {expr} {literal(hi,w)})')
  if zr:out.append(f'(= (bvand {expr} {literal(zr,w)}) {literal(0,w)})')
  if on:out.append(f'(= (bvand {expr} {literal(on,w)}) {literal(on,w)})')
  return out
 needed=set()
 def visit(x):
  if x in needed or d.nodes[x][0][0]in['const','sym']or not facts('X',x):return
  needed.add(x)
  for a in children(d,x):visit(a)
 for row in rows:
  if row['family']not in['0x440dd2cf:40','UDIV']:visit(row['argument_node']if row['coefficient']==0x649eb3 else row['numerator_node'])
 transfers=[]
 for index,x in enumerate(sorted(needed)):
  cs=children(d,x);refs=[literal(d.const(v),d.nodes[v][1])if d.const(v)is not None else'A'+str(j)for j,v in enumerate(cs)];decl=''.join(f'(declare-fun {name} () {typ(d,v)})\n'for name,v in zip(refs,cs)if d.const(v)is None);pre=[f for name,v in zip(refs,cs)if d.const(v)is None for f in facts(name,v)];out=expression(d,x,refs)
  name=solve('range_transfer_node_'+str(x),decl+''.join('(assert '+f+')\n'for f in pre)+'(assert (not (and '+' '.join(facts(out,x))+')))')
  transfers.append({'node':x,'parents':cs,'abstract_facts':abstract(x),'certificate':name})
  if index%100==0:print('range_transfers',index,flush=True)
 limits={0x2207:65535,0x440dd3:727477,0x440dd2cf:4294967295,0x649eb3:15};math={}
 for coef,shift in[(0x2207,23),(0x440dd3,32),(0x440dd2cf,40),(0x649eb3,23)]:
  num='(* X 757)'if coef==0x649eb3 else'X';limit=limits[coef];name=solve('exact_reciprocal_'+hex(coef),f'(declare-fun X () Int)\n(assert (and (<= 0 X) (<= X {limit})))\n(assert (distinct (div (* X {coef}) {1<<shift}) (div {num} 963)))','QF_LIA');math[coef]=name
 solve('integer_euclidean_remainder_bounds','(declare-fun X () Int)\n(assert (<= 0 X))\n(define-fun R () Int (- X (* 963 (div X 963))))\n(assert (or (< R 0) (>= R 963)))','QF_LIA')
 solve('mask16_and_extract16_preserve_bounded_values','(declare-fun X () (_ BitVec 32))\n(assert (bvule X #x0000ffff))\n(assert (or (distinct (bvand X #x0000ffff) X) (distinct ((_ zero_extend 16) ((_ extract 15 0) X)) X)))')
 for name,body in[('universal_divisor1',DIV1),('universal_divisor2',DIV2)]:solve(name,'(declare-fun V () (_ BitVec 32))\n(assert (distinct '+body+' #x000003c3))')
 family_counts={};certified=[]
 for row in rows:
  family_counts[row['family']]=family_counts.get(row['family'],0)+1
  if row['family']=='UDIV':
   certified.append({**row,'numerator_range':[0,4294967295],'quotient_source':'Exact source UDIV with universally proved nonzero divisor963','byte_offset_range':[0,962],'byte_domain_lemma':row['divisor_binding']['lemma']});continue
  argument=row['argument_node']if row['coefficient']==0x649eb3 else row['numerator_node'];lo,hi,_,_=abstract(argument);assert hi<=limits[row['coefficient']]
  if row['quotient_numerator_mask16']:assert hi<=65535
  numerator_max=hi*757 if row['coefficient']==0x649eb3 else hi;assert numerator_max<2**32 and hi*row['coefficient']<2**row['product_width']
  quotient_max=numerator_max//963;assert quotient_max<2**32 and quotient_max*963<=numerator_max
  certified.append({**row,'certified_argument_range':[lo,hi],'source_product_max':hi*row['coefficient'],'source_product_fits_bits':row['product_width'],'integer_numerator_max':numerator_max,'integer_quotient_max':quotient_max,'reciprocal_certificate':math[row['coefficient']],'byte_offset_range':[0,962]})
 assert family_counts=={'0x2207:23':15,'0x440dd3:32':10,'0x440dd2cf:40':35,'0x649eb3:23':7,'UDIV':2}
 # Two direct map subsets require no table-value premise. Their logical
 # positions follow from the numerator shapes and the certified0..15 inputs.
 direct_maps=[]
 for row in rows:
  if row['coefficient']==0x649eb3:direct_maps.append({'site':row['site'],'map':'U','logical_indices':[0,15],'reason':'757*ARG mod963;ARG0..15'})
  elif row['coefficient']==0x2207:
   k,w=d.nodes[row['numerator_node']]
   if k[0]=='bvadd'and any(d.const(x)==12869 for x in k[1:]):
    product=next(x for x in k[1:]if d.const(x)!=12869);kp,_=d.nodes[product]
    if kp[0]=='bvmul'and any(d.const(x)==757 for x in kp[1:]):
     arg=next(x for x in kp[1:]if d.const(x)!=757)
     if abstract(arg)[1]<=15:direct_maps.append({'site':row['site'],'map':'B','logical_indices':[17,32],'reason':'12869+757*ARG=757*(17+ARG);ARG0..15'})
 negative=[]
 for name,body,logic in[
  ('wrong_reciprocal2208_has_counterexample','(declare-fun X () Int)\n(assert (and (<= 0 X) (<= X 65535)))\n(assert (distinct (div (* X 8712) 8388608) (div X 963)))','QF_LIA'),
  ('false_nibble_upper14_has_counterexample','(declare-fun X () (_ BitVec 32))\n(assert (bvugt (bvand X #x0000000f) #x0000000e))','QF_BV')]:
  solve(name,body,logic,result='sat');negative.append({'name':name,'result':'sat','meaning':'The altered arithmetic/range claim has a counterexample;this is an abstract proof-checker control,not native target evidence.'})
 solve('component_domain_nonempty','(declare-fun X () Int)\n(assert (and (<= 0 X) (<= X 65535)))','QF_LIA',result='sat')
 semantics={'source_SSA_sha256':hashlib.sha256(parent['semantics']['source_SSA'].encode()).hexdigest(),'source_SSA_bindings':source_aliases,'canonical_nodes':d.nodes,'normalization_rewrite_ledger':d.rewrites,'normalization_method':'Topological alias substitution,typed structural interning,and per-instance applications of checked rewrite identities. A diagnostic aggregate graph-equivalence query timed out and is excluded.','range_transfer_ledger':transfers,'range_input_assumptions':'Only source bit-vector widths;all original scalar/word inputs and byte-load values remain arbitrary. No SIZE or iteration-range restriction is needed for these bounds.','source_access_certificates':certified,'family_counts':family_counts,'direct_digit_map_accesses':direct_maps,'all69_byte_addresses_bounded_to963_proved':True,'byte_read_sites':69,'byte_reads_in48_iterations':3312,'minimum_byte_offset':0,'maximum_byte_offset_inclusive':962,'source_root':'F+0xd00','byte_table_values_proved':False,'all_table_families_classified':False,'compact_word_recurrence_proved':False,'native_mapping_proved':False,'native_claim':False,'scope_boundary':'Bounds certify positions inside the private scratch domain,not table values,full algorithm identity,caller publication,hardware PAC or native daemon-kext exchange.'}
 semantics['negative_arithmetic_range_controls']=negative
 semantics['certified_bounds_are_overapproximation']=True;semantics['attainment_of_endpoints_proved']=False
 return pp,semantics
def verify(s):return s==build()
def alterations(s):
 cases=[('wrong_byte_source',lambda q:q['fragments']['loop'].__setitem__('bytes','00'+q['fragments']['loop']['bytes'][2:])),('wrong_lookup_operand',lambda q:q['fragments']['loop']['instructions'][593].__setitem__('operands','w8, [sp]')),('wrong_root',lambda q:q['fragments']['views']['instructions'][3].__setitem__('operands','x8, x8, #0x471')),('wrong_target',lambda q:q['branch_edges'][2].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'source_nonbranch_sites_covered_by_parent_replay':2024,'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'parent_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'canonical_nodes':len(sem['canonical_nodes']),'source_SSA_bindings':len(sem['source_SSA_bindings']),'normalization_rewrite_instances':len(sem['normalization_rewrite_ledger']),'range_transfers_checked':len(sem['range_transfer_ledger']),'byte_accesses_bounded':69,'direct_digit_map_sites_classified':len(sem['direct_digit_map_accesses']),'reciprocal_families':4,'universal_divisor_identities':2,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','daemon_word_lookup_algebra.py','validate_daemon_mode_one_word_schedule.py','daemon_mode_one_word_schedule_source.json','daemon_mode_one_word_schedule_checks.json']
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'all_lookup_addresses_bounded':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
