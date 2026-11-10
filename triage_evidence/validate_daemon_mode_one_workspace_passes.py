#!/usr/bin/env python3
"""Prove two74-word passes and15 source swaps with explicit bounded cuts."""
import copy,json,re,subprocess,shutil
from recover_daemon_mode_one_workspace_passes import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_checkpoint import PostSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq
from validate_daemon_list_output import split
from daemon_mode_one_handoff_tools import parse
from validate_daemon_mode_one_record_long_prefix import dependency_census
SOLVER=shutil.which('z3');assert SOLVER
D={3:(0xaaaaaaab,33,0),5:(0xcccccccd,34,0),6:(0xaaaaaaab,34,0),9:(0x38e38e39,33,0),10:(0xcccccccd,35,0),11:(0xba2e8ba3,35,0),12:(0xaaaaaaab,35,0),13:(0x4ec4ec4f,34,0),14:(0x92492493,34,1),15:(0x88888889,35,0)}
CUT={0x100b0c218:(14,'w21','w5'),0x100b0c238:(15,'w22','w6'),0x100b0c280:(13,'w19','w16'),0x100b0c2d0:(12,'w7','w6'),0x100b0c360:(11,'w4','w5'),0x100b0c37c:(9,'w23','w16'),0x100b0c3b0:(10,'w19','w19'),0x100b0c45c:(7,'w24','w4'),0x100b0c484:(6,'w11','w6'),0x100b0c4c4:(5,'w21','w7'),0x100b0c590:(3,'w17','w6')}
class ByteSSA(PostSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   p=split(i['operands']);m=i['mnemonic']
   if m=='ldrb':
    name='BYTE'+str(len([r for r in self.reads if r['width_bits']==8]));self.decl[name]=8;self.reads.append({'site':i['ea'],'address':self.address(p[1]),'width_bits':8,'input':name});self.put(p[0],'((_ zero_extend 24) '+name+')');self.sites.append(i['ea'])
   elif m=='strb':self.stores.append({'site':i['ea'],'address':self.address(p[1]),'width_bits':8,'value':'((_ extract 7 0) '+self.get(p[0],32)+')'});self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def certificates(s):
 pp=[];models={};cuts=[];replays=[];fs=s['fragments']
 def solve(name,body,result='unsat',extra='',cc=(),logic='QF_BV'):
  query='(set-option :timeout 15000)\n(set-logic '+logic+')\n'+(''if logic=='QF_LIA'else DECL)+extra+body+'\n'+''.join('(assert '+v+')\n'for v in cc)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':query,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def dec(g):return''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())
 def cert(name,g,terms,cc=()):solve(name,g.prefix()+'(assert (or '+' '.join(terms)+'))',extra=dec(g),cc=cc)
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 def run(g,label):
  for v,w in g.supplied_loads.values():
   if re.fullmatch('[A-Z][A-Z0-9_]*',v):g.decl[v]=w
  f=fs[label];g.run(f,int(f['instructions'][-1]['ea'],16));models[label]=g;return g
 selections={'daemon_mode_one_record_checkpoint':{'LOCAL_present_source_predicate_derived_views_and_entry_constants','original_wrapper_cookie_coded_SEL_is_sufficient_for_new_phase'},'daemon_mode_one_record_word_gather':{'original_private_word_view_root'}}
 for name,wanted in selections.items():
  old=json.loads(read(ROOT/(name+'_checks.json')));assert old['all_checks_pass'];rows=[p for p in old['proofs']if p['name']in wanted];assert{p['name']for p in rows}==wanted
  for p in rows:
   r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_'+name+'_'+p['name'],'replayed_query':True})
  replays.append({'checks':name+'_checks.json','sha256':sha(ROOT/(name+'_checks.json')),'selected_queries':len(rows),'all_historical_queries_replayed':False})
 previous=json.loads(read(ROOT/'daemon_mode_one_record_checkpoint_source.json'));ef=previous['fragments']['local_present']
 entry=PostSSA('entry',{8:bv(0x4923),10:'LOCAL'},presets={0x740:('TABLE',64),0x388:('R',64),0x2c0:('COOKIE',64)},loads={'0x100c578b8':('SEL',32),'0x100c57a84':('ENTRY_FN',64)});entry.decl.update(LOCAL=64,R=64,COOKIE=64,SEL=32,ENTRY_FN=64);entry.run(ef,int(ef['instructions'][-1]['ea'],16));models['entry']=entry
 first_seed={5:0xa9502f98,6:0xa20cd51f,14:0x79705c69,16:0x71b2bb0c};cert('actual_entry_first_state_counter_control_and_frame_view',entry,[neq(entry.get('x'+str(k)),bv(v))for k,v in{**first_seed,10:0x56d3,13:0x39eba85c}.items()]+[neq(entry.get('x26'),frame(0xc80))])
 assert not{r['frame_offset']+j for r in entry.frame_writes for j in range(r['width_bits']//8)}&set(range(0x758,0x760))
 extra='(declare-fun IDX () (_ BitVec 32))\n'+''.join('(declare-fun S'+str(j)+' () (_ BitVec 32))\n'for j in range(4));domain=['(bvult IDX #x0000004a)'];reg1={r:z('S'+str(j))for j,r in enumerate([5,6,14,16])};reg1.update({10:bv(0x56d3),13:'(bvadd '+bv(0x39eba85c)+' '+z('IDX')+')',26:frame(0xc80)})
 first=PostSSA('first',reg1,presets={0x740:('TABLE',64)},loads={'0x100d3ce90':('WORD',32),'0x100d3d29c':('FIRST_FN',64)});first.decl.update(IDX=32,**{'S'+str(j):32 for j in range(4)});run(first,'first')
 second_seed={8:0xa9502f98,9:0xa20cd51f,12:0x5bfaf402,21:0x5e281186};invariant={0:0x404a,1:0x9c46cba1,2:0x0d92891d,3:0x5385c82f,4:0xa0c828c7,20:0x06a7eeda}
 cert('first_read_counter_exact74_dispatch_and_second_seed',first,[neq(rd(first,0x100d3ce90)['address'],'(bvadd '+frame(0x768)+' (bvshl '+z('IDX')+' '+bv(2)+'))'),neq(first.get('x13'),'(bvadd '+bv(0x39eba85d)+' '+z('IDX')+')'),neq(rd(first,0x100d3d29c)['address'],f'(ite (= IDX #x00000049) {at(0x7e25)} {at(0x56d3)})'),neq(first.get('x15'),frame(0x768)),neq(first.get('w11'),bv(0,32)),neq(first.get('x10'),bv(0x56d3)),neq(first.get('x17'),bv(0xe138))]+[neq(first.get('x'+str(k)),bv(v))for k,v in{**invariant,**second_seed}.items()],domain);assert not first.stores and len(first.reads)==3
 reg2={r:z('S'+str(j))for j,r in enumerate([8,9,12,21])};reg2.update({k:bv(v)for k,v in invariant.items()});reg2.update({11:z('IDX'),15:frame(0x768),26:frame(0xc80)})
 second=PostSSA('second',reg2,presets={0x740:('TABLE',64)},loads={'0x100ab7b80':('WORD',32),'0x100ab7d28':('SECOND_FN',64)});second.decl.update(IDX=32,**{'S'+str(j):32 for j in range(4)});run(second,'second')
 cert('second_read_unit_progress_exact74_dispatch_and_shuffle_ABI',second,[neq(rd(second,0x100ab7b80)['address'],'(bvadd '+frame(0x768)+' (bvshl '+z('IDX')+' '+bv(2)+'))'),neq(second.get('w11'),'(bvadd IDX #x00000001)'),neq(rd(second,0x100ab7d28)['address'],f'(ite (bvult (bvadd IDX #x00000001) #x0000004a) {at(0x406e)} {at(0x404a)})'),neq(second.get('x13'),bv(0x8721)),neq(second.get('x22'),bv(1)),neq(second.get('x26'),frame(0xc80)),neq(second.get('x17'),bv(0xc65))]+[neq(second.get('x'+str(k)),bv(v))for k,v in invariant.items()],domain);assert not second.stores and len(second.reads)==3
 for name,g in [('first',first),('second',second)]:cert(name+'_TABLE_frame_read_address',g,[neq(next(r for r in g.reads if r['site']==g.frame_reads[0]['site'])['address'],frame(0x740))],domain)
 assert not set(s['register_write_sets']['second'])&{p+str(r)for p in['x','w']for r in[5,6,7,16,19,26]}
 recurrence=[]
 for label,g,registers in[('first',first,[5,6,14,16]),('second',second,[8,9,12,21])]:
  names=set(re.findall(r'\(declare-fun (\w+) ',DECL))|set(g.decl);ds=dependency_census(g.prefix(),names,[g.get('w'+str(r))for r in registers]);assert all(set(v)<={'IDX','WORD','S0','S1','S2','S3'}for v in ds);recurrence.append({'pass':label,'state_registers':registers,'entry_state_words':['S0','S1','S2','S3'],'outgoing_u32_expressions':[g.get('w'+str(r))for r in registers],'declared_dependency_upper_bounds':ds,'dependency_membership_is_not_influence':True})
 solve('u32_counter_domain_progress_and_296_byte_coverage','(declare-fun I () (_ BitVec 32))\n(assert (bvult I #x0000004a))\n(assert (or (bvule (bvadd I #x00000001) I) (bvugt (bvadd I #x00000001) #x0000004a) (bvugt (bvmul I #x00000004) #x00000124)))')
 intervals=[{'word':j,'start_byte':4*j,'end_byte_exclusive':4*j+4}for j in range(74)];assert [v for r in intervals for v in range(r['start_byte'],r['end_byte_exclusive'])]==list(range(296))
 # Exact integer correspondence for the full u32 source domain. UMULL's
 # u32*u32 product is below2^64;source Q/R shapes are separately bound.
 divs={**D,347:(0x5e6ea9af,39,0)};integer=[]
 for d in[3,5,6,7,9,10,11,12,13,14,15,347]:
  body='(declare-fun N () Int)\n(declare-fun Q () Int)\n(declare-fun R () Int)\n(assert (and (<= 0 N) (<= N 4294967295) (<= 0 Q) (<= 0 R) (< R '+str(d)+') (= N (+ (* Q '+str(d)+') R))))\n'
  if d==7:
   body+='(define-fun T () Int (div (* N 613566757) 4294967296))\n';formula='(div (+ T (div (- N T) 2)) 4)';bad='(or (distinct '+formula+' Q) (< T 0) (> T N) (> (+ T (div (- N T) 2)) 4294967295))'
  else:
   m,shift,half=divs[d];formula='(div (* '+('(div N 2)'if half else'N')+' '+str(m)+') '+str(2**shift)+')';bad='(distinct '+formula+' Q)'
  solve('reciprocal_division_'+str(d)+'_all_u32_integer_theorem',body+'(assert '+bad+')',logic='QF_LIA');integer.append({'divisor':d,'quotient_integer_formula':formula,'domain':'0<=N<=4294967295','unsigned_typed_correspondence':'UMULL32x32->u64,logical shifts,floors;source BV remainder-shape proof at each cut;no u64 product overflow.'})
 g=ByteSSA('shuffle',{13:bv(0x8721),22:bv(1),26:frame(0xc80)},presets={0x740:('TABLE',64),0x758:(frame(0x8b0),64)},loads={'0x100b0c600':('SHUFFLE_FN',64)});g.decl['SHUFFLE_FN']=64;cc=[]
 for i in fs['shuffle']['instructions'][:-1]:
  pc=int(i['ea'],16)
  if pc in CUT:d,reg,src=CUT[pc];n=g.get(src)
  g.run({'instructions':[i]},pc+4)
  if pc in[0x100b0c184,0x100b0c464,0x100b0c564]:
   d,reg={0x100b0c184:(16,'w0'),0x100b0c464:(8,'w22'),0x100b0c564:(4,'w3')}[pc];cert('source_mask_bound_'+str(d),g,['(bvuge '+g.get(reg)+' '+bv(d,32)+')'],cc);cuts.append({'site':i['ea'],'register':reg,'original_expression':g.get(reg),'replacement':'RES'+str(d),'range_u32':[0,d-1],'justification':'Fresh original-source mask bound;independent bounded overapproximation.'});g.put(reg,'RES'+str(d));g.decl['RES'+str(d)]=32;cc.append('(bvult RES'+str(d)+' '+bv(d,32)+')')
  if pc in CUT:
   if d==7:
    t='((_ extract 31 0) (bvlshr (bvmul '+z(n)+' '+bv(0x24924925)+') '+bv(32)+'))';q='(bvlshr (bvadd '+t+' (bvlshr (bvsub '+n+' '+t+') #x00000001)) #x00000002)'
   else:
    m,shift,half=D[d];assert 0<=m<2**32 and(2**32-1)*m<2**64;q='((_ extract 31 0) (bvlshr (bvmul '+z('(bvlshr '+n+' #x00000001)'if half else n)+' '+bv(m)+') '+bv(shift)+'))'
   cert('source_remainder_'+str(d)+'_exact_BV_shape',g,[neq(g.get(reg),'(bvsub '+n+' (bvmul '+q+' '+bv(d,32)+'))')],cc);cuts.append({'site':i['ea'],'register':reg,'divisor':d,'source_N':n,'source_quotient':q,'original_expression':g.get(reg),'replacement':'RES'+str(d),'range_u32':[0,d-1],'justification':'Fresh BV shape + full-u32 integer division theorem + verified unsigned source widths;independent bounded overapproximation,not a compact value identity.'});g.put(reg,'RES'+str(d));g.decl['RES'+str(d)]=32;cc.append('(bvult RES'+str(d)+' '+bv(d,32)+')')
 models['shuffle']=g;assert len(cuts)==14 and len(g.reads)==32 and len(g.stores)==47 and len(g.frame_writes)==1 and not g.initial
 br=[r for r in g.reads if r['width_bits']==8];bs=[r for r in g.stores if r['width_bits']==8];assert len(br)==29 and len(bs)==46
 selected=[br[j]for j in[0,2,4,5,8,10,12,13,16,17,19,21,24,26,28]];P16=[0x8b0+799*j%962 for j in range(16)];assert len(set(P16))==16
 cases=[]
 for j in range(14):
  d=16-j
  for r in range(d):
   if j==0:
    n=r;v=((n^0x32ba9927)+0xf4f08136)^((n^0xad3778d9)+0x6b7d60cc)^((n^0x9f8de1f4)+0x59c7f9e7);v=(v*799+0x1ebec9f9)&0xffffffff;off=v-(((v>>1)*0x883fddf1)>>40)*962;assert off in[799*k%962 for k in range(16)];logical=next(k for k in range(16)if 799*k%962==off)
   else:logical=(14^r)if j==12 else j+r
   assert j<=logical<16;cert('selected_cell_'+str(j)+'_residue_'+str(r),g,[neq(selected[j]['address'],frame(P16[logical]))],cc+['(= RES'+str(d)+' '+bv(r,32)+')']);cases.append({'swap':j,'bounded_symbol':'RES'+str(d),'value':r,'logical_selected_cell':logical,'frame_offset':P16[logical]})
 cert('last_selected_cell_is14_or15',g,['(and '+neq(selected[14]['address'],frame(P16[14]))+' '+neq(selected[14]['address'],frame(P16[15]))+')'],cc)
 assert len(cases)==133 and{c['logical_selected_cell']for c in cases if c['swap']==0}==set(range(16))
 swaps=[];terms=[]
 for j in range(15):
  store_fixed,store_selected=bs[16+2*j:18+2*j];want=frame(P16[j]);terms.extend([neq(store_fixed['address'],want),neq(store_selected['address'],selected[j]['address']),neq(store_fixed['value'],selected[j]['input'])])
  if j==0:terms.append(neq(store_selected['value'],'#x00'));other=None;source_loads=[selected[0]]
  else:
   source_loads=br[2*j-1:2*j+1];other=next(r for r in source_loads if r is not selected[j]);terms.extend([neq(other['address'],want),neq(store_selected['value'],other['input'])])
  assert all(int(r['site'],16)<int(store_fixed['site'],16)and int(r['site'],16)<int(store_selected['site'],16)for r in source_loads)
  swaps.append({'logical_fixed_cell':j,'selected_read':selected[j],'fixed_read':other,'fixed_store':store_fixed,'selected_store':store_selected,'all_reads_before_both_stores':True,'selected_logical_range':[j,15]})
 cert('all15_source_swaps_exact_read_before_write_value_and_address_flow',g,terms,cc)
 cert('all16_identity_seed_addresses_and_byte_values',g,[v for j,row in enumerate(bs[:16])for v in[neq(row['address'],frame(P16[j])),neq(row['value'],bv(j,8))]],cc)
 outgoing={0:799,1:962,2:545,3:0x441fef,4:16,5:0x2527,13:0x8721,15:0,16:0x73acf,30:0x422b}
 cert('shuffle_root_epoch_control_and_next_ABI',g,[neq(g.get('x'+str(k)),bv(v))for k,v in outgoing.items()]+[neq(g.get('x20'),frame(0x8b0)),neq(g.get('x26'),frame(0x8b0)),neq(g.get('x17'),bv(0xaf8b)),neq(g.stores[0]['address'],frame(0x750)),neq(g.stores[0]['value'],frame(0xc80)),neq(rd(g,0x100b0c108)['address'],frame(0x758)),neq(rd(g,0x100b0c5fc)['address'],frame(0x740)),neq(rd(g,0x100b0c600)['address'],at(0x8721))],cc)
 # Raw byte loads are independent component inputs. They are intentionally
 # not forwarded from a stale literal-only model when computed stores alias.
 # The source swap laws compose with coherent16-cell memory via this array law.
 array='(declare-fun ARR () (Array (_ BitVec 4) (_ BitVec 8)))\n(declare-fun I4 () (_ BitVec 4))\n(declare-fun J4 () (_ BitVec 4))\n(declare-fun N4 () (_ BitVec 4))\n(define-fun NEW () (Array (_ BitVec 4) (_ BitVec 8)) (store (store ARR I4 (select ARR J4)) J4 (select ARR I4)))\n'
 solve('coherent16_cell_swap_matches_index_transposition',array+'(assert '+neq('(select NEW N4)','(select ARR (ite (= N4 J4) I4 (ite (= N4 I4) J4 N4)))')+')',logic='QF_ABV')
 solve('coherent16_cell_swap_involution_including_equal_indices',array+'(assert '+neq('(store (store NEW I4 (select NEW J4)) J4 (select NEW I4))','ARR')+')',logic='QF_ABV')
 swap_cases=[]
 for i in range(16):
  for j in range(16):
   a=list(range(16));a[i],a[j]=a[j],a[i];assert sorted(a)==list(range(16))and len(set(a))==16;swap_cases.append({'I':i,'J':j,'index_transposition':a})
 records={n:m.record_full()for n,m in models.items()};actual={pc for n,m in models.items()if n!='entry'for pc in m.sites};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==728
 # Bounded shape proves every store stays in one root cell or the seeded
 # byte set. The296-byte input workspace and saved request/LOCAL words survive.
 assert not set(range(0x768,0x890))&set(P16)and all(0x8b0<=p<0xc72 for p in P16)
 sem={'source_models':records,'source_nonbranch_sites_translated':728,'entry_sites_translated':len(entry.sites),'predecessor_replays':replays,'first_seed_u32':{str(k):hex(v)for k,v in first_seed.items()},'second_seed_u32':{str(k):hex(v)for k,v in second_seed.items()},'two_independent_state_seeds_proved':True,'scalar_recurrences':recurrence,'recurrence_is_encoded_source_not_decoded_algorithm':True,'state_dependency_census_is_upper_bound':True,'workspace_word_intervals':intervals,'words_per_pass':74,'bytes_per_pass':296,'workspace_read_operations':148,'workspace_read_bytes':592,'workspace_reads_once_per_pass':True,'workspace_stores':0,'first_counter':'X13=0x39eba85c+IDX;exit at incremented0x39eba8a6','second_counter':'W11=IDX;next IDX+1;repeat iff next<74','first_outputs_preserved_by_second':[5,6,7,16,19],'first_state_preserved_encoding_identity_proved':False,'integer_division_theorems':integer,'source_cuts':cuts,'source_cut_bounds':cc,'all_raw_byte_loads_are_independent_component_inputs':True,'coherent_array_composition_required':True,'broad_unsplit_membership_queries_accepted':False,'excluded_exploration':'Unsplit direct membership queries timed out;only bounded-source component and exhaustive residue proofs are accepted.','permutation_root':'F+0x8b0','physical_slot_formula':'F+0x8b0+((799*j)mod962),0<=j<16','physical_slot_offsets':P16,'identity_seed_byte_stores':16,'selected_address_exhaustive_cases':cases,'selected_address_cases':133,'last_selected_range':[14,15],'source_swap_ledger':swaps,'source_swaps':15,'source_byte_reads':29,'source_byte_stores':46,'generic_index_transpositions':swap_cases,'final_values_are_a_permutation_of_0_to15':True,'uniform_or_random_permutation_proved':False,'decoded_workspace_recurrence_identity_proved':False,'LOCAL_pointer_dereferences':0,'LOCAL_biased_saved_word_consumed':False,'F750_new_root':'F+0xc80;saved at0x100b0c100','F758_root':'F+0x8b0;retained','outgoing_constants':{str(k):hex(v)for k,v in outgoing.items()},'next_target':'0x100a4f144','next_target_semantics_proved':False,'native_ownership_proved':False,'successful_output_proved':False,'daemon_kext_pairing_proved':False,'Mach_port_emissions':0,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['first'].__setitem__('bytes','00'+q['fragments']['first']['bytes'][2:])),('wrong_counter',lambda q:next(i for i in q['fragments']['first']['instructions']if i['ea']=='0x100d3d0b8').__setitem__('operands','x13, x13, #2')),('wrong_byte_swap',lambda q:next(i for i in q['fragments']['shuffle']['instructions']if i['ea']=='0x100b0c240').__setitem__('operands','w19, [x2]')),('wrong_next_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('wrong_TST_bit',lambda q:q['TST_decode_checks'][0].__setitem__('operand','W11 AND2')),('wrong_UMULL',lambda q:q['UMULL_decode_checks'][0].__setitem__('bytes','00000000')),('wrong_lineage',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];original=build();out=[]
 for n,fn in cases:
  q=copy.deepcopy(s);fn(q);assert q!=original;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':728,'entry_sites_translated':sem['entry_sites_translated'],'words_per_pass':74,'workspace_read_operations':148,'workspace_read_bytes':592,'state_words_per_pass':4,'integer_division_theorems':12,'source_remainder_shape_proofs':11,'source_mask_bounds':3,'source_overapproximations':14,'selected_address_cases':133,'identity_seed_stores':16,'source_swaps':15,'source_byte_reads':29,'source_byte_stores':46,'shuffle_stores':47,'shuffle_distinct_byte_destinations':16,'shuffle_root_stores':1,'generic_array_laws':2,'finite_index_transpositions':256,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','daemon_word_lookup_algebra.py','validate_daemon_mode_one_record_long_prefix.py','validate_daemon_mode_one_word_schedule.py','validate_daemon_existing_scalar_reader.py','validate_daemon_constructor_inputs.py','validate_daemon_constructor_lookup.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'dual_workspace_passes_and_byte_permutation_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
