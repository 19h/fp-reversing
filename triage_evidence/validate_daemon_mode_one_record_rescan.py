#!/usr/bin/env python3
"""Source-bound first-arrival lineage,two counted byte loops and bank handoff."""
import copy,json,re,shutil,subprocess,functools
from recover_daemon_mode_one_record_rescan import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_mode_one_handoff_tools import FrameSSA,parse
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,at,frame
from validate_daemon_mode_one_record_codecs import EXTRA
SOLVER=shutil.which('z3');assert SOLVER
def certificates(s):
 pp=[];models={};fs=s['fragments'];common={0x728:('COUNT',32),0x738:(bv(0,32),32),0x740:('TABLE',64),0x748:('PBUF',64),0x750:(frame(0xd10),64)}
 def solve(name,body,result='unsat',cc=(),integer=False):
  q='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+('(declare-fun XI () Int)\n'if integer else DECL+EXTRA)+body+'\n'+''.join('(assert '+v+')\n'for v in cc)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def pre(g):return ''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
 def cert(name,g,terms,cc=()):solve(name,pre(g)+'(assert (or '+' '.join(terms)+'))',cc=cc)
 def rd(g,pc):return next(v for v in g.reads if v['site']==hex(pc))
 def run(g,name,a=None,end=None):
  f=fs[name];ii=[v for v in f['instructions']if a is None or int(v['ea'],16)>=a];g.run({'instructions':ii},end or int(f['instructions'][-1]['ea'],16));return g
 def chained(name,previous,overrides=None,loads=None):
  g=FrameSSA(name,{**previous.r,**(overrides or{})},loads=loads);g.defs=list(previous.defs);g.decl=dict(previous.decl);g.byte_cells=dict(previous.byte_cells);g.loaded=previous.loaded;return g
 from recover_daemon_mode_one_record_codecs import build as codecs_build
 from validate_daemon_mode_one_record_codecs import certificates as codecs_certificates
 from recover_daemon_mode_one_record_passes import build as passes_build
 from validate_daemon_mode_one_record_passes import certificates as passes_certificates
 refreshed={}
 for family,builder,validator in [('codecs',codecs_build,codecs_certificates),('passes',passes_build,passes_certificates)]:
  old=builder();assert old==json.loads(read(ROOT/f'daemon_mode_one_record_{family}_source.json'));prior=json.loads(read(ROOT/f'daemon_mode_one_record_{family}_checks.json'));bp,bs=validator(old)
  assert bp==prior['proofs']and json.loads(json.dumps(bs))==prior['semantics'];refreshed[family]=bs
  pp.extend({**v,'name':'replayed_'+family+'_'+v['name'],'replayed_query':True}for v in bp)
 # Independently bind every pre-gate source store to a bounded frame region.
 # Complete parent source contracts justify their explicit address cuts.
 parent_models={n:json.loads(read(ROOT/f'daemon_mode_one_record_{n}_checks.json'))['semantics']['source_models']for n in ['permutation','adder']}
 parent_models.update({n:bs['source_models']for n,bs in refreshed.items()})
 chosen={'passes':['between','scatter_seed']+['scatter'+str(j)for j in range(16)],'permutation':['permutation']+[v+str(j)for j in range(16)for v in ['inverse','reset']],'adder':['second','sum_step','carry_step'],'codecs':['xor_step','decode_step','encode_step']}
 census=[];covered=set();instances=0;sel=[f'(bvult SEL{j} {bv(16-j,32)})'for j in range(15)]
 for family,names in chosen.items():
  for name in names:
   m=parent_models[family][name];decl=m['declarations'];decl=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in decl.items())if isinstance(decl,dict)else decl;terms=[]
   for row in m['stores']:
    covered.add(row['site']);instances+=1;delta=f'(bvsub {row["address"]} K)'
    if row['width_bits']==32:terms.append(neq(delta,bv(0x730)))
    else:assert row['width_bits']==8;terms.append(f'(or (bvult {delta} {bv(0xd10)}) (bvugt {delta} {bv(0x10d0)}))')
   cc=[]
   if(family=='permutation'and name=='permutation')or(family=='adder'and name=='second'):cc=sel
   elif family=='permutation'and name.startswith('inverse'):cc=['(bvult (bvxor B0 #x74) #x10)']
   elif family=='adder':cc=['(bvult ARG #x00000100)','(bvult NIB #x00000010)','(bvult (bvxor B0 #x74) #x10)','(bvult (bvxor B1 #x74) #x10)']
   elif family=='codecs':
    cc=['(bvult ARG '+bv(256 if name=='xor_step'else 16,32)+')']
    if name!='decode_step':cc.append('(bvult NIB #x00000010)')
    if name!='encode_step':cc.append('(bvult (bvxor B0 #x74) #x10)')
    if name=='xor_step':cc.append('(bvult (bvxor B1 #x74) #x10)')
   solve('lineage_store_domain_'+family+'_'+name,decl+m['source_SSA']+'(assert (or '+' '.join(terms)+'))',cc=cc)
   census.append({'family':family,'model':name,'stores':m['stores'],'source_contract_refreshed':True,'conditions':cc,'arbitrary_record_byte_domain_unrestricted':family=='passes','allowed_u32_frame_offset':0x730,'allowed_byte_frame_interval':[0xd10,0x10d0]})
 actual=set();lineage_ranges=0
 for family in ['passes','permutation','adder','codecs']:
  source=json.loads(read(ROOT/f'daemon_mode_one_record_{family}_source.json'))
  for name,f in source['fragments'].items():
   if name=='gate':continue
   lineage_ranges+=1
   for i in f['instructions']:
    if i['mnemonic'].startswith('st'):assert i['mnemonic']in ['str','strb'];actual.add(i['ea'])
 assert actual==covered and len(actual)==70 and len(census)==57 and instances==115
 protected=[*range(0x728,0x72c),*range(0x738,0x73c),*range(0x740,0x758)];allowed=[*range(0x730,0x734),*range(0xd10,0x10d1)];assert not set(protected)&set(allowed)
 selection=FrameSSA('selection',{0:'NODE',12:'PBUF',10:bv(0x4cc6),11:bv(0x4f)},presets=common,loads={'0x100bf2d2c':('COUNT',32),'0x100bf2d74':('FN',64)});run(selection,'selection');models['selection']=selection
 cert('selection_initializes_zero_state_and_saved_record_fields',selection,[neq(rd(selection,0x100bf2d2c)['address'],f'(bvadd NODE {bv(0x10)})'),neq(selection.loadframe(0x738,32),bv(0,32)),neq(selection.loadframe(0x728,32),'COUNT'),neq(selection.loadframe(0x748,64),'PBUF')]);assert len(selection.stores)==len(selection.frame_writes)==4
 gate=FrameSSA('first_gate',{13:bv(0xa0fd)},presets=common,loads={'0x100d69ddc':('FN',64)});run(gate,'gate');models['gate']=gate
 cert('first_arrival_gate_zero_preimage_and_phase_state_stores',gate,[neq(rd(gate,0x100d69ddc)['address'],f'(ite (= COUNT #x00000000) {at(0x828b)} {at(0x8284)})'),neq(gate.loadframe(0x730,32),bv(0x4923,32)),neq(gate.loadframe(0x738,32),bv(0x34c96b7f,32)),neq(gate.get('w8'),bv(0x424f,32))]);assert len(gate.stores)==len(gate.frame_writes)==2
 seed=chained('rescan_seed',gate,loads={'0x100ca1f10':('FN',64)});run(seed,'seed');models['seed']=seed
 constants={6:0xb26f34a3,7:0x117805e7,8:0x424f,9:0xd67ff57d,10:0,12:0x3d5c657c,13:0x95ccb056,16:0xd93db98f,19:0x1e82fbe4,20:0x3a6212b0,21:0x271c27da,22:0xa6212b10,23:0x22200200,24:0x8fc34f90,25:0xe41452eb,26:0x3acafe69,27:0x3a620000,28:0x9ba929a1,30:0x6baffe5e}
 phase1=0x2414dbd9;byte_mask=phase1^0x2414db23
 cert('rescan_seed_original_edge_constants_and_saved_phase',seed,[neq(seed.get('w'+str(k)),bv(v,32))for k,v in constants.items()]+[neq(seed.get('w11'),'(bvadd COUNT #x95ccb055)'),neq(seed.get('w14'),bv(byte_mask,32)),neq(seed.get('x5'),'PBUF'),neq(seed.loadframe(0x730,32),bv(phase1,32)),neq(rd(seed,0x100ca1f10)['address'],at(0x424f))]);assert len(seed.stores)==len(seed.frame_writes)==1
 first=chained('rescan_first',seed,{10:z('IDX'),12:z('(bvadd IDX #x3d5c657c)'),13:z('(bvadd IDX #x95ccb056)'),**{j:z('S'+str(k))for k,j in enumerate([19,7,6,16])}},loads={'0x100d75de0':('B0',8),'0x100d762ec':('FN',64)});run(first,'first');models['first']=first
 pred='(bvult (bvadd IDX #x00000001) COUNT)';domain='(bvult IDX COUNT)'
 cert('first_rescan_source_byte_counters_unsigned_control_and_D_encoding',first,[neq(rd(first,0x100d75de0)['address'],f'(bvadd PBUF {z("IDX")})'),neq(first.get('w10'),'(bvadd IDX #x00000001)'),neq(first.get('w12'),'(bvadd IDX #x3d5c657d)'),neq(first.get('w13'),'(bvadd IDX #x95ccb057)'),neq(rd(first,0x100d762ec)['address'],f'(ite {pred} {at(0x424f)} {at(0x4289)})'),neq(first.get('w16'),f'(bvadd {first.get("w15")} #x7d902fc1)'),neq(f'(bvadd {first.get("w16")} #xcb349f7a)',f'(bvadd {first.get("w15")} #x48c4cf3b)')],cc=[domain]);assert not first.stores
 first_keep=[5,8,9,11,14,20,21,22,23,24,25,26,27,28,30]
 for k in first_keep:assert not{v+str(k)for v in ['w','x']}&set(s['register_write_sets']['first']),k
 between=chained('rescan_between',first,loads={'0x100c2ad28':('FN',64)});run(between,'between');models['between']=between
 second_constants={0:0x489e39cd,1:0xd162ee7d,2:0xebe8aefd,4:0xfffff7f7,6:0x055154e8,7:0xab62c4af,8:0,9:0x54a6,11:0x40b82431,12:0xf44a7c5c,19:0x3bfff7f3,20:0x5bdd6506,21:0x38753524,22:0xedb74433,23:0x51e99c39,25:0xfc08e219,26:0xc46b5986,27:0x4d50290c,28:0x62e72318,30:0x80e643d0}
 cert('between_rescans_spills_first_bank_reseeds_second_and_phase',between,[neq(between.get('w'+str(k)),bv(v,32))for k,v in second_constants.items()]+[neq(between.get('w10'),'(bvadd COUNT #xf44a7c5b)'),neq(between.get('w24'),'COUNT'),neq(between.loadframe(0x700,32),first.get('w19')),neq(between.loadframe(0x708,32),first.get('w7')),neq(between.loadframe(0x710,32),first.get('w6')),neq(between.loadframe(0x730,32),bv(0x4923,32)),neq(between.loadframe(0x738,32),bv(0x34c96b7f,32)),neq(between.get('x5'),'PBUF'),neq(between.get('w15'),first.get('w15')),neq(rd(between,0x100c2ad28)['address'],at(0x54a6))]);assert len(between.stores)==len(between.frame_writes)==5
 second=chained('rescan_second',between,{8:z('IDX'),11:z('(bvadd IDX #x40b82431)'),12:z('(bvadd IDX #xf44a7c5c)'),**{j:z('T'+str(k))for k,j in enumerate([0,1,2])}},loads={'0x100c193b8':('B1',8),'0x100c197cc':('FN',64)});second.save(0x738,'T3',32,'second-state input');run(second,'second');models['second']=second
 cert('second_rescan_source_byte_counters_unsigned_control_and_preservation',second,[neq(rd(second,0x100c193b8)['address'],f'(bvadd PBUF {z("IDX")})'),neq(rd(second,0x100c193e8)['address'],frame(0x730)),neq(rd(second,0x100c19460)['address'],frame(0x738)),neq(second.get('w8'),'(bvadd IDX #x00000001)'),neq(second.get('w11'),'(bvadd IDX #x40b82432)'),neq(second.get('w12'),'(bvadd IDX #xf44a7c5d)'),neq(rd(second,0x100c197cc)['address'],f'(ite {pred} {at(0x54a6)} {at(0x54b9)})'),neq(second.get('w15'),first.get('w15')),neq(second.loadframe(0x700,32),first.get('w19')),neq(second.loadframe(0x708,32),first.get('w7')),neq(second.loadframe(0x710,32),first.get('w6'))],cc=[domain]);assert len(second.stores)==len(second.frame_writes)==1 and second.frame_writes[0]['frame_offset']==0x738
 second_keep=[4,5,6,7,9,10,15,19,20,21,22,23,24,25,26,27,28,30]
 for k in second_keep:assert not{v+str(k)for v in ['w','x']}&set(s['register_write_sets']['second']),k
 restore=chained('rescan_restore',second,loads={'0x100cde750':('FN',64)});run(restore,'restore');models['restore']=restore
 cert('rescan_exit_restores_canonical_first_bank_and_common_join',restore,[neq(rd(restore,0x100cde750)['address'],at(0x828b)),neq(restore.get('w12'),first.get('w19')),neq(restore.get('w13'),first.get('w7')),neq(restore.get('w11'),first.get('w6')),neq(restore.get('w10'),f'(bvadd {first.get("w16")} #xcb349f7a)')]+[neq(restore.get('w'+str(k)),second.get('w'+str(k)))for k in [0,1,2]]+[neq(restore.loadframe(0x738,32),second.loadframe(0x738,32))]);assert not restore.stores
 initial_first=[constants[j]for j in [19,7,6]]+[(constants[16]+0xcb349f7a)%2**32]
 cert('zero_count_gate_supplies_empty_rescan_banks',gate,[neq(gate.get('w'+str(j)),bv(v,32))for j,v in zip([12,13,11,10],initial_first)]+[neq(gate.get('w'+str(j)),bv(second_constants[j],32))for j in [0,1,2]]+[neq(gate.loadframe(0x738,32),bv(0x34c96b7f,32))])
 # Original reciprocal components compute an exact remainder before the
 # surrounding source adds it to its own accumulator expression.
 quotient='((_ extract 31 0) (bvlshr (bvmul ((_ zero_extend 32) VALUE) #x00000000ff00ff01) #x0000000000000028))'
 for name,a,end,reg,out in [('first',0x100d75f24,0x100d75f34,1,1),('second',0x100c19438,0x100c19448,14,14)]:
  g=FrameSSA(name+'_remainder',{reg:z('VALUE'),3:bv(0xff00ff01),16:bv(0xff00ff01)});run(g,name,a,end);models[name+'_remainder']=g
  cert(name+'_source_remainder257',g,[neq(g.get('w'+str(out)),f'(bvsub VALUE (bvmul {quotient} #x00000101))')])
 solve('reciprocal257_exact_unsigned32','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or (distinct (div (* XI 4278255361) 1099511627776) (div XI 257)) (>= (* XI 4278255361) 18446744073709551616) (>= (* 257 (div XI 257)) 4294967296)))',integer=True)
 solve('ordered_rescan_next_index_no_wrap','(assert (or (bvule (bvadd IDX #x00000001) IDX) (bvugt (bvadd IDX #x00000001) COUNT) (distinct '+pred+' (distinct (bvadd IDX #x00000001) COUNT))))',cc=[domain])
 for name,count in [('zero',0),('one',1),('first_wrap_before',0x6a334faa),('first_wrap_after',0x6a334fab),('second_wrap_before',0x0bb583a4),('second_wrap_after',0x0bb583a5),('max',0xffffffff)]:
  solve(name+'_count_domain','(assert (= COUNT '+bv(count,32)+'))'+(''if count==0 else'\n(assert (= IDX '+bv(count-1,32)+'))\n(assert '+domain+')'),result='sat')
 # New store effects are exclusively known u32 frame cells;the table domain
 # and all832 previous arithmetic cells remain intact.
 store_ledger=[]
 for name in ['gate','seed','first','between','second','restore']:
  g=models[name];assert len(g.stores)==len(g.frame_writes)
  if g.stores:cert(name+'_all_stores_are_source_bound_private_u32_cells',g,[neq(row['address'],frame(fr['frame_offset']))for row,fr in zip(g.stores,g.frame_writes)])
  for row in g.frame_writes:assert row['width_bits']==32 and row['frame_offset']in[0x700,0x708,0x710,0x730,0x738];store_ledger.append({'routine':name,**row})
 preserved=[*range(0xd10,0x10d1),*range(0x728,0x72c),*range(0x740,0x758),*range(0x2b8,0x2c8),*range(0x388,0x390),*range(0x580,0x588),*range(0x1210,0x1218)];written={r['frame_offset']+j for r in store_ledger for j in range(4)};assert not written&set(preserved)
 records={n:g.record_full()for n,g in models.items()};actual={pc for m in records.values()for pc in m['source_sites']};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 dependencies={}
 for label in ['first','second']:
  m=records[label];defs={}
  for line in m['source_SSA'].splitlines():
   a=parse(line);assert a[0]=='define-fun'and a[1]not in defs;defs[a[1]]=a[-1]
  declared=set(re.findall(r'\(declare-fun (\w+) ',DECL+EXTRA))|set(m['declarations'])
  @functools.lru_cache(None)
  def atom(a):return walk(defs[a])if a in defs else {a}if a in declared else set()
  def walk(a):return set().union(*(walk(v)for v in a))if isinstance(a,list)else atom(a)
  regs=[19,7,6,16]if label=='first'else[0,1,2];rows={str(k):sorted(walk(parse(m['final_registers'][k])))for k in regs}
  if label=='second':rows['F738']=sorted(walk(parse(m['frame_writes'][0]['value'])))
  allowed={'B0','IDX',*['S'+str(j)for j in range(4)]}if label=='first'else{'B1','IDX',*['T'+str(j)for j in range(4)]}
  assert all(set(v)==allowed for v in rows.values());dependencies[label]=rows
 sem={'source_models':records,'source_nonbranch_sites_translated':len(actual),'state_SSA_input_dependencies':dependencies,'state_dependency_membership_is_not_a_proof_of_influence':True,'lineage_store_certificates':census,'lineage_source_ranges':lineage_ranges,'lineage_distinct_source_store_sites':len(covered),'lineage_model_store_instances':instances,'lineage_models_checked':len(census),'first_arrival_old_state_u32':0,'first_arrival_equal_iff_COUNT_zero':True,'first_arrival_table_construction_stores_preserve_COUNT_PBUF_state_and_roots':True,'first_loop_invariant_registers':first_keep,'second_loop_invariant_registers':second_keep,'first_loop_counter_biases':['0x3d5c657c','0x95ccb056'],'second_loop_counter_biases':['0x40b82431','0xf44a7c5c'],'both_continue_predicate':'u32(IDX+1)<COUNT,unsigned under IDX<COUNT','post_table_record_byte_reads_integer':'2*COUNT','with_prior_record_passes_byte_reads_integer':'4*COUNT','earlier_header_reads':4,'source_buffer_cell':'F+0x748','count_cell':'F+0x728','same_addresses_do_not_prove_equal_byte_values':True,'first_initial_canonical_bank_u32':initial_first,'second_initial_bank_u32':[second_constants[j]for j in [0,1,2]]+[0x34c96b7f],'first_D_entry_encoding':'W16=u32(D-0xcb349f7a)','first_D_exit_encoding':'D=u32(W15+0x48c4cf3b)=u32(W16+0xcb349f7a)','first_bank_spills':{'F+0x700':'W19','F+0x708':'W7','F+0x710':'W6','retained_W15':'encoded fourth canonical word'},'common_join':'0x100c7d5dc','join_first_bank_order':['W12','W13','W11','W10'],'join_second_bank_order':['W0','W1','W2','u32[F+0x738]'],'zero_count_supplies_same_initial_canonical_banks':True,'source_store_ledger':store_ledger,'nonzero_suffix_u32_stores_integer':'COUNT+6;gate adds2','table_cells_preserved':832,'compact_recurrence_equivalence_proved':False,'two_bank_final_equality_proved':False,'whole_reentry_gate_semantics_proved':False,'Mach_port_emissions':0,'native_reachability_proved':False,'successful_output_publication_proved':False,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['first'].__setitem__('bytes','00'+q['fragments']['first']['bytes'][2:])),('second_read_offset',lambda q:q['fragments']['second']['instructions'][3].__setitem__('operands','w13, [x5, #1]')),('wrong_join',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('wrong_seed',lambda q:q['fragments']['seed'].__setitem__('start','0x0')),('wrong_lineage_hash',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(v['result']=='unsat'for v in pp),'queries_sat':sum(v['result']=='sat'for v in pp),'predecessor_queries_replayed':sum(v.get('replayed_query',False)for v in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'lineage_models_checked':57,'lineage_distinct_source_store_sites':70,'lineage_model_store_instances':115,'ordered_post_table_passes':2,'table_cells_preserved':832,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','recover_daemon_mode_one_record_codecs.py','validate_daemon_mode_one_record_codecs.py','recover_daemon_mode_one_record_passes.py','validate_daemon_mode_one_record_passes.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'record_first_arrival_and_post_table_rescans_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
