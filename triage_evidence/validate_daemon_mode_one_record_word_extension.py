#!/usr/bin/env python3
"""Source-proved48-step schedule,bounded scratch reads and exact SHA-2 sigma projections."""
import copy,json,re,subprocess,shutil
from recover_daemon_mode_one_record_word_extension import ROOT,P,SCOPE,FLAGS,DEPS,PDF,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_join import JoinSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,neq,at
from daemon_mode_one_handoff_tools import CandidateDAG,parse
SOLVER=shutil.which('z3');assert SOLVER
DATA_REGS=[1,9,10,14,22,23,24,25,27,28]
WORD_READ_PCS=[0x100c55850,0x100c55858,0x100c55884,0x100c558c4,0x100c55ce0,0x100c55d40,0x100c55e38,0x100c55e50]
READ_BASES=[1,72,14,85,211,220,143,152]
WRITE_BASES=[227,159,16,87]
class ExtensionSSA(JoinSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.snapshots={}
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   super().run({'instructions':[i]},pc+4)
   if pc in[0x100c558dc,0x100c55960,0x100c55988,0x100c559e0]:self.snapshots[i['ea']]={str(k):self.get('w'+str(k))for k in[0,2,3,11,15,16]}
  return self
 def record_full(self):return{**super().record_full(),'sigma_source_snapshots':self.snapshots}
def sigma(x,which):
 a,b,c=(7,18,3)if which==0 else(17,19,10)
 return f'(bvxor (bvxor ((_ rotate_right {a}) {x}) ((_ rotate_right {b}) {x})) (bvlshr {x} {bv(c,32)}))'
def remainder_candidates(g):
 d=CandidateDAG()
 for n,w in g.decl.items():d.alias[n]=d.intern(('sym',n),w)
 d.defs(g.prefix());inverse={}
 for name,node in d.alias.items():inverse.setdefault(node,name)
 rows=[]
 def kind(x):return d.nodes[x][0][0]
 for r in g.reads:
  if r['width_bits']!=8:continue
  original=d.index(r['address']);index=original;short=kind(index)=='extract'
  if short:assert d.nodes[index][0][2:]==(15,0);index=d.nodes[index][0][1]
  k,w=d.nodes[index];assert k[0]=='bvsub'and w==32;n,product=k[1:];kp,_=d.nodes[product];assert kp[0]=='bvmul'and any(d.const(v)==961 for v in kp[1:]);q=next(v for v in kp[1:]if d.const(v)!=961)
  if kind(q)=='extract':assert d.nodes[q][0][2:]==(31,0);q=d.nodes[q][0][1]
  kq,_=d.nodes[q];assert kq[0]=='bvlshr';prod,shift=kq[1:];km,pw=d.nodes[prod];assert km[0]=='bvmul'and pw==64;cs=[v for v in km[1:]if d.const(v)is not None];assert len(cs)==1;coef=d.const(cs[0]);arg=next(v for v in km[1:]if v!=cs[0]);assert kind(arg)=='zext';arg=d.nodes[arg][0][1];assert arg==n
  shift=d.const(shift);assert(coef,shift)in[(0x443215,32),(0x8864298f,41)];source=inverse[n];assert source in{parse(v)[1]for v in g.prefix().splitlines()}
  rows.append({'site':r['site'],'original_address':r['address'],'numerator_source_ref':source,'coefficient':coef,'shift':shift,'product_width':64,'extract_low16':short,'candidate_method':'Typed DAG aliases propose a source reference and shape;accepted claims use original-source SMT,not an assumed normalization theorem.'})
 assert len(rows)==69 and sum(r['coefficient']==0x443215 for r in rows)==56;return rows
def certificates(s):
 pp=[];models={};fs=s['fragments']
 def solve(name,body,result='unsat',extra='',integer=False):
  query='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+(''if integer else DECL)+extra+body+'\n(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':query,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def decl(g):return''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())
 def cert(name,g,terms,domain=True):solve(name,g.prefix()+('(assert (bvult IX #x00000030))\n'if domain else'')+'(assert (or '+' '.join(terms)+'))',extra=decl(g))
 from recover_daemon_mode_one_record_word_gather import build as previous_build
 old=previous_build();assert old==json.loads(read(ROOT/DEPS[0]));prior=json.loads(read(ROOT/DEPS[1]));assert prior['all_checks_pass']
 selected={'original_record_seed_biased_view_root_and_T','original_private_word_view_root','seed_all21_constants_state_reloads_full64_reset_and_branch','seed_all_private_read_and_store_addresses','exit_encoder_byte_raw_formula_state_reload_and_target','exit_all_private_frame_accesses'}|{'round'+str(q)+'_'+n for q in range(4)for n in['all32_plane_and16_word_addresses','all48_frame_stores_and81_frame_reads','exact_four_round_counter_phase_and_branch']};done=set()
 for v in prior['proofs']:
  if v['name']not in selected:continue
  r=subprocess.run([SOLVER,'-in'],input=v['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**v,'name':'replayed_gather_'+v['name'],'replayed_query':True});done.add(v['name'])
 assert done==selected and len(done)==18
 pm=prior['semantics']['source_models']['exit'];rr=pm['final_registers'];saved={r['frame_offset']:r['value']for r in pm['frame_writes']}
 pd=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in pm['declarations'].items());solve('actual_predecessor_entry_controls_and_64bit_state_word_type',pm['source_SSA']+'(assert (or '+neq(saved[0x720],bv(0x3f03,32))+' '+neq(saved[0x718],bv(0xc013729f,32))+' '+neq('((_ extract 63 32) '+rr['23']+')',bv(0,32))+'))',extra=pd)
 expected=['w16','w3','w2','x21','w14','w27','w24','w9','w22','w28','w25','w1','w23','w10','x23'];assert[r['register']for r in s['operand_based_GPR_first_reads']['loop']]==expected
 regs={j:z('J'+str(j))for j in DATA_REGS};regs.update({16:z('IX'),2:bv(0xea0f),3:bv(280),21:frame(0x8b0)})
 presets={0x720:(bv(0x3f03,32),32),0x718:('(bvsub #xc013729f IX)',32),0x740:('TABLE',64),0x750:(frame(0xd10),64),0x758:(frame(0x8b0),64),0x6bc:('STATE',32)}
 loads={hex(pc):('WORD'+str(j),32)for j,pc in enumerate(WORD_READ_PCS)};g=ExtensionSSA('word_extension',regs,presets=presets,loads=loads);g.decl.update({**{'J'+str(j):32 for j in DATA_REGS},**{'WORD'+str(j):32 for j in range(8)},'STATE':32});g.run(fs['loop'],int(fs['loop']['instructions'][-1]['ea'],16));assert not g.initial and len(g.sites)==1478 and len(g.reads)==148 and len(g.stores)==21 and len(g.frame_writes)==17;models['loop']=g
 frame_sites={r['site']for r in g.frame_reads};word_reads=[r for r in g.reads if r['width_bits']==32 and r['site']not in frame_sites];store_sites={r['site']for r in g.frame_writes};word_stores=[r for r in g.stores if r['site']not in store_sites];assert len(word_reads)==8 and len(word_stores)==4
 def word_address(base):return f'(bvadd {frame(0x8b0)} ((_ zero_extend 32) (bvshl (bvurem (bvmul (bvadd IX {bv(base,32)}) #x000000e3) #x00000118) #x00000002)))'
 cert('all_eight_word_read_addresses',g,[neq(r['address'],word_address(b))for r,b in zip(word_reads,READ_BASES)])
 cert('all_four_word_store_addresses',g,[neq(r['address'],word_address(b))for r,b in zip(word_stores,WRITE_BASES)])
 cert('source_counter_registers_frame_epoch_and_repeat_exit',g,[neq(g.get('w16'),'(bvadd IX #x00000001)'),neq(g.loadframe(0x730,32),'IX'),neq(g.loadframe(0x738,32),'(bvmul IX #x000000e3)'),neq(g.loadframe(0x718,32),'(bvsub #xc013729e IX)'),neq(g.loadframe(0x720,32),bv(0x3f03,32)),neq(g.loadframe(0x6bc,32),'STATE'),neq('((_ extract 63 32) '+g.get('x23')+')',bv(0,32)),neq(g.get('w2'),bv(0xea0f,32)),neq(g.get('w3'),bv(280,32)),neq(g.get('x21'),frame(0x8b0)),neq(g.get('x17'),bv(0x7e96)),neq(next(r for r in g.reads if r['site']=='0x100c56edc')['address'],f'(ite (= IX #x0000002f) {at(0x3f03)} {at(0x3f10)})')])
 solve('finite_next_index_and_last_iteration','(assert (bvult IX #x00000030))\n(assert (or (bvule (bvadd IX #x00000001) IX) (bvugt (bvadd IX #x00000001) #x00000030) (distinct (= IX #x0000002f) (= (bvadd IX #x00000001) #x00000030))))')
 cert('all17_private_frame_stores_and70_frame_reads',g,[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip([r for r in g.stores if r['site']in store_sites],g.frame_writes)]+[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip([r for r in g.reads if r['site']in frame_sites],g.frame_reads)])
 S=g.snapshots;sigma_rows=[('sigma0_unmasked_pair','0x100c558dc',f'(bvxor {S["0x100c558dc"]["16"]} {S["0x100c558dc"]["2"]})',sigma('WORD1',0),'WORD1',0),('sigma1_unmasked_pair','0x100c55960',f'(bvxor {S["0x100c55960"]["0"]} {S["0x100c55960"]["11"]})',sigma('WORD3',1),'WORD3',1),('sigma0_masked_word','0x100c55988',S['0x100c55988']['15'],f'(bvxor {sigma("(bvxor WORD0 #x88cc152e)",0)} {bv(0x88cc152e>>3,32)})','WORD0',0),('sigma1_masked_word','0x100c559e0',S['0x100c559e0']['3'],f'(bvxor {sigma("(bvxor WORD2 #xfe383a95)",1)} {bv(0xfe383a95>>10,32)})','WORD2',1)]
 for name,pc,original,want,input_name,which in sigma_rows:cert(name,g,[neq(original,want)],False)
 byte_rows=remainder_candidates(g);short=[r for r in byte_rows if r['coefficient']==0x443215]
 cert('all56_bounded_reciprocal_numerators',g,[f'(bvugt {r["numerator_source_ref"]} {bv(4033828,32)})'for r in short])
 solve('smaller485826_bound_has_abstract_counterexample',g.prefix()+'(assert (bvult IX #x00000030))\n(assert (or '+' '.join(f'(bvugt {r["numerator_source_ref"]} {bv(485826,32)})'for r in short)+'))',result='sat',extra=decl(g))
 shape=[]
 for r in byte_rows:
  n=r['numerator_source_ref'];rem=f'(bvsub {n} (bvmul ((_ extract 31 0) (bvlshr (bvmul ((_ zero_extend 32) {n}) {bv(r["coefficient"])}) {bv(r["shift"])})) #x000003c1))'
  if r['extract_low16']:rem=f'((_ zero_extend 16) ((_ extract 15 0) {rem}))'
  shape.append(neq(r['original_address'],f'(bvadd {frame(0xd10)} ((_ zero_extend 32) {rem}))'))
 cert('all69_original_scratch_address_remainder_shapes',g,shape)
 math=[]
 for coef,shift,limit in[(0x443215,32,4033828),(0x8864298f,41,0xffffffff)]:
  solve('exact_integer_reciprocal_'+hex(coef),f'(declare-fun X () Int)\n(assert (and (<= 0 X) (<= X {limit})))\n(assert (distinct (div (* X {coef}) {1<<shift}) (div X 961)))',integer=True)
  solve('integer_product_quotient_and_msub_widths_'+hex(coef),f'(declare-fun X () Int)\n(assert (and (<= 0 X) (<= X {limit})))\n(define-fun Q () Int (div X 961))\n(assert (or (> (* X {coef}) {2**64-1}) (> Q {2**32-1}) (> (* Q 961) {2**32-1}) (> (* Q 961) X) (< (- X (* Q 961)) 0) (>= (- X (* Q 961)) 961)))',integer=True)
  math.append({'coefficient':hex(coef),'shift':shift,'numerator_max':limit,'maximum_u64_product':limit*coef,'product_fits_u64':limit*coef<2**64,'maximum_quotient':limit//961,'source_product_width':64,'source_msub_width':32,'remainder_domain':[0,960]})
 solve('low16_extract_preserves961_remainders','(assert (bvule VALUE #x000003c0))\n(assert (distinct ((_ zero_extend 16) ((_ extract 15 0) VALUE)) VALUE))')
 byte_certificates=[{**r,'numerator_domain':[0,4033828 if r['coefficient']==0x443215 else 0xffffffff],'certified_offset_domain':[0,960],'source_root':'F+0xd10','endpoint_attainment_claimed':False}for r in byte_rows]
 bases=[0,71,211,143];known={b+j for b in bases for j in range(16)};initial=set(known);ledger=[];written=set()
 assert len(known)==64
 for i in range(48):
  reads=[i+b for b in READ_BASES];new=[i+b for b in WRITE_BASES];assert set(reads)<=known and not set(new)&known and len(set(new))==4 and not set(new)&set(reads)
  effects=[]
  for label,row in zip(new,word_stores):
   off=0x8b0+4*(227*label%280);assert not written&set(range(off,off+4));written.update(range(off,off+4));effects.append({'site':row['site'],'label':label,'slot':227*label%280,'frame_offset':off})
  ledger.append({'IX':i,'conventional_schedule_position_t':16+i,'read_labels':reads,'new_word_stores':effects,'known_words_before':len(known),'repeat':i<47});known.update(new)
 assert len(known)==256 and known=={b+j for b in bases for j in range(64)}and len(written)==768
 initial_bytes={0x8b0+4*(227*label%280)+j for label in initial for j in range(4)};assert len(initial_bytes)==256 and not initial_bytes&written and len(initial_bytes|written)==1024 and max(written)==0xd0f
 fbytes={r['frame_offset']+j for r in g.frame_writes for j in range(r['width_bits']//8)};assert len(fbytes)==56 and not fbytes&(written|initial_bytes)and max(fbytes)<0x8b0
 scratch=set(range(0xd10,0xd10+961));protected=scratch|{off+j for off,n in[(0x560,8),(0x6bc,4),(0x720,4),(0x728,4),(0x740,8),(0x748,8),(0x750,8),(0x758,8),(0x768,296),(0x1210,8)]for j in range(n)};assert not(fbytes|written)&protected
 # Only the final-index state reaches this seven-instruction next-block prefix.
 after=ExtensionSSA('after_extension',g.r);after.defs=list(g.defs);after.decl=dict(g.decl);after.byte_cells=dict(g.byte_cells);after.loaded=g.loaded;after.decl['CTX']=32;after.save(0x458,'CTX',32,'new next-block frame-input premise');f=fs['after'];after.run(f,int(f['end'],16));assert not after.initial and len(after.sites)==7;models['after']=after
 cert('next_block_low32_reset_and_new_F458_dependent_state',after,[neq(after.loadframe(0x738,32),bv(0,32)),neq(after.loadframe(0x708,32),f'(bvadd (bvsub CTX {g.get("w1")}) #xadcdd50d)')])
 cert('next_block_original_two_stores_and_new_frame_read',after,[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip(after.stores,after.frame_writes)]+[neq(after.reads[0]['address'],frame(0x458))])
 for name,ix in[('first',0),('last',47)]:solve(name+'_iteration_domain','(assert (= IX '+bv(ix,32)+'))',result='sat')
 actual={pc for m in models.values()for pc in m.sites};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==1485
 sem={'source_models':{n:m.record_full()for n,m in models.items()},'source_nonbranch_sites_translated':1485,'selected_traversal_nonbranch_instances':48*1478+7,'input_data_GPRs_u32':DATA_REGS,'incoming_X23_upper32_zero_proved':True,'source_operand_live_in_register_views':[r['register']for r in s['operand_based_GPR_first_reads']['loop']],'iteration_domain':'0<=IX<48;logical t=IX+16','iterations':48,'word_read_source_sites':word_reads,'word_store_source_sites':word_stores,'word_read_label_offsets':READ_BASES,'word_store_label_offsets':WRITE_BASES,'four_stream_bases':bases,'word_grid_slots':280,'word_permutation':227,'iteration_coverage_ledger':ledger,'initial_known_words':sorted(initial),'final_known_words':sorted(known),'initial_word_bytes':256,'new_word_store_operations':192,'new_word_bytes_written':768,'total_populated_words':256,'total_populated_word_bytes':1024,'unpopulated_word_slots':24,'word_read_operations':384,'word_read_bytes':1536,'sigma_identities':[{'name':name,'site':pc,'actual_source_expression':orig,'standard_projection':want,'input_symbol':inp,'sigma':which,'kind':'XOR projection of two registers'if'pair'in name else'affine input/output XOR representation'}for name,pc,orig,want,inp,which in sigma_rows],'sigma_standard_reference':s['standard_reference'],'sigma0':'ROR32(x,7) XOR ROR32(x,18) XOR SHR32(x,3)','sigma1':'ROR32(x,17) XOR ROR32(x,19) XOR SHR32(x,10)','SHA224_and_SHA256_share_these_functions':True,'full_decoded_standard_schedule_recurrence_proved':False,'whole_hash_algorithm_identified':False,'byte_access_certificates':byte_certificates,'reciprocal_integer_certificates':math,'all69_scratch_byte_addresses_bounded':True,'scratch_offset_domain':[0,960],'bounds_need_lookup_value_codomain_assumptions':False,'scratch_lookup_values_proved':False,'scratch_initialized_bank_membership_proved':False,'scratch_byte_reads_per_iteration':69,'scratch_byte_reads_total':3312,'scratch_bytes_preserved':961,'private_frame_store_ledger':g.frame_writes,'frame_store_effects_per_iteration':17,'frame_store_bytes_per_iteration':68,'frame_bytes_written_distinct':56,'new_word_min_frame_offset':min(written),'new_word_max_frame_offset_inclusive':max(written),'additional_former963_scratch_bytes_written':[hex(v)for v in sorted(written&set(range(0xd00,0xd10)))],'F730_meaning':'Saved current IX,0..47;not next IX','W16_after_iteration':'IX+1;48 on exit','F738_meaning':'low32=227*IX;upper32 is not loaded in captured loop','F718_meaning':'decreasing bias c013729f-IX;not the branch termination counter','retained_STATE_F6bc':True,'exit_target':'0x100af5f50','new_after_frame_input':'u32[F+0x458]=CTX;owner/semantic role unknown','after_F708':'CTX-final_W1+adcdd50d mod2^32','after_F738':'low32 zero;no full-u64 clear claimed','incoming_gather_queries_replayed':18,'excluded_exploratory_query':'Aggregate source69-address bounds query returned unknown at15000 ms;excluded. Accepted source shapes,numerator bounds,integer reciprocals,width checks and extraction theorem compose all69 bounds.','negative_bound_control':'A485826 bound is false over the unrestricted abstract byte/state domain;its SAT result is not native target evidence.','native_mapping_proved':False,'native_ownership_proved':False,'native_reachability_proved':False,'successful_output_publication_proved':False,'Mach_port_emissions':0,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['loop'].__setitem__('bytes','00'+q['fragments']['loop']['bytes'][2:])),('wrong_rotate',lambda q:next(i for i in q['fragments']['loop']['instructions']if i['ea']=='0x100c558c8').__setitem__('operands','w2, w16, #0x11')),('wrong_word_read',lambda q:next(i for i in q['fragments']['loop']['instructions']if i['ea']=='0x100c55850').__setitem__('operands','w12, [x21, w11, uxtw #2]')),('wrong_exit',lambda q:q['branch_edges'][1].__setitem__('target','0x0')),('wrong_standard_hash',lambda q:q['standard_reference'].__setitem__('sha256','0'*64)),('wrong_post_width',lambda q:q['fragments']['after']['instructions'][0].__setitem__('operands','xzr, [sp, #0x738]')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':1485,'selected_traversal_nonbranch_instances':70951,'iterations':48,'word_read_operations':384,'new_word_stores':192,'new_word_bytes':768,'total_populated_words':256,'word_grid_slots':280,'scratch_byte_accesses_bounded':69,'scratch_byte_reads':3312,'bounded_reciprocal_sites':56,'full_u32_reciprocal_sites':13,'source_sigma_identities':4,'retained_scratch_bytes':961,'private_frame_stores_per_iteration':17,'private_frame_bytes_written_distinct':56,'primary_standard_bytes':833315,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','recover_daemon_mode_one_record_word_gather.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_lookup_algebra.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'word_extension_bounds_and_exact_small_sigma_components_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
