#!/usr/bin/env python3
"""Universal four-step geometry and post-import ABI with arbitrary plane bytes."""
import copy,json,re,shutil,subprocess,math
from recover_daemon_mode_one_secondary_word_import import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_checkpoint import PostSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
READ_LABELS=[0,1,2,3,593,594,595,596,5,6,7,598,599,597,600,4,8,9,10,11,13,12,605,606,607,14,608,15,602,601,604,603]
WRITE_LABELS=[142,212,72,0,143,213,144,73,1,145,215,75,3,214,74,2]
STREAM_BASES=[0,72,142,212]
def C(j):return 0x8b0+799*j%962
def D(j):return 0xc80+4*(241*j%286)
class ImportSSA(PostSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.divisors=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='udiv':self.divisors.append({'site':i['ea'],'value':self.get(split(i['operands'])[2],32)})
   super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'original_UDIV_denominators':self.divisors}
def dependency_bounds(g,stores):
 # Iterative syntactic upper bounds;these are not nonzero-influence proofs.
 dependencies={n:{n}for n in list(g.decl)+['K','TABLE']+['Z'+str(j)for j in range(31)]}
 for line in g.defs:
  m=re.match(r'\(define-fun ([^ ]+) \(\) \(_ BitVec [0-9]+\) (.*)\)$',line);assert m,line
  tokens=set(re.findall(r'[A-Za-z_][A-Za-z_0-9]*',m[2]));dependencies[m[1]]=set().union(*(dependencies[t]for t in tokens if t in dependencies))
 out=[]
 for row in stores:
  tokens=set(re.findall(r'[A-Za-z_][A-Za-z_0-9]*',row['value']));leaves=set().union(*(dependencies[t]for t in tokens if t in dependencies));out.append({'site':row['site'],'syntactic_input_upper_bound':sorted(leaves),'proves_actual_influence':False})
 return out
def certificates(s):
 pp=[];models={};fs=s['fragments']
 def solve(name,g,terms=(),cc=(),result='unsat'):
  q='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL+''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()+''.join('(assert '+v+')\n'for v in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout[:1000],r.stderr);row={'name':name,'query':q,'result':result,'scope':SCOPE};pp.append(row);print(name,result,flush=True);return row
 parent='daemon_mode_one_word_xor_plane_refresh';old=json.loads(read(ROOT/(parent+'_checks.json')));assert old['all_checks_pass']
 replayed=[p for p in old['proofs']if not p.get('replayed_query',False)or p['name'].endswith('shuffle_root_epoch_control_and_next_ABI')];assert len(replayed)==16
 for row in replayed:
  r=subprocess.run([SOLVER,'-in'],input=row['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr,(row['name'],r.stdout[:1000],r.stderr)
  assert r.stdout.strip()=='unsat'if row['result']=='unsat'else row['result']=='sat'and r.stdout.startswith('sat\n'),(row['name'],r.stdout[:1000])
  pp.append({**row,'name':'replayed_'+parent+'_'+row['name'],'replayed_query':True})
 print('replayed_selected_parent',len(replayed),flush=True)
 # Actual earlier caller supplies W7;seed preserves it. The two literal writes
 # suffice regardless of the unresolved preceding mutation address.
 prior=json.loads(read(ROOT/'daemon_mode_one_parity_state_adapters_source.json'));tog=prior['fragments']['toggle'];ii=[i for i in tog['instructions']if i['ea']in['0x100c2abac','0x100c2abb0']];assert len(ii)==2
 caller=PostSSA('W7_producer');caller.run({'instructions':ii},0x100c2abb4);solve('actual_toggle_literal_W7_producer',caller,[neq(caller.get('x7'),bv(0x883fddf1))]);models['W7_literal_source_slice']=caller
 for label in['join']:
  assert all('7'!=r[1:]for r in prior['register_write_sets'][label]if re.fullmatch('[wx][0-9]+',r))
 parent_source=json.loads(read(ROOT/(parent+'_source.json')))
 assert all('7'!=r[1:]for label in['word_xor','seed']for r in parent_source['register_write_sets'][label]if re.fullmatch('[wx][0-9]+',r))
 byteii=[i for i in fs['import_words']['instructions']if i['mnemonic']=='ldrb'];assert len(byteii)==32
 ll={i['ea']:('RB'+str(j),8)for j,i in enumerate(byteii)};ll['0x100d53b8c']=('CFN',64)
 regs={15:z('(bvmul QUAD '+bv(16,32)+')'),3:z('(bvmul QUAD '+bv(4,32)+')'),4:bv(799),7:bv(0x883fddf1),16:bv(962),14:bv(241),21:frame(0x8b0),27:frame(0xc80)}
 presets={0x740:('TABLE',64),0x750:(frame(0xc80),64),0x758:(frame(0x8b0),64),0x6cc:(bv(0x1f61,32),32),0x6c4:(bv(0x8b7a81df,32),32),0x6c8:(bv(962,32),32)}
 g=ImportSSA('free_consumer',regs,presets=presets,loads=ll);g.decl.update(QUAD=32,CFN=64,**{'RB'+str(j):8 for j in range(32)});g.run(fs['import_words'],int(fs['import_words']['instructions'][-1]['ea'],16));models['import_words']=g
 frame_sites={r['site']for r in g.frame_writes};words=[r for r in g.stores if r['site']not in frame_sites];bytes_read=[r for r in g.reads if r['width_bits']==8];target=next(r for r in g.reads if r['site']=='0x100d53b8c');assert len(words)==16 and all(r['width_bits']==32 for r in words)
 assert(len(g.sites),len(g.reads),len(g.frame_reads),len(g.stores),len(g.frame_writes),len(g.initial),len(g.cuts))==(1470,89,56,37,21,0,0)
 assert not g.alias_records and not g.indexed_records and not g.pairs and not g.pair_loads
 rr={r['site']:r for r in g.reads};ss={r['site']:r for r in g.stores};frame_terms=[neq(rr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_reads]+[neq(ss[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_writes]
 ledger=[];all_primary=set();all_words=set()
 for q in range(4):
  ro=[C(label+16*q)for label in READ_LABELS];wo=[D(label+4*q)for label in WRITE_LABELS];slot=0x1f73 if q<3 else 0x1f61
  constants={3:4*(q+1),4:799,7:0x883fddf1,14:241,15:16*(q+1),16:962}
  terms=[neq(r['address'],frame(off))for r,off in zip(bytes_read+words,ro+wo)]+[neq(target['address'],at(slot))]+[neq(g.get('x'+str(k)),bv(v))for k,v in constants.items()]+[neq(g.get('x21'),frame(0x8b0)),neq(g.get('x27'),frame(0xc80))]
  solve('quad'+str(q)+'_all_original_byte_word_addresses_counters_and_target',g,terms,cc=['(= QUAD '+bv(q,32)+')'])
  ledger.append({'quad':q,'entry_byte_cursor':16*q,'entry_word_cursor':4*q,'read_ledger':[dict(r,coordinate_label=label+16*q,frame_offset=off)for r,label,off in zip(bytes_read,READ_LABELS,ro)],'word_store_ledger':[dict(r,coordinate_label=label+4*q,frame_offset=off)for r,label,off in zip(words,WRITE_LABELS,wo)],'outgoing_register_constants':constants,'slot':hex(slot),'target':'0x100d524a8'if q<3 else'0x100d85430'})
  assert len(set(ro))==32 and not all_primary&set(ro);all_primary.update(ro)
  assert len(set(wo))==16 and not all_words&set(wo);all_words.update(wo)
 solve('all_literal_frame_addresses_first_divisor_and_terminal_modifier',g,frame_terms+[neq(g.divisors[0]['value'],bv(962,32)),neq(g.get('x17'),bv(0xcf0c))])
 # Second divisor is a masked-subset identity. The source-preserving slice
 # avoids conjoining its diagnostic equality with the large geometry query.
 pcs={0x100d5294c,0x100d52950,0x100d529c0,0x100d529c4,0x100d529c8};slice_ii=[i for i in fs['import_words']['instructions']if int(i['ea'],16)in pcs];assert len(slice_ii)==5
 assert not[i for i in fs['import_words']['instructions']if 0x100d52950<int(i['ea'],16)<0x100d529c0 and i['mnemonic']not in['str','strb','cmp','tst']and split(i['operands'])[0]in['w1','x1','w22','x22']]
 denom=PostSSA('masked_divisor');denom.run({'instructions':slice_ii},0x100d529cc);solve('second_UDIV_masked_subset_source_identity_arbitrary_W1',denom,[neq(denom.get('w19'),bv(962,32))]);models['second_divisor_preserving_source_slice']=denom
 assert len(all_primary)==128 and all_primary=={C(j)for j in list(range(64))+list(range(593,657))}
 labels={base+j for base in STREAM_BASES for j in range(16)};assert len(labels)==64 and all_words=={D(j)for j in labels}and math.gcd(241,286)==1 and pow(241,-1,286)==197
 word_bytes={o+j for o in all_words for j in range(4)};assert len(word_bytes)==256 and max(word_bytes)==0x10c7 and min(word_bytes)==0xc80
 fw={r['frame_offset']+j for r in g.frame_writes for j in range(r['width_bits']//8)};assert len(fw)==76 and max(fw)==0x74b and min(fw)==0x6d0 and not fw&word_bytes
 arithmetic={C(j)for a,b in[(72,328),(333,589),(659,675),(677,933),(936,952)]for j in range(a,b)};assert len(arithmetic)==800 and not all_primary&arithmetic
 protected=[(0x350,8),(0x358,8),(0x360,8),(0x368,16),(0x380,16),(0x6c4,4),(0x6c8,4),(0x6cc,4),(0x740,8),(0x750,16),(0x768,296),(0x8b0,962)]
 assert all(not(fw|word_bytes)&set(range(o,o+n))for o,n in protected)
 # The consumer has no data-word loads,only32 arbitrary primary bytes and
 # known private frame inputs. Array values are retained as exact source SSA.
 assert all(r['width_bits']==8 or r['site']in{v['site']for v in g.frame_reads}|{'0x100d53b8c'}for r in g.reads)
 nxt=PostSSA('post_import',g.r,loads={'0x100d854b8':('PFN',64)});nxt.defs=list(g.defs);nxt.decl=dict(g.decl);nxt.decl.update(PFN=64,ENC0=8);nxt.byte_cells=dict(g.byte_cells);nxt.save(0xa36,'ENC0',8,'raw inherited primary ENC0 cell');before={j:g.get('x'+str(j))for j in[13,24,26,28,30]};nxt.run(fs['post_import'],int(fs['post_import']['instructions'][-1]['ea'],16));models['post_import_chained_to_quad3']=nxt
 assert(len(nxt.sites),len(nxt.reads),len(nxt.stores),len(nxt.frame_writes),len(nxt.initial))==(64,4,6,6,0)
 b=z('ENC0');tau='(bvsub ((_ zero_extend 24) ENC0) (bvand (bvshl ((_ zero_extend 24) ENC0) #x00000001) #x000000b0))';phi='(bvxor (bvadd (bvshl '+tau+' #x00000004) #x4546e580) #xb6c257ca)'
 pc={1:0xe525982b,2:0x7293,3:286,4:0x5f521b8d,12:0,15:0x879,17:0x5b22,20:0xdf2,22:0xd6a4,23:47,24:0xd4c2}
 fields={0x6bc:0x1ef1,0x530:0xa9d0,0x6a8:286}
 nrr={r['site']:r for r in nxt.reads};nss={r['site']:r for r in nxt.stores};terms=[neq(nxt.get('x'+str(k)),bv(v))for k,v in pc.items()]+[neq(nxt.loadframe(off,32),bv(v,32))for off,v in fields.items()]+[neq(nxt.get('x21'),frame(0x8b0)),neq(nxt.get('x27'),frame(0xc80)),neq(nxt.get('x11'),before[24]),neq(nxt.get('x30'),before[24]),neq(nxt.get('x26'),before[28]),neq(nxt.get('x7'),before[30]),neq(nxt.loadframe(0x738,32),'(bvadd ((_ extract 31 0) '+before[13]+') #xbf6c09d3)'),neq(nxt.loadframe(0x730,32),'((_ extract 31 0) '+before[26]+')'),neq(nxt.loadframe(0x6b0,32),phi),neq(nrr['0x100d854b8']['address'],at(0x1ef1))]+[neq(nrr[r['site']]['address'],frame(r['frame_offset']))for r in nxt.frame_reads]+[neq(nss[r['site']]['address'],frame(r['frame_offset']))for r in nxt.frame_writes]
 solve('post_quad3_exact_control_handoff_six_frame_fields_and_raw_u8_function',nxt,terms,cc=['(= QUAD #x00000003)'])
 solve('post_encoder_nibble_simplification_only_under_u4_premise',nxt,[neq(nxt.loadframe(0x6b0,32),'(bvxor (bvshl ((_ zero_extend 24) ENC0) #x00000004) #xf384b24a)')],cc=['(= QUAD #x00000003)','(bvult ENC0 #x10)'])
 # Retain the rejected exploratory hypothesis as an explicit negative control.
 solve('post_F738_equal16_is_not_a_universal_contract',nxt,[neq(nxt.loadframe(0x738,32),bv(16,32))],cc=['(= QUAD #x00000003)'],result='sat')
 nw={r['frame_offset']+j for r in nxt.frame_writes for j in range(r['width_bits']//8)};assert len(nw)==24 and len(nw-fw)==16 and not nw&word_bytes and not nw&arithmetic
 assert all(not nw&set(range(o,o+n))for o,n in protected)
 actual=set(g.sites)|set(nxt.sites);expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==1534
 read_bytes=sum(r['width_bits']//8 for r in g.reads);store_bytes=sum(r['width_bits']//8 for r in g.stores);assert(read_bytes,store_bytes)==(416,168)
 sem={'source_models':{n:m.record_full()for n,m in models.items()},'immediate_parent_queries_replayed':len(replayed),'immediate_parent_all_queries_replayed':False,'immediate_parent_direct_queries_all_replayed':True,'inherited_control_GPRs':{'W4':799,'W7':'0x883fddf1','W14':241,'W16':962,'X21':'F+0x8b0','X27':'F+0xc80'},'all_other_entry_GPRs':'Arbitrary64-bit Z0..Z30,except the two explicit u32 cursor expressions;no R0/R19/R30 value restriction.','inherited_frame_presets':{hex(off):{'value':v,'width_bits':w}for off,(v,w)in presets.items()},'counter_domain':[0,1,2,3],'counter_contract':'entry W15=16*q,W3=4*q;exit W15=16*(q+1),W3=4*(q+1);q0..2 repeat,q3 exits','primary_coordinate':'C(j)=F+0x8b0+((799*j)mod962)','secondary_coordinate':'D(j)=F+0xc80+4*((241*j)mod286)','secondary_inverse_multiplier':197,'read_label_order_at_quad0':READ_LABELS,'write_label_order_at_quad0':WRITE_LABELS,'stream_coordinate_bases':STREAM_BASES,'stream_words_each':16,'coordinate_labels_written':sorted(labels),'iteration_ledger':ledger,'word_value_dependency_upper_bounds':dependency_bounds(g,words),'word_numeric_transform_decoded':False,'four_stream_plaintext_or_mutual_equivalence_proved':False,'array_word_loads':0,'array_word_store_sites':[r['site']for r in words],'private_frame_store_ledger':g.frame_writes,'private_frame_distinct_written_bytes':76,'private_frame_u32_store_effects':16,'private_frame_u64_store_effects':5,'per_iteration_loads':89,'per_iteration_stores':37,'per_iteration_read_bytes':416,'per_iteration_store_bytes':168,'four_iterations_byte_reads':128,'four_iterations_word_stores':64,'four_iterations_array_bytes_written':256,'four_iterations_distinct_written_bytes':332,'four_iterations_load_operations':356,'four_iterations_store_operations':148,'four_iterations_read_bytes':1664,'four_iterations_store_bytes':672,'source_value_cuts':0,'computed_address_normalizations':0,'initial_unprescribed_frame_inputs':0,'arithmetic_cells_read_by_import':0,'arithmetic_cells_written':0,'secondary_unclaimed_coordinate_slots':222,'secondary_coordinate_capacity_is_allocation_extent_proof':False,'primary_domain_end_exclusive':'F+0xc72','secondary_root':'F+0xc80','inter_root_gap_bytes':14,'written_secondary_last_byte':'F+0x10c7','protected_frame_ranges':[{'offset':o,'size_bytes':n}for o,n in protected],'post_raw_encoder_cell_coordinate':936,'post_raw_encoder_cell_frame_offset':0xa36,'post_raw_encoder_value':'Arbitrary u8 ENC0;earlier codec-validity proof not carried across prior mutation','post_encoder_function_u32':phi,'post_encoder_u4_simplification':'(ENC0<<4) XOR0xf384b24a,conditional ENC0<16','post_frame_constants':{hex(k):hex(v)for k,v in fields.items()},'post_F738':'u32(incoming W13+0xbf6c09d3);not proved equal16','post_F730':'incoming W26,low32;numeric meaning unknown','post_register_constants':pc,'post_slot':'0x1ef1','post_target':'0x100c503c8','post_target_body_translated':False,'post_control_diversity':'0x5b22','post_load_operations':4,'post_store_operations':6,'post_read_bytes':21,'post_store_bytes':24,'combined_four_imports_and_post_loads':360,'combined_four_imports_and_post_stores':154,'combined_four_imports_and_post_read_bytes':1685,'combined_four_imports_and_post_store_bytes':696,'combined_four_imports_and_post_distinct_written_bytes':348,'LOCAL_pointer_dereferences':0,'Mach_port_emissions':0,'IDA_snapshot_semantic_memory_claims_imported':0,'IDA_complete_code_identity_proved':False,'whole_cryptographic_algorithm_identified':False,'native_ownership_proved':False,'successful_output_proved':False,'daemon_kext_pairing_proved':False,'native_claim':False,'excluded_exploration':'An initial all54-parent-query replay stopped on unknown at15000ms in a recursively inherited coherent_install_original_normalized_addresses query;that attempt is not a certificate and the accepted selection is all15 direct parent queries plus the saved-root producer. Combined geometry/denominator and geometry/literal-frame diagnostics returned unknown at15000ms;split geometry queries also reached the15-second limit in case2;accepted new queries use a45000ms solver limit and50000ms process limit with explicit simplify/bit-blast/sat tactics;the accepted geometry and literal-frame/control queries are split;the second divisor is instead established by a five-instruction source-preserving arbitrary-W1 identity,without cutting or modifying the full geometry SSA. Initial candidate comparison used string register keys as integers and compared root values without F;corrected before accepted proofs. Exploratory F738==16 has a SAT counterexample and is expressly excluded. Full IDB byte batch timed out after300s;subsequent file probe found no authenticated worker;neither supplies source identity.'}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['import_words'].__setitem__('bytes','00'+q['fragments']['import_words']['bytes'][2:])),('wrong_repeat_target',lambda q:q['branch_edges'][0].__setitem__('target','0x0')),('wrong_post_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('wrong_UDIV_width',lambda q:q['UDIV_decode_checks'][0].__setitem__('width_bits',64)),('wrong_bitfield_width',lambda q:q['bitfield_decode_checks'][0].__setitem__('source_count',0)),('wrong_root_lineage',lambda q:q['prior_recaptures'][-1].__setitem__('sha256','0'*64)),('invent_full_IDB_equivalence',lambda q:q['IDA_observation_snapshot'].__setitem__('full_container_slice_equivalence_verified',True)),('invent_native',lambda q:q.__setitem__('target_executed',True))];original=build();out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert q!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':1534,'fresh_caller_literal_sites':2,'induction_cases':4,'independent_byte_inputs_per_case':32,'plane_bytes_read_once':128,'secondary_word_stores':64,'secondary_bytes_written':256,'secondary_streams':4,'secondary_words_per_stream':16,'unclaimed_secondary_coordinates':222,'initial_unprescribed_frame_inputs':0,'source_value_cuts':0,'computed_address_normalizations':0,'UDIV_denominator_source_slice_sites':5,'per_iteration_loads':89,'per_iteration_stores':37,'four_iterations_loads':356,'four_iterations_stores':148,'four_iterations_read_bytes':1664,'four_iterations_store_bytes':672,'four_iterations_distinct_bytes_written':332,'post_loads':4,'post_stores':6,'combined_read_bytes':1685,'combined_store_bytes':696,'combined_distinct_bytes_written':348,'IDA_spot_bytes_matched':96,'IDA_semantic_memory_claims_imported':0,'arithmetic_cells_read_by_import':0,'arithmetic_cells_written':0,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','validate_daemon_mode_one_word_schedule.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'secondary_word_import_geometry_and_post_ABI_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
