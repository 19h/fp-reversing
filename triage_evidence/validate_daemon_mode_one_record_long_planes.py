#!/usr/bin/env python3
"""Prove full long-plane source effects with universal intermediate overapproximations."""
import copy,json,re,subprocess,shutil,functools
from recover_daemon_mode_one_record_long_planes import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_join import JoinSSA
from validate_daemon_existing_scalar_reader import DECL,bv,frame,neq,at
from daemon_mode_one_handoff_tools import parse
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
EXTRA='(declare-fun COUNT () (_ BitVec 32))\n'
INDEXED={0x100c89214:(0xd3f,600),0x100c89528:(0xfe3,None),0x100c89728:(0xec6,892),0x100c89844:(0xe67,1152),0x100c8aa88:(0xf29,2367)}
class LongSSA(JoinSSA):
 def __init__(self,*args,**kw):super().__init__(*args,**kw);self.indexed_stores=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   row=i
   if pc in INDEXED:
    off,_=INDEXED[pc];p=split(i['operands']);assert i['mnemonic']=='strb'
    self.indexed_stores.append({'site':i['ea'],'original_address':self.address(p[1]),'frame_offset':off})
    row={**i,'operands':p[0]+', [sp, #'+hex(off)+']'}
   super().run({'instructions':[row]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'indexed_store_normalizations':self.indexed_stores}
def certificates(s):
 pp=[];fs=s['fragments'];f=fs['initializer']
 def solve(name,body,result='unsat',cc=()):
  query='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+body+'\n'+''.join('(assert '+v+')\n'for v in cc)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=20)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':query,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def cert(name,g,tt,cc=()):solve(name,g.prefix()+'(assert (or '+' '.join(tt)+'))',cc=cc)
 # Freshly recapture both incoming sources and replay the seven exact
 # incoming-state/control/store contracts needed by this long-only increment.
 from recover_daemon_mode_one_record_input_planes import build as previous_build
 from recover_daemon_mode_one_record_join import build as join_build
 old=previous_build();assert old==json.loads(read(ROOT/DEPS[0]));assert join_build()==json.loads(read(ROOT/DEPS[2]));prior=json.loads(read(ROOT/DEPS[1]))
 selected={'replayed_join_unsigned_COUNT64_controls_original_branch_slots','replayed_join_outgoing_constant_words_and_branch_ABI','actual_join_supplies_both_successor_control_fields','long_joining_fields_select_equality_edge_and_new_state_spill','long_handoff_new_frame_epoch_and_plane_initializer_ABI','long_all_word_stores_have_original_private_addresses','long_setup_all_word_stores_have_original_private_addresses'};done=set()
 for v in prior['proofs']:
  if v['name']not in selected:continue
  r=subprocess.run([SOLVER,'-in'],input=v['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat',(v['name'],r.stdout,r.stderr)
  pp.append({**v,'name':'replayed_input_planes_'+v['name'],'replayed_query':True});done.add(v['name']);print('replayed_'+v['name'],'unsat',flush=True)
 assert done==selected
 # W24=0x23 is established in the join and neither long prelude nor handoff
 # writes W24/X24. Earlier proofs already cover the other constant arguments.
 join=json.loads(read(ROOT/DEPS[3]))['semantics']['source_model']
 decl=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in join['declarations'].items())
 from validate_daemon_mode_one_record_join import EXTRA as JOIN_EXTRA
 solve('original_join_supplies_W24_23',JOIN_EXTRA.replace(EXTRA,'')+decl+join['source_SSA']+'(assert '+neq('((_ extract 31 0) '+join['final_registers']['24']+')',bv(0x23,32))+')')
 for label in ['long','long_setup']:assert not{'x24','w24'}&set(old['register_write_sets'][label])
 assert not{'x19','w19'}&set(old['register_write_sets']['long_setup'])
 assert {r['register']for r in s['live_in_GPR_read_sites']['initializer']}=={'w'+str(n)for n in[19,9,0,10,6,2,5,4,1,23,24,22,27,21]}
 initial={19:bv(0x4923),8:bv(0x7f3081c2),23:bv(0xc8),22:bv(0x5c),21:bv(0x74),27:bv(0x16),24:bv(0x23)}
 presets={0x728:('COUNT',32),0x18:(bv(0x53921748,32),32),0x740:('TABLE',64),0x750:(frame(0xd10),64)}
 args=dict(presets=presets,loads={'0x100c8c55c':('FN',64)})
 raw=JoinSSA('long_init',initial,**args);raw.run(f,int(f['instructions'][-1]['ea'],16));assert not raw.initial and not raw.decl
 # Replacing a single 32-bit internal definition by a free value broadens its
 # domain. No equality to a selected valuation or desired result is asserted.
 cuts=[]
 for pc,(off,num)in INDEXED.items():
  source=raw.prefix();record={'site':hex(pc),'frame_offset':off,'overapproximation':None}
  if num is not None:
   key='long_init_v'+str(num);lines=source.splitlines();hits=[line for line in lines if parse(line)[1]==key];assert len(hits)==1 and parse(hits[0])[3]==['_','BitVec','32']
   source='\n'.join('(declare-fun '+key+' () (_ BitVec 32))'if line==hits[0]else line for line in lines)+'\n';record['overapproximation']={'symbol':key,'width_bits':32,'removed_definition':hits[0],'replacement':'unconstrained u32;universal overapproximation,not a concrete source cut'}
  row=next(r for r in raw.stores if r['site']==hex(pc));record['original_address']=row['address']
  solve('original_indexed_store_address_'+hex(pc),source+'(assert '+neq(row['address'],frame(off))+')');cuts.append(record)
 g=LongSSA('long_init',initial,**args);g.run(f,int(f['instructions'][-1]['ea'],16));assert g.prefix()==raw.prefix()and len(g.alias_records)==27 and len(g.indexed_stores)==5
 cert('all27_literal_private_frame_aliases',g,[neq(row['original_address'],frame(row['frame_offset']))for row in g.alias_records])
 assert len(g.stores)==len(g.frame_writes)==131 and len(g.reads)==6 and len(g.frame_reads)==5 and len(g.external)==1
 cert('all131_normalized_store_addresses',g,[neq(row['address'],frame(fr['frame_offset']))for row,fr in zip(g.stores,g.frame_writes)])
 cert('all_five_saved_frame_read_addresses',g,[neq(next(r for r in g.reads if r['site']==fr['site'])['address'],frame(fr['frame_offset']))for fr in g.frame_reads])
 phase730=((0x4923+0x401226d9)&0xffffffff)&0xbfedf7f3;phase620=((0x4923+0x64d9343c)&0xffffffff)&0x9b26bead
 cert('three_saved_word_replacements_and_branch_ABI',g,[neq(g.loadframe(0x738,32),bv(0x4923,32)),neq(g.loadframe(0x730,32),bv(phase730,32)),neq(g.loadframe(0x620,32),bv(phase620,32)),neq(g.get('x10'),'FN'),neq(g.get('x17'),bv(0x6307)),neq(g.get('x6'),bv(0x53921748)),neq(g.get('w4'),bv(0x39c7500a,32))])
 branch=next(r for r in g.reads if r['site']=='0x100c8c55c')
 cert('exact_unsigned_COUNT64_retest',g,[neq(branch['address'],f'(ite (bvult COUNT #x00000040) {at(0xb1fc)} {at(0xb217)})')])
 cert('actual_long_entry_excludes_short_edge',g,[neq(branch['address'],at(0xb217))],['(bvuge COUNT #x00000040)'])
 # This is a syntactic upper bound on dependencies,not a proof of influence.
 defs={a[1]:a[-1]for a in map(parse,g.prefix().splitlines())};declared=set(re.findall(r'\(declare-fun (\w+) ',DECL+EXTRA))
 @functools.lru_cache(None)
 def atom(a):return walk(defs[a])if a in defs else{a}if a in declared else set()
 def walk(a):return set().union(*(walk(v)for v in a))if isinstance(a,list)else atom(a)
 banks=[{'Z0','Z6','Z9','Z10'},{'Z1','Z2','Z4','Z5'}];ledger=[];coordinates=set();plane_domains={0:set(),1:set()}
 for row in g.frame_writes:
  if row['width_bits']!=8:continue
  label=((row['frame_offset']-0xd10)*pow(866,-1,961))%961;assert label not in coordinates;coordinates.add(label)
  deps=walk(parse(row['value']));assert deps in banks;plane=0 if 896<=label<960 else 1;index=label-(896 if plane==0 else 827);assert 0<=index<64
  domain=banks.index(deps);plane_domains[plane].add(domain);ledger.append({**row,'coordinate_label':label,'plane':plane,'index':index,'declared_dependency_upper_bound':sorted(deps),'input_bank':domain})
 assert coordinates==set(range(896,960))|set(range(827,891))and len(ledger)==128 and plane_domains=={0:{0},1:{1}}
 written={r['frame_offset']+j for r in g.frame_writes for j in range(r['width_bits']//8)};cells={r['frame_offset']for r in ledger};assert len(written)==140 and len(cells)==128
 retained={0xd10+(base+866*j)%961 for base,n in[(0x77086,256),(0x368c4,256),(0,256),(0x73704,16),(0x6e272,16)]for j in range(n)};assert len(retained)==800 and not written&retained
 protected={off+j for off,n in[(0x18,4),(0x2b8,8),(0x2c0,8),(0x388,8),(0x4d8,8),(0x568,8),(0x580,8),(0x588,8),(0x728,4),(0x740,8),(0x748,8),(0x750,8),(0x768,296),(0x1210,8)]for j in range(n)};assert not written&protected
 actual=set(g.sites);expected={i['ea']for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(g.sites)==len(actual)==4174
 for label,c in [('zero',0),('last_short',63),('first_long',64),('max',0xffffffff)]:solve(label+'_abstract_COUNT_domain','(assert (= COUNT '+bv(c,32)+'))',result='sat')
 sem={'source_model':g.record_full(),'original_indexed_store_address_overapproximations':cuts,'source_nonbranch_sites_translated':len(actual),'predecessor_replay_scope':'Seven selected incoming-state/control/store queries;other historical proofs are retained provenance and are not claimed refreshed. A broad exploratory replay ended on an unrelated earlier byte-loop timeout and is excluded.','excluded_exploratory_unknowns':'Monolithic/direct source-address attempts and an unrelated earlier predecessor byte-loop timeout are excluded;only exact accepted results are counted.','W24_origin':'original join W24=23;long prelude/handoff write sets exclude W24 and X24','incoming_constant_registers_u64':{str(k):v for k,v in initial.items()},'input_bank_registers':[[0,6,9,10],[1,2,4,5]],'plane_dependency_domains':{str(k):sorted(v)for k,v in plane_domains.items()},'plane_store_ledger':ledger,'coordinate_rule':'F+d10+((866*(base+i))mod961),base0=896,base1=827,0<=i<64','dependency_membership_proves_influence':False,'whole_compact_byte_function_proved':False,'old_plane_bytes_read':0,'new_record_byte_reads':0,'byte_stores':128,'word_stores':3,'logical_store_effects':131,'distinct_store_bytes':140,'frame_loads':5,'branch_pointer_loads':1,'read_bytes':sum(r['width_bits']//8 for r in g.reads),'old_plane_values_fully_replaced':True,'retained_arithmetic_and_codebook_cells':800,'saved_roots_workspace_count_and_budget_preserved':True,'F738':hex(0x4923),'F730':hex(phase730),'F620':hex(phase620),'COUNT_lt64_target':'0x100c4a194','COUNT_ge64_target':'0x100c9148c','actual_long_entry_target':'0x100c9148c','both_branch_IA_diversity':'0x6307','Mach_port_emissions':0,'native_reachability_proved':False,'successful_output_publication_proved':False,'whole_algorithm_identified':False,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['initializer'].__setitem__('bytes','00'+q['fragments']['initializer']['bytes'][2:])),('wrong_indexed_store',lambda q:next(v for v in q['fragments']['initializer']['instructions']if v['ea']=='0x100c89214').__setitem__('operands','w14, [x28, x14]')),('wrong_long_target',lambda q:q['branch_edges'][1].__setitem__('target','0x0')),('wrong_short_PAC',lambda q:q['branch_edges'][0].__setitem__('IA_diversity','0x1c91')),('wrong_parent_hash',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(v['result']=='unsat'for v in pp),'queries_sat':sum(v['result']=='sat'for v in pp),'predecessor_queries_replayed':sum(v.get('replayed_query',False)for v in pp),'source_nonbranch_sites_translated':4174,'frame_alias_normalizations':27,'indexed_store_normalizations':5,'universal_intermediate_overapproximations':4,'plane_byte_stores':128,'u32_stores':3,'logical_store_effects':131,'distinct_store_bytes':140,'arithmetic_and_codebook_cells_retained':800,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','recover_daemon_mode_one_record_input_planes.py','validate_daemon_mode_one_record_input_planes.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'long_record_plane_replacement_and_COUNT64_retest_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
