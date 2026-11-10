#!/usr/bin/env python3
"""Static four-round plane gathering,280-slot word grid and typed encoder handoff."""
import copy,json,re,subprocess,shutil,functools
from recover_daemon_mode_one_record_word_gather import ROOT,P,SCOPE,FLAGS,DEPS,LINEAGE,LINEAGE_SOURCES,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_join import JoinSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,neq,at
from validate_daemon_list_output import split
from daemon_mode_one_handoff_tools import parse
SOLVER=shutil.which('z3');assert SOLVER
DATA=[0x6cc,8,0x10,0x6c4,0x6c0,0xc,0x6bc,0x6c8]
EXTRA='(declare-fun NIB0 () (_ BitVec 4))\n'
class GatherSSA(JoinSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.extra_lowerings=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   p=split(i['operands']);m=i['mnemonic']
   if m=='ldp':
    assert pc==0x100b8ef04 and p==['w27','w24','[sp, #0xc]'];self.extra_lowerings.append({'site':i['ea'],'kind':'two_u32_loads','frame_offsets':[0xc,0x10]})
    for j in range(2):super().run({'instructions':[{**i,'mnemonic':'ldr','operands':p[j]+', [sp, #'+hex(0xc+4*j)+']'}]},pc+4)
    self.sites.pop()
   elif m=='ldr'and p[1]=='[sp, #8]':
    self.extra_lowerings.append({'site':i['ea'],'kind':'decimal_SP_load','frame_offset':8,'original_address':self.address(p[1])});super().run({'instructions':[{**i,'operands':p[0]+', [sp, #0x8]'}]},pc+4)
   else:super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'additional_source_lowerings':self.extra_lowerings}
def census(source,declared,expressions):
 defs={d[1]:d[-1]for d in map(parse,source.splitlines())}
 @functools.lru_cache(None)
 def atom(a):return{a}if a in declared else walk(defs[a])if a in defs else set()
 def walk(a):return set().union(*(walk(v)for v in a))if isinstance(a,list)else atom(a)
 return[sorted(walk(parse(e)))for e in expressions]
def certificates(s):
 pp=[];models={};fs=s['fragments'];rounds=[]
 def solve(name,body,result='unsat',values=None,extra=''):
  query='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+extra+body+'\n(check-sat)\n'
  if values is not None:query+='(get-value ('+' '.join(values)+'))\n'
  r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr,(name,r.stdout,r.stderr);v={'name':name,'query':query,'result':result,'scope':SCOPE}
  if values is None:assert r.stdout.strip()==result,(name,r.stdout)
  else:
   assert result=='sat'and r.stdout.startswith('sat\n'),(name,r.stdout);rows=parse(r.stdout[4:]);assert len(rows)==len(values);v['model_value_hex']=[row[-1]for row in rows];assert all(re.fullmatch('#x[0-9a-f]+',x)for x in v['model_value_hex'])
  pp.append(v);print(name,result,flush=True);return v
 def decl(g):return''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())
 def cert(name,g,tt):return solve(name,g.prefix()+'(assert (or '+' '.join(tt)+'))',extra=decl(g))
 def run(g,label):g.run(fs[label],int(fs[label]['instructions'][-1]['ea'],16)if label in['seed','loop','exit']else int(fs[label]['end'],16));assert not g.initial;return g
 def chained(old,label):
  g=GatherSSA(label,old.r);g.defs=list(old.defs);g.decl=dict(old.decl);g.byte_cells=dict(old.byte_cells);g.loaded=old.loaded;return g
 # Only incoming memory/control/exit contracts are needed:the current byte
 # inputs and eight state words are universally abstract,not replaced by a
 # presumed compact predecessor function or plaintext relation.
 from recover_daemon_mode_one_record_long_prefix import build as previous_build
 assert previous_build()==json.loads(read(ROOT/DEPS[0]));prior=json.loads(read(ROOT/DEPS[1]))
 selected={'seed_all47_original_store_and_three_frame_read_addresses','exit_pair_reloads_biased64_advances_state_reload_and_target','exit_both_stores_and_all_five_original_frame_reads'}|{'round'+str(q)+'_'+n for q in range(4)for n in['all80_original_byte_addresses','all64_private_stores_and131_frame_reads','exact_branch_counter_and_saved_phase']};done=set()
 for v in prior['proofs']:
  if v['name']not in selected:continue
  r=subprocess.run([SOLVER,'-in'],input=v['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat',(v['name'],r.stdout,r.stderr);pp.append({**v,'name':'replayed_prefix_'+v['name'],'replayed_query':True});done.add(v['name']);print('replayed_'+v['name'],'unsat',flush=True)
 assert done==selected and len(done)==15
 # Verify root producers and retain a full literal/normalized frame-write
 # census. Older computed byte stores retain their source-proved scratch-bank
 # domains;all historical solver obligations are not claimed refreshed.
 roots={off+j for off in[0x560,0x758]for j in range(8)};lineage=[]
 for file,source_file in zip(LINEAGE,LINEAGE_SOURCES):
  c=json.loads(read(ROOT/file));assert c['all_checks_pass'];sem=c['semantics'];mm=sem.get('source_models',{'single':sem.get('source_model',{})});rows=[]
  for label,m in mm.items():
   for row in m.get('frame_writes',[]):
    if file=='daemon_mode_one_record_scan_checks.json'and label=='seed':continue
    assert not set(range(row['frame_offset'],row['frame_offset']+row['width_bits']//8))&roots;rows.append(row)
  literal=[];src=json.loads(read(ROOT/source_file))
  for label,f in src['fragments'].items():
   for i in f['instructions']:
    if i['mnemonic']not in['str','strb','stp','stur']:continue
    p=split(i['operands']);a=p[-1];m=re.fullmatch(r'\[sp(?:, #(0x[0-9a-f]+|[0-9]+))?\]',a)
    if not m:continue
    off=int(m[1],0)if m[1]else 0;w=1 if i['mnemonic']=='strb'else(4 if p[0].startswith('w')else 8)*(2 if i['mnemonic']=='stp'else 1)
    if set(range(off,off+w))&roots:
     assert source_file=='daemon_mode_one_record_scan_source.json'and i['ea']=='0x100a7654c'and off==0x560 and w==8
    literal.append({'site':i['ea'],'frame_offset':off,'width_bytes':w})
  lineage.append({'checks':file,'checks_sha256':sha(ROOT/file),'source':source_file,'source_sha256':sha(ROOT/source_file),'normalized_frame_store_instances_checked':len(rows),'literal_source_stores_checked':len(literal),'both_roots_preserved_after_original_biased_view_seed':True,'computed_historical_byte_store_bounds':'Retained prior source certificates place stores in the established scratch banks;not all historical queries are refreshed.'})
 biased=run(GatherSSA('biased_root',presets={0x740:('TABLE',64)},loads={'0x100a7653c':('FN',64)}),'biased_view');models['biased_view']=biased
 cert('original_record_seed_biased_view_root_and_T',biased,[neq(biased.loadframe(0x560,64),frame(0xbe2f2)),neq(biased.get('x26'),frame(0xd10)),neq(biased.stores[0]['address'],frame(0x560))])
 view=run(GatherSSA('word_root'),'word_view');models['word_view']=view
 cert('original_private_word_view_root',view,[neq(view.loadframe(0x758,64),frame(0x8b0)),neq(view.stores[0]['address'],frame(0x758))])
 # The I(0) byte is kept abstract. A separate typed corollary uses its prior
 # established E0(Rout(0)) representation;Rout(0) is not assumed zero.
 codecs=json.loads(read(ROOT/'daemon_mode_one_record_codecs_checks.json'));assert codecs['all_checks_pass']and codecs['semantics']['output_encoder_offsets'][0]==0x1dd
 code_names={'encode_complete_source_step_IO_control_and_root','encode_strictly_increasing_bounded_loop'};done=set()
 from recover_daemon_mode_one_record_codecs import build as codec_build
 assert codec_build()==json.loads(read(ROOT/'daemon_mode_one_record_codecs_source.json'))
 for v in codecs['proofs']:
  if v['name']not in code_names:continue
  r=subprocess.run([SOLVER,'-in'],input=v['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**v,'name':'replayed_codebook_'+v['name'],'replayed_query':True});done.add(v['name'])
 assert done==code_names
 presets={0x740:('TABLE',64),0x560:(frame(0xbe2f2),64),0x750:(frame(0xd10),64),0x758:(frame(0x8b0),64),0xeed:('B0',8),**{off:('J'+str(j),32)for j,off in enumerate(DATA)}}
 seed=GatherSSA('gather_seed',{10:bv(0x4923),11:z('J0')},presets=presets,loads={'0x100b8edb8':('FN',64)});seed.decl.update({'J'+str(j):32 for j in range(8)});run(seed,'seed');models['seed']=seed;assert len(seed.sites)==101 and len(seed.stores)==len(seed.frame_writes)==22 and len(seed.reads)==6
 fixed={r['frame_offset']:r for r in seed.frame_writes if r['frame_offset']!=0x6cc};assert len(fixed)==21
 values=solve('seed_phase_coordinate_candidates',seed.prefix(),result='sat',values=[r['value']for r in fixed.values()],extra=decl(seed))['model_value_hex'];cc=[int(v[2:],16)for v in values]
 cert('seed_all21_constants_state_reloads_full64_reset_and_branch',seed,[neq(r['value'],bv(v,r['width_bits']))for r,v in zip(fixed.values(),cc)]+[neq(seed.loadframe(0x6cc,32),'J0'),neq(seed.loadframe(0x738,64),bv(0)),neq(seed.loadframe(0x730,32),bv(0,32)),neq(seed.get('w27'),'J5'),neq(seed.get('w24'),'J2'),neq(seed.get('x5'),z('J2')),neq(seed.get('w25'),'J1'),neq(seed.get('w1'),'J6'),neq(seed.get('w16'),bv(227,32)),neq(seed.get('x26'),bv(0x22190a63a12a5b1b)),neq(next(r for r in seed.reads if r['site']=='0x100b8edb8')['address'],at(0x4b91)),neq(seed.get('x17'),bv(0x2ee7))])
 def frame_cert(name,g):
  sf={r['site']for r in g.frame_writes};cert(name,g,[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip([r for r in g.stores if r['site']in sf],g.frame_writes)]+[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip([r for r in g.reads if r['site']in{f['site']for f in g.frame_reads}],g.frame_reads)])
 frame_cert('seed_all_private_read_and_store_addresses',seed)
 planes=set();word_bytes=set();labels=set();g=seed
 bases=[0,71,211,143];byte_order=[897,896,898,899,827,828,829,830,901,900,902,903,832,831,833,834,904,905,906,907,836,837,835,838,908,909,910,911,839,840,841,842]
 for q in range(4):
  g=run(chained(g,'gather_round'+str(q)),'loop');models['round'+str(q)]=g;assert len(g.sites)==1474 and len(g.reads)==114 and len(g.stores)==64 and len(g.frame_writes)==48
  rr=[r for r in g.reads if r['width_bits']==8];sf={r['site']for r in g.frame_writes};ww=[r for r in g.stores if r['site']not in sf];assert len(rr)==32 and len(ww)==16
  zeros=['(= K '+bv(0)+')']+['(= Z'+str(j)+' '+bv(0)+')'for j in range(31)]+[f'(= {n} {bv(0,w)})'for n,w in g.decl.items()]
  candidate=solve('round'+str(q)+'_address_candidates',g.prefix()+''.join('(assert '+c+')\n'for c in zeros),result='sat',values=[r['address']for r in rr+ww],extra=decl(g))['model_value_hex'];offsets=[int(v[2:],16)for v in candidate]
  cert('round'+str(q)+'_all32_plane_and16_word_addresses',g,[neq(r['address'],frame(off))for r,off in zip(rr+ww,offsets)])
  assert offsets[:32]==[0xd10+(866*(v+16*q))%961 for v in byte_order]
  for off in offsets[:32]:assert off not in planes;planes.add(off)
  word_ledger=[]
  for k,(row,off)in enumerate(zip(ww,offsets[32:])):
   label=bases[k%4]+4*q+k//4;assert label not in labels;labels.add(label);assert off==0x8b0+4*((227*label)%280)and not word_bytes&set(range(off,off+4));word_bytes.update(range(off,off+4));word_ledger.append({**row,'logical_label':label,'word_slot':(227*label)%280,'frame_offset':off})
  frame_cert('round'+str(q)+'_all48_frame_stores_and81_frame_reads',g)
  cert('round'+str(q)+'_exact_four_round_counter_phase_and_branch',g,[neq(g.loadframe(0x730,32),bv(4*(q+1),32)),neq(g.loadframe(0x738,64),bv(0x3620*(q+1))),neq(next(r for r in g.reads if r['site']=='0x100ccdb54')['address'],at(0x8999 if q<3 else 0x8951)),neq(g.get('x17'),bv(0xf948))])
  declared=set(re.findall(r'\(declare-fun (\w+) ',DECL+EXTRA))|set(g.decl);outputs=census(g.prefix(),declared,[r['value']for r in ww]);state=census(g.prefix(),declared,[g.loadframe(off,32)for off in[0x6bc,0x6c0,0x6c4,0x6c8,0x6cc]])
  rounds.append({'round':q,'plane_read_ledger':[{**row,'coordinate_label':v+16*q,'frame_offset':off}for row,v,off in zip(rr,byte_order,offsets[:32])],'word_store_ledger':word_ledger,'word_value_declared_dependency_upper_bounds':outputs,'five_saved_state_dependency_upper_bounds':state,'dependency_membership_is_not_proof_of_influence':True})
 assert planes=={0xd10+(866*(base+i))%961 for base in[896,827]for i in range(64)}and len(word_bytes)==256 and labels=={base+i for base in bases for i in range(16)}
 tail=run(chained(g,'gather_exit'),'exit');models['exit']=tail;assert len(tail.sites)==38 and len(tail.reads)==9 and len(tail.stores)==4
 cert('exit_encoder_byte_raw_formula_state_reload_and_target',tail,[neq(tail.loadframe(0x6bc,32),'(bvxor #x00000734 (bvshl ((_ zero_extend 24) B0) #x00000004))'),neq(next(r for r in tail.reads if r['site']=='0x100caa310')['address'],frame(0xeed)),neq(next(r for r in tail.reads if r['site']=='0x100caa328')['address'],at(0x3f10)),neq(tail.get('w16'),bv(0,32)),neq(tail.get('w2'),bv(0xea0f,32)),neq(tail.get('w3'),bv(280,32)),neq(tail.get('x21'),frame(0x8b0)),neq(tail.get('x17'),bv(0x7e96))])
 frame_cert('exit_all_private_frame_accesses',tail)
 solve('typed_output_codebook_zero_E0_to_E1','(assert '+neq('(bvxor #x00000734 (bvshl ((_ zero_extend 24) (bvxor #x74 ((_ zero_extend 4) NIB0))) #x00000004))','(bvxor #x00000074 (bvshl ((_ zero_extend 28) NIB0) #x00000004))')+')')
 retained={0xd10+(base+866*j)%961 for base,n in[(0x77086,256),(0x368c4,256),(0,256),(0x73704,16),(0x6e272,16)]for j in range(n)};assert len(retained)==800 and 0xeed in retained and not retained&planes
 protected={off+j for off,n in[(0x560,8),(0x728,4),(0x740,8),(0x748,8),(0x750,8),(0x758,8),(0x768,296),(0x1210,8)]for j in range(n)};written=set(word_bytes)
 for name,m in models.items():
  if name in['biased_view','word_view']:continue
  fb={r['frame_offset']+j for r in m.frame_writes for j in range(r['width_bits']//8)};assert not fb&(protected|retained|planes|word_bytes);written|=fb
 assert not word_bytes&(retained|planes|protected)and min(word_bytes)==0x8b0 and max(word_bytes)==0xd0b
 assert len({227*j%280 for j in range(280)})==280
 old_overlap=sorted(word_bytes&set(range(0xd00,0xd00+963)));assert old_overlap==list(range(0xd00,0xd04))+list(range(0xd08,0xd0c))
 solve('abstract_eight_state_words_and_codebook_byte_domain','',result='sat')
 expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};actual={pc for m in models.values()for pc in m.sites};assert expected==actual and len(actual)==1626 and sum(len(m.sites)for m in models.values())==6048
 active=[m for n,m in models.items()if n not in['biased_view','word_view']];reads=[r for m in active for r in m.reads];stores=[r for m in active for r in m.stores]
 sem={'source_models':{n:m.record_full()for n,m in models.items()},'rounds':rounds,'root_lifetime_census':lineage,'root_lifetime_limit':'Selected captured frame/literal stores and retained source-proved scratch-bank domains;not a native full-path reachability or ownership proof.','source_nonbranch_sites_translated':1626,'translated_instances':6048,'iterations':4,'biased_root_F560':'F+0xbe2f2','plane_root_F750':'F+0xd10','word_root_F758':'F+0x8b0','word_grid_slots':280,'word_grid_extent_bytes':1120,'word_grid_permutation_multiplier':227,'word_stream_bases':bases,'word_logical_labels':sorted(labels),'word_slots_populated':64,'full_word_slot_permutation_size_checked':280,'overwritten_former963_scratch_byte_offsets':[hex(x)for x in old_overlap],'word_bytes_written':256,'word_view_initialized_completely':False,'plane_bytes_read':128,'plane_bytes_written':0,'direct_record_byte_reads':0,'image_byte_reads':0,'arithmetic_codebook_reads_in_body':0,'codebook_reads_in_exit':1,'codebook_read':'F+0xeed=T+I(0) physical offset0x1dd;E0(Rout(0)) under retained codebook contract','encoder_zero_corollary':'E0(Rout(0))=0x74 XOR Rout(0) -> new F6bc=E1(Rout(0))=0x74 XOR(Rout(0)<<4);Rout(0) is not assumed zero','retained_arithmetic_and_codebook_cells':800,'preserved_plane_cells':128,'eight_entry_state_words':[hex(x)for x in DATA],'state_compact_transform_proved':False,'word_value_compact_transform_proved':False,'saved_roots_workspace_COUNT_and_budget_preserved':True,'seed_full_u64_F738_reset':True,'index_F730_values':[0,4,8,12,16],'phase_F738_step':hex(0x3620),'exit_target':'0x100c557e8','source_load_effects':len(reads),'source_store_effects':len(stores),'read_bytes':sum(r['width_bits']//8 for r in reads),'store_bytes':sum(r['width_bits']//8 for r in stores),'distinct_store_bytes':len(written),'native_ownership_proved':False,'native_reachability_proved':False,'successful_output_publication_proved':False,'whole_algorithm_identified':False,'Mach_port_emissions':0,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['loop'].__setitem__('bytes','00'+q['fragments']['loop']['bytes'][2:])),('wrong_grid_store',lambda q:next(i for i in q['fragments']['loop']['instructions']if i['ea']=='0x100ccc75c').__setitem__('operands','w14, [x1, x7]')),('wrong_exit',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('wrong_root_producer',lambda q:q['fragments']['biased_view']['instructions'][-1].__setitem__('operands','x8, [sp, #0x568]')),('wrong_pair',lambda q:q['pair_load_decode_checks'][0]['frame_offsets'].__setitem__(1,0x14)),('wrong_old_hash',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(v['result']=='unsat'for v in pp),'queries_sat':sum(v['result']=='sat'for v in pp),'predecessor_queries_replayed':sum(v.get('replayed_query',False)for v in pp),'source_nonbranch_sites_translated':1626,'translated_instances':6048,'iterations':4,'plane_byte_reads':128,'word_stores':64,'word_bytes_written':256,'word_grid_slots':280,'all_plane_and_word_addresses_certified':192,'root_producer_certificates':2,'root_lifetime_artifacts':len(sem['root_lifetime_census']),'arithmetic_and_codebook_cells_retained':800,'exit_codebook_reads':1,'typed_zero_encoder_corollaries':1,'rejected_alterations':len(aa),'source_load_effects':sem['source_load_effects'],'source_store_effects':sem['source_store_effects'],'read_bytes':sem['read_bytes'],'store_bytes':sem['store_bytes'],'distinct_store_bytes':sem['distinct_store_bytes']}
 deps=[P+'_source.json','recover_daemon_mode_one_record_long_prefix.py','recover_daemon_mode_one_record_codecs.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'paired_plane_gather_280_word_grid_and_encoder_handoff_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
