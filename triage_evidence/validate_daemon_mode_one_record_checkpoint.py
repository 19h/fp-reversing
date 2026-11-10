#!/usr/bin/env python3
"""Source-pinned checkpoint,iterator and request-field contracts;no target execution."""
import copy,json,re,shutil,subprocess
from recover_daemon_mode_one_record_checkpoint import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_join import JoinSSA
from validate_daemon_existing_scalar_reader import DECL,bv,frame,at,neq
from validate_daemon_list_output import split
from daemon_mode_one_handoff_tools import parse
SOLVER=shutil.which('z3');assert SOLVER
DECODER={2:0x471b,3:0x5605,4:0x18df,7:0x622c5d3364e575a7,19:0x6d44f77ef42a3bc3,20:0x1dd3a2cc9b1a2a60,21:0x92bb08810bd51832,22:0xfffffffffffffffe,23:0x3505b74e1c8517b5,24:0x24675ed53babbb4e,27:0x324a764c67af2e0e,28:0xda740029fd112266,30:0x92c5ffeb01776ecd}
class PostSSA(JoinSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.pair_loads=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   p=split(i['operands']);m=i['mnemonic'];w=32 if p[0].startswith('w')else 64
   if m=='ldp':
    assert p[0].startswith('w')and p[1].startswith('w');off=int(re.fullmatch(r'\[sp, #(0x[0-9a-f]+)\]',p[2])[1],16);self.pair_loads.append({'site':i['ea'],'frame_offsets':[off,off+4]})
    for j in range(2):super().run({'instructions':[{**i,'mnemonic':'ldr','operands':p[j]+', [sp, #'+hex(off+4*j)+']'}]},pc+4)
    self.sites.pop()
   elif m=='tst':
    v=f'(bvand {self.get(p[0],w)} {self.get(p[1],w)})';self.flags={'eq':f'(= {v} {bv(0,w)})','ne':f'(distinct {v} {bv(0,w)})'};self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'pair_load_lowerings':self.pair_loads}
def certificates(s):
 pp=[];models={};replays=[];fs=s['fragments']
 def solve(name,body,result='unsat',extra='',cc=(),values=None):
  query='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+extra+body+'\n'+''.join('(assert '+v+')\n'for v in cc)+'(check-sat)\n'
  if values is not None:query+='(get-value ('+' '.join(values)+'))\n'
  r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr,(name,r.stdout,r.stderr)
  row={'name':name,'query':query,'result':result,'scope':SCOPE}
  if values is None:assert r.stdout.strip()==result,(name,r.stdout)
  else:
   assert result=='sat'and r.stdout.startswith('sat\n'),(name,r.stdout);v=parse(r.stdout[4:]);assert len(v)==len(values);row['model_value_hex']=[a[-1]for a in v];assert all(re.fullmatch('#x[0-9a-f]+',x)for x in row['model_value_hex'])
  pp.append(row);print(name,result,flush=True);return row
 def dec(g):return''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())
 def cert(name,g,terms,cc=()):return solve(name,g.prefix()+'(assert (or '+' '.join(terms)+'))',extra=dec(g),cc=cc)
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 def run(g,label):
  for value,w in g.supplied_loads.values():
   if re.fullmatch('[A-Z][A-Z0-9_]*',value):g.decl[value]=w
  f=fs[label];end=int(f['end'],16)if label=='raw_result'else int(f['instructions'][-1]['ea'],16);g.run(f,end);models[label]=g;return g
 def frame_cert(label,g):
  sf={r['site']for r in g.frame_writes};rf={r['site']for r in g.frame_reads};sr=[r for r in g.stores if r['site']in sf];rr=[r for r in g.reads if r['site']in rf];assert len(sr)==len(g.frame_writes)and len(rr)==len(g.frame_reads)
  cert(label+'_all_private_frame_effect_addresses',g,[neq(r['address'],frame(v['frame_offset']))for r,v in zip(sr,g.frame_writes)]+[neq(r['address'],frame(v['frame_offset']))for r,v in zip(rr,g.frame_reads)])
 selections={
 'daemon_mode_one_record_join':{'outgoing_constant_words_and_branch_ABI'},
 'daemon_mode_one_record_rounds':{'update_raw_COUNT_biased_position_predicate_and_two_targets'},
 'daemon_mode_one_record_reentry':{'short_remaining_zero_partition_and_shifted_threshold_word'},
 'daemon_mode_one_record_scan':{'seed_live_constants_and_workspace','BE32_merge_and_exact_byte_addresses','decoded_header_controls_original_edges','repeat_entry_preserves_header_predicate','equal_header_advances_or_joins_LOCAL','core_saves_cookie_in_F2c0'}|{'byte'+str(j)+'_'+s for j in range(4)for s in ['seed']+['round'+str(k)for k in range(1,8)]},
 'daemon_mode_one_adapter':{'private48_record_fields_and_address_cookie','aligned_request_decodes_mode4923_and_length_operand','ordinary_stack_alignment_supplies_request_cookie_premise'},
 'daemon_mode_one_phase_handoff':{'core_saves_private_request_R_at_F388'}}
 for name,wanted in selections.items():
  path=ROOT/(name+'_checks.json');old=json.loads(read(path));assert old['all_checks_pass'];rows=[p for p in old['proofs']if p['name']in wanted];assert{p['name']for p in rows}==wanted
  for p in rows:
   assert p['result']=='unsat';r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat',(name,p['name'],r.stdout,r.stderr);pp.append({**p,'name':'replayed_'+name+'_'+p['name'],'replayed_query':True})
  replays.append({'checks':path.name,'sha256':sha(path),'queries_replayed':len(rows),'all_historical_queries_replayed':False});print('replayed',name,len(rows),flush=True)
 # Producer and preservation contracts carry the full64-bit numeric word.
 protected={off+j for off,n in[(0x2b8,8),(0x2c0,8),(0x388,8),(0x4d8,8)]for j in range(n)};lifetime=[]
 for name in ['input_planes','long_planes','long_prefix','word_gather','word_extension','rounds','reentry']:
  c=json.loads(read(ROOT/('daemon_mode_one_record_'+name+'_checks.json')));assert c['all_checks_pass'];writes=[]
  for label,m in c['semantics'].get('source_models',{'single':c['semantics'].get('source_model')}).items():
   if name=='word_gather'and label in['biased_view','word_view']:continue
   for r in m['frame_writes']:assert not protected&set(range(r['frame_offset'],r['frame_offset']+r['width_bits']//8)),(name,label,r);writes.append(r)
  lifetime.append({'stage':name,'literal_frame_store_instances':len(writes),'protected_bytes':sorted(protected),'computed_access_scope':'Retained stage address contracts;source and frame disjointness remain premises.'})
 presets={0x740:('TABLE',64),0x750:(frame(0xd10),64),0x6f8:(bv(0x4719,32),32),0x2b8:('NODE',64),0x4d8:(bv(0x7f3081c2),64)}
 g=PostSSA('checkpoint',presets=presets,loads={'0x100c7b26c':('CHECKPOINT_FN',64)});g.decl['NODE']=64;run(g,'checkpoint');assert s['operand_based_GPR_first_reads']['checkpoint']==[]
 assert len(g.sites)==6894 and len(set(g.sites))==6894 and len(g.reads)==622 and len(g.frame_reads)==592 and len(g.stores)==len(g.frame_writes)==250
 assert[(p['site'],p['frame_offsets'])for p in g.pair_loads]==[(p['site'],p['frame_offsets'])for p in s['pair_load_decode_checks']]
 frame_cert('checkpoint',g)
 # Candidate addresses are proposed from one abstract valuation,then proved
 # against the unmodified source for all remaining component inputs.
 byte=[r for r in g.reads if r['width_bits']==8];assert len(byte)==128
 zero=['(= K '+bv(0)+')']+['(= '+n+' '+bv(0,w)+')'for n,w in g.decl.items()]
 values=solve('plane_address_candidate_valuation',g.prefix(),result='sat',extra=dec(g),cc=zero,values=[r['address']for r in byte])['model_value_hex'];offsets=[int(x[2:],16)for x in values]
 planes={0xd10+866*(base+j)%961 for base in[896,827]for j in range(64)};assert set(offsets)==planes and len(set(offsets))==128
 cert('all128_original_byte_addresses_are_exact_unique_planes',g,[neq(r['address'],frame(off))for r,off in zip(byte,offsets)])
 assert next(off for r,off in zip(byte,offsets)if r['site']=='0x100c7589c')==0xf8f and next(off for r,off in zip(byte,offsets)if r['site']=='0x100c760d4')==0xe34
 broad=PostSSA('broad_checkpoint',presets={k:v for k,v in presets.items()if k!=0x4d8},loads={'0x100c7b26c':('CHECKPOINT_FN',64)});broad.decl.update(NODE=64,CHECKPOINT_FN=64);broad.run(fs['checkpoint'],int(fs['checkpoint']['instructions'][-1]['ea'],16))
 solve('dropping_full64_F4d8_word_allows_different_opaque_address',broad.prefix()+'(assert '+neq(rd(broad,0x100c7589c)['address'],frame(0xf8f))+')',extra=dec(broad),result='sat');models['untyped_checkpoint_negative_control']=broad
 cert('checkpoint_restores_complete_decoder_and_next_ABI',g,[neq(g.get('x'+str(k)),bv(v))for k,v in DECODER.items()]+[neq(g.get('x0'),'NODE'),neq(g.get('w9'),bv(0xac0a,32)),neq(g.get('x26'),frame(0xd10)),neq(g.get('x17'),bv(0xcd7e)),neq(g.loadframe(0x6f8,32),bv(0x4719,32)),neq(rd(g,0x100c7b26c)['address'],at(0x4719)),neq(g.get('x8'),'CHECKPOINT_FN')])
 workspace=[r for r in g.frame_writes if 0x768<=r['frame_offset']<0x890];assert len(workspace)==74 and all(r['width_bits']==32 for r in workspace)and{r['frame_offset']for r in workspace}==set(range(0x768,0x890,4))
 assert all(not set(range(r['frame_offset'],r['frame_offset']+r['width_bits']//8))&set(range(0x768,0x890))for r in g.initial)
 written={r['frame_offset']+j for r in g.frame_writes for j in range(r['width_bits']//8)};assert len(written)==796 and min(written)==0x3d0 and max(written)==0x88f
 assert sum(r['width_bits']//8 for r in g.stores)==1020 and sum(r['width_bits']==32 for r in g.stores)==245 and sum(r['width_bits']==64 for r in g.stores)==5
 preserved=[(0,0x3d0),(0x6f8,4),(0x740,8),(0x750,16),(0x8b0,1120),(0xd10,961),(0x1210,8)]
 assert all(not written&set(range(off,off+n))for off,n in preserved)
 epochs={hex(off):[r for r in g.frame_writes if r['frame_offset']==off]for off in[0x728,0x748,0x4d8]};assert[len(epochs[hex(off)])for off in[0x728,0x748,0x4d8]]==[2,3,1]
 assert rd(g,0x100c75210)['width_bits']==64
 # Next is composed from the exact outgoing register and byte snapshots.
 def chain(old,label,loads):
  q=PostSSA(label,old.r,loads=loads);q.defs=list(old.defs);q.decl=dict(old.decl);q.byte_cells=dict(old.byte_cells);q.loaded=old.loaded;return q
 nxt=chain(g,'next',{'0x100d07434':('NEXT',64),'0x100d0745c':('NEXT_FN',64)});run(nxt,'next')
 cert('next_loads_link_restores_W5_and_selects_NULL_or_decoder',nxt,[neq(rd(nxt,0x100d07434)['address'],'NODE'),neq(nxt.get('x0'),'NEXT'),neq(nxt.get('w5'),bv(0x4719,32)),neq(nxt.get('w8'),bv(0x4923,32)),neq(rd(nxt,0x100d0745c)['address'],f'(ite (= NEXT {bv(0)}) {at(0xac0a)} {at(0xac4c)})'),neq(nxt.get('x17'),bv(0xef9d))]+[neq(nxt.get('x'+str(k)),bv(v))for k,v in DECODER.items()]+[neq(nxt.get('x26'),frame(0xd10))]);assert not nxt.stores
 assert not(set(s['register_write_sets']['next'])&{'x'+str(k)for k in DECODER}|set(s['register_write_sets']['next'])&{'w'+str(k)for k in DECODER})
 local=PostSSA('local',{8:bv(0x4923)},presets={0x740:('TABLE',64),0x388:('R',64)},loads={'0x100cbddd4':('LOCAL',64),'0x100cbddf0':('LOCAL_FN',64)});local.decl['R']=64;run(local,'local')
 cert('LOCAL_request18_NULL_partition_and_raw_marker',local,[neq(rd(local,0x100cbddd4)['address'],'(bvadd R '+bv(0x18)+')'),neq(local.get('x10'),'LOCAL'),neq(local.get('w8'),bv(0x4923,32)),neq(rd(local,0x100cbddf0)['address'],f'(ite (= LOCAL {bv(0)}) {at(0x4923)} {at(0x4928)})'),neq(local.get('w9'),bv(0x74c29dee,32)),neq(local.get('x17'),bv(0xe138))]);frame_cert('local',local);assert not local.stores
 gate=chain(local,'local_present',{'0x100c578b8':('SEL',32),'0x100c57a84':('GATE_FN',64)});gate.save(0x2c0,'COOKIE',64,'saved cookie premise');gate.decl['COOKIE']=64
 # Retain the exact opaque precomparison expression;no inverse is assumed.
 for i in fs['local_present']['instructions'][:-1]:
  if i['ea']=='0x100c57a6c':predicate_value=gate.get('w9')
  gate.run({'instructions':[i]},int(i['ea'],16)+4)
 gate.decl.update(SEL=32,GATE_FN=64);models['local_present']=gate
 cert('LOCAL_present_source_predicate_derived_views_and_entry_constants',gate,[neq(rd(gate,0x100c578b8)['address'],'(bvadd R '+bv(0x28)+')'),neq(rd(gate,0x100c57a84)['address'],f'(ite (= {predicate_value} #x5e62effc) {at(0x56d3)} {at(0x4923)})'),neq(gate.loadframe(0x370,64),frame(0x1100)),neq(gate.loadframe(0x368,64),frame(0x1150)),neq(gate.loadframe(0x358,64),'(bvadd LOCAL '+bv(0x2c238c16ca76f3a8)+')'),neq(gate.get('x26'),frame(0xc80)),neq(gate.get('x0'),bv(0x4008640)),neq(gate.get('w9'),bv(0x74c29dee,32)),neq(gate.get('w5'),bv(0xa9502f98,32)),neq(gate.get('w6'),bv(0xa20cd51f,32)),neq(gate.get('w13'),bv(0x39eba85c,32)),neq(gate.get('w14'),bv(0x79705c69,32)),neq(gate.get('w16'),bv(0x71b2bb0c,32)),neq(gate.get('x17'),bv(0xe138))]);frame_cert('local_present',gate)
 assert len(gate.stores)==len(gate.frame_writes)==3 and [r['frame_offset']for r in gate.frame_writes]==[0x370,0x368,0x358]
 # Construct the original wrapper field expression as a sufficient case.
 # This is not the unproved all-u32 inverse of the source predicate.
 typed=PostSSA('wrapper_gate',{8:bv(0x4923),10:'LOCAL'},presets={0x740:('TABLE',64),0x388:('R',64),0x2c0:('COOKIE',64)},loads={'0x100c578b8':('(bvadd ((_ extract 31 0) COOKIE) #x3e060fa6)',32),'0x100c57a84':('GATE_FN',64)});typed.decl.update(LOCAL=64,R=64,COOKIE=64);run(typed,'local_present');models['wrapper_gate']=typed;models['local_present']=gate
 cert('original_wrapper_cookie_coded_SEL_is_sufficient_for_new_phase',typed,[neq(rd(typed,0x100c57a84)['address'],at(0x56d3))])
 reject=PostSSA('raw_result',{9:bv(0x74c29dee)},presets={0x388:('R',64)});reject.decl['R']=64;run(reject,'raw_result');assert len(reject.stores)==1 and not reject.frame_writes
 cert('raw_result_prefix_writes_private_R0_only',reject,[neq(reject.stores[0]['address'],'R'),neq(reject.stores[0]['value'],bv(0x74c29dee,32))]);frame_cert('raw_result',reject)
 # Independent instruction-alias algebra,with unrestricted32-bit operands.
 extra='(declare-fun A32 () (_ BitVec 32))\n(declare-fun B32 () (_ BitVec 32))\n'
 solve('TST_CNEG_NE_matches_inverted_CSNEG_EQ_alias','(assert '+neq('(ite (distinct (bvand A32 B32) #x00000000) (bvneg A32) A32)','(ite (= (bvand A32 B32) #x00000000) A32 (bvneg A32))')+')',extra=extra)
 for shift in[10,18]:solve('EXTR32_shift'+str(shift)+'_concatenation_identity','(assert '+neq(f'((_ extract 31 0) (bvlshr (concat A32 B32) {bv(shift,64)}))',f'(bvor (bvlshr B32 {bv(shift,32)}) (bvshl A32 {bv(32-shift,32)}))')+')',extra=extra)
 records={n:m.record_full()for n,m in models.items()}
 actual={pc for n,m in models.items()if n not in['untyped_checkpoint_negative_control','wrapper_gate']for pc in m.sites};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==7068
 sem={'source_models':records,'predecessor_replay_ledger':replays,'protected_context_lifetime':lifetime,'source_nonbranch_sites_translated':len(actual),'checkpoint_no_GPR_liveins':True,'checkpoint_initial_frame_inputs':len(g.initial),'full64_F4d8_premise':'0x000000007f3081c2','plane_read_ledger':[dict(r,expected_frame_offset=o)for r,o in zip(byte,offsets)],'plane_cells_read_once':128,'plane_bytes_written':0,'workspace_replacement_ledger':workspace,'workspace_bytes_replaced':296,'old_workspace_inputs_read':0,'checkpoint_store_effects':250,'checkpoint_store_bytes':1020,'checkpoint_distinct_frame_bytes_written':796,'preserved_frame_ranges':[{'offset':o,'size_bytes':n}for o,n in preserved],'epoch_ending_stores':epochs,'decoder_constants':{str(k):hex(v)for k,v in DECODER.items()},'next_link_load':'0x100d07434:NEXT=u64[NODE]','next_nonnull_target':'0x100bda488','next_null_target':'0x100cbddd0','LOCAL_field':'u64[R+0x18]','LOCAL_is_dereferenced_here':False,'LOCAL_biased_saved_word':'u64[F+0x358]=LOCAL+0x2c238c16ca76f3a8','LOCAL_selector_field':'u32[R+0x28]','LOCAL_exact_source_comparison_value':predicate_value,'LOCAL_comparison_constant':'0x5e62effc','LOCAL_wrapper_sufficient_difference':'u32(SEL-low32(COOKIE))=0x3e060fa6','arbitrary_selector_inverse_proved':False,'excluded_exploration':'Broad inverse equivalence timed out;no timeout or unknown query is accepted as a proof.','LOCAL_true_target':'0x100d3ce60','LOCAL_false_raw_result':'0x74c29dee at private R+0','LOCAL_derived_views':['F+0xc80','F+0x1100','F+0x1150'],'LOCAL_derived_view_extents_proved':False,'checkpoint_workspace_decoded_function_proved':False,'termination_requires_finite_stable_acyclic_records':True,'native_reachability_proved':False,'successful_output_proved':False,'daemon_kext_pairing_proved':False,'Mach_port_emissions':0,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['checkpoint'].__setitem__('bytes','00'+q['fragments']['checkpoint']['bytes'][2:])),('wrong_NEXT_offset',lambda q:next(i for i in q['fragments']['next']['instructions']if i['ea']=='0x100d07434').__setitem__('operands','x0, [x0, #8]')),('wrong_LOCAL_bias_input',lambda q:next(i for i in q['fragments']['local_present']['instructions']if i['ea']=='0x100c578ac').__setitem__('operands','x9, xzr, x9')),('wrong_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('wrong_CNEG_condition',lambda q:q['CNEG_decode_checks'][0].__setitem__('alias_condition','EQ')),('wrong_pair_offset',lambda q:q['pair_load_decode_checks'][0]['frame_offsets'].__setitem__(1,0)),('wrong_lineage',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];original=build();out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert q!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(v['result']=='unsat'for v in pp),'queries_sat':sum(v['result']=='sat'for v in pp),'predecessor_queries_replayed':sum(v.get('replayed_query',False)for v in pp),'source_nonbranch_sites_translated':7068,'checkpoint_frame_reads':592,'checkpoint_loads':622,'checkpoint_stores':250,'checkpoint_u32_stores':245,'checkpoint_u64_stores':5,'checkpoint_store_bytes':1020,'checkpoint_distinct_written_bytes':796,'checkpoint_plane_byte_reads':128,'checkpoint_workspace_u32_stores':74,'checkpoint_workspace_bytes':296,'checkpoint_GPR_liveins':0,'checkpoint_paired_loads':5,'protected_precheckpoint_stages':7,'LOCAL_present_stores':3,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','daemon_word_lookup_algebra.py','validate_daemon_mode_one_word_schedule.py','validate_daemon_existing_scalar_reader.py','validate_daemon_constructor_inputs.py','validate_daemon_constructor_lookup.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'checkpoint_iterator_and_wrapper_gate_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
