#!/usr/bin/env python3
"""Prove the86-visit bank completion and bounded workspace/budget interface."""
import copy,hashlib,json,re,shutil,subprocess
from recover_daemon_mode_one_second_phase_handoff import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_result_publication import PublicationSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq,low
SOLVER=shutil.which('z3');assert SOLVER

def chain(old,name,loads=None):
 g=PublicationSSA(name,old.r,loads=loads);g.defs=list(old.defs);g.decl=dict(old.decl);g.byte_cells=dict(old.byte_cells);g.loaded=old.loaded;g.aliases=dict(old.aliases);return g

def certificates(s):
 pp=[];mm={};fs=s['fragments'];replays=[]
 def solve(name,g=None,terms=(),cc=(),result='unsat',extra='',body=''):
  q='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL+extra
  if g is not None:q+=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
  q+=body+''.join('(assert '+v+')\n'for v in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.returncode,r.stdout[:1600],r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def replay(name,names):
  c=json.loads(read(ROOT/(name+'_checks.json')));rows=[p for p in c['proofs']if p['name']in names];assert{p['name']for p in rows}==set(names)
  for p in rows:
   orig=p['query'];q=orig.replace('(set-option :timeout 15000)','(set-option :timeout 45000)');r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat',(name,p['name'],r.stdout[:1000],r.stderr);pp.append({**p,'name':'replayed_'+name+'_'+p['name'],'query':q,'original_query_sha256':hashlib.sha256(orig.encode()).hexdigest(),'historical_timeout_raised_to45000_ms':q!=orig,'replayed_query':True})
  replays.append({'checks':name+'_checks.json','sha256':sha(ROOT/(name+'_checks.json')),'selected_propositions':names,'all_historical_queries_replayed':False});print('replayed',name,len(rows),flush=True)
 replay('daemon_mode_one_phase_handoff',['equal52_gate_and_repack_live_coordinates','all_sixteen_compact_repack_values','phase_bit_selects_reentry_or_workspace','reentry_rearms_private_phase_and_selects_distinct_mix','repeat_mix_rejoins_spills_with_new_control_context','shared_spills_changes_F460_to86_and_preserves_phase_one','workspace_request_C0_chain_and_null_dispatch','unaligned_STUR_is_private_F834'])
 replay('daemon_mode_one_word_rounds',['gate_signed_threshold86_partition','state_update_phase_counter_epoch_and_dispatch','round_counter_and_two_way_dispatch'])
 replay('daemon_mode_one_word_schedule',['iteration48_counter_codecs_roots_and_repeat_exit'])
 replay('daemon_mode_one_adapter',['core_budget_add144_cancels_adapter_entry_bias','returned_delta_bounds_alignment_and_zero_criterion'])
 def run(g,name,label=None):
  f=fs[name];g.run(f,int(f['instructions'][-1]['ea'],16));mm[label or name]=g;return g
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 def frame_cert(name,g):
  rr={r['site']:r for r in g.reads};ss={r['site']:r for r in g.stores};tt=[neq(rr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_reads]+[neq(ss[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_writes]+[neq(r['original_address'],frame(r['frame_offset']))for r in g.alias_records]+[neq(r['original_address'],frame(r['frame_offset']))for r in g.normalizations if r.get('kind')=='STUR_private_alias'];solve(name+'_all_original_frame_effect_addresses',g,tt or['false'])
 roots={0x740:('TABLE',64),0x388:('REQUEST',64),0x730:(bv(0x2ac4,32),32),0x460:('QCOUNT',32),0x448:('FLAGWORD',32)}
 g=PublicationSSA('round_gate',presets=roots,loads={'0x100cad3b4':('GATEFN',64)});g.decl.update(REQUEST=64,QCOUNT=32,FLAGWORD=32,GATEFN=64);run(g,'round_gate');frame_cert('round_gate',g)
 solve('actual_round_gate_supplies_both_equality_bridges_live_inputs',g,[neq(g.get('w0'),bv(0x2ac4,32)),neq(g.get('w14'),bv(0x32ff,32)),neq(g.get('w9'),bv(-0x32a9,32)),neq(g.get('w27'),'QCOUNT'),neq(g.get('w4'),bv(0x528cdb78,32)),neq(rd(g,0x100cad3b4)['address'],'(ite (bvslt QCOUNT #x00000056) '+at(0x2aca)+' '+at(0x2ac4)+')')])
 f=chain(g,'first_equal',{'0x100cec6c8':('FIRSTFN',64)});f.decl['FIRSTFN']=64;run(f,'first_equal');frame_cert('first_equal',f);solve('first_equality_bridge_exact52_and_common_advance_coordinates',f,[neq(rd(f,0x100cec6c8)['address'],'(ite (= QCOUNT #x00000034) '+at(0x56a0)+' '+at(0x32ff)+')'),neq(f.get('w16'),bv(0x30fa,32)),neq(f.get('w8'),bv(0x30fa,32))])
 n=chain(g,'second_equal',{'0x100dc96a0':('SECONDFN',64)});n.decl['SECONDFN']=64;run(n,'second_equal');frame_cert('second_equal',n);solve('second_equality_bridge_exact86_and_repack_phase_coordinates',n,[neq(rd(n,0x100dc96a0)['address'],'(ite (= QCOUNT #x00000056) '+at(0x3305)+' '+at(0x32ff)+')'),neq(n.get('w8'),bv(0x30fa,32)),neq(n.get('w28'),bv(0xd4,32)),neq(n.get('w15'),g.loadframe(0x750,32))])
 # QCOUNT is an internal word;this partitions every32-bit pattern,including negatives.
 solve('signed_gate_plus_both_equalities_admits_only52_or86',extra='(declare-fun C32 () (_ BitVec 32))\n',terms=[neq('(ite (bvslt C32 #x00000056) (= C32 #x00000034) (= C32 #x00000056))','(or (= C32 #x00000034) (= C32 #x00000056))')])
 first=chain(f,'first_repack',{'0x100db4b58':('FREPACKFN',64)});first.decl['FREPACKFN']=64;run(first,'first_repack');frame_cert('first_repack',first)
 second=chain(n,'second_repack',{'0x100b75084':('SREPACKFN',64)});second.decl['SREPACKFN']=64;run(second,'second_repack');frame_cert('second_repack',second)
 old_rows=first.frame_writes;new_rows=second.frame_writes;old_offsets={r['frame_offset']for r in old_rows};new_offsets={r['frame_offset']for r in new_rows};sparse=set(range(0x3b0,0x434,4))-{0x424};assert len(old_rows)==len(old_offsets)==len(new_rows)==len(new_offsets)==16 and not old_offsets&new_offsets and old_offsets|new_offsets==sparse
 vals={0x40c:'(bvadd (bvadd IF_444_32 ((_ extract 31 0) Z7)) #xe2b587fa)',0x418:'(bvadd (bvadd IF_508_32 IF_720_32) #xb6b1549e)',0x3bc:'(bvadd IF_514_32 #x0e2ee34a)',0x41c:'(bvadd IF_51c_32 #x5055dd69)',0x3d8:'(bvadd IF_50c_32 #x3a1ed165)'}
 for dst,src in[(0x400,0x52c),(0x3c4,0x558),(0x3e8,0x548),(0x428,0x540),(0x404,0x534),(0x3d4,0x520),(0x3ec,0x550),(0x3c8,0x510),(0x420,0x538),(0x3b4,0x518),(0x3f8,0x530)]:vals[dst]='IF_'+format(src,'x')+'_32'
 solve('all16_original_second_repack_values_including_hidden_addition',second,[neq(r['value'],vals[r['frame_offset']])for r in new_rows]+[neq(second.get('w14'),bv(0x6284,32)),neq(rd(second,0x100b75084)['address'],at(0x30fa))])
 solve('independent_shift_mask_XOR_sum_is_u32_addition',extra='(declare-fun X32 () (_ BitVec 32))\n',terms=[neq('(bvadd (bvand (bvshl X32 #x00000001) #x743da2ca) (bvxor X32 #x3a1ed165))','(bvadd X32 #x3a1ed165)')])
 phase=chain(second,'phase_gate',{'0x100c4c878':('PHASEFN',64)});phase.decl['PHASEFN']=64;run(phase,'phase_gate');frame_cert('phase_gate',phase)
 odd='(= (bvand FLAGWORD #x00000001) #x00000001)';solve('completed_second_repack_reaches_workspace_exactly_on_set_low_bit',phase,[neq(rd(phase,0x100c4c878)['address'],'(ite '+odd+' '+at(0x8aaf)+' '+at(0x6284)+')'),neq(phase.get('w12'),bv(0x7a8c,32)),neq(phase.get('w4'),bv(0x528cdb78,32)),neq(phase.get('w20'),bv(0x4cdb,32)),neq(phase.get('w22'),bv(0xad732488,32)),neq(phase.get('w27'),bv(86,32))])
 solve('selected86_and_phase1_contract_reaches_original_workspace_target',phase,[neq(rd(g,0x100cad3b4)['address'],at(0x2ac4)),neq(rd(n,0x100dc96a0)['address'],at(0x3305)),neq(rd(second,0x100b75084)['address'],at(0x30fa)),neq(rd(phase,0x100c4c878)['address'],at(0x8aaf))],cc=['(= QCOUNT #x00000056)',odd])
 # Preserve the first half and the two phase words across the retained repeat stages.
 protected={off+j for off in old_offsets|{0x448,0x460}for j in range(4)}|set(range(0x388,0x390))|set(range(0x1210,0x1218));lifetime=[]
 def keep(name,label,rows):
  changed=set();allow=[]
  for r in rows:
   w=r.get('width_bytes',r.get('width_bits',0)//8);assert w in[1,4,8];bb=set(range(r['frame_offset'],r['frame_offset']+w))
   if r['site']=='0x100bf3390':assert r['frame_offset']==0x460 and w==4;bb-=set(range(0x460,0x464));allow.append(r['site'])
   assert not bb&protected,(name,label,r);changed.update(bb)
  artifact=name+('_source.json'if name==P else'_checks.json')
  lifetime.append({'artifact':artifact,'sha256':sha(ROOT/artifact),'component':label,'write_effect_rows':len(rows),'old16_word_bytes_preserved':64,'F448_request_and_budget_preserved_under_retained_address_contracts':True,'F460_only_permitted_producer_sites':sorted(set(allow)),'maximum_frame_offset_inclusive':max(changed)if changed else None})
 def obj(name):return json.loads(read(ROOT/(name+'_checks.json')))['semantics']
 ph=obj('daemon_mode_one_phase_handoff');keep('daemon_mode_one_phase_handoff','shared_spills_F46086_producer',ph['source_models']['shared_spills']['frame_writes'])
 sm=obj('daemon_mode_one_state_materialization');keep('daemon_mode_one_state_materialization','shared_spills_and_following_byte_materialization',sm['source_store_ledger'])
 ab=obj('daemon_mode_one_source_absorption');rows=list(ab['handoff_store_ledger'])
 for r in ab['per_iteration_layout']:
  for k in['plane0_physical_offset','plane1_physical_offset']:rows.append({'site':'retained_absorption_byte','frame_offset':0xd00+r[k],'width_bytes':1})
 keep('daemon_mode_one_source_absorption','source_absorption_and_handoff',rows)
 pg=obj('daemon_mode_one_plane_consumer');keep('daemon_mode_one_plane_consumer','plane_word_consumer',pg['frame_store_ledger']+pg['output_word_layout'])
 ws=obj('daemon_mode_one_word_schedule');rows=list(ws['frame_store_ledger'])
 for r in ws['iteration_coverage_ledger']:rows.extend({**v,'width_bytes':4}for v in r['new_word_stores'])
 keep('daemon_mode_one_word_schedule','word_extension',rows)
 wr=obj('daemon_mode_one_word_rounds');rows=[r for m in wr['source_models'].values()for r in m['frame_writes']];keep('daemon_mode_one_word_rounds','setup_round_update_gate',rows)
 keep(P,'new_second_repack',new_rows)
 # The generic unequal bridge also has a fully bounded private frame footprint.
 adv=PublicationSSA('advance',{8:bv(0x30fa),15:z('PW32')},presets={0x740:('TABLE',64),0x464:('N32',32),0x504:('POS32',32),0x508:('A32X',32),0x560:('B32X',32)},loads={'0x100c8df84':('ADVFN',64)});adv.decl.update(PW32=32,N32=32,POS32=32,A32X=32,B32X=32,ADVFN=64);run(adv,'advance');frame_cert('advance',adv)
 hi='(or (= N32 #x00000000) (bvuge N32 #xffffff80))';solve('generic_advance_four_exact_word_updates_and_overflow_aware_control',adv,[neq(adv.loadframe(0x508,32),'(bvadd A32X PW32)'),neq(adv.loadframe(0x560,32),'(bvadd B32X ((_ extract 31 0) Z7))'),neq(adv.loadframe(0x504,32),'(bvadd POS32 #x00000040)'),neq(adv.loadframe(0x464,32),'(bvadd N32 #x00000040)'),neq(rd(adv,0x100c8df84)['address'],'(ite '+hi+' '+at(0x3146)+' '+at(0x30fa)+')'),neq(adv.get('w14'),bv(0x6284,32))]);assert len(adv.stores)==len(adv.frame_writes)==4
 # Instantiate the existing workspace directly from the newly proved phase ABI.
 initial_words={off:phase.loadframe(off,32)for off in sparse};roots=s['codec_roots'];supplied={'0x100d9dc14':('CCOLL',64),'0x100d9dccc':('CHEAD',64),'0x100d9dcec':(bv(roots[0]['fixup']['target']),64),'0x100d9dd00':(bv(roots[1]['fixup']['target']),64),'0x100d9dd18':('WORKFN',64)}
 workspace=chain(phase,'workspace',supplied);workspace.decl.update(CCOLL=64,CHEAD=64,WORKFN=64);run(workspace,'workspace');frame_cert('workspace',workspace)
 codec=ph['workspace_codec_ledger'];constants=ph['workspace_literal_ledger'];assert len(codec)==32 and{r['recovered_input_frame_offset']for r in codec}==sparse;terms=[]
 for r in codec:
  x=initial_words[r['recovered_input_frame_offset']];expected='(bvadd (bvmul (bvxor '+x+' '+bv(r['xor_mask'],32)+') '+bv(r['multiplier'],32)+') '+bv(r['bias'],32)+')';terms.append(neq(workspace.loadframe(r['frame_offset'],32),expected))
 solve('new_second_phase_workspace_all32_original_word_encodings',workspace,terms)
 terms=[neq(workspace.loadframe(r['frame_offset'],r['width_bits']),bv(r['constant_u64'],r['width_bits']))for r in constants];solve('new_second_phase_workspace_all168_literal_bytes',workspace,terms)
 solve('new_workspace_REQUEST_C0_pointee_dispatch_and_codebook_roots',workspace,[neq(rd(workspace,0x100d9dc14)['address'],'(bvadd REQUEST #x0000000000000008)'),neq(rd(workspace,0x100d9dccc)['address'],'CCOLL'),neq(rd(workspace,0x100d9dd18)['address'],'(ite (= CHEAD #x0000000000000000) '+at(0x7acf)+' '+at(0x7a8c)+')'),neq(workspace.get('x0'),'CHEAD'),neq(workspace.get('w8'),bv(0x4923,32)),neq(workspace.get('w9'),bv(0xf518,32)),neq(workspace.loadframe(0x588,64),bv(0x100fc4130)),neq(workspace.loadframe(0x568,64),bv(0x101031ea0))])
 written={r['frame_offset']+j for r in workspace.frame_writes for j in range(r['width_bits']//8)};assert len(workspace.stores)==len(workspace.frame_writes)==65 and len(written)==312 and set(range(0x768,0x890))<=written
 assert all(not set(range(r['frame_offset'],r['frame_offset']+r['width_bits']//8))&set(range(0x1210,0x1218))for q in mm.values()for r in q.frame_writes)
 solve('all_private_offsets_below1210_are_disjoint_from_budget8',terms=['(= (bvadd K OFF64) (bvadd K #x0000000000001210 BYTE64))'],cc=['(bvult OFF64 #x0000000000001210)','(bvult BYTE64 #x0000000000000008)'],extra='(declare-fun OFF64 () (_ BitVec 64))\n(declare-fun BYTE64 () (_ BitVec 64))\n')
 solve('selected86_phase1_component_domain_nonempty',phase,cc=['(= QCOUNT #x00000056)',odd],result='sat')
 solve('even_phase_word2_would_select_reentry_despite_nonzero_word',phase,[neq(rd(phase,0x100c4c878)['address'],at(0x8aaf))],cc=['(= QCOUNT #x00000056)','(= FLAGWORD #x00000002)'],result='sat')
 expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};actual={pc for q in mm.values()for pc in q.sites};assert actual==expected and len(actual)==561
 effects={n:{'nonbranch_sites':len(q.sites),'loads':len(q.reads),'stores':len(q.stores),'read_bytes':sum(r['width_bits']//8 for r in q.reads),'store_effect_bytes':sum(r['width_bits']//8 for r in q.stores),'frame_stores':len(q.frame_writes)}for n,q in mm.items()}
 sem={'source_models':{n:g.record_full()for n,g in mm.items()},'predecessor_replays':replays,'source_nonbranch_sites_translated':len(actual),'first_repack_word_offsets':sorted(old_offsets),'second_repack_word_offsets':sorted(new_offsets),'repack_sets_disjoint':True,'combined_sparse_words':32,'combined_sparse_data_bytes':128,'unwritten_bank_hole':'F+0x424..F+0x427','second_repack_word_equations':{hex(k):v for k,v in vals.items()},'second_repack_hidden_addition':'u32[F+0x3d8]=u32(F50c+0x3a1ed165)','phase_word_low_bit_only':True,'selected_reentry_lifetime':lifetime,'workspace_word_codecs_rechecked':32,'workspace_literal_bytes_rechecked':168,'workspace_data_bytes':296,'workspace_frame_store_bytes_distinct':312,'phase86_set_bit_workspace_handoff_proved':True,'generic_advance_store_words':4,'generic_advance_step':64,'generic_advance_predicate':'N32==0 OR N32>=0xffffff80 (unsigned u32)','generic_advance_field_semantic_identity_proved':False,'effect_counts':effects,'protected_budget_interval':'[F+0x1210,F+0x1218)','current_and_retained_selected_footprints_preserve_budget8':True,'whole_core_budget_history_proved':False,'whole_program_control_coverage_proved':False,'zero_wrapper_delta_for_processing_proved':False,'native_normal_return_proved':False,'native_ownership_extent_alias_policy_proved':False,'whole_algorithm_identified':False,'daemon_kext_pairing_proved':False,'Mach_port_emissions':0,'new_IDA_access':False,'source_value_cuts':0,'coherence_boundary':'Retained selected-stage destination contracts and stable disjoint frame/image/source owners are premises. The first16 sparse words and phase/request/budget cells are preserved across the recorded repeat-stage footprints;the shared-spill producer intentionally sets F460 to86. A45-artifact locator union is not whole-program control or memory coverage. The new bridge applies to actual saved-word86 on a returned repeat-stage visit;native arrival,normal return and complete budget history remain unproved.','excluded_exploration':'The initial budget investigation exposed an unanalysed86 branch. No absence-of-literal-SP-store scan is treated as absence of aliased budget writes. The whole-core budget claim is withheld;the newly discovered bridge and complementary repack are source-proved separately.'}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('source_byte',lambda t:t['fragments']['second_equal'].__setitem__('bytes','00'+t['fragments']['second_equal']['bytes'][2:])),('wrong_complement_destination',lambda t:next(i for i in t['fragments']['second_repack']['instructions']if i['ea']=='0x100b75014').__setitem__('operands','w15, [sp, #0x408]')),('wrong_hidden_add_mask',lambda t:next(i for i in t['fragments']['second_repack']['instructions']if i['ea']=='0x100b75070').__setitem__('operands','w12, w12, w10')),('wrong_branch',lambda t:t['branch_edges'][0].__setitem__('target','0x0')),('wrong_register_shift',lambda t:next(i for i in t['ISA_decode_checks']if i['kind']=='register_LSL').__setitem__('shift_mask',63)),('wrong_locator_scope',lambda t:t['captured_artifact_locator_inventory'].__setitem__('whole_program_coverage',True)),('wrong_lineage',lambda t:t['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda t:t.__setitem__('native_target_executed',True))];out=[]
 for name,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'second_repack_u32_stores':16,'combined_sparse_words':32,'workspace_word_codecs_rechecked':32,'workspace_literal_bytes_rechecked':168,'workspace_distinct_bytes_written':312,'retained_repeat_stage_lifetime_components':len(sem['selected_reentry_lifetime']),'source_value_cuts':0,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'second_phase_bank_completion_and_workspace_handoff_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
