#!/usr/bin/env python3
"""Source-proved phase latch,re-entry,word codecs and C0/LOCAL request suffixes."""
import copy,json,re,subprocess,shutil,collections
from recover_daemon_mode_one_phase_handoff import ROOT,P,SCOPE,FLAGS,DEPS,BLOCKS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq
from validate_daemon_mode_one_inverse_tables import frame,at
from daemon_mode_one_handoff_tools import FrameSSA,graph,leaves,emit,affine_candidate,parse
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec 64))\n'for n in['R','COLL','LOCAL','CELL0'])
def certificates(s):
 pp=[];models={};fs=s['fragments'];cuts=[]
 def solve(name,body,conditions=(),result='unsat'):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+body+'\n'+''.join('(assert '+c+')\n'for c in conditions)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-handoff-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True);return name
 def pre(g):return ''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
 def cert(name,g,terms,conditions=(),extra=''):return solve(name,pre(g)+extra+'(assert (or '+' '.join(terms)+'))',conditions)
 def rd(g,pc):return next(v for v in g.reads if v['site']==hex(pc))
 def run(g,name):
  f=fs[name];end=int(f['instructions'][-1]['ea'],16)if name in BLOCKS else int(f['end'],16);g.run(f,end);return g
 from recover_daemon_mode_one_word_rounds import build as parent_build
 from validate_daemon_mode_one_word_rounds import certificates as parent_certificates
 old=parent_build();assert old==json.loads(read(ROOT/DEPS[0]));bp,bs=parent_certificates(old);parent=json.loads(read(ROOT/DEPS[1]));assert bp==parent['proofs']and json.loads(json.dumps(bs))==parent['semantics']
 for p in bp:pp.append({**p,'name':'replayed_rounds_'+p['name'],'replayed_query':True})
 from recover_daemon_mode_one_bank_combine import build as combine_build
 from validate_daemon_mode_one_bank_combine import certificates as combine_certificates
 old=combine_build();assert old==json.loads(read(ROOT/DEPS[2]));cp,ct,cs=combine_certificates(old);comb=json.loads(read(ROOT/DEPS[3]));assert cp==comb['proofs']and ct==comb['translations']and json.loads(json.dumps(cs))==comb['semantics']
 for p in cp:pp.append({**p,'name':'replayed_combine_'+p['name'],'replayed_query':True})
 adapter=json.loads(read(ROOT/DEPS[11]));names={'private48_record_fields_and_address_cookie','entry_reads_object_C0_length_and_saves_continuation','immediate_rejection_publishes_raw_result_before_guard'};done=set()
 for p in adapter['proofs']:
  if p['name']not in names:continue
  r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_adapter_'+p['name'],'replayed_query':True});done.add(p['name'])
 assert done==names
 # Recheck the known frame writes from the first combiner through the round gate.
 preservation=[]
 def keep(file,rows):
  used=set()
  for r in rows:used.update(range(r['frame_offset'],r['frame_offset']+r.get('width_bytes',r.get('width_bits',0)//8)))
  assert not used&(set(range(0x448,0x44c))|set(range(0x388,0x390))),file
  preservation.append({'artifact':file,'sha256':sha(ROOT/file),'write_rows_checked':len(rows),'phase_F448_and_request_F388_preserved':True,'full_proof_freshly_replayed':file==DEPS[1]})
 mix=json.loads(read(ROOT/DEPS[5]));assert mix['all_checks_pass']and mix['semantics']['new_memory_stores']==0;keep(DEPS[5],[])
 sm=json.loads(read(ROOT/DEPS[6]));keep(DEPS[6],sm['semantics']['source_store_ledger'])
 ab=json.loads(read(ROOT/DEPS[7]));rows=list(ab['semantics']['handoff_store_ledger'])
 for r in ab['semantics']['per_iteration_layout']:
  for key in['plane0_physical_offset','plane1_physical_offset']:rows.append({'frame_offset':0xd00+r[key],'width_bytes':1})
 keep(DEPS[7],rows)
 pg=json.loads(read(ROOT/DEPS[8]));keep(DEPS[8],pg['semantics']['frame_store_ledger']+pg['semantics']['output_word_layout'])
 ws=json.loads(read(ROOT/DEPS[9]));rows=list(ws['semantics']['frame_store_ledger'])
 for r in ws['semantics']['iteration_coverage_ledger']:rows.extend({**v,'width_bytes':4}for v in r['new_word_stores'])
 keep(DEPS[9],rows)
 keep(DEPS[1],[v for m in bs['source_models'].values()for v in m['frame_writes']])
 # Bind the actual previous gate's live registers,not just its destination PC.
 pm=bs['source_models']['gate'];decl=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in pm['declarations'].items());regs=pm['final_registers'];low=lambda x:f'((_ extract 31 0) {x})'
 solve('predecessor_live_equal_gate_inputs',decl+pm['source_SSA']+'(assert (or '+neq(low(regs[14]),bv(0x32ff,32))+' '+neq(low(regs[27]),bv(0x34,32))+' '+neq(low(regs[4]),bv(0x528cdb78,32))+'))',['(= VALUE #x00000034)'])
 common={0x740:('TABLE',64),0x388:('R',64)}
 gate=FrameSSA('equal_gate',{14:bv(0x32ff),27:z('VALUE'),4:bv(0x528cdb78)},presets=common);run(gate,'equal_gate');models['equal_gate']=gate
 cert('equal52_gate_and_repack_live_coordinates',gate,[neq(rd(gate,0x100cec6c8)['address'],f'(ite (= VALUE #x00000034) {at(0x56a0)} {at(0x32ff)})'),neq(gate.get('w16'),bv(0x30fa,32))])
 prefix=FrameSSA('selected_prefix',{14:bv(0x32ff),27:bv(0x34),4:bv(0x528cdb78)},presets={**common,0x448:('VALUE',32)})
 for name in['equal_gate','repack','phase_gate']:run(prefix,name)
 models['selected_prefix']=prefix
 phase_pred='(= (bvand VALUE #x00000001) #x00000000)'
 cert('phase_bit_selects_reentry_or_workspace',prefix,[neq(rd(prefix,0x100c4c878)['address'],f'(ite {phase_pred} {at(0x6284)} {at(0x8aaf)})'),neq(rd(prefix,0x100db4b58)['address'],at(0x30fa)),neq(prefix.get('w0'),bv(1,32)),neq(prefix.get('w20'),bv(0x4cdb,32)),neq(prefix.get('w22'),bv(0xad732488,32)),neq(prefix.get('w12'),bv(0x7a8c,32))])
 repack=[r for r in prefix.frame_writes if 0x100db4af0<=int(r['site'],16)<0x100db4bd0];assert len(repack)==16 and len({r['frame_offset']for r in repack})==16
 for r in repack:assert r['width_bits']==32 and not set(range(r['frame_offset'],r['frame_offset']+4))&set(range(0x448,0x44c))
 repack_values={0x408:'(bvadd (bvadd ((_ extract 31 0) Z7) IF_444_32) #xe2b587fa)',0x410:'(bvadd (bvadd IF_508_32 ((_ extract 31 0) Z6)) #xb6b1549e)',0x3dc:'(bvadd ((_ extract 31 0) Z1) #x34edd591)',0x414:'(bvadd IF_51c_32 #x5055dd69)',0x3d0:'(bvadd IF_514_32 #x0e2ee34a)'}
 for dest,src in[(0x3b8,0x518),(0x3e4,0x534),(0x3e0,0x52c),(0x3f4,0x550),(0x3cc,0x520),(0x3fc,0x530),(0x430,0x540),(0x3f0,0x548),(0x3c0,0x558),(0x42c,0x538),(0x3b0,0x510)]:repack_values[dest]='IF_'+format(src,'x')+'_32'
 cert('all_sixteen_compact_repack_values',prefix,[neq(r['value'],repack_values[r['frame_offset']])for r in repack])
 # The combiner's universal identities apply again to the new bank values.
 reentry=FrameSSA('reentry',{**prefix.r},presets=common);reentry.defs=list(prefix.defs);reentry.decl=dict(prefix.decl);reentry.loaded=prefix.loaded
 bank_regs={'A0':10,'A1':5,'A2':25,'A3':30,'S0':13,'S1':11,'S2':3,'S3':26};bindings={n:reentry.get('w'+str(r))for n,r in bank_regs.items()};bindings['A3']=f'(bvsub {bindings["A3"]} #xad732488)';defs=''.join(f'(define-fun H_{n} () (_ BitVec 32) {e})\n'for n,e in bindings.items());v=u=b=None
 for i in fs['reentry']['instructions'][:-1]:
  pc=int(i['ea'],16)
  if pc==0x100bdba84:v=reentry.get('w16')
  if pc==0x100bdbc00:u,b=reentry.get('w12'),reentry.get('w1')
  reentry.run({'instructions':[i]},pc+4)
  if pc in[0x100bdbbf4,0x100bdbc54]:
   value=f'(bvxor (bvadd {v} #x6891e1c7) #x08156cbf)'if pc==0x100bdbbf4 else f'(bvadd (bvxor (bvadd {u} #x01fe06c9) #x59259907) (bvxor {b} #x08156cbf))';reg='w1'if pc==0x100bdbbf4 else'w12';lemma='parallel_carry_circuit_is_add_then_xor'if pc==0x100bdbbf4 else'masked_boolean_sum_is_two_encoded_operands_added';cuts.append({'site':i['ea'],'register':reg,'original_value':reentry.get(reg),'replacement':value,'universal_lemma':'replayed_combine_'+lemma,'actual_input_bindings':{'V':v}if pc==0x100bdbbf4 else{'U':u,'B':b}});reentry.put(reg,value)
 models['reentry']=reentry
 for reg,value in cs['compact_outputs_SMT'].items():
  expected=re.sub(r'\b(?:A[0-3]|S[0-3])\b',lambda m:'H_'+m[0],value);cert('reentry_compact_W'+reg,reentry,[neq(reentry.get('w'+reg),expected)],extra=defs)
 cert('reentry_rearms_private_phase_and_selects_distinct_mix',reentry,[neq(reentry.stores[0]['address'],frame(0x448)),neq(reentry.stores[0]['value'],bv(1,32)),neq(rd(reentry,0x100bdbcb0)['address'],at(0x4cdb))]);assert len(reentry.stores)==1
 repeat=FrameSSA('repeat_mix',{**reentry.r},presets=common);repeat.defs=list(reentry.defs);repeat.decl=dict(reentry.decl);repeat.loaded=reentry.loaded;run(repeat,'repeat_mix');models['repeat_mix']=repeat
 cert('repeat_mix_rejoins_spills_with_new_control_context',repeat,[neq(rd(repeat,0x100d41c20)['address'],at(0x17d8)),neq(repeat.get('w8'),bv(0x3146,32)),neq(repeat.get('w16'),bv(0x17d8,32)),neq(repeat.get('w27'),bv(0x56,32)),neq(repeat.get('w28'),bv(0xd4,32))]);assert not repeat.stores
 spills=FrameSSA('shared_spills',{**repeat.r},presets={**common,0x448:(bv(1,32),32)});spills.defs=list(repeat.defs);spills.decl=dict(repeat.decl);spills.loaded=repeat.loaded;run(spills,'shared_spills');models['shared_spills']=spills
 cert('shared_spills_changes_F460_to86_and_preserves_phase_one',spills,[neq(spills.loadframe(0x460,32),bv(86,32)),neq(spills.loadframe(0x448,32),bv(1,32)),neq(rd(spills,0x100bf3370)['address'],at(0x3146))]);assert len(spills.stores)==20
 save=FrameSSA('save_request',{0:'R'});run(save,'save_request');models['save_request']=save;cert('core_saves_private_request_R_at_F388',save,[neq(save.stores[0]['address'],frame(0x388)),neq(save.stores[0]['value'],'R')])
 supplied={0x100d9dcec:(bv(int(s['codec_roots'][0]['fixup']['target'])),64),0x100d9dd00:(bv(int(s['codec_roots'][1]['fixup']['target'])),64)}
 workspace=FrameSSA('workspace',{12:bv(0x7a8c),4:bv(0x528cdb78)},presets=common,loads={hex(k):v for k,v in supplied.items()});run(workspace,'workspace');models['workspace']=workspace
 coll=rd(workspace,0x100d9dc14)['input'];value=rd(workspace,0x100d9dccc)['input']
 cert('workspace_request_C0_chain_and_null_dispatch',workspace,[neq(rd(workspace,0x100d9dc14)['address'],f'(bvadd R {bv(8)})'),neq(rd(workspace,0x100d9dccc)['address'],coll),neq(rd(workspace,0x100d9dd18)['address'],f'(ite (= {value} {bv(0)}) {at(0x7acf)} {at(0x7a8c)})'),neq(workspace.get('x0'),value),neq(workspace.get('w8'),bv(0x4923,32)),neq(workspace.get('w9'),bv(0xf518,32)),neq(rd(workspace,0x100d9dcec)['address'],bv(0x1010a4328)),neq(rd(workspace,0x100d9dd00)['address'],bv(0x1010a6578)),neq(workspace.loadframe(0x588,64),bv(0x100fc4130)),neq(workspace.loadframe(0x568,64),bv(0x101031ea0))])
 norm=next(v for v in workspace.normalizations if v['kind']=='STUR_private_alias');cert('unaligned_STUR_is_private_F834',workspace,[neq(norm['original_address'],frame(0x834))])
 # A candidate simplifier proposes forms;every acceptance query uses raw source SSA.
 d=graph(workspace);codec=[];constants=[]
 for row in workspace.frame_writes:
  off=row['frame_offset'];x=d.get(parse(row['value']));names=sorted(leaves(d,x));candidate=affine_candidate(d,x);expr=emit(d,x)
  if names and candidate is None:
   proposals=[]
   for target in names:
    cut=expr
    for n in names:
     if n!=target:cut=re.sub(r'\b'+re.escape(n)+r'\b','#x00000000',cut)
    a=affine_candidate(d,d.get(parse(cut)))
    if a:proposals.append(a)
   if len(proposals)==1:candidate=proposals[0]
   else:
    assert not proposals
    for n in names:expr=re.sub(r'\b'+re.escape(n)+r'\b','#x00000000',expr)
    c=d.const(d.get(parse(expr)));assert c is not None
    constants.append({**row,'constant_u64':c,'source_dependencies_eliminated':names});continue
  if candidate:
   assert row['width_bits']==32 and candidate['multiplier']in[0x883dd861,0x77c2279f]
   expected=f'(bvadd (bvmul (bvxor {candidate["input"]} {bv(candidate["xor_mask"],32)}) {bv(candidate["multiplier"],32)}) {bv(candidate["bias"],32)})';name=cert('workspace_word_codec_'+hex(off),workspace,[neq(row['value'],expected)]);codec.append({**row,**candidate,'source_dependencies_before_reduction':names,'certificate':name,'inverse_multiplier':pow(candidate['multiplier'],-1,2**32),'recovered_input_frame_offset':int(candidate['input'].split('_')[1],16)})
  else:
   c=d.const(x);assert c is not None;constants.append({**row,'constant_u64':c,'source_dependencies_eliminated':[]})
 cert('workspace_all_literal_values_including_cancelled_input',workspace,[neq(r['value'],bv(r['constant_u64'],r['width_bits']))for r in constants])
 assert len(codec)==32 and len({r['input']for r in codec})==32 and{r['frame_offset']for r in codec}==set(range(0x768,0x7e8,4))
 assert {r['recovered_input_frame_offset']for r in codec}==set(range(0x3b0,0x434,4))-{0x424}
 for a in[0x883dd861,0x77c2279f]:
  inv=pow(a,-1,2**32);assert a*inv%2**32==1;solve('workspace_inverse_multiplier_'+hex(a),'(assert '+neq(f'(bvmul {bv(a,32)} {bv(inv,32)})',bv(1,32))+')')
 workspace_bytes={r['frame_offset']+j for r in workspace.frame_writes for j in range(r['width_bits']//8)if 0x768<=r['frame_offset']<0x890};assert workspace_bytes==set(range(0x768,0x890));assert sum(r['width_bits']//8 for r in workspace.frame_writes)==312
 assert len(workspace.frame_writes)==65 and len({r['frame_offset']+j for r in workspace.frame_writes for j in range(r['width_bits']//8)})==312
 null=FrameSSA('cell_null',{8:bv(0x4923)},presets=common);run(null,'cell_null');models['cell_null']=null;local=rd(null,0x100cbddd4)['input'];cert('null_C0_value_tests_LOCAL_and_sets_raw_error',null,[neq(rd(null,0x100cbddd4)['address'],f'(bvadd R {bv(0x18)})'),neq(rd(null,0x100cbddf0)['address'],f'(ite (= {local} {bv(0)}) {at(0x4923)} {at(0x4928)})'),neq(null.get('w9'),bv(0x74c29dee,32))])
 present=FrameSSA('cell_present',{0:'U',9:bv(0xf518)},presets=common);run(present,'cell_present');models['cell_present']=present
 cert('present_C0_value_preserves_pointee_and_rebases_workspace',present,[neq(present.get('x0'),'U'),neq(rd(present,0x100a7653c)['address'],at(0xac4c)),neq(present.get('x26'),frame(0xd10)),neq(present.loadframe(0x750,64),frame(0xd10))])
 reject=FrameSSA('reject_prefix',{9:bv(0x74c29dee)},presets=common);run(reject,'reject_prefix');models['reject_prefix']=reject;cert('late_null_null_suffix_publishes_raw_result_before_guard',reject,[neq(reject.stores[0]['address'],'R'),neq(reject.stores[0]['value'],bv(0x74c29dee,32)),neq(reject.flags['eq'],f'(= {rd(reject,0x100d7cc64)["input"]} {rd(reject,0x100d7cc58)["input"]})')])
 # Source frame-address certification covers data stores and saved-root epochs.
 for name in['selected_prefix','reentry','shared_spills','workspace','cell_present']:
  g=models[name];assert len(g.stores)==len(g.frame_writes);cert(name+'_all_private_frame_store_addresses',g,[neq(r['address'],frame(v['frame_offset']))for r,v in zip(g.stores,g.frame_writes)])
  written={r['frame_offset']+j for r in g.frame_writes for j in range(r['width_bits']//8)};assert not written&(set(range(0x8b0,0xcf4))|set(range(0xd00,0x10c3))|set(range(0x388,0x390)))
 # The original request save is outside this post-round preservation window.
 solve('phase_zero_domain_nonempty','(assert (= (bvand VALUE #x00000001) #x00000000))',result='sat')
 solve('phase_one_domain_nonempty','(assert (= (bvand VALUE #x00000001) #x00000001))',result='sat')
 solve('wrong_PHASE_upper_bits_test_counterexample','(assert (= (bvand VALUE #x00000001) #x00000000))\n(assert (distinct VALUE #x00000000))',result='sat')
 solve('C0_and_pointee_null_tests_differ_counterexample','(assert (distinct COLL #x0000000000000000))\n(assert (= U #x0000000000000000))',result='sat')
 records={n:g.record_full()for n,g in models.items()};actual={pc for m in records.values()for pc in m['source_sites']};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 semantics={'source_nonbranch_sites_translated':len(actual),'source_models':records,'combiner_cut_bindings':cuts,'predecessor_F448_and_F388_preservation':preservation,'phase_lifecycle':{'earlier_combiner_value':0,'preserved_until_new_gate':True,'new_gate_uses_low_bit_only':True,'zero_bit_reentry_store':1,'reentry_target':'0x100d41af4','shared_spill_target':'0x100bf3160','repeat_entry_W27':86,'repeat_spilled_F460':86,'later_phase_one_visit_reachability_proved':False},'repack_store_ledger':repack,'repack_words':16,'repack_bytes':64,'workspace_codec_ledger':sorted(codec,key=lambda r:r['frame_offset']),'workspace_literal_ledger':constants,'workspace_input_word_offsets':sorted(r['recovered_input_frame_offset']for r in codec),'workspace_data_offset':0x768,'workspace_data_bytes':128,'workspace_literal_offset':0x7e8,'workspace_literal_bytes':168,'workspace_total_bytes':296,'workspace_frame_store_operations':65,'workspace_bytes_including_two_saved_roots':312,'workspace_positive_multiplier_fields':sum(r['multiplier']==0x883dd861 for r in codec),'workspace_negative_multiplier_fields':sum(r['multiplier']==0x77c2279f for r in codec),'word_encoding_bijection_under_entry_constants':True,'source_candidate_reduction_is_not_trusted_without_queries':True,'input_hole_F424_read':False,'request_interface':{'saved_request_cell':'F388=R','R_plus8':'C0 from u64[OBJ]','R_plus18':'LOCAL','nonnull_C0_pointee_target':'0x100a76520','null_C0_pointee_nonnull_LOCAL_target':'0x100c57884','null_C0_pointee_null_LOCAL_target':'0x100d7cc50','raw_result_store':'0x100d7cc54: u32[R]=0x74c29dee','guard_before_return_remains_required':True},'saved_root_epochs':{'F568':'0x101031ea0 replaces earlier biased frame view','F588':'0x100fc4130 replaces earlier shift-count value7','F750_on_present_cell_path':'u64 pointer F+d10 replaces earlier u32 counter/data role'},'word_view_and_old_scratch_contents_unwritten_by_new_blocks':True,'future_codec_may_reuse_old_scratch_view':True,'conditional_suffix_native_reachability_proved':False,'caller_output_publication_proved':False,'complete_algorithm_identified':False,'Mach_port_emissions':0,'native_claim':False}
 return pp,semantics
def verify(s):return s==build()
def alterations(s):
 cases=[('wrong_repack_source',lambda q:q['fragments']['repack'].__setitem__('bytes','00'+q['fragments']['repack']['bytes'][2:])),('wrong_request_save',lambda q:q['fragments']['save_request']['instructions'][0].__setitem__('operands','x1, [sp, #0x388]')),('wrong_STUR_offset',lambda q:q['unscaled_immediate_checks'][0].__setitem__('immediate_s9',0)),('wrong_pointer_bias',lambda q:q['codec_roots'][0].__setitem__('bias_u64','0x0')),('wrong_error_target',lambda q:q['branch_edges'][-2].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for n,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'repack_word_stores':16,'workspace_word_codecs_proved':32,'workspace_bytes':296,'workspace_store_operations':65,'positive_multiplier_word_codecs':sem['workspace_positive_multiplier_fields'],'negative_multiplier_word_codecs':sem['workspace_negative_multiplier_fields'],'combiner_cuts_bound':len(sem['combiner_cut_bindings']),'rejected_alterations':len(aa)}
 deps=[P+'_source.json','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','daemon_word_lookup_algebra.py','validate_daemon_mode_one_word_rounds.py','validate_daemon_mode_one_bank_combine.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_phase_handoff_and_request_suffixes_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
