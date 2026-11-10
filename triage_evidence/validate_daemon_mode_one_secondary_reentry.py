#!/usr/bin/env python3
"""Source-pinned state commit,modular progression and generalized parity reentry."""
import copy,json,shutil,subprocess
from recover_daemon_mode_one_secondary_reentry import ROOT,P,SCOPE,FLAGS,DEPS,FIELDS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_checkpoint import PostSSA
from validate_daemon_mode_one_word_xor_plane_refresh import RefreshSSA,OFFSETS
from validate_daemon_list_output import split
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq,low
SOLVER=shutil.which('z3');assert SOLVER

class ToggleSSA(PostSSA):
 def __init__(self,*a,forward=False,**kw):super().__init__(*a,**kw);self.forward=forward;self.original_byte_accesses=[];self.numerator=None
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc==0x100c2aba8:self.numerator=self.get('w9')
   if pc in[0x100c2abc8,0x100c2abd0]:
    p=split(i['operands']);self.original_byte_accesses.append({'site':i['ea'],'mnemonic':i['mnemonic'],'original_address':self.address(p[1]),'frame_offset':0x8b0})
    if self.forward:i={**i,'operands':p[0]+', [sp, #0x8b0]'}
   super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'original_byte_accesses':self.original_byte_accesses,'guarded_zero_numerator_source_ref':self.numerator,'guarded_byte_address_normalizations':2 if self.forward else 0}

def chain(old,name,loads=None,cls=PostSSA,**kw):
 g=cls(name,old.r,loads=loads,**kw);g.defs=list(old.defs);g.decl=dict(old.decl);g.byte_cells=dict(old.byte_cells);g.loaded=old.loaded;return g

def certificates(s):
 pp=[];mm={};fs=s['fragments']
 def solve(name,g=None,terms=(),cc=(),result='unsat'):
  q='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL
  if g is not None:q+=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
  q+=''.join('(assert '+v+')\n'for v in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout[:1600],r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def replay(prefix,names):
  c=json.loads(read(ROOT/(prefix+'_checks.json')));rows=[p for p in c['proofs']if p['name']in names];assert len(rows)==len(names)
  for p in rows:
   r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_'+prefix+'_'+p['name'],'replayed_query':True})
  print('replayed',prefix,len(rows),flush=True)
 replay('daemon_mode_one_secondary_rounds',['round_counter_progress_repeat_exit_and_update_W4','update_caller_bound_flag_partition_and_phase_words','gate_overflow_aware_rotated_unsigned_comparison'])
 replay('daemon_mode_one_word_xor_plane_refresh',['first_masked_complement_address_lemma','second_masked_complement_address_lemma','raw_word_full_mask_shift_counts_and_computed_fourth_read','coherent_word_numeric_XOR_contract_and_original_byte_address','secondary_root_seed_divisor_and_full_known_entry_contract'])
 replay('daemon_mode_one_parity_state_adapters',['join_exact_word_comparison_and_two_targets'])
 parent=json.loads(read(ROOT/'daemon_mode_one_secondary_rounds_source.json'))['fragments']
 def run(g,name,fragment=None):
  f=fragment or fs[name];g.run(f,int(f['instructions'][-1]['ea'],16));mm[name]=g;return g
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 def frame_cert(name,g):
  rr={r['site']:r for r in g.reads};ss={r['site']:r for r in g.stores};solve(name+'_all_frame_effect_addresses',g,[neq(rr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_reads]+[neq(ss[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_writes])
 gate=PostSSA('incoming_gate',presets={0x740:('TABLE',64),0x6c0:(bv(0x66f1,32),32),0x4a8:('POSA',32),0x4b0:('BOUND',32)},loads={'0x100b50508':('GFN',64)});gate.decl.update(POSA=32,BOUND=32,GFN=64);run(gate,'incoming_gate',parent['gate'])
 solve('actual_incoming_gate_supplies_W12_34d0',gate,[neq(gate.get('x12'),bv(0x34d0))]);frame_cert('incoming_gate',gate)
 fp={0x740:('TABLE',64),0x758:(frame(0x8b0),64),0x37c:('SAVEC',32),0x4a8:('POSA',32),0x4ac:('BASEA',32),0x380:('VIEW',64)}
 f=PostSSA('finish',{12:bv(0x34d0)},presets=fp,loads={'0x100c58630':('FFN',64)});f.decl.update(SAVEC=32,POSA=32,BASEA=32,VIEW=64,FFN=64);run(f,'finish');frame_cert('finish',f)
 def plus(*xs):
  a=xs[0]
  for x in xs[1:]:a='(bvadd '+a+' '+x+')'
  return a
 fw={0x4e8:low('Z21'),0x4ec:plus('IF_4ec_32',low('Z4'),bv(0x8ede8a84,32)),0x4e4:plus('IF_4e4_32','IF_748_32',bv(0x8a43bb97,32)),0x4d4:plus('IF_4d4_32','IF_6e0_32',bv(0xe4640623,32)),0x4f4:plus('IF_4f4_32',low('Z1'),bv(0xb04e19a8,32)),0x4f0:plus('IF_4f0_32','IF_6c8_32',bv(0x9e2d27b0,32)),0x4c4:plus(low('Z24'),bv(0x30afe1d7,32)),0x4b8:plus(low('Z28'),bv(0x7ac330f3,32)),0x4cc:plus(low('Z0'),bv(0x64568826,32)),0x4d0:plus('IF_700_32',bv(0xdc0fe53c,32)),0x4c8:plus(low('Z6'),bv(0xb334fa38,32)),0x4d8:plus('IF_6cc_32',bv(0xd3144844,32)),0x4a8:plus('POSA',bv(64,32))}
 solve('all13_exact_finish_word_store_values',f,[neq(f.loadframe(off,32),value)for off,value in fw.items()])
 solve('finish_obfuscated_SAVEC_plus64_and_preserved_difference',f,[neq(f.get('x19'),z('(bvadd SAVEC #x00000040)')),neq('(bvsub '+f.get('w19')+' '+f.loadframe(0x4a8,32)+')','(bvsub SAVEC POSA)')])
 const={13:0x4923,7:0xb4,20:0xd6,27:0x2dd9b66a,10:0xc4a2eed2,12:0x34d0,17:0x63f8}
 solve('finish_full_known_refresh_ABI_and_selected_edge',f,[neq(f.get('x'+str(j)),bv(v))for j,v in const.items()]+[neq(f.get('x6'),'TABLE'),neq(f.get('x21'),frame(0x8b0)),neq(f.get('x0'),'VIEW'),neq(f.get('w22'),'BASEA'),neq(f.get('w1'),plus(low('Z5'),bv(0xa2b7b62e,32))),neq(f.get('w25'),plus(low('Z20'),bv(0x041f9635,32))),neq(f.get('w2'),plus(low('Z3'),bv(0xac0023c3,32))),neq(rd(f,0x100c58630)['address'],at(0x34d0))])
 solve('old_fixed_refresh_W19_is_not_current_finish_ABI',f,[neq(f.get('w19'),bv(0x4a62f57c,32))],cc=['(= SAVEC #x4a62f57c)'],result='sat')
 # Compose the actual state-update and gate bodies before the12-field finish.
 u=PostSSA('update',{4:bv(0xa9d0)},presets={**fp,0x4f8:('FLAG',32),0x4b0:('BOUND',32)},loads={'0x100c54110':('UFN',64)});u.decl.update(SAVEC=32,POSA=32,BASEA=32,VIEW=64,FLAG=32,BOUND=32,UFN=64);run(u,'incoming_update',parent['update'])
 ug=chain(u,'chained_gate',{'0x100b50508':('CGFN',64)});ug.decl['CGFN']=64;run(ug,'chained_gate',parent['gate']);uf=chain(ug,'chained_finish',{'0x100c58630':('CFFN',64)});uf.decl['CFFN']=64;run(uf,'chained_finish',fs['finish'])
 selected=['(= (bvand FLAG #x00000001) #x00000000)','(bvule (bvadd POSA #xad3f0bc9) (bvadd BOUND #x4444fb6c))']
 solve('chained_update_gate_finish_control_and_progress',uf,[neq(uf.get('x19'),z('(bvadd SAVEC #x00000040)')),neq(uf.loadframe(0x4a8,32),'(bvadd POSA #x00000040)'),neq(rd(uf,0x100c58630)['address'],at(0x34d0))],cc=selected)
 state_writes=[r for q in[u,ug,uf]for r in q.frame_writes if r['frame_offset']in FIELDS];assert len(state_writes)==16 and{r['frame_offset']for r in state_writes}==set(FIELDS)and all(r['width_bits']==32 for r in state_writes)
 # The previous refresh's fixed W19 premise is generalized to everyu32 PSTATE.
 rr={6:'TABLE',13:bv(0x4923),19:z('PSTATE'),22:z('AWORD'),21:frame(0x8b0),27:bv(0x2dd9b66a),7:bv(0xb4),20:bv(0xd6)};rp={0x740:('TABLE',64),0x4ac:('AWORD',32),0x728:('RSTATE',32),0x6f8:('SSTATE',32),0x4b4:('PAR',32),0x4a4:('BWORD',32)}
 def refresh(name,forward):
  q=RefreshSSA(name,rr,presets=rp,loads={'0x100c65114':('RFN',64)},forward=forward);q.decl.update(RSTATE=32,SSTATE=32,PAR=32,AWORD=32,BWORD=32,RFN=64,PSTATE=32);return run(q,name,fs['refresh'])
 raw=refresh('raw_refresh',False);solve('generalized_refresh_four_original_computed_addresses',raw,[neq(r['original_address'],frame(r['frame_offset']))for r in raw.original_addresses]);frame_cert('raw_refresh',raw)
 g=refresh('refresh',True);solve('coherent_generalized_refresh_original_addresses',g,[neq(r['original_address'],frame(r['frame_offset']))for r in g.original_addresses]);frame_cert('refresh',g)
 solve('generalized_refresh_PSTATE_and_parity_control_handoff',g,[neq(rd(g,0x100c65114)['address'],'(ite (= (bvand PAR #x00000001) #x00000000) '+at(0x1e11)+' '+at(0x1e31)+')'),neq(g.get('w2'),'PSTATE'),neq(g.get('w10'),'(bvadd PSTATE AWORD)'),neq(g.get('w16'),'BWORD'),neq(g.get('x8'),bv(0x4d20)),neq(g.get('x13'),bv(0x4923)),neq(g.get('x4'),bv(799)),neq(g.get('x23'),bv(0xb3)),neq(g.get('x7'),bv(0x883fddf1)),neq(g.get('x20'),bv(0xd6)),neq(g.get('x21'),frame(0x8b0)),neq(g.get('x17'),bv(0xe346))])
 assert len(g.stores)==len(g.frame_writes)==130 and len(g.reads)==5 and not g.initial and len(g.proved_cuts)==2
 planes=[r for r in g.frame_writes if r['width_bits']==8];assert len(planes)==128 and{r['frame_offset']for r in planes}=={0x8b0+799*j%962 for j in list(range(64))+list(range(593,657))}
 odd=chain(g,'odd',{'0x100c55498':('OFN',64)});odd.decl.update(BOUND=32,OFN=64);odd.save(0x4b0,'BOUND',32,'explicit incoming bound word');run(odd,'odd');frame_cert('odd',odd)
 loose=PostSSA('missing_saved_table',{2:z('PSTATE'),8:bv(0x4d20),10:z('(bvadd PSTATE AWORD)')},presets={0x4b0:('BOUND',32)},loads={'0x100c55498':('LOFN',64)});loose.decl.update(PSTATE=32,AWORD=32,BOUND=32,LOFN=64);run(loose,'missing_saved_table',fs['odd'])
 op='(= BOUND (bvadd (bvadd PSTATE AWORD) #x1e971aa1))'
 solve('missing_saved_TABLE_allows_different_dispatch_base',loose,[neq(rd(loose,0x100c55498)['address'],'(ite '+op+' '+at(0x662c)+' '+at(0x4d20)+')')],result='sat')
 solve('odd_gate_exact_all_u32_threshold_and_saved_progress_word',odd,[neq(rd(odd,0x100c55498)['address'],'(ite '+op+' '+at(0x662c)+' '+at(0x4d20)+')'),neq(odd.loadframe(0x37c,32),'PSTATE'),neq(odd.get('x8'),bv(0x4d20)),neq(odd.get('x9'),bv(0x4923)),neq(odd.get('x7'),bv(0x883fddf1)),neq(odd.get('x4'),bv(799)),neq(odd.get('x23'),bv(0xb3)),neq(odd.get('x20'),bv(0xd6)),neq(odd.get('x21'),frame(0x8b0)),neq(odd.get('x17'),bv(0x1aad))])
 even=chain(g,'even',{'0x100d773ec':('EFN',64)});even.decl['EFN']=64;run(even,'even');frame_cert('even',even)
 ep='(= BWORD (bvadd (bvadd PSTATE AWORD) #xd61193e0))'
 solve('even_gate_exact_all_u32_threshold_and_preserved_pair',even,[neq(rd(even,0x100d773ec)['address'],'(ite '+ep+' '+at(0xc94e)+' '+at(0xc96f)+')'),neq(even.loadframe(0x6f8,32),g.get('w24')),neq(even.get('x14'),g.get('x28')),neq(even.get('x12'),bv(0x1e31)),neq(even.get('x13'),bv(0xa05a)),neq(even.get('w2'),'PSTATE'),neq(even.get('x17'),bv(0x24d9))])
 guards=[ep,'(= (bvand PAR #x00000001) #x00000000)']
 rawt=chain(even,'raw_toggle',{'0x100c2abc8':('TB',8),'0x100c2abd8':('TFN',64)},cls=ToggleSSA);rawt.decl.update(TB=8,TFN=64);run(rawt,'raw_toggle',fs['toggle'])
 solve('even_equality_forces_original_toggle_numerator_zero_and_first_plane_cell',rawt,[neq(rawt.numerator,bv(0,32))]+[neq(r['original_address'],frame(0x8b0))for r in rawt.original_byte_accesses]+[neq(rawt.stores[0]['value'],'(bvxor TB #x80)'),neq(rd(rawt,0x100c2abd8)['address'],at(0x1e31))],cc=guards)
 t=chain(even,'toggle',{'0x100c2abd8':('CTFN',64)},cls=ToggleSSA,forward=True);t.decl['CTFN']=64;run(t,'toggle');frame_cert('toggle',t)
 solve('coherent_guarded_toggle_value_pair_restoration_and_join_ABI',t,[neq(t.loadframe(0x8b0,8),'(bvxor '+g.loadframe(0x8b0,8)+' #x80)'),neq(t.get('w24'),g.get('w24')),neq(t.get('x28'),g.get('x28')),neq(t.get('w2'),'PSTATE'),neq(t.get('w10'),'(bvadd PSTATE AWORD)'),neq(t.get('x8'),bv(0x4d20)),neq(t.get('w16'),'BWORD'),neq(t.get('x17'),bv(0xe346)),neq(rd(t,0x100c2abd8)['address'],at(0x1e31))]+[neq(r['original_address'],frame(0x8b0))for r in t.original_byte_accesses],cc=guards)
 assert len(t.stores)==len(t.frame_writes)==1 and t.frame_writes[0]['frame_offset']==0x8b0 and t.frame_writes[0]['width_bits']==8
 for name in['finish','refresh','odd','even','toggle']:
  assert set(mm[name].sites)=={i['ea']for i in fs[name]['instructions'][:-1]}
 assert sum(len(mm[n].sites)for n in fs)==2418
 state_bytes={off+j for off in FIELDS for j in range(4)};arith={0x8b0+799*j%962 for a,b in[(72,328),(333,589),(659,675),(677,933),(936,952)]for j in range(a,b)}
 union=set()
 for n in fs:
  q=mm[n];assert len(q.stores)==len(q.frame_writes);written={r['frame_offset']+j for r in q.frame_writes for j in range(r['width_bits']//8)};union|=written
  protected=set(range(0x350,0x378))|set(range(0x380,0x390))|set(range(0x570,0x588))|set(range(0x740,0x748))|set(range(0x750,0x760))|set(range(0x768,0x890))|set(range(0xc80,0xc80+286*4))|arith
  assert not written&protected,(n,written&protected)
  if n!='finish':assert not written&state_bytes and not written&set(range(0x4a8,0x4ac))
 assert len(union)==196 and len(arith)==800
 solve('abstract_selected_finish_domain_nonempty',uf,cc=selected,result='sat')
 effects={n:{'nonbranch_sites':len(mm[n].sites),'loads':len(mm[n].reads),'stores':len(mm[n].stores),'read_bytes':sum(r['width_bits']//8 for r in mm[n].reads),'store_effect_bytes':sum(r['width_bits']//8 for r in mm[n].stores),'distinct_frame_bytes_written':len({r['frame_offset']+j for r in mm[n].frame_writes for j in range(r['width_bits']//8)})}for n in fs}
 sem={'source_models':{n:g.record_full()for n,g in mm.items()},'source_nonbranch_sites_translated':2418,'guarded_toggle_constraints':guards,'guarded_toggle_cell':'C(0)=F+0x8b0','guarded_toggle_operation':'refreshed_byte XOR0x80','guarded_toggle_original_numerator':rawt.numerator,'guarded_toggle_address_normalizations':2,'current_source_ranges':list(fs),'finish_state_store_equations':{hex(k):v for k,v in fw.items()},'finish_progress_W19':'u32(SAVEC+64)','finish_progress_F4a8':'u32(POSA+64)','preserved_modular_difference':'W19-new_F4a8=SAVEC-POSA mod2^32','chained_state_field_write_ledger':state_writes,'chained_state_fields_written':16,'chained_state_field_bytes':64,'chained_selected_path_constraints':selected,'refresh_entry_PSTATE':'arbitraryu32;actual finish supplies SAVEC+64','refresh_proved_value_cuts':g.proved_cuts,'refresh_computed_store_normalizations':4,'refresh_plane_store_ledger':planes,'plane_bytes_written':128,'arithmetic_cells_preserved':800,'odd_gate_predicate':op,'even_gate_predicate':ep,'odd_saved_F37c':'PSTATE;with finish interface,SAVEC+64','even_saved_F6f8':'incoming refresh-output W24','even_copy_X14':'incoming refresh-output X28','effect_counts':effects,'all_current_ranges_distinct_bytes_written':196,'whole_arithmetic_proved':False,'native_field_meanings_proved':False,'outer_loop_termination_proved':False,'native_mapping_proved':False,'native_output_proved':False,'daemon_kext_pairing_proved':False,'Mach_port_emissions':0,'new_IDA_access':False,'coherence_boundary':'Named computed loads are broad independent inputs;literal private-frame byte forwarding is exact. Current four refresh store normalizations use original-address proofs and two replayed arbitrary-input slice lemmas. Stable nonwrapping mappings,root continuity and no outside writes remain premises. SAT valuations may omit native correlations.','unresolved_frontier':'Even equal is now proved to toggle C(0) under its correlated source guard and to restore the refresh-output register pair before the odd comparison. Even unequal reaches31-instruction0x100daefe8;neither outgoing body is newly translated here. The separate9241-instruction continuation remains unresolved.','excluded_exploration':'A fixed W19=4a62f57c proposal was false even with saved SAVEC=4a62f57c. Accepted source identity is W19=SAVEC+64;the refresh contract is freshly generalized to everyu32 PSTATE. An exploratory chained gate lacked the saved F740=TABLE premise and admitted a different dispatch base;the accepted model binds both saved F740 and cached X6 to TABLE and retains that negative control. No native byte-count,cursor,loop-termination,digest or public output identity follows from modular increments alone.'}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('source_byte',lambda q:q['fragments']['finish'].__setitem__('bytes','00'+q['fragments']['finish']['bytes'][2:])),('finish_target',lambda q:q['branch_edges'][0].__setitem__('target','0x0')),('even_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('modifier',lambda q:q['branch_edges'][0].__setitem__('IA_diversity','0x0')),('bitfield_width',lambda q:q['ISA_decode_checks'][0].__setitem__('width_bits',64)),('lineage_hash',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert q!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':2418,'finish_u32_stores':13,'chained_saved_state_fields_written':16,'chained_saved_state_bytes':64,'plane_byte_stores':128,'arithmetic_cells_preserved':800,'refresh_proved_value_cuts':2,'refresh_store_address_normalizations':4,'current_distinct_bytes_written':196,'guarded_first_plane_byte_XOR_sites':1,'guarded_byte_address_normalizations':2,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','validate_daemon_existing_scalar_reader.py','validate_daemon_mode_one_word_xor_plane_refresh.py','daemon_word_round_tools.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'secondary_state_commit_generalized_refresh_and_reentry_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
