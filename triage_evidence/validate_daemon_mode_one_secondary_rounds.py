#!/usr/bin/env python3
"""Prove source-bound scalar control,selector composition and word address contracts."""
import copy,json,math,shutil,subprocess
from recover_daemon_mode_one_secondary_rounds import ROOT,P,SCOPE,FLAGS,DEPS,FIELDS,LEFT,RIGHT,ROM,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_checkpoint import PostSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq
from validate_daemon_mode_one_secondary_word_extension import frame_value,model as parent_model
from daemon_word_round_tools import lookup
SOLVER=shutil.which('z3');assert SOLVER

def models(s):
 fs=s['fragments'];f=fs['setup'];bb=[i for i in f['instructions']if i['mnemonic']=='ldrb'and'[sp,'not in i['operands']];assert len(bb)==483
 loads={i['ea']:('RB'+str(j),8)for j,i in enumerate(bb)};loads['0x100c3685c']=('SFN',64)
 presets={off:('IV'+str(j),32)for j,off in enumerate(FIELDS)};presets.update({0x740:('TABLE',64),0x530:(bv(0xa9d0,32),32),0x730:('ST0',32),0x738:('ST1',32),0xa36:('E0',8)})
 setup=PostSSA('setup',{6:bv(799),16:bv(962),21:frame(0x8b0)},presets=presets,loads=loads);setup.decl.update({**{'IV'+str(j):32 for j in range(16)},**{'RB'+str(j):8 for j in range(483)},'SFN':64,'ST0':32,'ST1':32,'E0':8});div=[]
 for i in f['instructions'][:-1]:
  if i['mnemonic']=='udiv':div.append({'site':i['ea'],'denominator':setup.get(i['operands'].split(',')[-1].strip(),32)})
  setup.run({'instructions':[i]},int(i['ea'],16)+4)
 presets={0x740:('TABLE',64),0x750:(frame(0xc80),64),0x758:(frame(0x8b0),64),0x570:(bv(RIGHT),64),0x578:(bv(LEFT),64),0x580:('CELL0',64),0x748:('(bvmul IX #x000000f1)',32),0x738:('(bvadd #x000043c8 (bvmul IX #x000000f1))',32),0x6e0:('(bvsub #x0000003f IX)',32),0x530:(bv(0xa9d0,32),32),0x51c:(bv(0xbfee13c6,32),32)}
 pointer=int(s['coded_word_bank_pointer']['fixup']['target']);loads={'0x100b18d9c':('C0',32),'0x100b18da4':('G0',32),'0x100b18dd4':('LEFTBYTE',8),'0x100b18de4':('RIGHTBYTE',8),'0x100b19034':(bv(pointer),64)}
 def round_model(name,cut):
  g=PostSSA(name,{**{j:z('J'+str(j))for j in range(31)},28:z('(bvadd #x28ef15ed IX)')},presets=presets,loads=loads);g.decl.update({**{'J'+str(j):32 for j in range(31)},'CELL0':64,'C0':32,'G0':32,'LEFTBYTE':8,'RIGHTBYTE':8});snapshot=None
  for i in fs['round']['instructions'][:-1]:
   g.run({'instructions':[i]},int(i['ea'],16)+4)
   if i['ea']=='0x100b19024':
    snapshot=g.get('w9')
    if cut:
     g.cuts.append({'site':i['ea'],'register':'w9','original_value':snapshot,'replacement':bv(0xb6,32),'justification':['raw_controller_CELL0_global_and_two_bank_addresses','original_image_bank_composition_is_b6_for_all_u8']});g.put('w9',bv(0xb6,32))
    else:break
  return g,snapshot
 raw,snapshot=round_model('raw_selector',False);rnd,_=round_model('round',True)
 update=PostSSA('update',{4:bv(0xa9d0)},presets={0x740:('TABLE',64),0x4f8:('FLAG',32)},loads={'0x100c54110':('UFN',64)});update.decl.update(FLAG=32,UFN=64);update.run(fs['update'],int(fs['update']['instructions'][-1]['ea'],16))
 gate=PostSSA('gate',presets={0x740:('TABLE',64),0x6c0:(bv(0x66f1,32),32),0x4a8:('GA',32),0x4b0:('GB',32)},loads={'0x100b50508':('GFN',64)});gate.decl.update(GA=32,GB=32,GFN=64);gate.run(fs['gate'],int(fs['gate']['instructions'][-1]['ea'],16))
 return {'setup':setup,'raw_selector_prefix':raw,'round':rnd,'update':update,'gate':gate},div,snapshot

def certificates(s):
 pp=[]
 def solve(name,g=None,terms=(),cc=(),result='unsat',body='',extra=''):
  q='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL+extra
  if g is not None:q+=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
  q+=body+''.join('(assert '+v+')\n'for v in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout[:1600],r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def replay(prefix,names):
  c=json.loads(read(ROOT/(prefix+'_checks.json')));rows=[p for p in c['proofs']if p['name']in names];assert len(rows)==len(names)
  for p in rows:
   r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_'+prefix+'_'+p['name'],'replayed_query':True})
  print('replayed',prefix,len(rows),flush=True);return c
 old=replay('daemon_mode_one_secondary_word_extension',['actual_parent_full_initial_control_ABI_and_saved_roots','closing_counter_biases_roots_and_repeat_exit','all_four_original_word_store_addresses','all_eight_original_word_addresses'])
 replay('daemon_mode_one_secondary_word_import',['post_quad3_exact_control_handoff_six_frame_fields_and_raw_u8_function'])
 replay('daemon_mode_one_inverse_tables',['left_root_rebased_pointer_and_bias','right_root_rebased_pointer_and_bias','frame_bank_and_counter_root_publication','frame_counter_pointer_publication'])
 replay('daemon_mode_one_parity_state_adapters',['fresh_initializer_dispatch_flag_zero_position_and_roots','odd_setup_initial_zero_flag_selects_toggle','even_setup_initial_zero_flag_selects_toggle'])
 parent=json.loads(read(ROOT/'daemon_mode_one_secondary_word_extension_source.json'));pg=parent_model(parent,'extension')
 solve('actual_parent_final_W6_W16_and_primary_root',pg,[neq(pg.get('w6'),bv(799,32)),neq(pg.get('w16'),bv(962,32)),neq(pg.get('x21'),frame(0x8b0))],cc=['(= IX #x0000002f)'])
 imp=json.loads(read(ROOT/'daemon_mode_one_secondary_word_import_checks.json'))['semantics']['source_models']['post_import_chained_to_quad3']
 solve('post_import_saved_a9d0_control_word',terms=[neq(frame_value(imp,0x530,32),bv(0xa9d0,32))],extra=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in imp['declarations'].items()),body=imp['source_SSA'],cc=['(= QUAD #x00000003)'])
 mm,div,snapshot=models(s);setup=mm['setup'];g=mm['round'];raw=mm['raw_selector_prefix'];update=mm['update'];gate=mm['gate'];domain=['(bvult IX #x00000040)']
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 def frame_cert(name,g):
  lr={r['site']:r for r in g.reads};sr={r['site']:r for r in g.stores}
  solve(name+'_literal_frame_read_store_addresses',g,[neq(lr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_reads]+[neq(sr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_writes])
 for n in['setup','round','update','gate']:
  q=mm[n];frame_cert(n,q);assert len(q.stores)==len(q.frame_writes)and all(r['width_bits']==32 for r in q.stores)
  assert set(q.sites)=={i['ea']for i in s['fragments'][n]['instructions'][:-1]}
 assert len(g.cuts)==1 and all(not q.alias_records and not q.indexed_records and not q.normalizations for q in mm.values())
 assert not setup.initial and(len(setup.sites),len(setup.reads),len(setup.frame_writes))==(10636,668,172)
 const={0x748:0,0x738:0x43c8,0x6e0:63,0x51c:0xbfee13c6}
 solve('setup_initial_counter_63_biases_W28_and_zero_high_liveins',setup,[neq(setup.loadframe(off,32),bv(v,32))for off,v in const.items()]+[neq(setup.get('x28'),bv(0x28ef15ed)),neq(rd(setup,0x100c3685c)['address'],at(0xa9d0)),neq(setup.get('x17'),bv(0x4bdb))]+[neq('((_ extract 63 32) '+setup.get('x'+str(j))+')',bv(0,32))for j in[3,11,15]])
 solve('setup_all16_UDIV_denominators_are962',setup,[neq(r['denominator'],bv(962,32))for r in div])
 solve('setup_F700_copies_saved_F510_low_word',setup,[neq(setup.loadframe(0x700,32),'IV15')])
 for off,value in[(0x520,0x88dd8ab5),(0x52c,0xc90e62e0)]:solve('reject_zero_valuation_F'+hex(off)[2:]+'_constant',setup,[neq(setup.loadframe(off,32),bv(value,32))],result='sat')
 # Source binding first;then original finite image-bank composition;only then value cut.
 zz='((_ extract 7 0) (bvmul (bvxor (bvsub G0 C0) #x000000a6) #x0a5cd4cf))'
 solve('raw_controller_CELL0_global_and_two_bank_addresses',raw,[neq(rd(raw,0x100b18d9c)['address'],'CELL0'),neq(rd(raw,0x100b18da4)['address'],bv(0x1010c4670)),neq(rd(raw,0x100b18dd4)['address'],'(bvadd '+bv(LEFT)+' '+z(zz,8)+')'),neq(rd(raw,0x100b18de4)['address'],'(bvadd '+bv(RIGHT)+' '+z('(bvxor LEFTBYTE #x54)',8)+')'),neq(snapshot,'((_ zero_extend 24) (bvxor '+zz+' RIGHTBYTE))')])
 left=bytes.fromhex(s['original_banks']['left']['bytes']);right=bytes.fromhex(s['original_banks']['right']['bytes']);truth=[j^right[left[j]^0x54]for j in range(256)];assert truth==[0xb6]*256
 l=lookup(list(left),'SEL8');r=lookup(list(right),'(bvxor '+l+' #x54)')
 solve('original_image_bank_composition_is_b6_for_all_u8',terms=[neq('(bvxor SEL8 '+r+')','#xb6')],extra='(declare-fun SEL8 () (_ BitVec 8))\n')
 solve('selected_encoded_pool_slot_and_root',g,[neq(rd(g,0x100b19034)['address'],bv(int(s['coded_word_bank_pointer']['slot'],16)))],cc=domain)
 def grid(base):return '(bvadd '+frame(0xc80)+' ((_ zero_extend 32) (bvshl (bvurem (bvmul (bvadd IX '+bv(base,32)+') #x000000f1) #x0000011e) #x00000002)))'
 def rom(mask,bias):return '(bvadd '+bv(ROM)+' ((_ zero_extend 32) (bvshl (bvurem (bvmul (bvadd (bvxor IX '+bv(mask,32)+') '+bv(bias,32)+') #x00000053) #x000000c0) #x00000002)))'
 solve('all_two_grid_word_read_addresses',g,[neq(rd(g,0x100b1913c)['address'],grid(72)),neq(rd(g,0x100b19160)['address'],grid(0))],cc=domain)
 solve('all_two_image_word_read_addresses',g,[neq(rd(g,0x100b19044)['address'],rom(10,67)),neq(rd(g,0x100b19174)['address'],rom(42,0))],cc=domain)
 solve('round_counter_progress_repeat_exit_and_update_W4',g,[neq(g.loadframe(0x748,32),'(bvmul (bvadd IX #x00000001) #x000000f1)'),neq(g.loadframe(0x738,32),'(bvadd #x000043c8 (bvmul (bvadd IX #x00000001) #x000000f1))'),neq(g.loadframe(0x6e0,32),'(bvsub #x0000003e IX)'),neq(g.get('x28'),z('(bvadd #x28ef15ee IX)')),neq(g.get('x4'),bv(0xa9d0)),neq(rd(g,0x100b1c6cc)['address'],'(ite (= IX #x0000003f) '+at(0xa9df)+' '+at(0xa9d0)+')'),neq(g.get('x17'),bv(0x4bdb))]+[neq('((_ extract 63 32) '+g.get('x'+str(j))+')',bv(0,32))for j in[3,11,15]],cc=domain)
 solve('update_caller_bound_flag_partition_and_phase_words',update,[neq(update.loadframe(0x6e8,32),bv(0xaa1c,32)),neq(update.loadframe(0x738,32),bv(0xb55a,32)),neq(update.loadframe(0x6c0,32),bv(0x66f1,32)),neq(update.get('w2'),'(bvand FLAG #x00000001)'),neq(rd(update,0x100c54110)['address'],'(ite (= (bvand FLAG #x00000001) #x00000000) '+at(0xaa1c)+' '+at(0xaa31)+')'),neq(update.get('x17'),bv(0x97d1))])
 aa='(bvadd GA '+bv((0x7f34a683-0xd1f59aba)&0xffffffff,32)+')';bb='(bvadd GB '+bv((0x163a9626-0xd1f59aba)&0xffffffff,32)+')';predicate='(bvugt '+aa+' '+bb+')'
 solve('gate_overflow_aware_rotated_unsigned_comparison',gate,[neq(gate.loadframe(0x738,32),bv(0xb55a,32)),neq(rd(gate,0x100b50508)['address'],'(ite '+predicate+' '+at(0x6703)+' '+at(0x66f1)+')'),neq(gate.get('x17'),bv(0xbf61))])
 for n in['setup','round','update','gate']:
  written={r['frame_offset']+j for r in mm[n].frame_writes for j in range(4)}
  protected=set(range(0x570,0x588))|set(range(0x740,0x748))|set(range(0x750,0x760))|set(range(0x8b0,0x8b0+962))|set(range(0xc80,0xc80+4*286))|set(range(0x4f8,0x4fc))|set(range(0x51c,0x520))|set(range(0x530,0x534))
  if n=='setup':protected-=set(range(0x51c,0x520))
  assert not written&protected,(n,written&protected)
 assert len(g.reads)==271 and len(g.frame_reads)==123 and len(g.frame_writes)==112
 known={base+j for base in[0,72,142,212]for j in range(64)};ledger=[];word_addresses=set();image_addresses=set()
 for ix in range(64):
  labels=[ix+72,ix];assert set(labels)<=known;d=[0xc80+4*((241*j)%286)for j in labels];rr=[ROM+4*((83*((ix^10)+67))%192),ROM+4*((83*(ix^42))%192)];word_addresses.update(d);image_addresses.update(rr);ledger.append({'IX':ix,'word_labels':labels,'word_frame_offsets':d,'image_word_addresses':[hex(v)for v in rr],'repeat':ix<63,'outgoing_countdown':(62-ix)&0xffffffff})
 assert all(not set(range(0x530,0x534))&set(range(r['frame_offset'],r['frame_offset']+r['width_bits']//8))for r in pg.frame_writes)
 assert math.gcd(241,286)==math.gcd(83,192)==1 and len(word_addresses)==len(image_addresses)==128
 solve('abstract_round_domain_nonempty',cc=domain,result='sat')
 sem={'source_models':{n:g.record_full()for n,g in mm.items()},'source_nonbranch_sites_translated':16742,'selected_traversal_nonbranch_instances':10636+64*4470+1597+39,'setup_UDIV_denominators':div,'setup_prescribed_input_fields':[hex(v)for v in FIELDS],'scalar_producer_rows':s['scalar_producer_ledger'],'source_value_cuts':[{'site':'0x100b19024','value':'0x000000b6','justification':['raw_controller_CELL0_global_and_two_bank_addresses','original_image_bank_composition_is_b6_for_all_u8'],'scope':'One proved value cut per modeled round;all other loads remain independent component inputs.'}],'computed_address_normalizations':0,'round_controller_z':zz,'round_selector_truth_table':truth,'round_count':64,'round_domain':'0<=IX<64','round_input_W28':'0x28ef15ed+IX','round_input_F748':'241*IX','round_input_F738':'0x43c8+241*IX','round_input_F6e0':'63-IX','round_output_W4':'0xa9d0;required by state-update caller ABI','round_F520_F52c':'arbitraryu32 data;zero-valuation constant hypotheses refuted only in broad component model','round_initial_unprescribed_u32_fields':g.initial,'word_geometry':'D(j)=F+0xc80+4*((241*j)mod286)','round_word_reads':{'0x100b1913c':'D(IX+72)','0x100b19160':'D(IX)'},'round_ROM_reads':{'0x100b19044':'ROM+4*((83*((IX XOR0x0a)+67))mod192)','0x100b19174':'ROM+4*((83*(IX XOR0x2a))mod192)'},'round_iteration_coverage':ledger,'distinct_grid_words_read':128,'distinct_image_words_read':128,'image_word_domain':192,'image_word_bytes':768,'update_direct_saved_state_fields_written':[hex(v)for v in FIELDS if any(r['frame_offset']==v for r in update.frame_writes)],'update_zero_flag_target':'0x100b50474','update_one_flag_target':'0x100d183e8','gate_predicate':predicate,'gate_false_target':'0x100c583b0','gate_true_target':'0x100d183e8','frame_effect_counts':{n:{'nonbranch_sites':len(mm[n].sites),'loads':len(mm[n].reads),'frame_reads':len(mm[n].frame_reads),'stores':len(mm[n].stores),'read_bytes':sum(r['width_bits']//8 for r in mm[n].reads),'store_effect_bytes':sum(r['width_bits']//8 for r in mm[n].stores),'distinct_frame_bytes_written':len({r['frame_offset']+j for r in mm[n].frame_writes for j in range(r['width_bits']//8)})}for n in['setup','round','update','gate']},'Mach_port_emissions':0,'LOCAL_pointer_dereferences':0,'new_IDA_access':False,'complete_round_arithmetic_proved':False,'whole_algorithm_identified':False,'native_reachability_proved':False,'native_owner_proved':False,'native_output_proved':False,'daemon_kext_pairing_proved':False,'coherence_boundary':'Named reads are independent even when addresses may coincide. UNSAT covers the coherent-memory subset;SAT counterexamples need not be native-coherent. Byte/word frame forwarding is exact for literal offsets. Other mappings,root continuity,image-bank immutability and absence of outside writes remain premises.','unproved_bounds':'Setup483 and round138 computed primary-byte addresses are not universally bounded or classified in this increment. Native faults/mapping and table-value alphabet remain unknown.','excluded_exploration':'An update model with unbound W4 selected unrelated slots0x4c/0x61;accepted model uses caller-proved W4=a9d0. Setup F520/F52c zero-valuation values were refuted and remain arbitrarydata. Abstract ROM address samples proposed formulas;accepted source-SMT proofs establish them universally withinIX<64. Both172/9241-instruction frontiers are census/hash only.'}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('source_byte',lambda q:q['fragments']['round'].__setitem__('bytes','00'+q['fragments']['round']['bytes'][2:])),('exit_target',lambda q:q['branch_edges'][2].__setitem__('target','0x0')),('bank_byte',lambda q:q['original_banks']['right'].__setitem__('bytes','00'+q['original_banks']['right']['bytes'][2:])),('pool_root',lambda q:q['coded_word_bank_pointer'].__setitem__('resolved_root','0x0')),('producer_site',lambda q:q['scalar_producer_ledger'][0].__setitem__('last_store','0x0')),('ADRP_page',lambda q:next(r for r in q['ISA_decode_checks']if r['kind']=='adrp').__setitem__('page_target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert q!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':16742,'selected_traversal_nonbranch_instances':sem['selected_traversal_nonbranch_instances'],'rounds':64,'round_word_reads':128,'round_image_word_reads':128,'round_byte_reads':64*140,'selector_finite_cases':256,'source_value_cuts':1,'computed_address_normalizations':0,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','validate_daemon_existing_scalar_reader.py','validate_daemon_mode_one_secondary_word_extension.py','daemon_word_round_tools.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'secondary_round_control_selector_word_addresses_and_update_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
