#!/usr/bin/env python3
"""Source-pinned parity ABI,conditional byte update and reciprocal reduction."""
import copy,json,re,subprocess,shutil
from recover_daemon_mode_one_parity_state_adapters import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_checkpoint import PostSSA
from validate_daemon_mode_one_workspace_state_install import InstallSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq
from daemon_mode_one_handoff_tools import parse
SOLVER=shutil.which('z3');assert SOLVER
def certificates(s):
 pp=[];models={};fs=s['fragments']
 def solve(name,g=None,terms=(),cc=(),result='unsat',values=None,body='',logic='QF_BV',extra=''):
  q='(set-option :timeout 15000)\n(set-logic '+logic+')\n'+(DECL if logic=='QF_BV'else'')+extra
  if g is not None:q+=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
  q+=body+''.join('(assert '+x+')\n'for x in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat)\n'
  if values is not None:q+='(get-value ('+' '.join(values)+'))\n'
  r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr,(name,r.stdout[:1000],r.stderr)
  row={'name':name,'query':q,'result':result,'scope':SCOPE}
  if values is None:assert r.stdout.strip()==result,(name,r.stdout[:1000])
  else:
   assert result=='sat'and r.stdout.startswith('sat\n'),(name,r.stdout[:1000]);v=parse(r.stdout[4:]);assert len(v)==len(values);row['model_value_hex']=[x[-1]for x in v];assert all(re.fullmatch('#x[0-9a-f]+',x)for x in row['model_value_hex'])
  pp.append(row);print(name,result,flush=True);return row
 def run(g,label,key=None):
  f=fs[label];g.run(f,int(f['instructions'][-1]['ea'],16));models[key or label]=g;return g
 def rd(g,site):return next(r for r in g.reads if r['site']==hex(site))
 def chain(old,name,loads):
  g=PostSSA(name,old.r,loads=loads);g.defs=list(old.defs);g.decl=dict(old.decl);g.byte_cells=dict(old.byte_cells);g.loaded=old.loaded
  for value,w in loads.values():g.decl[value]=w
  return g
 def frame_cert(name,g):
  rr={r['site']:r for r in g.reads};ss={r['site']:r for r in g.stores}
  solve(name,g,[neq(rr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_reads]+[neq(ss[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_writes])
 replay=[]
 for name,wanted in [('daemon_mode_one_workspace_state_install',None),('daemon_mode_one_record_checkpoint',{'LOCAL_present_source_predicate_derived_views_and_entry_constants'})]:
  c=json.loads(read(ROOT/(name+'_checks.json')));assert c['all_checks_pass'];rows=[p for p in c['proofs']if wanted is None or p['name']in wanted];assert rows and(wanted is None or{p['name']for p in rows}==wanted)
  for p in rows:
   r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr
   if p['result']=='unsat':assert r.stdout.strip()=='unsat'
   else:assert p['result']=='sat'and r.stdout.startswith('sat\n')
   pp.append({**p,'name':'replayed_'+name+'_'+p['name'],'replayed_query':True})
  replay.append({'artifact':name+'_checks.json','queries':len(rows),'all_historical_queries':wanted is None});print('replayed',name,len(rows),flush=True)
 parent=json.loads(read(ROOT/'daemon_mode_one_workspace_state_install_source.json'));f=parent['fragments']['install'];presets={0x740:('TABLE',64),0x758:(frame(0x8b0),64),0x358:('(bvadd LOCAL '+bv(0x2c238c16ca76f3a8)+')',64),0x368:(frame(0x1150),64),0x370:(frame(0x1100),64)}
 ini=InstallSSA('incoming',{23:bv(0x40d0)},presets=presets,loads={'0x100b5c504':('PFN',64)});ini.decl.update(LOCAL=64,PFN=64);ini.run(f,int(f['instructions'][-1]['ea'],16));models['incoming_initializer']=ini
 solve('fresh_initializer_dispatch_flag_zero_position_and_roots',ini,[neq(ini.loadframe(0x708,32),bv(0xc83d,32)),neq(ini.loadframe(0x4f8,32),bv(0,32)),neq(ini.loadframe(0x380,64),bv(0)),neq(ini.get('x11'),bv(1)),neq(ini.loadframe(0x358,64),presets[0x358][0]),neq(ini.loadframe(0x368,64),frame(0x1150)),neq(ini.loadframe(0x370,64),frame(0x1100)),neq(ini.loadframe(0x350,64),bv(0x2c238c16ca76f3a8))]+[neq(r['original_address'],frame(r['frame_offset']))for r in ini.original_addresses])
 d=chain(ini,'dispatch',{'0x100b6fe3c':('DFN',64)});d.r[11]=z('PAR');d.decl['PAR']=32;run(d,'dispatch')
 odd='(= (bvand PAR #x00000001) #x00000001)'
 solve('dispatcher_all_u32_parity_exact_targets_and_saved_word',d,[neq(rd(d,0x100b6fe3c)['address'],f'(ite {odd} {at(0xc86a)} {at(0xc83d)})'),neq(d.loadframe(0x4b4,32),'PAR'),neq(d.get('x12'),bv(0x255c)),neq(d.get('x15'),bv(0x255c)),neq(d.get('w20'),ini.loadframe(0x748,32)),neq(d.get('x17'),bv(0xb0ef))]);frame_cert('dispatcher_frame_effect_addresses',d)
 branches={}
 for label,site,fn in [('odd',0x100c23890,'OFN'),('even',0x100be12d8,'EFN')]:
  g=run(chain(d,label,{hex(site):(fn,64)}),label);branches[label]=g;frame_cert(label+'_all_frame_effect_addresses',g)
  terms=[neq(rd(g,site)['address'],at(0x255c)),neq(g.get('x12'),fn),neq(g.get('x21'),frame(0x8b0)),neq(g.get('x20'),bv(0xd6)),neq(g.get('x17'),bv(0x5630))]
  if label=='odd':terms+=[neq(g.loadframe(0x350,64),presets[0x358][0]),neq(g.get('x16'),presets[0x358][0]),neq(g.get('x0'),bv(0)),neq(g.loadframe(0x360,64),ini.loadframe(0x360,64))]
  else:terms+=[neq(g.loadframe(0x350,64),ini.loadframe(0x350,64)),neq(g.loadframe(0x360,64),ini.loadframe(0x300,64)),neq(g.get('x0'),frame(0x1100))]
  solve(label+'_register_and_pointer_representation_contract',g,terms)
  u=run(chain(g,label+'_setup',{'0x100d75154':(label.upper()+'_SETUP_FN',64)}),'setup',label+'_setup');frame_cert(label+'_setup_frame_effect_addresses',u)
  solve(label+'_setup_initial_zero_flag_selects_toggle',u,[neq(rd(u,0x100d75154)['address'],at(0x966a)),neq(u.get('x9'),bv(0x9654)),neq(u.get('x12'),bv(0x1e31)),neq(u.get('x2'),bv(0x4a62f57c)),neq(u.loadframe(0x4f8,32),bv(0,32)),neq(u.loadframe(0x380,64),g.get('x0'))])
 # Standalone components characterize broader entries without claiming that
 # either parity or flag value has been reached in a later native iteration.
 u=PostSSA('generic_setup',{9:bv(0x9654),0:'IN0'},presets={0x740:('TABLE',64),0x4f8:('FLAG',32)},loads={'0x100d75154':('SFN',64)});u.decl.update(IN0=64,FLAG=32,SFN=64);run(u,'setup','generic_setup');frame_cert('generic_setup_all_frame_effect_addresses',u)
 solve('generic_setup_flag_partition_and_saved_input_word',u,[neq(rd(u,0x100d75154)['address'],f'(ite (= (bvand FLAG #x00000001) #x00000000) {at(0x966a)} {at(0x9654)})'),neq(u.loadframe(0x380,64),'IN0'),neq(u.get('x12'),bv(0x1e31)),neq(u.get('x2'),bv(0x4a62f57c)),neq(u.get('x9'),bv(0x9654))])
 t=PostSSA('toggle',{2:bv(0x4a62f57c),12:bv(0x1e31),21:frame(0x8b0)},presets={0x740:('TABLE',64),0x4ac:('AWORD',32),0x4a4:('BWORD',32),0x6f8:('TSTATE',32)},loads={'0x100c2abc8':('TB',8),'0x100c2abd8':('TFN',64)});t.decl.update(AWORD=32,BWORD=32,TSTATE=32,TB=8,TFN=64)
 numerator=quotient=None
 for i in fs['toggle']['instructions'][:-1]:
  t.run({'instructions':[i]},int(i['ea'],16)+4)
  if i['ea']=='0x100c2aba4':numerator=t.get('w9')
  if i['ea']=='0x100c2abb8':quotient=t.get('x11')
 models['toggle']=t;assert numerator and quotient
 n=f'(bvadd (bvmul (bvadd (bvsub BWORD (bvadd {bv(0x4a62f57c,32)} AWORD)) {bv(0x94b008bb,32)}) {bv(799,32)}) {bv(0xcdb8383b,32)})'
 q=f'(bvlshr (bvmul {z("(bvlshr "+n+" "+bv(1,32)+")")} {bv(0x883fddf1)}) {bv(40)})';rem=f'(bvsub {n} (bvmul ((_ extract 31 0) {q}) {bv(962,32)}))';address=f'(bvadd {frame(0x8b0)} {z(rem)})'
 solve('toggle_exact_numerator_reciprocal_and_original_effect_addresses',t,[neq(numerator,n),neq(quotient,q),neq(rd(t,0x100c2abc8)['address'],address),neq(t.stores[0]['address'],address),neq(t.stores[0]['value'],'(bvxor TB #x80)'),neq(rd(t,0x100c2abd8)['address'],at(0x1e31)),neq(t.get('x8'),bv(0x4d20)),neq(t.get('x10'),z('(bvadd '+bv(0x4a62f57c,32)+' AWORD)')),neq(t.get('x17'),bv(0xe346))]);frame_cert('toggle_literal_frame_read_addresses',t)
 # Independent integer theorem connects the exact UMULL/shift shape above
 # to modulo962,including every relevant machine-width bound.
 c=0x883fddf1;power=1<<40;assert c==(power+480)//481
 body='(declare-fun M () Int)\n(declare-fun Q () Int)\n(declare-fun R () Int)\n(declare-fun E () Int)\n(declare-fun N () Int)\n'
 cc=['(<= 0 M)','(< M 2147483648)','(<= 0 Q)','(<= 0 R)','(< R 481)','(= M (+ (* 481 Q) R))','(<= 0 E)','(<= E 1)','(= N (+ (* 2 M) E))']
 bad=[f'(< (* M {c}) (* Q {power}))',f'(>= (* M {c}) (* (+ Q 1) {power}))','(< N (* 962 Q))','(>= N (+ (* 962 Q) 962))','(>= Q 4294967296)','(>= (* 962 Q) 4294967296)',f'(>= (* M {c}) 18446744073709551616)']
 solve('reciprocal481_half_u32_exact_floor_remainder_and_widths',logic='QF_LIA',body=body,cc=cc,terms=bad)
 inverse=pow(799,-1,1<<32);t.decl['RIDX']=32
 preimage=f'(bvadd {bv(0x4a62f57c-0x94b008bb,32)} (bvmul (bvsub RIDX {bv(0xcdb8383b,32)}) {bv(inverse,32)}))'
 component_cc=['(bvult RIDX '+bv(962,32)+')','(= AWORD '+bv(0,32)+')','(= BWORD '+preimage+')']
 solve('component_all962_cells_have_symbolic_preimages',t,[neq(n,'RIDX'),neq(rd(t,0x100c2abc8)['address'],'(bvadd '+frame(0x8b0)+' '+z('RIDX')+')')],component_cc)
 for label,index in [('first',0),('last',961)]:
  solve('abstract_component_'+label+'_cell_example',t,cc=component_cc+['(= RIDX '+bv(index,32)+')','(= K '+bv(0)+')','(= TABLE '+bv(0)+')','(= TB #x00)'],result='sat',values=[rd(t,0x100c2abc8)['address'],t.stores[0]['value']])
 sk=PostSSA('skip',{9:bv(0x9654)},presets={0x740:('TABLE',64),0x4ac:('ASKIP',32),0x720:('SSKIP',32)},loads={'0x100dc42a8':('SKFN',64)});sk.decl.update(ASKIP=32,SSKIP=32,SKFN=64);run(sk,'skip');frame_cert('skip_all_frame_effect_addresses',sk)
 solve('skip_register_copy_and_distinct_dispatch_interface',sk,[neq(rd(sk,0x100dc42a8)['address'],at(0x34d0)),neq(sk.loadframe(0x4a8,32),'ASKIP'),neq(sk.get('x2'),'Z14'),neq(sk.get('w23'),'SSKIP'),neq(sk.get('x19'),bv(0x4a62f57c)),neq(sk.get('x17'),bv(0x63f8))]);assert not any(r['width_bits']==8 for r in sk.reads+sk.stores)
 j=PostSSA('join',{2:bv(0x4a62f57c),8:bv(0x4d20),10:z('(bvadd '+bv(0x4a62f57c,32)+' AJOIN)')},presets={0x740:('TABLE',64),0x4b0:('BOUND',32)},loads={'0x100c55498':('JFN',64)});j.decl.update(AJOIN=32,BOUND=32,JFN=64);run(j,'join');frame_cert('join_all_frame_effect_addresses',j)
 right=0xe34ecea3|0;right^=(0x4d20-0x4fd)|0x100
 pred='(= (bvadd (bvsub BOUND (bvadd '+bv(0x4a62f57c,32)+' AJOIN)) '+bv(0xc4b76cdf,32)+') '+bv(right,32)+')'
 solve('join_exact_word_comparison_and_two_targets',j,[neq(rd(j,0x100c55498)['address'],f'(ite {pred} {at(0x662c)} {at(0x4d20)})'),neq(j.loadframe(0x37c,32),bv(0x4a62f57c,32)),neq(j.get('x17'),bv(0x1aad))])
 actual={pc for name,g in models.items()if name!='incoming_initializer'for pc in g.sites};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==1220
 protected=[(0x358,8),(0x368,16),(0x388,8),(0x740,8),(0x750,16),(0x768,296)]
 effects={}
 for name,g in models.items():
  if name=='incoming_initializer':continue
  written={r['frame_offset']+v for r in g.frame_writes for v in range(r['width_bits']//8)};assert all(not written&set(range(off,off+n))for off,n in protected)
  assert all(r['frame_offset']+r['width_bits']//8<=0x768 for r in g.frame_writes)
  effects[name]={'loads':len(g.reads),'stores':len(g.stores),'frame_reads':len(g.frame_reads),'frame_writes':len(g.frame_writes),'frame_distinct_bytes_written':len(written),'store_bytes':sum(r['width_bits']//8 for r in g.stores),'read_bytes':sum(r['width_bits']//8 for r in g.reads)}
 source_loads=sum(i['mnemonic'].startswith('ld')for f in fs.values()for i in f['instructions']);source_stores=sum(i['mnemonic'].startswith('st')for f in fs.values()for i in f['instructions']);assert(source_loads,source_stores)==(68,43)
 sem={'source_models':{n:g.record_full()for n,g in models.items()},'source_nonbranch_sites_translated':1220,'predecessor_replays':replay,'initial_dispatch_PAR':1,'initial_F708':'0xc83d','initial_F4f8':0,'initial_F380_u64':0,'parity_word_saved_at':'F+0x4b4,u32;counter identity not established','all_u32_parities_proved':True,'later_even_native_entry_proved':False,'odd_F350':'LOCAL+0x2c238c16ca76f3a8','odd_X0':'0,u64','even_F350':'0x2c238c16ca76f3a8,numeric word under initial incoming context','even_F360':'preserved initializer F300 numeric word','even_X0':'F+0x1100,saved frame view','private_root_X21':'F+0x8b0','common_setup_target':'0x100d74e68','setup_flag_lowbit0_target':'0x100c2ab70','setup_flag_lowbit1_target':'0x100dc4288','initial_flag_selects_toggle_for_both_abstract_parity_entries':True,'later_skip_native_entry_proved':False,'toggle_read_site':'0x100c2abc8','toggle_store_site':'0x100c2abd0','toggle_value':'input_u8 XOR0x80','toggle_numerator_u32':n,'toggle_quotient_u64':q,'toggle_remainder_u32':rem,'toggle_address':address,'toggle_offset_domain_inclusive':[0x8b0,0xc71],'reciprocal_half_divisor':481,'reciprocal_numerator':c,'reciprocal_power_of_two':power,'reciprocal_excess':481*c-power,'NUM_u32_machine_remainder_is_mod962':True,'coordinate_words_independent_in_component_model':True,'all962_component_cells_have_preimages':True,'component_preimage_BWORD':preimage,'component_preimage_multiplier_inverse_u32':inverse,'exact_actual_correlated_cell_or_table_classification_proved':False,'component_samples_are_native_requests':False,'prior800_cell_retention_proved_past_toggle':False,'LOCAL_pointer_dereferences':0,'Mach_port_emissions':0,'join_predicate':pred,'join_equal_target':'0x100ce305c','join_other_target':'0x100c03f6c','skip_target':'0x100c62f48','next_target_semantics_proved':False,'effects_by_model':effects,'source_load_operations':source_loads,'source_store_operations':source_stores,'source_byte_loads':1,'source_byte_stores':1,'source_value_cuts':0,'excluded_exploration':'Unrestricted full-source and standalone-tail bit-vector range queries returned unknown at15000 ms;not accepted. The exact original BV expression and an independent QF_LIA floor/remainder/width theorem establish the domain.','whole_cryptographic_algorithm_identified':False,'native_ownership_proved':False,'successful_output_proved':False,'daemon_kext_pairing_proved':False,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['odd'].__setitem__('bytes','00'+q['fragments']['odd']['bytes'][2:])),('wrong_parity_target',lambda q:q['branch_edges'][0].__setitem__('target','0x0')),('wrong_common_target',lambda q:q['branch_edges'][2].__setitem__('target','0x0')),('wrong_UMULL_operands',lambda q:q['UMULL_decode_checks'][0].__setitem__('operands','x11, w11, w11')),('wrong_pointer_modifier',lambda q:q['branch_edges'][-1].__setitem__('IA_diversity','0x0')),('wrong_lineage',lambda q:q['prior_recaptures'][-1].__setitem__('sha256','0'*64)),('invent_SP_write',lambda q:q['verified_source_counts'].__setitem__('SP_writes',1)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':1220,'fresh_incoming_initializer_sites':4869,'distinct_parity_adapters':2,'shared_setup_contexts_proved':2,'source_load_operations':68,'source_store_operations':43,'source_byte_loads':1,'source_byte_stores':1,'private_domain_bytes':962,'component_cells_with_symbolic_preimages':962,'integer_reciprocal_theorems':1,'abstract_component_address_examples':2,'source_value_cuts':0,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_workspace_state_install.py','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','validate_daemon_mode_one_word_schedule.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'parity_state_ABIs_toggle_and_dispatch_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
