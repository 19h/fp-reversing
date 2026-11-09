#!/usr/bin/env python3
"""Source-linked64-round read coverage,frame epochs and signed continuation proofs."""
import copy,json,subprocess,shutil,math
from recover_daemon_mode_one_word_rounds import ROOT,P,SCOPE,FLAGS,DEPS,BLOCKS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq
from validate_daemon_mode_one_inverse_tables import frame,at
from daemon_word_round_tools import FrameSSA,lookup
SOLVER=shutil.which('z3');assert SOLVER
EXTRA='(declare-fun CELL0 () (_ BitVec 64))\n'
def certificates(s):
 pp=[];models={};cuts=[];fs=s['fragments']
 def solve(name,body,conditions=(),result='unsat',extra=''):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+extra+body+'\n'+''.join('(assert '+c+')\n'for c in conditions)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-rounds-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True);return name
 def pre(g):return ''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
 def cert(name,g,terms,conditions=()):return solve(name,pre(g)+'(assert (or '+' '.join(terms)+'))',conditions)
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 def run(name,presets=None,regs=None,loads=None):
  g=FrameSSA(name,regs,presets,loads);g.run({'instructions':fs[name]['instructions'][:-1]},int(fs[name]['instructions'][-1]['ea'],16));models[name]=g;return g
 # Fresh source/control replay;earlier table values are not substituted into this model.
 from recover_daemon_mode_one_word_schedule import build as previous_build
 from validate_daemon_mode_one_word_schedule import certificates as previous_certificates
 old=previous_build();assert old==json.loads(read(ROOT/DEPS[0]));bp,bt,bs=previous_certificates(old);prior=json.loads(read(ROOT/DEPS[1]));assert bp==prior['proofs']and bt==prior['translations']and json.loads(json.dumps(bs))==prior['semantics']
 for p in bp:pp.append({**p,'name':'replayed_word_'+p['name'],'replayed_query':True})
 for file,names in[(DEPS[3],{'frame_bank_and_counter_root_publication','frame_counter_pointer_publication'}),(DEPS[5],{'compact_spilled_word_0x460'})]:
  old=json.loads(read(ROOT/file));assert old['all_checks_pass'];done=set()
  for p in old['proofs']:
   if p['name']not in names:continue
   r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_'+p['name'],'replayed_query':True});done.add(p['name'])
  assert done==names
 # The retained selected path does not overwrite the established F+460 value.
 chronology={}
 for file,key in[(DEPS[6],'handoff_store_ledger'),(DEPS[7],'frame_store_ledger'),(DEPS[1],'frame_store_ledger')]:
  c=json.loads(read(ROOT/file));assert c['all_checks_pass'];writes=c['semantics'][key];assert all(not set(range(r['frame_offset'],r['frame_offset']+r.get('width_bytes',r.get('width_bits',0)//8)))&set(range(0x460,0x464))for r in writes);chronology[file]={'sha256':sha(ROOT/file),'F460_preserved':True,'full_proof_replayed':file==DEPS[1]}
 # Fixed-width little-endian laws cover the new byte-forwarding frontend.
 for w in[32,64]:
  parts=[f'((_ extract {j*8+7} {j*8}) X)'for j in reversed(range(w//8))];expr=parts[0]
  for part in parts[1:]:expr=f'(concat {expr} {part})'
  solve('little_endian_store_reload_'+str(w),f'(declare-fun X () (_ BitVec {w}))\n(assert (distinct {expr} X))')
 solve('partial32_overwrite_of64','(declare-fun A64 () (_ BitVec 64))\n(declare-fun B32 () (_ BitVec 32))\n(assert (distinct (concat ((_ extract 63 32) A64) B32) (bvor (bvand A64 #xffffffff00000000) ((_ zero_extend 32) B32))))')
 for shift in sorted({int(i['operands'].split('#')[-1],0)for f in fs.values()for i in f['instructions']if i['mnemonic']=='extr'}):
  solve('EXTR32_shift_'+str(shift),f'(declare-fun A32 () (_ BitVec 32))\n(declare-fun B32 () (_ BitVec 32))\n(assert (distinct ((_ extract 31 0) (bvlshr (concat A32 B32) {bv(shift)})) (bvor (bvshl A32 {bv(32-shift,32)}) (bvlshr B32 {bv(shift,32)}))))')
 roots={0x758:(frame(0x8b0),64),0x738:(frame(0xd00),64),0x740:('TABLE',64),0x598:(bv(0x9033,32),32),0x570:(bv(0x100f4e390),64),0x578:(bv(0x100e99a00),64),0x580:('CELL0',64),0x460:(bv(0x34,32),32)}
 setup=run('setup',roots)
 cert('setup_resets_round_counter_and_publishes_control_cells',setup,[neq(setup.loadframe(0x750,32),bv(0,32)),neq(setup.loadframe(0x598,32),bv(0x9033,32)),neq(setup.loadframe(0x5a0,32),bv(0xab26,32)),neq(setup.loadframe(0x588,64),bv(7)),neq(rd(setup,0x100c626d8)['address'],at(0x9033)),neq(setup.get('x17'),bv(0xf68f)),neq(setup.loadframe(0x6d8,32),'IF_540_32')])
 for name in['bank_roots','cell_root']:
  g=FrameSSA(name,{24:'U',23:bv(0x100f4e390),22:bv(0x100e99a00),2:'CELL0'});g.run(fs[name],int(fs[name]['end'],16));models[name]=g
  terms=[neq(r['address'],frame(off))for r,off in zip(g.stores,[0x438,0x570,0x578]if name=='bank_roots'else[0x580])]
  terms+=[neq(r['value'],value)for r,value in zip(g.stores,['U',bv(0x100f4e390),bv(0x100e99a00)]if name=='bank_roots'else['CELL0'])];cert('fresh_'+name+'_publication',g,terms)
 left,right=[bytes.fromhex(v['bytes'])for v in s['data_banks'][:2]]
 left_expr=lookup(left,'B0');generic=f'(bvxor B0 {lookup(right,f"(bvxor {left_expr} #xd7)")})'
 selector_lemma=solve('all_byte_selector_values_choose8c','(assert (distinct '+generic+' #x8c))')
 rr={**roots,0x750:('IX',32),0x5a0:(bv(0xab26,32),32),0x588:(bv(7),64)};cc=['(bvult IX #x00000040)'];pointer=int(s['word_bank_pointer']['fixup']['target']);loop=FrameSSA('round',presets=rr,loads={'0x100d54864':(bv(pointer),64)})
 for i in fs['round']['instructions'][:-1]:
  pc=int(i['ea'],16);loop.run({'instructions':[i]},pc+4)
  if pc==0x100d54854:
   a=rd(loop,0x100d5442c)['input'];b=rd(loop,0x100d54434)['input'];l=rd(loop,0x100d54458)['input'];r=rd(loop,0x100d54468)['input'];v=f'((_ extract 7 0) (bvmul (bvxor (bvsub {b} {a}) #x000000a6) #x0a5cd4cf))'
   source_binding=cert('round_global_bank_addresses_and_selector_binding',loop,[neq(rd(loop,0x100d5442c)['address'],'CELL0'),neq(rd(loop,0x100d54434)['address'],bv(0x1010c4670)),neq(rd(loop,0x100d54458)['address'],f'(bvadd {bv(0x100e99a00)} {z(v,8)})'),neq(rd(loop,0x100d54468)['address'],f'(bvadd {bv(0x100f4e390)} {z(f"(bvxor {l} #xd7)",8)})'),neq(loop.get('w0'),f'((_ zero_extend 24) (bvxor {v} {r}))')],cc)
   cuts.append({'site':i['ea'],'register':'w0','original_value':loop.get('w0'),'replacement':bv(0x8c,32),'universal_lemma':selector_lemma,'source_binding_certificate':source_binding,'immutable_original_bank_premise':True,'byte_bindings':{'input_byte':v,'left_read':l,'right_read':r}});loop.put('w0',bv(0x8c,32))
  if pc==0x100d54864:cert('round_selected_word_bank_pointer_slot',loop,[neq(rd(loop,pc)['address'],bv(int(s['word_bank_pointer']['slot'],16)))],cc)
 models['round']=loop
 grid=lambda base:f'(bvadd {frame(0x8b0)} {z(f"(bvmul (bvurem (bvmul (bvadd IX {bv(base,32)}) #x0000002f) #x00000111) #x00000004)")})'
 rom=lambda mask:f'(bvadd {bv(0x100f4aaf0)} {z(f"(bvmul (bvurem (bvmul (bvxor IX {bv(mask,32)}) #x00000035) #x000000c0) #x00000004)")})'
 cert('round_two_grid_and_two_image_word_addresses',loop,[neq(rd(loop,0x100d5455c)['address'],grid(135)),neq(rd(loop,0x100d545a8)['address'],grid(67)),neq(rd(loop,0x100d5487c)['address'],rom(0x74)),neq(rd(loop,0x100d54884)['address'],rom(0x0d))],cc)
 cert('round_counter_and_two_way_dispatch',loop,[neq(loop.loadframe(0x750,32),'(bvadd IX #x00000001)'),neq(rd(loop,0x100d56dec)['address'],f'(ite (= IX #x0000003f) {at(0x9043)} {at(0x9033)})'),neq(loop.get('x17'),bv(0xf68f)),neq(loop.loadframe(0x598,32),bv(0x9033,32)),neq(loop.loadframe(0x5a0,32),bv(0xab26,32))],cc)
 update=run('state_update',{**roots,0x5a0:(bv(0xab26,32),32)})
 cert('state_update_phase_counter_epoch_and_dispatch',update,[neq(update.loadframe(0x730,32),bv(0x2ac4,32)),neq(update.loadframe(0x750,32),'((_ extract 31 0) Z5)'),neq(rd(update,0x100b2b38c)['address'],at(0xab26)),neq(update.get('x17'),bv(0xe7b9)),neq(update.loadframe(0x540,32),'(bvadd IF_540_32 IF_6d8_32)'),neq(update.loadframe(0x510,32),f'(bvadd {update.loadframe(0x710,32)} {update.loadframe(0x728,32)})')])
 gate=run('gate',{**roots,0x730:(bv(0x2ac4,32),32),0x460:('VALUE',32)})
 cert('gate_signed_threshold86_partition',gate,[neq(rd(gate,0x100cad3b4)['address'],f'(ite (bvslt VALUE #x00000056) {at(0x2aca)} {at(0x2ac4)})'),neq(gate.get('w14'),bv(13055,32)),neq(gate.get('x17'),bv(0xb560))])
 cert('selected_F460_52_reaches_100cec684',gate,[neq(rd(gate,0x100cad3b4)['address'],at(0x2aca))],['(= VALUE #x00000034)'])
 # Every store in the selected source is a literal private-frame store.
 protected=set(range(0x8b0,0xcf4))|set(range(0xd00,0xd00+963))|set(range(0x460,0x464))|set(range(0x570,0x588))|set(range(0x598,0x59c))|set(range(0x738,0x748))|set(range(0x758,0x760))
 preservation=[]
 for name in BLOCKS:
  g=models[name];assert len(g.stores)==len(g.frame_writes);written={r['frame_offset']+j for r in g.frame_writes for j in range(r['width_bits']//8)};assert not written&protected,(name,sorted(written&protected))
  cert(name+'_all_literal_frame_addresses',g,[neq(r['address'],frame(v['frame_offset']))for r,v in zip(g.stores,g.frame_writes)]+[neq(rd(g,int(v['site'],16))['address'],frame(v['frame_offset']))for v in g.frame_reads]or['false'])
  preservation.append({'fragment':name,'frame_store_operations':len(g.frame_writes),'distinct_frame_bytes_written':len(written),'minimum_frame_offset':min(written)if written else None,'maximum_frame_offset_inclusive':max(written)if written else None,'protected_word_view_and_scratch_and_roots_unwritten':True})
 assert len(update.stores)==20
 coverage=[];grid_cells=set();rom_cells=set();known=set(bs['final_known_logical_words']);assert math.gcd(47,273)==math.gcd(53,192)==1
 for index in range(64):
  labels=[135+index,67+index];assert set(labels)<=known;words=[47*v%273 for v in labels];slots=[53*(index^0x74)%192,53*(index^0xd)%192];assert not grid_cells&set(words)and not rom_cells&set(slots);grid_cells.update(words);rom_cells.update(slots);coverage.append({'round_index':index,'grid_logical_labels':labels,'grid_slots':words,'grid_frame_offsets':[0x8b0+4*v for v in words],'image_slots':slots,'image_word_addresses':[hex(0x100f4aaf0+4*v)for v in slots],'repeat':index<63})
 assert len(grid_cells)==len(rom_cells)==128
 solve('round_domain_nonempty','',cc,result='sat')
 solve('wrong_grid_base134_counterexample','(assert (distinct (bvurem (bvmul (bvadd IX #x00000086) #x0000002f) #x00000111) (bvurem (bvmul (bvadd IX #x00000087) #x0000002f) #x00000111)))',cc,result='sat')
 solve('signed_unsigned_gate_difference_counterexample','(assert (distinct (bvslt VALUE #x00000056) (bvult VALUE #x00000056)))',result='sat')
 records={n:g.record_full()for n,g in models.items()};actual={pc for r in records.values()for pc in r['source_sites']};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==13400
 semantics={'source_models':records,'source_cuts':cuts,'source_nonbranch_sites_translated':len(actual),'retained_chronology':chronology,'rounds':64,'round_counter_epoch':'F750=0 in setup;IX in round entry;IX+1 after each round;then low32 incoming W5 in state-update block','setup_control_cells':{'F598':'0x9033','F5a0':'0xab26','F588':'0x7'},'grid_read_bases':[135,67],'grid_read_sites':['0x100d5455c','0x100d545a8'],'word_grid_read_operations':128,'word_grid_read_bytes':512,'word_grid_distinct_words_read':128,'populated_grid_words_outside_two_classified_word_reads':128,'word_grid_bytes_preserved':1024,'scratch_bytes_preserved':963,'image_word_bank':{'root':'0x100f4aaf0','slots':192,'extent_bytes':768,'read_sites':['0x100d5487c','0x100d54884'],'slot_rule':['53*(IX XOR0x74) mod192','53*(IX XOR0x0d) mod192'],'read_operations':128,'distinct_words_read':128,'read_bytes':512,'slots_outside_two_classified_word_reads':64},'byte_selector_constant':'0x8c','global_word_reads':{'0x100d5442c':'CELL0 from F580;native identity not independently established here','0x100d54434':'0x1010c4670'},'global_values_arbitrary_u32_in_proofs':True,'image_word_values_in_source_order':[int.from_bytes(bytes.fromhex(s['data_banks'][2]['bytes'])[j:j+4],'little')for j in range(0,768,4)],'iteration_coverage_ledger':coverage,'preservation_ledger':preservation,'state_update_store_operations':20,'state_update_control_phase':'0x2ac4 at F730','gate_signed_threshold':86,'selected_F460':52,'selected_gate_index':'0x2aca','next_target':'0x100cec684','all_new_stores_private_frame':True,'other_byte_access_bounds_fully_proved':False,'all_round_value_equations_proved':False,'whole_algorithm_identified':False,'caller_publication_proved':False,'Mach_port_emissions':0,'native_claim':False}
 return pp,semantics
def verify(s):return s==build()
def alterations(s):
 cases=[('wrong_round_source',lambda q:q['fragments']['round'].__setitem__('bytes','00'+q['fragments']['round']['bytes'][2:])),('wrong_bank_byte',lambda q:q['data_banks'][0].__setitem__('bytes','00'*256)),('wrong_word_pointer',lambda q:q['word_bank_pointer'].__setitem__('resolved_target','0x0')),('wrong_gate_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for n,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);records=sem['source_models']
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'rounds':64,'grid_word_read_operations':128,'image_word_read_operations':128,'state_update_stores':20,'source_cut_count':len(sem['source_cuts']),'new_byte_read_sites':sum(sum(r['width_bits']==8 for r in m['reads'])for m in records.values()),'rejected_alterations':len(aa)}
 deps=[P+'_source.json','daemon_word_round_tools.py','validate_daemon_mode_one_word_schedule.py','validate_daemon_mode_one_plane_consumer.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_word_round_consumer_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
