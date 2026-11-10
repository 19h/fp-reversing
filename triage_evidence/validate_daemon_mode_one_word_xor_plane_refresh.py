#!/usr/bin/env python3
"""Compact word XOR,compositional exact plane addresses and secondary-root ABI."""
import copy,json,re,subprocess,shutil
from recover_daemon_mode_one_word_xor_plane_refresh import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_checkpoint import PostSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq
from daemon_mode_one_handoff_tools import parse
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
OFFSETS={0x100c63f7c:0xa04,0x100c6448c:0x903,0x100c64630:0x9a4,0x100c648cc:0xa09}
class RefreshSSA(PostSSA):
 def __init__(self,*a,forward=False,**kw):super().__init__(*a,**kw);self.forward=forward;self.bindings={};self.proved_cuts=[];self.original_addresses=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc==0x100c63f38:self.bindings['first']=self.get('w14')
   if pc==0x100c64428:self.bindings['second']=self.get('w16')
   if pc in OFFSETS:
    p=split(i['operands']);off=OFFSETS[pc];self.original_addresses.append({'site':i['ea'],'frame_offset':off,'original_address':self.address(p[1])})
    if self.forward:i={**i,'operands':p[0]+', [sp, #'+hex(off)+']'}
   super().run({'instructions':[i]},pc+4)
   if pc in[0x100c63f58,0x100c64488]:
    rd,off,label=('x0',0x154,'first')if pc==0x100c63f58 else('w3',0x53,'second');w=64 if rd.startswith('x')else 32;original=self.get(rd);replacement=bv(off,w);row={'site':hex(pc),'register':rd,'original_value':original,'replacement':replacement,'universal_lemma':label+'_masked_complement_address_lemma','input_binding_LVAL':self.bindings[label]};self.proved_cuts.append(row);self.cuts.append(row);self.put(rd,replacement)
  return self
 def record_full(self):return{**super().record_full(),'proved_address_value_cuts':self.proved_cuts,'original_computed_store_addresses':self.original_addresses}
class WordSSA(PostSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.original_byte_read=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc==0x100ce3334:
    self.original_byte_read.append({'site':i['ea'],'original_address':self.address(split(i['operands'])[1]),'frame_offset':0xbd2});i={**i,'operands':'w11, [sp, #0xbd2]'}
   super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'computed_byte_read_normalization':self.original_byte_read}
def certificates(s):
 pp=[];models={};fs=s['fragments']
 def solve(name,g=None,terms=(),cc=(),result='unsat',values=None,tactic=False):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL
  if g is not None:q+=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
  q+=''.join('(assert '+v+')\n'for v in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat-using (then simplify propagate-values solve-eqs bit-blast sat))\n'if tactic else'(check-sat)\n'
  if values is not None:q+='(get-value ('+' '.join(values)+'))\n'
  r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr,(name,r.stdout[:1200],r.stderr);row={'name':name,'query':q,'result':result,'scope':SCOPE}
  if values is None:assert r.stdout.strip()==result,(name,r.stdout[:1200])
  else:
   assert result=='sat'and r.stdout.startswith('sat\n'),(name,r.stdout[:1200]);vv=parse(r.stdout[4:]);assert len(vv)==len(values);row['model_value_hex']=[v[-1]for v in vv];assert all(re.fullmatch('#x[0-9a-f]+',v)for v in row['model_value_hex'])
  pp.append(row);print(name,result,flush=True);return row
 def run(g,label,key=None):
  f=fs[label];g.run(f,int(f['instructions'][-1]['ea'],16));models[key or label]=g;return g
 def rd(g,site):return next(r for r in g.reads if r['site']==hex(site))
 def frame_cert(name,g):
  rr={r['site']:r for r in g.reads};ss={r['site']:r for r in g.stores};solve(name,g,[neq(rr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_reads]+[neq(ss[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_writes])
 replay=[]
 for name,wanted in [('daemon_mode_one_parity_state_adapters',None),('daemon_mode_one_workspace_passes',{'shuffle_root_epoch_control_and_next_ABI'})]:
  c=json.loads(read(ROOT/(name+'_checks.json')));assert c['all_checks_pass'];rows=[p for p in c['proofs']if wanted is None or p['name']in wanted];assert rows and(wanted is None or{p['name']for p in rows}==wanted)
  for p in rows:
   print('replay_start',name,p['name'],flush=True);r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr,(name,p['name'],r.stdout[:1200],r.stderr)
   if p['result']=='unsat':assert r.stdout.strip()=='unsat',(name,p['name'],r.stdout[:1200])
   else:assert p['result']=='sat'and r.stdout.startswith('sat\n'),(name,p['name'],r.stdout[:1200])
   pp.append({**p,'name':'replayed_'+name+'_'+p['name'],'replayed_query':True})
  replay.append({'artifact':name+'_checks.json','queries':len(rows),'all_immediate_parent_queries':wanted is None});print('replayed',name,len(rows),flush=True)
 # Re-establish caller constants from the actual setup+skip source. No later
 # native flag1 reachability is inferred from this component composition.
 parent=json.loads(read(ROOT/'daemon_mode_one_parity_state_adapters_source.json'))['fragments']
 caller=PostSSA('caller_setup',{9:bv(0x9654),20:bv(0xd6),21:frame(0x8b0)},presets={0x740:('TABLE',64),0x4f8:('FLAG',32)},loads={'0x100d75154':('CALL_FN',64)});caller.decl.update(FLAG=32,CALL_FN=64);f=parent['setup'];caller.run(f,int(f['instructions'][-1]['ea'],16))
 sk=PostSSA('caller_skip',caller.r,loads={'0x100dc42a8':('SKIP_FN',64)});sk.defs=list(caller.defs);sk.decl=dict(caller.decl);sk.decl['SKIP_FN']=64;sk.byte_cells=dict(caller.byte_cells);sk.loaded=caller.loaded;f=parent['skip'];sk.run(f,int(f['instructions'][-1]['ea'],16));models['caller_setup']=caller;models['caller_skip']=sk
 solve('fresh_caller_setup_and_skip_supply_refresh_control_ABI',sk,[neq(sk.get('x13'),bv(0x4923)),neq(sk.get('x19'),bv(0x4a62f57c)),neq(sk.get('x27'),bv(0x2dd9b66a)),neq(sk.get('x20'),bv(0xd6)),neq(sk.get('x7'),bv(0xb4)),neq(sk.get('x21'),frame(0x8b0)),neq(sk.get('x6'),'TABLE'),neq(rd(sk,0x100dc42a8)['address'],at(0x34d0)),neq(rd(caller,0x100d75154)['address'],at(0x9654))],cc=['(= (bvand FLAG #x00000001) #x00000001)'])
 # Full original word source,then a coherent private-byte lowering.
 regs={8:bv(0x4d20),16:z('S16'),20:bv(0xd6),23:bv(0xb3),21:frame(0x8b0)};presets={0x740:('TABLE',64),0x9e9:('B0',8),0xa8c:('B1',8),0xb2f:('B2',8)}
 w=PostSSA('raw_word',regs,presets=presets,loads={'0x100ce3334':('B3',8),'0x100ce3374':('WFN',64)});w.decl.update(S16=32,WFN=64);snap={}
 for i in fs['word_xor']['instructions'][:-1]:
  if i['ea']in['0x100ce3324','0x100ce3350']:snap[i['ea']]=w.get('w13'if i['ea']=='0x100ce3324'else'w12')
  w.run({'instructions':[i]},int(i['ea'],16)+4)
  if i['ea']=='0x100ce31ac':snap['T']=w.get('w10')
 models['raw_word']=w;mask='(bvshl (bvadd S16 '+bv(0x8cca81ed,32)+') '+bv(3,32)+')';offsets=[0x9e9,0xa8c,0xb2f,0xbd2]
 solve('raw_word_full_mask_shift_counts_and_computed_fourth_read',w,[neq('(bvxor '+snap['T']+' '+bv(0xe61505d8,32)+')',mask),neq(snap['0x100ce3324'],bv(0,32)),neq(snap['0x100ce3350'],bv(24,32)),neq(rd(w,0x100ce3334)['address'],frame(0xbd2)),neq(rd(w,0x100ce3374)['address'],at(0x4d20)),neq(w.get('x9'),bv(0x4923)),neq(w.get('x17'),bv(0x1aad))]+[neq(r['value'],'(bvxor B'+str(j)+' ((_ extract '+str(j*8+7)+' '+str(j*8)+') '+mask+'))')for j,r in enumerate(w.stores)])
 cw=WordSSA('word',regs,presets={**presets,0xbd2:('B3',8)},loads={'0x100ce3374':('WFN',64)});cw.decl.update(S16=32,WFN=64);run(cw,'word_xor','word');frame_cert('coherent_word_all_read_and_store_addresses',cw)
 oldword='(concat B3 (concat B2 (concat B1 B0)))';newbytes=[cw.loadframe(off,8)for off in offsets];newword='(concat '+newbytes[3]+' (concat '+newbytes[2]+' (concat '+newbytes[1]+' '+newbytes[0]+')))'
 solve('coherent_word_numeric_XOR_contract_and_original_byte_address',cw,[neq(newword,'(bvxor '+oldword+' '+mask+')')]+[neq(r['original_address'],frame(r['frame_offset']))for r in cw.original_byte_read]);assert len(cw.stores)==len(cw.frame_writes)==4 and len(cw.reads)==6
 # Universal source slices avoid depending on the opaque rolling-state
 # expression feeding their arbitrary32-bit input.
 for label,a,b,reg,rdname,result in [('first',0x100c63f38,0x100c63f5c,14,'x0',0x154),('second',0x100c64428,0x100c6448c,16,'w3',0x53)]:
  f={'instructions':[i for i in fs['refresh']['instructions']if a<=int(i['ea'],16)<b]};g=PostSSA(label+'_lemma',{reg:z('LVAL'),20:bv(0xd6)});g.decl['LVAL']=32;g.run(f,b);models[label+'_lemma']=g;solve(label+'_masked_complement_address_lemma',g,[neq(g.get(rdname),bv(result,64 if rdname.startswith('x')else 32))])
 rr={6:'TABLE',13:bv(0x4923),19:bv(0x4a62f57c),22:z('AWORD'),21:frame(0x8b0),27:bv(0x2dd9b66a),7:bv(0xb4),20:bv(0xd6)};rp={0x728:('RSTATE',32),0x6f8:('SSTATE',32),0x4b4:('PAR',32),0x4a4:('BWORD',32)}
 def refresh(name,forward):
  g=RefreshSSA(name,rr,presets=rp,loads={'0x100c65114':('RFN',64)},forward=forward);g.decl.update(RSTATE=32,SSTATE=32,PAR=32,AWORD=32,BWORD=32,RFN=64);return run(g,'refresh',name)
 raw=refresh('raw_refresh_with_lemmas',False)
 solve('refresh_all_four_original_computed_addresses_with_proved_lemmas',raw,[neq(r['original_address'],frame(r['frame_offset']))for r in raw.original_addresses],tactic=True);frame_cert('refresh_literal_frame_effect_addresses',raw)
 g=refresh('refresh',True)
 solve('coherent_refresh_original_computed_addresses',g,[neq(r['original_address'],frame(r['frame_offset']))for r in g.original_addresses],tactic=True);frame_cert('coherent_refresh_every_frame_effect_address',g)
 assert len(raw.proved_cuts)==len(g.proved_cuts)==2 and len(g.original_addresses)==4 and len(g.stores)==len(g.frame_writes)==130 and len(g.reads)==5 and not g.initial
 assert[(r['site'],r['frame_offset'])for r in g.original_addresses]==[(hex(site),off)for site,off in OFFSETS.items()]
 solve('refresh_parity_targets_and_shared_comparison_ABI',g,[neq(rd(g,0x100c65114)['address'],f'(ite (= (bvand PAR #x00000001) #x00000000) {at(0x1e11)} {at(0x1e31)})'),neq(g.get('x8'),bv(0x4d20)),neq(g.get('x13'),bv(0x4923)),neq(g.get('x2'),bv(0x4a62f57c)),neq(g.get('w10'),'(bvadd '+bv(0x4a62f57c,32)+' AWORD)'),neq(g.get('w16'),'BWORD'),neq(g.get('x4'),bv(799)),neq(g.get('x23'),bv(0xb3)),neq(g.get('x7'),bv(0x883fddf1)),neq(g.get('x20'),bv(0xd6)),neq(g.get('x21'),frame(0x8b0)),neq(g.get('x6'),'TABLE'),neq(g.get('x17'),bv(0xe346))])
 byte=[r for r in g.frame_writes if r['width_bits']==8];assert len(byte)==128 and len({r['frame_offset']for r in byte})==128;inv=pow(799,-1,962);ledger=[{**r,'coordinate_label':(r['frame_offset']-0x8b0)*inv%962}for r in byte];assert{r['coordinate_label']for r in ledger}==set(range(64))|set(range(593,657))
 scalar=[r for r in g.frame_writes if r['width_bits']!=8];assert[(r['frame_offset'],r['width_bits'])for r in scalar]==[(0x720,32),(0x728,32)]
 samples=[]
 for label,value in [('zero',0),('repeated_one',0x01010101)]:
  cc=['(= K '+bv(0)+')','(= TABLE '+bv(0)+')']+['(= Z'+str(j)+' '+bv(value)+')'for j in range(31)]+['(= '+n+' '+bv(value if w==32 and n!='PAR'else 0,w)+')'for n,w in g.decl.items()]
  samples.append(solve('abstract_refresh_'+label+'_component_valuation',g,cc=cc,result='sat',values=[r['value']for r in byte])['model_value_hex'])
 differing=[j for j in range(128)if samples[0][j]!=samples[1][j]];assert differing
 seed=PostSSA('seed',{9:bv(0x4923),4:bv(799),21:frame(0x8b0)},presets={0x740:('TABLE',64),0x750:(frame(0xc80),64),0x728:('ENTRYA',32),0x720:('ENTRYB',32)},loads={'0x100c03f80':('SEED_FN',64)});seed.decl.update(ENTRYA=32,ENTRYB=32,SEED_FN=64);run(seed,'seed');frame_cert('seed_all_frame_effect_addresses',seed)
 constants={0:0xac9f729d,3:0,4:799,14:0xf1,15:0,16:962,17:0xcf0c};cells={0x6cc:0x1f61,0x6c4:0x8b7a81df,0x6c8:962}
 solve('secondary_root_seed_divisor_and_full_known_entry_contract',seed,[neq(seed.get('x'+str(k)),bv(v))for k,v in constants.items()]+[neq(seed.loadframe(off,32),bv(v,32))for off,v in cells.items()]+[neq(rd(seed,0x100c03f80)['address'],at(0x1f73)),neq(rd(seed,0x100c03fd0)['address'],frame(0x750)),neq(seed.get('x27'),frame(0xc80)),neq(seed.get('x21'),frame(0x8b0)),neq(seed.get('w19'),'ENTRYA'),neq(seed.get('w30'),'ENTRYB'),neq(seed.get('x7'),'Z7'),neq(seed.get('x8'),'SEED_FN')]);assert len(seed.stores)==3 and len(seed.reads)==5
 # A current-source control bridge from word update to seed is exact.
 assert{r[1:]for r in s['register_write_sets']['word_xor']if re.fullmatch('[xw][0-9]+',r)}.isdisjoint({'4','7','20','21','23'})
 actual={pc for name,m in models.items()if name not in['caller_setup','caller_skip']for pc in m.sites};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==2398
 banks={name:{0x8b0+799*j%962 for j in range(a,b)}for name,a,b in[('SUM',72,328),('XOR',333,589),('DEC',659,675),('CARRY',677,933),('ENC',936,952)]};arithmetic=set.union(*banks.values());assert len(arithmetic)==800;planes={r['frame_offset']for r in byte};assert not planes&arithmetic and set(offsets)<=planes
 all_written=set()
 for name,m in [('word',cw),('refresh',g),('seed',seed)]:
  written={r['frame_offset']+v for r in m.frame_writes for v in range(r['width_bits']//8)};assert len(m.stores)==len(m.frame_writes);assert not written&arithmetic;assert not written&set(range(0x768,0x890));assert all(not written&set(range(off,off+n))for off,n in[(0x350,8),(0x358,8),(0x360,8),(0x368,16),(0x380,16),(0x740,8),(0x750,16)]);all_written|=written
 assert len(all_written)==148
 primary=[cw,g,seed];assert(sum(len(m.reads)for m in primary),sum(len(m.stores)for m in primary),sum(r['width_bits']//8 for m in primary for r in m.reads),sum(r['width_bits']//8 for m in primary for r in m.stores))==(16,137,76,152)
 assert all(len(m.proved_cuts)==len(m.cuts)==2 for m in[raw,g])
 sem={'source_models':{n:m.record_full()for n,m in models.items()},'predecessor_replays':replay,'source_nonbranch_sites_translated':2398,'fresh_caller_nonbranch_sites':len(caller.sites)+len(sk.sites),'word_logical_byte_frame_offsets':offsets,'word_logical_byte_coordinates':[63,62,61,60],'word_byte_order':'W=B0+256*B1+65536*B2+16777216*B3;spatially scattered private cells','word_input':oldword,'word_output':newword,'word_mask_u32':mask,'word_contract':'W_after=W_before XOR u32((S16+0x8cca81ed)<<3)','word_dependency_input_S16':'incoming W16;no native/public field identity established','word_mask_low3_zero':True,'word_raw_T_xor_constant':'0xe61505d8','word_register_shift_counts':[0,24],'word_fourth_read_exact_frame_offset':0xbd2,'word_computed_read_normalized':True,'word_target':'0x100c03f6c','word_numeric_crypto_algorithm_identified':False,'plane_store_ledger':ledger,'plane0_labels':[0,63],'plane1_labels':[593,656],'plane_byte_writes':128,'refresh_scalar_writes':scalar,'refresh_computed_offsets':{hex(k):v for k,v in OFFSETS.items()},'refresh_address_lemmas':2,'refresh_source_value_cuts_per_model':2,'refresh_value_cut_scope':'Exact arbitrary-input source-slice lemmas,with actual input bindings;no assumed numeric cipher operation.','refresh_literal_byte_store_sites':124,'refresh_computed_byte_store_sites':4,'refresh_abstract_samples_differing_cells':len(differing),'refresh_all_plane_values_constant_proved':False,'refresh_samples_native_reachability_proved':False,'refresh_PAR_is_native_iteration_count_proved':False,'refresh_lowbit0_target':'0x100d77384','refresh_lowbit1_target':'0x100c55454','refresh_lowbit1_matches_prior_comparison_ABI':True,'refresh_numeric_state_recurrence_decoded':False,'refresh_word_and_seed_write_arithmetic_cells':False,'arithmetic_table_validity_after_prior_toggle_proved':False,'secondary_root_F750':'Inherited F+0xc80,producer proof replayed;native mapping/owner unknown','secondary_root_consumption_site':'0x100c03fd0','secondary_root_X27':'F+0xc80','retained_primary_root_X21':'F+0x8b0','seed_frame_constants':{hex(k):hex(v)for k,v in cells.items()},'seed_register_constants':constants,'seed_W7_left_inherited':True,'seed_target':'0x100d524a8','seed_target_body_semantics_proved':False,'source_load_operations':16,'source_store_operations':137,'source_read_bytes':76,'source_store_bytes':152,'source_distinct_bytes_written_union':148,'private_byte_store_effects':132,'scalar_u32_store_effects':5,'LOCAL_pointer_dereferences':0,'Mach_port_emissions':0,'excluded_exploration':'The unsplit refresh address query and first/second individual full-source bit-vector address queries returned unknown at15000 ms. They are not certificates. Two independently proved arbitrary-input source slices provide exact offset cuts before the accepted complete-address queries.','whole_cryptographic_algorithm_identified':False,'native_ownership_proved':False,'successful_output_proved':False,'daemon_kext_pairing_proved':False,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['word_xor'].__setitem__('bytes','00'+q['fragments']['word_xor']['bytes'][2:])),('wrong_word_target',lambda q:q['branch_edges'][0].__setitem__('target','0x0')),('wrong_refresh_target',lambda q:q['branch_edges'][1].__setitem__('target','0x0')),('wrong_bitfield_width',lambda q:q['bitfield_decode_checks'][0].__setitem__('source_count',0)),('wrong_shift_mask',lambda q:q['register_shift_decode_checks'][0].__setitem__('shift_count_mask',63)),('wrong_root_lineage',lambda q:q['prior_recaptures'][-1].__setitem__('sha256','0'*64)),('invent_SP_write',lambda q:q['verified_source_counts'].__setitem__('SP_writes',1)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':2398,'fresh_caller_nonbranch_sites':sem['fresh_caller_nonbranch_sites'],'word_bytes_updated':4,'word_computed_read_normalizations':1,'refresh_plane_bytes':128,'refresh_literal_byte_stores':124,'refresh_computed_store_normalizations':4,'refresh_scalar_u32_stores':2,'proved_address_source_cuts':2,'address_source_slice_lemmas':2,'abstract_refresh_valuations':2,'source_load_operations':16,'source_store_operations':137,'source_read_bytes':76,'source_store_bytes':152,'source_distinct_bytes_written_union':148,'private_byte_store_effects':132,'scalar_u32_store_effects':5,'saved_secondary_root_consumptions':1,'materialized_divisor':962,'arithmetic_cells_written':0,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','validate_daemon_mode_one_word_schedule.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'compact_word_XOR_plane_refresh_and_secondary_root_ABI_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
