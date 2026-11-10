#!/usr/bin/env python3
"""Rebuild three source models and compose exact finite store footprints."""
import copy,json,itertools,re,shutil,subprocess
from recover_daemon_mode_one_computed_store_footprints import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,neq,prefix
from validate_daemon_mode_one_record_word_extension import ExtensionSSA as RecordSSA,DATA_REGS,WORD_READ_PCS
from validate_daemon_mode_one_secondary_word_extension import model as secondary_model
from validate_daemon_mode_one_source_absorption import fresh
SOLVER=shutil.which('z3');assert SOLVER

def certificates(s):
 pp=[];models={};ledgers={};counterfactuals=[]
 def solve(name,body,extra='',result='unsat'):
  query='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL+extra+body+'\n(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n'
  r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.returncode,r.stdout[:1000],r.stderr)
  pp.append({'name':name,'query':query,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def cert(name,g,terms,domain):
  extra=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in getattr(g,'decl',{}).items())
  solve(name,prefix(g)+'(assert '+domain+')\n(assert (or '+' '.join(terms)+'))',extra)
 def old_fragment(phase,label):return s['fragments'][phase+'_'+label]
 f=old_fragment('record','loop');regs={j:z('J'+str(j))for j in DATA_REGS};regs.update({16:z('IX'),2:bv(0xea0f),3:bv(280),21:frame(0x8b0)})
 presets={0x720:(bv(0x3f03,32),32),0x718:('(bvsub #xc013729f IX)',32),0x740:('TABLE',64),0x750:(frame(0xd10),64),0x758:(frame(0x8b0),64),0x6bc:('STATE',32)}
 loads={hex(pc):('WORD'+str(j),32)for j,pc in enumerate(WORD_READ_PCS)};g=RecordSSA('word_extension',regs,presets=presets,loads=loads);g.decl.update({**{'J'+str(j):32 for j in DATA_REGS},**{'WORD'+str(j):32 for j in range(8)},'STATE':32});g.run(f,int(f['instructions'][-1]['ea'],16));assert not g.initial and not g.cuts;models['record']=g
 models['secondary']=secondary_model({'fragments':{'loop':old_fragment('secondary','loop')}},'extension');assert not models['secondary'].initial and not models['secondary'].cuts
 constants={8:0xeb,9:0x77453be2,27:0x6ada6bd2,28:527,30:0xba9559f3,16:757,4:0x440dd2cf,20:963,0:0xd693a272};rr={k:bv(v)for k,v in constants.items()};rr.update({26:frame(0xd00),25:'BUF',23:bv(0x100f715a0),24:z('SIZE')})
 ef=old_fragment('absorption','entry');entry=fresh('entry',rr,{'0x100c21d7c':('#x00004923',32),'0x100c21d94':('#x0dc87a81',32),'0x100c21d9c':('TABLE',64),'0x100c21da0':('FN',64)});entry.run(ef,int(ef['instructions'][-1]['ea'],16))
 loads={hex(pc):(v,w)for pc,v,w in[(0x100bd7994,'B0',8),(0x100bd79d4,'B1',8),(0x100bd7a68,'B2',8),(0x100bd7ac4,'B3',8),(0x100bd7b1c,'TABLE',64),(0x100bd7b20,'CONT',64)]}
 loop=fresh('loop',{**entry.r,13:z('(bvadd IX #xc12face8)')},loads);loop.defs=list(entry.defs);f=old_fragment('absorption','loop');loop.run(f,0x100bd79cc)
 cert('original_absorption_divisor_is16_before_any_cut',loop,[neq(loop.get('w17'),'#x00000010'),neq(loop.get('w3'),'IX')],'(bvult IX #x00000020)')
 divisor_original=loop.get('w17');loop.put('w17','#x00000010');loop.run({'instructions':[i for i in f['instructions']if int(i['ea'],16)>=0x100bd79cc]},int(f['instructions'][-1]['ea'],16));models['absorption']=loop
 domains={};source_bindings=[];all_bytes={};all_instances=[]
 for spec in s['phase_specs']:
  phase=spec['phase'];g=models[phase];prior=json.loads(read(ROOT/(spec['parent']+'_checks.json')))
  model=prior['semantics']['source_models']['loop']if phase!='absorption'else prior['translations']['loop_full_source'];fresh_record=g.record_full()if phase!='absorption'else g.record();assert json.loads(json.dumps(fresh_record))==model,(phase,[(k,str(fresh_record[k])[:100],str(model.get(k))[:100])for k in fresh_record if json.loads(json.dumps(fresh_record[k]))!=model.get(k)])
  domain='(bvult IX '+bv(spec['iterations'],32)+')';domains[phase]=domain;stores={r['site']:r for r in g.stores};terms=[];normalforms=[];ledger=[]
  for pc,label in zip(spec['sites'],spec['labels']):
   st=stores[pc];assert st['width_bits']==8*spec['width_bytes'];index='(bvurem (bvmul (bvadd IX '+bv(label,32)+') '+bv(spec['multiplier'],32)+') '+bv(spec['modulus'],32)+')'
   if spec['width_bytes']==4:index='(bvshl '+index+' #x00000002)'
   want='(bvadd '+frame(spec['root'])+' '+z(index)+')';terms.append(neq(st['address'],want));normalforms.append((pc,want));source_bindings.append({'phase':phase,'site':pc,'original_store_address':st['address'],'normal_form':want,'domain':domain,'width_bytes':spec['width_bytes']})
   for ix in range(spec['iterations']):
    # All intermediate add/product values are below2^32 in these finite domains.
    product=(ix+label)*spec['multiplier'];assert product<2**32
    off=spec['root']+spec['width_bytes']*(product%spec['modulus']);ledger.append({'phase':phase,'IX':ix,'site':pc,'frame_offset':off,'width_bytes':spec['width_bytes']})
  cert(phase+'_all_original_store_addresses_equal_exact_coordinate_forms',g,terms,domain)
  # These new queries contain only the normal forms;no previous negated goal
  # or assumed destination envelope is inserted into a new proof context.
  finite=[]
  for r in ledger:
   want=dict(normalforms)[r['site']];ground=re.sub(r'\bIX\b',bv(r['IX'],32),want);finite.append(neq('(bvsub '+ground+' K)',bv(r['frame_offset'])))
  solve(phase+'_all_finite_coordinate_evaluations','(assert (or '+' '.join(finite)+'))')
  solve(phase+'_finite_counter_domain_exhaustive','(assert '+domain+')\n(assert (and '+' '.join(neq('IX',bv(j,32))for j in range(spec['iterations']))+'))')
  solve(phase+'_entry_domain_has_model','(assert '+domain+')',result='sat')
  byteset={r['frame_offset']+b for r in ledger for b in range(r['width_bytes'])};assert len(byteset)==sum(r['width_bytes']for r in ledger);assert min(byteset)>=0x8b0 and max(byteset)<0x10f8
  # A common modular base permits cancellation without a no-wrap premise.
  lo,hi=min(byteset),max(byteset)+1
  solve(phase+'_every_written_byte_disjoint_from_protected_return_state','(assert (bvuge OFF '+bv(lo)+'))\n(assert (bvult OFF '+bv(hi)+'))\n(assert (bvuge PROT #x00000000000011a0))\n(assert (bvult PROT #x0000000000001218))\n(assert (= (bvadd K OFF) (bvadd K PROT)))',extra='(declare-fun OFF () (_ BitVec 64))\n(declare-fun PROT () (_ BitVec 64))\n')
  # Removing the shared-frame root contract admits protected-state aliasing.
  solve(phase+'_independent_root_can_alias_protected_byte','(assert (= (bvadd FOREIGN '+bv(ledger[0]['frame_offset']-spec['root'])+') '+frame(0x11a0)+'))',extra='(declare-fun FOREIGN () (_ BitVec 64))\n',result='sat')
  all_bytes[phase]=byteset;all_instances.extend(ledger);ledgers[phase]={'phase':phase,'store_sites':spec['sites'],'iterations':spec['iterations'],'store_instances':len(ledger),'byte_write_operations':sum(r['width_bytes']for r in ledger),'distinct_written_bytes':len(byteset),'min_written_frame_offset':lo,'max_written_frame_end_exclusive':hi,'canary_gap_bytes':0x11a0-hi,'within_phase_written_bytes_are_pairwise_disjoint':True,'byte_offsets':sorted(byteset),'instances':ledger}
 intersections=[]
 for a,b in itertools.combinations(all_bytes,2):
  overlap=sorted(all_bytes[a]&all_bytes[b]);intersections.append({'phases':[a,b],'same_frame_offsets':overlap,'overlapping_bytes':len(overlap),'common_base_required':True,'coexecution_or_order_proved_by_intersection':False})
 assert len(source_bindings)==10 and len(all_instances)==448 and sum(len(x)for x in all_bytes.values())==1600
 actual={pc for g in models.values()for pc in g.sites}|set(entry.sites);expected={i['ea']for phase,label in[('record','loop'),('secondary','loop'),('absorption','entry'),('absorption','loop')]for i in old_fragment(phase,label)['instructions']if i['mnemonic']!='braa'};assert actual==expected
 sem={'source_models':{k:(g.record_full()if k!='absorption'else g.record())for k,g in models.items()},'source_models_freshly_rebuilt_and_equal_retained_models':True,'source_bindings':source_bindings,'finite_phase_footprints':ledgers,'cross_epoch_byte_intersections':intersections,'source_nonbranch_sites_translated':len(actual),'new_destination_envelope_premises_used':0,'word_source_value_cuts':0,'absorption_divisor_cut':{'original_expression':divisor_original,'replacement':'#x00000010','fresh_universal_source_proof':'original_absorption_divisor_is16_before_any_cut'},'original_computed_array_sites':174,'computed_array_sites_newly_footprint_proved':10,'other_computed_array_sites_not_newly_proved':164,'retained_frame_offset_sites_not_newly_proved':236,'premises':['Each modeled phase is entered with the original source model entry registers,presets and named load contracts.','IX is unsigned32 and lies in the stated finite domain at each modeled visit.','K is the same core frame base for all destination roots within the corresponding phase;phase/root identities are preserved.','Loaded scalar/word/byte inputs obey their source widths;memory accesses are valid and coherent where used.','These proofs cover the ten listed stores,not every executed core path/callee or every phase transition.'],'whole_core_control_closure_proved':False,'unconditional_budget_or_return_proved':False,'native_ownership_or_reachability_proved':False,'cross_epoch_coexecution_proved':False,'daemon_kext_pairing_proved':False,'Mach_port_emissions':0,'new_IDA_access':False}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('missing_store',lambda t:t['store_source_ledger'].pop()),('wrong_store_width',lambda t:t['store_source_ledger'][0].__setitem__('width_bytes',8)),('wrong_root',lambda t:t['phase_specs'][0].__setitem__('root',0x11a0)),('wrong_modulus',lambda t:t['phase_specs'][1].__setitem__('modulus',287)),('wrong_counter_domain',lambda t:t['phase_specs'][2].__setitem__('iterations',33)),('wrong_instruction',lambda t:t['fragments']['record_loop']['instructions'][0].__setitem__('operands','w0, w0, #1')),('wrong_source_bytes',lambda t:t['fragments']['secondary_loop'].__setitem__('bytes','00'+t['fragments']['secondary_loop']['bytes'][2:])),('invent_native',lambda t:t.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'source_models_freshly_rebuilt':3,'destination_envelope_premises':0,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'ten_computed_store_finite_footprints_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
