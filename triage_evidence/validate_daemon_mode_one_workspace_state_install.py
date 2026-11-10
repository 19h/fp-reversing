#!/usr/bin/env python3
"""Prove workspace traversal,source address forwarding and table lifetime epochs."""
import copy,json,re,subprocess,shutil
from recover_daemon_mode_one_workspace_state_install import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_checkpoint import PostSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq
from validate_daemon_mode_one_record_long_prefix import dependency_census
from daemon_mode_one_handoff_tools import parse
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
NORMALIZE={0x100b5ac6c:0x824,0x100b5a518:0x961,0x100b5ad64:0x9f4}
class InstallSSA(PostSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.original_addresses=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc in NORMALIZE:
    p=split(i['operands']);assert i['mnemonic']in['ldr','strb'];off=NORMALIZE[pc];self.original_addresses.append({'site':i['ea'],'frame_offset':off,'original_address':self.address(p[1]),'mnemonic':i['mnemonic']});i={**i,'operands':p[0]+', [sp, #'+hex(off)+']'}
   super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'proved_computed_access_normalizations':self.original_addresses}
def certificates(s):
 pp=[];models={};fs=s['fragments']
 def solve(name,g=None,terms=None,cc=(),result='unsat',values=None,body='',extra=''):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+extra
  if g is not None:q+=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
  q+=body+''.join('(assert '+x+')\n'for x in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat)\n'
  if values is not None:q+='(get-value ('+' '.join(values)+'))\n'
  r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr,(name,r.stdout[:2000],r.stderr)
  row={'name':name,'query':q,'result':result,'scope':SCOPE}
  if values is None:assert r.stdout.strip()==result,(name,r.stdout[:2000])
  else:
   assert result=='sat'and r.stdout.startswith('sat\n'),(name,r.stdout[:2000]);v=parse(r.stdout[4:]);assert len(v)==len(values);row['model_value_hex']=[x[-1]for x in v];assert all(re.fullmatch('#x[0-9a-f]+',x)for x in row['model_value_hex'])
  pp.append(row);print(name,result,flush=True);return row
 def run(g,label):
  f=fs[label];g.run(f,int(f['instructions'][-1]['ea'],16));models[label]=g;return g
 def rd(g,site):return next(r for r in g.reads if r['site']==hex(site))
 def frame_cert(name,g):
  rr={r['site']:r for r in g.reads};ss={r['site']:r for r in g.stores}
  solve(name,g,[neq(rr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_reads]+[neq(ss[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_writes])
 prior=json.loads(read(ROOT/'daemon_mode_one_nibble_operation_suite_checks.json'));assert prior['all_checks_pass']and prior['semantics']['known_frame_cells']==832
 wanted={'encode_full_outgoing_register_epoch'};rows=[p for p in prior['proofs']if p['name']in wanted];assert len(rows)==1
 for p in rows:
  r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_'+p['name'],'replayed_query':True});print('replayed_'+p['name'],'unsat',flush=True)
 # Generic entry state covers the first entry and every repeated iteration.
 first_regs={2:'(bvadd '+bv(0x0a15c815)+' '+z('IDX')+')',15:bv(0x3489),4:z('AS0'),12:z('AS1'),22:z('AS2'),24:z('AS3')}
 a=PostSSA('first',first_regs,presets={0x740:('TABLE',64)},loads={'0x100d8460c':('AW',32),'0x100d84bc0':('AFN',64)});a.decl.update(IDX=32,AS0=32,AS1=32,AS2=32,AS3=32,AW=32,AFN=64);run(a,'first');domain=['(bvult IDX #x0000004a)']
 fixed={3:0x7203c9fe,5:0x6341b114,6:0xfaff40f3,7:0x0a2afbd8,10:0x9c46cba1,13:0x9d34,15:0x3489,16:0x5d5,17:0xbdfd,19:0x54734960}
 solve('first_workspace_address_counter_and_exact_two_targets',a,[neq(rd(a,0x100d8460c)['address'],'(bvadd '+frame(0x768)+' (bvshl '+z('IDX')+' '+bv(2)+'))'),neq(a.get('x2'),'(bvadd '+bv(0x0a15c816)+' '+z('IDX')+')'),neq(rd(a,0x100d84bc0)['address'],f'(ite (= IDX #x00000049) {at(0x34a3)} {at(0x3489)})')],domain)
 solve('first_repeat_invariant_and_second_entry_constants',a,[neq(a.get('x'+str(k)),bv(v))for k,v in fixed.items()]+[neq(a.get('x9'),frame(0x768)),neq(a.get('x8'),'AFN')],domain)
 frame_cert('first_all_frame_effect_addresses',a);assert[(r['frame_offset'],r['width_bits'])for r in a.frame_writes]==[(0x730,32),(0x728,32)]and len(a.stores)==2
 # The second loop accepts arbitrary first-pass survivors and arbitrary
 # rolling state. This overapproximation avoids invented cross-bank equality.
 varying=[0,1,5,6,7,14,19];br={j:z('BI'+str(j))for j in varying};br.update({3:'(bvadd '+bv(0x7203c9fe)+' '+z('J')+')',9:frame(0x768),10:bv(0x9c46cba1),13:bv(0x9d34),16:bv(0x5d5)})
 b=PostSSA('second',br,presets={0x740:('TABLE',64)},loads={'0x100d9c42c':('BW',32),'0x100d9ca44':('BFN',64)});b.decl.update({**{'BI'+str(j):32 for j in varying},'J':32,'BW':32,'BFN':64});run(b,'second');dd=['(bvult J #x0000004a)']
 solve('second_workspace_address_and_exact_adapter_or_install_targets',b,[neq(rd(b,0x100d9c42c)['address'],'(bvadd '+frame(0x768)+' (bvshl '+z('J')+' '+bv(2)+'))'),neq(rd(b,0x100d9ca44)['address'],f'(ite (= J #x00000049) {at(0x9d55)} {at(0x9d34)})')],dd)
 invariant={2:0x34a3,10:0x9c46cba1,13:0x9d34,16:0x5d5,17:0x8125,23:0x40d0}
 solve('second_counter_control_and_first_bank_survivors',b,[neq(b.get('x'+str(k)),bv(v))for k,v in invariant.items()]+[neq(b.get('x9'),frame(0x768)),neq(b.get('x3'),br[3])]+[neq(b.get('x'+str(k)),br[k])for k in[0,1,14]]+[neq(b.get('x'+str(k)),'Z'+str(k))for k in[22,24]],dd);assert not b.stores
 c=PostSSA('adapter',b.r);c.defs=list(b.defs);c.decl=dict(b.decl);c.byte_cells=dict(b.byte_cells);c.loaded=b.loaded;c.supplied_loads={'0x100cc80dc':('CFN',64)};c.decl['CFN']=64;run(c,'adapter')
 newstate=f'(bvadd (bvadd {b.get("w19")} {b.get("w20")}) {bv(0x9d34^0xe709472f,32)})'
 solve('adapter_increments_index_reconstructs_control_and_returns_second',c,[neq(c.get('x3'),z('(bvadd '+bv(0x7203c9ff,32)+' J)')),neq(c.get('w5'),newstate),neq(c.get('x13'),bv(0x9d34)),neq(rd(c,0x100cc80dc)['address'],at(0x34a3)),neq(c.get('x9'),frame(0x768)),neq(c.get('x17'),bv(0xbdfd))]+[neq(c.get('x'+str(k)),b.get('x'+str(k)))for k in[0,1,6,7,10,14,16,19,22,23,24]],dd);assert not c.stores
 # Prove computed addresses against the unmodified block before forwarding.
 presets={0x740:('TABLE',64),0x758:(frame(0x8b0),64)}
 raw=PostSSA('raw_install',{23:bv(0x40d0)},presets=presets,loads={'0x100b5ac6c':('W47',32),'0x100b5c504':('IFN',64)});raw.decl.update(W47=32,IFN=64);run(raw,'install');models['raw_install']=models.pop('install')
 accesses={r['site']:r for r in raw.reads+raw.stores};solve('unmodified_install_computed_workspace_and_plane_addresses',raw,[neq(accesses[hex(site)]['address'],frame(off))for site,off in NORMALIZE.items()])
 solve('unmodified_install_exact_dispatch_F710_and_literal_bias_words',raw,[neq(rd(raw,0x100b5c504)['address'],at(0x40d0)),neq(raw.loadframe(0x710,32),bv(0x40d0,32)),neq(raw.loadframe(0x350,64),bv(0x2c238c16ca76f3a8)),neq(raw.loadframe(0x360,64),bv(0x0ff0ed06a1ef8a89)),neq(raw.get('x11'),bv(1)),neq(raw.get('x17'),bv(0x465a)),neq(raw.get('x14'),'IFN')])
 g=InstallSSA('install',{23:bv(0x40d0)},presets=presets,loads={'0x100b5c504':('IFN',64)});g.decl['IFN']=64;run(g,'install')
 solve('coherent_install_original_normalized_addresses',g,[neq(r['original_address'],frame(r['frame_offset']))for r in g.original_addresses]);frame_cert('coherent_install_every_read_and_store_frame_address',g)
 assert len(g.frame_writes)==len(g.stores)==398 and len(g.frame_reads)+1==len(g.reads)==318
 assert{r['frame_offset']for r in g.initial}==set(range(0x768,0x890,4))|{0x728,0x730}and all(r['width_bits']==32 for r in g.initial)
 # Verify that fixed64-bit root words are preserved rather than retagged.
 solve('install_preserves_F758_table_root_and_TABLE',g,[neq(g.loadframe(0x758,64),frame(0x8b0)),neq(g.loadframe(0x740,64),'TABLE'),neq(rd(g,0x100b5c504)['address'],at(0x40d0))])
 byte=[r for r in g.frame_writes if r['width_bits']==8];assert len(byte)==128
 inv=pow(799,-1,962);ledger=[{**r,'coordinate_label':(r['frame_offset']-0x8b0)*inv%962}for r in byte];assert{r['coordinate_label']for r in ledger}==set(range(64))|set(range(593,657));assert len({r['frame_offset']for r in byte})==128
 banks={name:{0x8b0+799*j%962 for j in range(a,b)}for name,a,b in[('Q',0,16),('SUM',72,328),('XOR',333,589),('I',593,609),('DEC',659,675),('CARRY',677,933),('ENC',936,952)]};assert sum(map(len,banks.values()))==832
 written={r['frame_offset']+j for r in g.frame_writes for j in range(r['width_bits']//8)};plane={r['frame_offset']for r in byte};overlaps={n:sorted(v&written)for n,v in banks.items()};assert len(overlaps['Q'])==len(overlaps['I'])==16 and all(not overlaps[n]for n in['SUM','XOR','DEC','CARRY','ENC'])
 retained=set.union(*(banks[n]for n in['SUM','XOR','DEC','CARRY','ENC']));assert len(retained)==800 and not retained&plane and len(retained|plane)==928
 assert not written&set(range(0x768,0x890))and all(r['frame_offset']+r['width_bits']//8<=0x768 or r['width_bits']==8 and r['frame_offset']in plane for r in g.frame_writes)
 declared=set(re.findall(r'\(declare-fun (\w+) ',DECL))|set(g.decl);deps=dependency_census(g.prefix(),declared,[r['value']for r in byte]+[g.get('x'+str(j))for j in range(31)])
 for row,d in zip(ledger,deps[:128]):row['declared_input_upper_bound']=d
 # Two fully specified component valuations prevent a constant-plane claim.
 # They are abstract local state values,not native request encodings.
 samples=[]
 for label,value in [('zero',0),('repeated_one',0x01010101)]:
  cc=['(= K '+bv(0)+')','(= TABLE '+bv(0)+')']+['(= Z'+str(j)+' '+bv(0)+')'for j in range(31)]+['(= '+n+' '+bv(value if w==32 else 0,w)+')'for n,w in g.decl.items()]
  samples.append(solve('abstract_plane_'+label+'_component_valuation',g,cc=cc,result='sat',values=[r['value']for r in byte])['model_value_hex'])
 differing=[j for j in range(128)if samples[0][j]!=samples[1][j]];assert differing;varied=byte[differing[0]]
 slots=[0x2b8,0x2c0,0x350,0x358,0x360,0x368,0x370,0x388,0x568,0x580,0x588,0x740,0x750,0x758,0x1210];epochs={hex(off):[r for r in g.frame_writes if set(range(off,off+8))&set(range(r['frame_offset'],r['frame_offset']+r['width_bits']//8))]for off in slots}
 actual={pc for label,m in models.items()if label!='raw_install'for pc in m.sites};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==5675
 assert not a.initial and not b.initial and not c.initial and len(g.initial)==76
 for label in['second','adapter']:
  regs={r[1:]for r in s['register_write_sets'][label]if re.fullmatch('[xw][0-9]+',r)};assert not regs&{'22','24'}
 exit_target=next(r['target']for r in s['branch_edges']if r['fragment']=='install')
 sem={'source_models':{n:m.record_full()for n,m in models.items()},'source_nonbranch_sites_translated':5675,'predecessor_queries_replayed':len(rows),'all_predecessor_queries_replayed':False,'first_state_registers':[4,12,22,24],'first_seed_u32':[0x2a65c9df,0xa77b2501,0xf402e748,0xc5141de1],'first_counter_bias':hex(0x0a15c815),'first_outgoing_fixed_registers':fixed,'first_auxiliary_frame_slots':[0x728,0x730],'second_state_registers':[5,6,7,19],'second_seed_u32':[fixed[j]for j in[5,6,7,19]],'second_counter_bias':hex(0x7203c9fe),'second_adapter_W5_update':newstate,'second_generic_survivor_inputs':varying,'iteration_domain':[0,73],'words_per_traversal':74,'bytes_per_traversal':296,'total_workspace_loop_loads':148,'second_adapter_executions':73,'workspace_unchanged':True,'install_workspace_input_words':74,'install_auxiliary_input_words':2,'install_byte_loads':0,'install_data_plane_reads':0,'install_initial_frame_inputs':g.initial,'computed_accesses':g.original_addresses,'plane_coordinate_rule':'C(j)=F+0x8b0+((799*j)mod962)','plane0_labels':[0,63],'plane1_labels':[593,656],'plane_store_ledger':ledger,'plane_values_constant_proved':False,'abstract_nonconstant_control_site':varied['site'],'abstract_sample_differing_cells':len(differing),'abstract_samples_are_native_inputs':False,'dependency_membership_is_not_proof_of_influence':True,'register_declared_input_upper_bounds':{str(j):deps[128+j]for j in range(31)},'prior_table_write_intersections':overlaps,'Q_and_I_cells_repurposed':True,'arithmetic_and_codec_cells_retained':800,'known_domain_cells_after_install':928,'unclaimed_domain_cells':34,'saved_slot_write_epochs':epochs,'F350_u64':'0x2c238c16ca76f3a8','F360_u64':'0x0ff0ed06a1ef8a89','F350_and_F360_are_numeric_bias_words':True,'LOCAL_pointer_dereferences':0,'Mach_port_emissions':0,'install_source_loads':len(g.reads),'install_source_store_effects':len(g.stores),'install_store_bytes':sum(r['width_bits']//8 for r in g.stores),'install_distinct_bytes_written':len(written),'install_read_bytes':sum(r['width_bits']//8 for r in g.reads),'install_store_width_census':{str(w):sum(r['width_bits']==w for r in g.stores)for w in[8,32,64]},'next_target':exit_target,'next_target_semantics_proved':False,'decoded_workspace_recurrences_proved':False,'whole_cryptographic_algorithm_identified':False,'native_ownership_proved':False,'successful_output_proved':False,'daemon_kext_pairing_proved':False,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['install'].__setitem__('bytes','00'+q['fragments']['install']['bytes'][2:])),('first_counter_target',lambda q:q['branch_edges'][0].__setitem__('target','0x0')),('adapter_target',lambda q:q['branch_edges'][4].__setitem__('target','0x0')),('wrong_bitfield_width',lambda q:q['bitfield_decode_checks'][0].__setitem__('source_count',0)),('wrong_shift_mask',lambda q:q['register_shift_decode_checks'][0].__setitem__('shift_count_mask',63)),('wrong_workspace_lineage',lambda q:q['prior_recaptures'][-1].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True)),('wrong_install_slot',lambda q:q['branch_edges'][-1].__setitem__('index','0x0'))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sem['predecessor_queries_replayed'],'source_nonbranch_sites_translated':5675,'words_per_traversal':74,'workspace_loop_loads':148,'workspace_loop_read_bytes':592,'second_adapter_executions':73,'install_frame_input_words':76,'install_workspace_input_words':74,'install_source_loads':sem['install_source_loads'],'install_store_effects':sem['install_source_store_effects'],'install_store_bytes':sem['install_store_bytes'],'install_distinct_bytes_written':sem['install_distinct_bytes_written'],'install_read_bytes':sem['install_read_bytes'],'computed_accesses_normalized':3,'private_plane_bytes':128,'repurposed_permutation_cells':32,'retained_arithmetic_codec_cells':800,'known_domain_cells':928,'unclaimed_domain_cells':34,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','daemon_word_round_tools.py','daemon_mode_one_handoff_tools.py','validate_daemon_mode_one_record_join.py','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_long_prefix.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','validate_daemon_mode_one_word_schedule.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'workspace_traversals_state_install_and_epochs_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
