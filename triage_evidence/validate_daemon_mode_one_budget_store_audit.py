#!/usr/bin/env python3
"""Source-bound entry writes and conditional captured-path budget preservation."""
import copy,hashlib,json,re,shutil,subprocess
from recover_daemon_mode_one_budget_store_audit import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_result_publication import PublicationSSA
from validate_daemon_reader_container_origins import lut
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,neq
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
class CoreSSA(PublicationSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.guard_aliases=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc in[0x100cf0214,0x100cf0228,0x100cf0274,0x100cf028c]:
    left=pc in[0x100cf0214,0x100cf0274];a=self.address(split(i['operands'])[1]);base=0x100e99a00 if left else 0x100f4e390;self.supplied_loads[i['ea']]=('(LUT_CORE'+('L'if left else'R')+' ((_ extract 7 0) (bvsub '+a+' '+bv(base)+')))',8)
   if pc==0x100cf01dc:
    self.guard_aliases.append({'site':i['ea'],'original_address':self.address(split(i['operands'])[1]),'frame_offset':0x11a0});i={**i,'mnemonic':'str','operands':'x8, [sp, #0x11a0]'}
   super().run({'instructions':[i]},pc+4)
  return self

def chain(old,name,loads=None):
 g=PublicationSSA(name,old.r,loads=loads);g.defs=list(old.defs);g.decl=dict(old.decl);g.byte_cells=dict(old.byte_cells);g.loaded=old.loaded;g.aliases=dict(old.aliases);return g

def certificates(s):
 pp=[];mm={};fs=s['fragments'];replays=[]
 def solve(name,g=None,terms=(),cc=(),result='unsat',extra='',body='',logic='QF_BV',tactic=True):
  q='(set-option :timeout 45000)\n(set-logic '+logic+')\n'+DECL+extra
  if g is not None:q+=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
  q+=body+''.join('(assert '+v+')\n'for v in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n'if tactic else'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.returncode,r.stdout[:1800],r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def replay(name,names):
  c=json.loads(read(ROOT/(name+'_checks.json')));rows=[p for p in c['proofs']if p['name']in names];assert{p['name']for p in rows}==set(names)
  for p in rows:
   original=p['query'];q=original.replace('(set-option :timeout 15000)','(set-option :timeout 45000)');r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat',(name,p['name'],r.stdout[:500],r.stderr);pp.append({**p,'name':'replayed_'+name+'_'+p['name'],'query':q,'original_query_sha256':hashlib.sha256(original.encode()).hexdigest(),'historical_timeout_raised_to45000_ms':q!=original,'replayed_query':True})
  replays.append({'checks':name+'_checks.json','sha256':sha(ROOT/(name+'_checks.json')),'selected_propositions':names,'all_historical_queries_replayed':False});print('replayed',name,len(rows),flush=True)
 replay('daemon_mode_one_adapter',['adapter_reserve_and_budget_minus144','core_budget_add144_cancels_adapter_entry_bias','returned_delta_bounds_alignment_and_zero_criterion','caller_result_uses_saved_base_continuation_uses_adjusted_SP','same_saved_continuation_address_requires_zero_delta'])
 replay('daemon_mode_one_result_publication',['all32_original_LOCAL_output_byte_addresses','status_prefix_stores_raw_result_code_to_REQUEST0'])
 replay('daemon_mode_one_even_view_import',['first_original_source_byte_address_value_and_reciprocal_destination_shape','second_source_byte_address_raw_value_UDIV962_and_destination_shape'])
 replay('daemon_mode_one_secondary_word_extension',['all_four_original_word_store_addresses'])
 replay('daemon_mode_one_record_word_extension',['all_four_word_store_addresses'])
 replay('daemon_mode_one_source_absorption',['source_byte_and_two_state_addresses'])
 replay('daemon_mode_one_workspace_passes',['all16_identity_seed_addresses_and_byte_values','all15_source_swaps_exact_read_before_write_value_and_address_flow'])
 # Immutable byte-bank functions are reconstituted from the pinned original bytes.
 bank=s['controller_banks'][0];tables=lut('COREL',bytes.fromhex(bank['left_bytes']))+lut('CORER',bytes.fromhex(bank['right_bytes']))
 pointers={int(r['slot'],16):r['fixup']['target']for r in s['controller_pointer_records']}
 loads={'0x100cf01d4':('GPTR',64),'0x100cf01d8':('GUARDV',64),'0x100cf01e4':('((_ extract 31 0) CTLA)',32),'0x100cf01ec':('((_ extract 31 0) CTLB)',32),'0x100cf0240':(bv(pointers[0x1010a8d38]),64),'0x100cf0250':('CTLA',64),'0x100cf0260':(bv(pointers[0x1010a2fb8]),64),'0x100cf027c':(bv(pointers[0x1010a4000]),64),'0x100cf029c':(bv(pointers[0x1010a1e00]),64),'0x100cf02ac':('CTLB',64)}
 g=CoreSSA('controller_prefix',{29:frame(0x1200),1:frame(0x1210)},loads=loads);g.decl.update(GPTR=64,GUARDV=64,CTLA=64,CTLB=64);g.run(fs['controller_prefix'],int(fs['controller_prefix']['end'],16));mm['controller_prefix']=g
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 terms=[neq(g.guard_aliases[0]['original_address'],frame(0x11a0)),neq(g.stores[0]['address'],frame(0x11a0)),neq(g.stores[0]['value'],'GUARDV')]
 terms+=[neq(r['address'],bv(a))for r,a in zip(g.stores[1:],[0x1010b6838,0x1010c4670])]+[neq(rd(g,pc)['address'],bv(a))for pc,a in[(0x100cf0240,0x1010a8d38),(0x100cf029c,0x1010a1e00)]]
 terms+=[neq(rd(g,pc)['address'],bv(a))for pc,a in[(0x100cf01e4,0x1010b6838),(0x100cf01ec,0x1010c4670),(0x100cf0250,0x1010b6838),(0x100cf02ac,0x1010c4670)]]
 solve('whole72_instruction_prefix_exact_guard_controller_and_pointer_destinations',g,terms,extra=tables)
 delta='(bvsub (bvsub CTLB CTLA) '+frame(0x760)+')';a='(bvadd (bvmul '+delta+' #x000000000a5cd4cf) #x8c2fb9df71512e5a)';b='(bvmul (bvxor '+delta+' #x73d046208eaed1a6) #x000000000a5cd4cf)'
 solve('both_original_u64_controller_values_have_compact_stack_dependent_form',g,[neq(g.stores[1]['value'],a),neq(g.stores[2]['value'],b)],extra=tables);assert len(g.sites)==72 and len(g.stores)==3
 inverse_multiplier=8417723238837367343;assert (inverse_multiplier*0x0a5cd4cf)%(1<<64)==1
 solve('both_controller_outputs_independently_invert_to_one_u64_carrier',extra='(declare-fun CARRIER () (_ BitVec 64))\n',terms=[neq('(bvmul (bvsub (bvadd (bvmul CARRIER #x000000000a5cd4cf) #x8c2fb9df71512e5a) #x8c2fb9df71512e5a) '+bv(inverse_multiplier)+')','CARRIER'),neq('(bvxor (bvmul (bvmul (bvxor CARRIER #x73d046208eaed1a6) #x000000000a5cd4cf) '+bv(inverse_multiplier)+') #x73d046208eaed1a6)','CARRIER')])
 # The initial budget read is after the stack-probe/prefix. Its reaching value
 # V-144 is the retained adapter/probe preservation contract,not a native run.
 bg=chain(g,'budget_entry',{'0x100cf02f0':('(bvsub FRAMESEED #x0000000000000090)',64)});bg.decl['FRAMESEED']=64;bg.run(fs['budget_entry'],int(fs['budget_entry']['end'],16));mm['budget_entry']=bg;assert len(bg.stores)==1
 solve('source_initial_budget_plus144_cancels_retained_adapter_minus144',bg,[neq(rd(bg,0x100cf02f0)['address'],frame(0x1210)),neq(bg.stores[0]['address'],frame(0x1210)),neq(bg.stores[0]['value'],'FRAMESEED')],extra=tables)
 # SP decoding establishes literal positions; alias and array rows keep their
 # component-address contracts as explicit premises of this composition.
 rows=s['source_store_catalogue'];groups=s['source_store_categories'];raw=[r for r in rows if r['category']=='independently_decoded_SP'];body=[r for r in raw if not r['decoded']['initial_register_save']];init=[r for r in raw if r['decoded']['initial_register_save']];assert len(init)==6 and len(body)==3301
 saved={o for r in init for lo,hi in r['decoded']['frame_intervals']for o in range(lo,hi)};assert saved==set(range(0x11b0,0x1210))
 assert max(hi for r in body for lo,hi in r['decoded']['frame_intervals'])<=0x1170
 alias=[r for r in rows if r['category']=='retained_frame_offset_evidence'];assert len(alias)==236 and max(e['frame_offset']+e['width_bytes']for r in alias for e in r['frame_effect_evidence'])<=0x1170
 array=[r for r in rows if r['category']=='retained_computed_array_contract'];assert len(array)==174 and all(r['assumed_frame_envelope']==[0x8b0,0x10f8]for r in array)
 solve('private_byte_envelope1170_is_disjoint_from_canary_saved_registers_and_budget',terms=['(= (bvadd K OFF) (bvadd K PROTECTED))'],cc=['(bvult OFF #x0000000000001170)','(bvuge PROTECTED #x00000000000011a0)','(bvult PROTECTED #x0000000000001218)'],extra='(declare-fun OFF () (_ BitVec 64))\n(declare-fun PROTECTED () (_ BitVec 64))\n')
 solve('computed_array_envelope10f8_is_inside_private_return_state_bound',terms=['(bvuge ARRAYOFF #x0000000000001170)'],cc=['(bvuge ARRAYOFF #x00000000000008b0)','(bvult ARRAYOFF #x00000000000010f8)'],extra='(declare-fun ARRAYOFF () (_ BitVec 64))\n')
 # Each disjoint byte store preserves every protected byte; induction extends
 # this source memory law to any finite path satisfying the enumerated contracts.
 solve('byte_store_disjointness_preserves_protected_memory',terms=['(distinct (select (store MEM DEST BYTEVAL) PROT) (select MEM PROT))'],cc=['(distinct DEST PROT)'],extra='(declare-fun MEM () (Array (_ BitVec 64) (_ BitVec 8)))\n(declare-fun DEST () (_ BitVec 64))\n(declare-fun PROT () (_ BitVec 64))\n(declare-fun BYTEVAL () (_ BitVec 8))\n',logic='QF_AUFBV',tactic=False)
 # Structural source assertions identify96 saved bytes plus4528 locals.
 solve('source_frame_FP_canary_and_budget_geometry',terms=[neq('(bvsub BP #x0000000000000010)','(bvadd (bvsub BP #x0000000000001210) #x0000000000001200)'),neq('(bvsub (bvsub BP #x0000000000000010) #x0000000000000060)','(bvadd (bvsub BP #x0000000000001210) #x00000000000011a0)'),neq('(bvadd (bvadd (bvsub BP #x0000000000001210) #x00000000000011b0) #x0000000000000060)','BP')],extra='(declare-fun BP () (_ BitVec 64))\n')
 # The anchored request record is mathematically separate from protected core
 # bytes for every retained16..256-byte adapter reservation,even modulo2^64.
 caller='CALLER';bp='(bvsub (bvsub CALLER #x0000000000000040) RESERVE)';core='(bvsub '+bp+' #x0000000000001210)';req='(bvadd CALLER #x0000000000010cb8)'
 solve('anchored_request_result4_never_aliases_core_protected120_bytes',terms=['(= (bvadd '+req+' RBYTE) (bvadd '+core+' PBYTE))'],cc=['(bvuge RESERVE #x0000000000000010)','(bvule RESERVE #x0000000000000100)','(bvult RBYTE #x0000000000000004)','(bvuge PBYTE #x00000000000011a0)','(bvult PBYTE #x0000000000001218)'],extra=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in['CALLER','RESERVE','RBYTE','PBYTE']))
 st=PublicationSSA('status_prefix',{9:z('RAWCODE')},presets={0x388:('REQUEST',64)});st.decl.update(RAWCODE=32,REQUEST=64);st.run(fs['status_prefix'],int(fs['status_prefix']['end'],16));mm['status_prefix']=st
 solve('source_result_prefix_writes_only4_bytes_to_REQUEST0',st,[neq(st.stores[0]['address'],'REQUEST'),neq(st.stores[0]['value'],'RAWCODE')]);assert len(st.stores)==1
 ar=PublicationSSA('adapter_delta',{20:'BUDGETPTR',21:'FRAMESEED',19:'DOUT'},loads={'0x100d03584':('((_ extract 31 0) FINALBUDGET)',32)});ar.decl.update(BUDGETPTR=64,FRAMESEED=64,DOUT=64,FINALBUDGET=64);ar.run(fs['adapter_delta'],int(fs['adapter_delta']['end'],16));mm['adapter_delta']=ar
 exact='(bvshl ((_ zero_extend 48) ((_ extract 15 0) (bvsub FINALBUDGET FRAMESEED))) #x0000000000000004)';solve('source_adapter_delta_depends_only_on_low16_budget_difference',ar,[neq(rd(ar,0x100d03584)['address'],'BUDGETPTR'),neq(ar.stores[0]['address'],'DOUT'),neq(ar.stores[0]['value'],exact)])
 solve('captured_path_budget_preservation_implies_zero_adapter_delta',ar,[neq(ar.stores[0]['value'],bv(0))],cc=['(= FINALBUDGET FRAMESEED)'])
 solve('equal_low16_is_the_exact_minimum_zero_delta_condition',ar,[neq('(= '+ar.stores[0]['value']+' #x0000000000000000)','(= ((_ extract 15 0) FINALBUDGET) ((_ extract 15 0) FRAMESEED))')])
 solve('conditional_contract_domain_nonempty',ar,cc=['(= FINALBUDGET FRAMESEED)'],result='sat')
 solve('upper48_budget_changes_can_preserve_zero_delta',ar,[neq('FINALBUDGET','FRAMESEED')],cc=['(= ((_ extract 15 0) FINALBUDGET) ((_ extract 15 0) FRAMESEED))'],result='sat')
 actual={pc for m in mm.values()for pc in m.sites};expected={i['ea']for f in fs.values()for i in f['instructions']};assert actual==expected and len(actual)==81
 effects={n:{'source_sites':len(m.sites),'loads':len(m.reads),'stores':len(m.stores),'store_bytes':sum(r['width_bits']//8 for r in m.stores)}for n,m in mm.items()}
 sem={'source_models':{n:m.record_full()for n,m in mm.items()},'predecessor_replays':replays,'source_nonbranch_sites_translated':len(actual),'current_controller_guard_budget_result_delta_store_effects':6,'store_categories':groups,'core_store_catalogue_sites':3754,'independently_decoded_SP_stores':3307,'SP_initial_register_save_sites':6,'SP_body_store_sites':3301,'retained_frame_offset_sites':236,'retained_array_envelope_premise_sites':174,'LOCAL_output_sites':32,'special_destination_sites':5,'maximum_private_effect_end_exclusive':hex(0x1170),'canary_interval':[0x11a0,0x11a8],'saved_register_interval':[0x11b0,0x1210],'budget_interval':[0x1210,0x1218],'controller_A_address':'0x1010b6838','controller_B_address':'0x1010c4670','controller_accesses':'Selector reads use low32;data reads and writes use full64 with coherent stable old values.','initial_canary_original_aliases':g.guard_aliases,'raw_SP_body_end_exclusive':hex(max(hi for r in body for lo,hi in r['decoded']['frame_intervals'])),'controller_difference':delta,'controller_A_new':a,'controller_B_new':b,'controller_inverse_multiplier':hex(inverse_multiplier),'controller_pair_represents_one_u64_carrier_after_both_source_stores':True,'controller_update_depends_on_private_stack_address':True,'controller_target_independent_of_controller_values_under_original_banks':True,'fresh_controller_source_value_cuts':0,'budget_entry_value':'FRAMESEED after source+144 under reaching adapter/probe contract','captured_path_budget_preservation_and_zero_delta_law_proved':True,'conditional_law_premises':['Every executed core store is represented by this catalogue or a modeled imported-helper contract.','The reaching request and control roots retain the identities used by each destination contract.','236 retained frame-offset and174 computed-array destination contracts hold in their required root/counter/epoch domains.','LOCAL32,image-controller destinations and modeled callees do not alias or mutate protected core return state.','The stack probe preserves the reaching budget value V-144;the bounded fill obeys its retained contract.','No outside writer changes protected stack bytes or the live canary;ordinary calling/PAC conditions hold.','The modeled path returns finitely through the captured normal epilogue.'],'whole_core_control_closure_proved':False,'all_retained_computed_destinations_freshly_proved':False,'whole_core_budget_preservation_unconditionally_proved':False,'native_return_observed':False,'native_ownership_and_alias_policy_proved':False,'whole_file_IDB_identity_established':False,'IDA_text_identity_established':True,'IDA_macro_item_heads':169,'IDA_macro_tail_words':46,'raw_entry_A64_words':215,'IDA_metadata_not_used_as_logical_routine_bounds':True,'memory_claims_used':0,'exact_delta_low_bits_required':16,'exact_delta_range_bytes':[0,0xffff0],'effect_counts':effects,'Mach_port_emissions':0,'new_IDA_access':True,'IDB_observation_validation_boundary':'The saved read-only live observation is retained;validation freshly matches the original__text hash and local source bytes. It does not claim to reobserve current IDB metadata or establish whole-file/data-section identity.','native_daemon_kext_pairing_proved':False,'source_value_cuts':0,'excluded_claims':'A frame-offset record is retained evidence,not a new universal alias proof. The174 computed-site envelope is an explicit component premise. The catalogue is exhaustive for the listed captured ranges,not every path in the logical core. Native return,unconditional zero delta and matched transport remain unknown.'}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('missing_store',lambda t:t['source_store_catalogue'].pop()),('wrong_SP_offset',lambda t:next(r for r in t['source_store_catalogue']if r['category']=='independently_decoded_SP')['decoded'].__setitem__('frame_offset',0x1210)),('wrong_controller_destination',lambda t:t['controller_banks'][0].__setitem__('target','0x1010b1e18')),('wrong_source_operand',lambda t:t['fragments']['controller_prefix']['instructions'][-1].__setitem__('operands','x11, [x1]')),('wrong_IDA_text_hash',lambda t:t['IDA_observation']['text_hash'].__setitem__('sha256','0'*64)),('wrong_IDA_identity_claim',lambda t:t.__setitem__('whole_file_IDB_identity_established',True)),('wrong_memory_scope',lambda t:t['IDA_observation'].__setitem__('memory_claims_used',1)),('invent_native',lambda t:t.__setitem__('target_executed',True))];out=[]
 for n,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;out.append({'name':n,'rejected_by_fresh_local_source_and_recorded_observation_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':81,'fresh_controller_value_cuts':0,'current_store_effects':6,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'captured_core_store_catalogue_and_conditional_budget_law_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
