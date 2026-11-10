#!/usr/bin/env python3
"""Source-to-SMT specification packing,min/max updates and metadata interfaces."""
import copy,json,re,shutil,subprocess,hashlib
from recover_dma_map_constraints import ROOT,P,SCOPE,FLAGS,DEPS,build,G,C,selected_graph
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_buffer_construction_flow import ConstructionSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
NAMES={n:64 for n in ['OBJ','META','DATA','SPEC','ALIGN','OLDALIGN','MAPPER_PTR','HEAP','CAP','REQUEST','USED','NEW','RET','BYTEIX','SPBASE']};NAMES.update(BITS=8,BITS2=8,OLDBITS=8,OLDSTATE=8,OLDBYTE=8,WORD=32)
BASE_DECL=set(re.findall(r'\(declare-fun (\w+) ',DECL));DECLARED=BASE_DECL|set(NAMES)
def add(a,b):return '(bvadd '+a+' '+(bv(b)if isinstance(b,int)else b)+')'
class SpecSSA(ConstructionSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.vector_zero_lowerings=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='movi':
    assert i['operands']=='v0.2d, #0000000000000000';self.vector_is_zero=True;self.vector_zero_lowerings.append({'site':i['ea'],'destination':'V0','value128':'0x00000000000000000000000000000000'});self.sites.append(i['ea'])
   elif i['mnemonic']=='stp'and i['operands'].startswith('q0, q0,'):
    assert getattr(self,'vector_is_zero',False)and i['operands']=='q0, q0, [sp, #0x30]'
    for off in [0x30,0x38,0x40,0x48]:
     super().run({'instructions':[{**i,'mnemonic':'str','operands':'xzr, [sp, #'+hex(off)+']'}]},pc+4)
    del self.sites[-3:];self.vector_zero_lowerings.append({'site':i['ea'],'original':'STP Q0,Q0','scalar_offsets':[0x30,0x38,0x40,0x48],'all128_bit_lanes_zero':True})
   else:super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return {**super().record_full(),'vector_zero_lowerings':self.vector_zero_lowerings}
def certificates(s):
 pp=[];models={};bounds={};bindings=[];extra=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in NAMES.items()if n not in BASE_DECL)
 def solve(n,body,more='',result='unsat'):
  q='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL+extra+more+body+'\n(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.returncode,r.stdout[:1800],r.stderr);pp.append({'name':n,'query':q,'result':result,'static_scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,conditions=(),result='unsat'):
  solve(n,g.prefix()+''.join('(assert '+c+')\n'for c in conditions)+'(assert (or '+' '.join(bounds.get(g.namespace,[])+terms)+'))',''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items()if n not in DECLARED),result)
 def make(n,regs=None,presets=None,loads=None,existing=None):
  g=existing or SpecSSA(n,regs,presets);bb=bounds.get(g.namespace,[]);loads=loads or{}
  for i in s['fragments'][n]['instructions']:
   if i['ea']in loads:
    a,v,w=loads[i['ea']];v=bv(v,w)if isinstance(v,int)else v;g.supplied_loads[i['ea']]=(v,w)
    if re.fullmatch(r'[A-Za-z_]\w*',v)and v not in DECLARED:g.decl[v]=w
   g.run({'instructions':[i]},int(i['ea'],16)+4)
   if i['ea']in loads:
    a,v,w=loads[i['ea']];a=bv(a)if isinstance(a,int)else a;bb.append(neq(g.reads[-1]['address'],a));bindings.append({'phase':n,'site':i['ea'],'source_address':g.reads[-1]['address'],'expected_address':a,'width_bits':w})
  bounds[g.namespace]=bb;return g
 def keep(n,g):models[n]=g
 def st(g,j=0):return g.stores[j]
 g=make('request_zero',{3:'ALIGN'});cert('request_has32_zero_bytes_after_full64_alignment_word',g,[neq(st(g,j)['address'],add('K',off))for j,off in enumerate([0x30,0x38,0x40,0x48,0x28])]+[neq(st(g,j)['value'],bv(0))for j in range(4)]+[neq(st(g,4)['value'],'ALIGN')]);keep('request_zero',copy.deepcopy(g))
 g=make('request_bit_choice',{8:bv(0)});cert('physical_mask0_selects_literal64_address_bits',g,[neq(g.get('w11'),bv(64,32)),'(not '+g.branches[0]['condition']+')']);keep('request_bit_choice',g)
 g=make('request_bit_store',{11:bv(64)});cert('address_bits_are_stored_at_spec_offset14',g,[neq(st(g)['address'],add('K',0x3c)),neq(st(g)['value'],bv(64,8))]);keep('request_bit_store',g)
 g=make('request_call',{19:'OBJ'});cert('constructor_requests_operation4000000_and40_byte_specification',g,[neq(g.get('x0'),'OBJ'),neq(g.get('w1'),bv(0x4000000,32)),neq(g.get('x2'),add('K',0x28)),neq(g.get('w3'),bv(40,32))]);keep('request_call',g)
 # Exact forty-byte source-store join. Reads are symbolic selectors,not memory execution.
 stores=models['request_zero'].stores+models['request_bit_store'].stores;address=add(add('K',0x28),'BYTEIX');value='OLDBYTE'
 for row in stores:
  for j in range(row['width_bits']//8):value='(ite (= '+address+' '+add(row['address'],j)+') ((_ extract '+str(j*8+7)+' '+str(j*8)+') '+row['value']+') '+value+')'
 more=models['request_zero'].prefix()+models['request_bit_store'].prefix();expected='(ite (bvult BYTEIX #x0000000000000008) ((_ extract 7 0) (bvlshr ALIGN (bvmul BYTEIX #x0000000000000008))) (ite (= BYTEIX #x0000000000000014) #x40 #x00))';solve('all40_specification_bytes_match_alignment_zero_fields_and_address_bits',more+'(assert (bvult BYTEIX #x0000000000000028))\n(assert '+neq(value,expected)+')')
 g=make('selector',{1:bv(0x4000000)});cert('original_selector_takes_signed_greater_branch_to_case_dispatch',g,[neq(g.get('w8'),bv(3,32)),'(not '+g.branches[0]['condition']+')']);keep('selector',g)
 g=make('case3_select',{8:bv(3)});cert('original_case3_comparison_takes_operation4000000_target',g,['(not '+g.branches[0]['condition']+')']);keep('case3_select',g)
 g=make('size_guard',{3:bv(40)});cert('exact40_byte_request_passes_original_unsigned_size_guard',g,[g.branches[0]['condition'],neq(g.get('w19'),bv(0xe00002e7,32))]);keep('size_guard',g)
 g=make('bit_read',{8:'META',2:'SPEC'},loads={hex(G+0x671c):(add('META',0x10),'DATA',64),hex(G+0x6720):(add('SPEC',0x14),'BITS',8),hex(G+0x6724):(add('DATA',0x2c),'OLDBITS',8)})
 cert('bit_limit_compares_request_and_metadata_as_unsigned_bytes',g,[neq(g.get('x8'),'DATA'),neq(g.branches[0]['condition'],'(bvuge BITS OLDBITS)')]);keep('bit_read',g)
 g=make('bit_store',{8:'DATA',9:'((_ zero_extend 56) BITS)'});cert('bit_limit_update_writes_only_record2c',g,[neq(st(g)['address'],add('DATA',0x2c)),neq(st(g)['value'],'BITS')]);keep('bit_store',g)
 g=make('alignment_read',{8:'DATA',2:'SPEC'},loads={hex(G+0x6734):('SPEC','ALIGN',64),hex(G+0x6738):(add('DATA',8),'OLDALIGN',64)})
 cert('alignment_compares_unsigned64_and_skips_when_request_is_not_greater',g,[neq(g.branches[0]['condition'],'(bvule ALIGN OLDALIGN)')]);keep('alignment_read',g)
 g=make('alignment_store',{8:'DATA',9:'ALIGN'});cert('alignment_update_is_full64_and_returns_success',g,[neq(st(g)['address'],add('DATA',8)),neq(st(g)['value'],'ALIGN'),neq(g.get('w19'),bv(0,32))]);keep('alignment_store',g)
 g=make('lazy_args',{0:'OBJ',2:'SPEC'});cert('missing_metadata_calls_helper_with48_bytes_and_mapper_selector1',g,[neq(g.get('x0'),'OBJ'),neq(g.get('x19'),'SPEC'),neq(g.get('x20'),'OBJ'),neq(g.get('x1'),bv(48)),neq(g.get('w2'),bv(1,32))]);keep('lazy_args',g)
 g=make('lazy_result',{0:'RET',20:'OBJ',19:'SPEC'},loads={hex(G+0x68e4):(add('OBJ',0x90),'META',64)})
 cert('helper_false_selects_error_and_nonnull_reloaded_metadata_reenters_constraint_block',g,[neq(g.branches[0]['condition'],'(= ((_ extract 31 0) RET) #x00000000)'),neq(g.branches[1]['condition'],'(distinct META #x0000000000000000)'),neq(g.get('x2'),'SPEC')]);keep('lazy_result',g)
 g=make('success');cert('success_path_returns_zero_status',g,[neq(g.get('w19'),bv(0,32))]);keep('success',g)
 g=make('no_memory',{21:bv(0xe00002e7)});cert('helper_failure_status_is_raw_e00002bd',g,[neq(g.get('w19'),bv(0xe00002bd,32))]);keep('no_memory',g)
 g=make('return_status',{19:bv(0xe00002e7)});cert('method_return_moves_zero_extended32_bit_status_into_X0',g,[neq(g.get('x0'),bv(0xe00002e7))]);keep('return_status',g)
 g=make('helper_initialize',{20:'DATA',19:'MAPPER_PTR'},loads={hex(G+0x713c):(add('DATA',0x2d),'OLDSTATE',8)})
 offsets=[0x28,0x2c,8,16,0,0x20,0x2d];values=[bv(0,32),bv(64,8),bv(0),bv(0),'MAPPER_PTR',bv(0),'(bvand OLDSTATE #xfc)'];assert len(g.stores)==7
 cert('helper_initializes_mapper_zero_alignment64_bit_limit_and_partial_state',g,[neq(row['address'],add('DATA',off))for row,off in zip(g.stores,offsets)]+[neq(row['value'],v)for row,v in zip(g.stores,values)]+[neq(g.get('w0'),bv(1,32))]);keep('helper_initialize',g)
 # Exact record-byte footprint,including ten wholly unwritten bytes.
 init=g;address=add('DATA','BYTEIX');value='OLDBYTE';touched=set()
 for row,off in zip(g.stores,offsets):
  for j in range(row['width_bits']//8):
   touched.add(off+j);value='(ite (= '+address+' '+add(row['address'],j)+') ((_ extract '+str(j*8+7)+' '+str(j*8)+') '+row['value']+') '+value+')'
 untouched=sorted(set(range(48))-touched);assert len(touched)==38 and untouched==list(range(24,32))+[46,47]
 mapperbyte='((_ extract 7 0) (bvlshr MAPPER_PTR (bvmul BYTEIX #x0000000000000008)))';expected='(ite (bvult BYTEIX #x0000000000000008) '+mapperbyte+' (ite (= BYTEIX #x000000000000002c) #x40 (ite (= BYTEIX #x000000000000002d) (bvand OLDSTATE #xfc) (ite (or (and (bvuge BYTEIX #x0000000000000008) (bvult BYTEIX #x0000000000000018)) (and (bvuge BYTEIX #x0000000000000020) (bvult BYTEIX #x000000000000002c))) #x00 OLDBYTE))))'
 solve('all48_metadata_record_bytes_and_ten_unwritten_bytes',g.prefix()+'(assert (bvult BYTEIX #x0000000000000030))\n(assert '+neq(value,expected)+')')
 solve('metadata_state_clears_low2_bits_and_preserves_upper6','(assert (or '+neq('((_ extract 1 0) (bvand OLDSTATE #xfc))','#b00')+' '+neq('((_ extract 7 2) (bvand OLDSTATE #xfc))','((_ extract 7 2) OLDSTATE)')+'))')
 g=make('helper_size_guard',{1:bv(48)});cert('48_byte_helper_request_passes_upper32_bit_size_guard',g,['(not '+g.branches[0]['condition']+')']);keep('helper_size_guard',g)
 g=make('helper_bad_size');cert('helper_oversized_request_returns_false',g,[neq(g.get('w0'),bv(0,32))]);keep('helper_bad_size',g)
 g=make('helper_reuse_guard',{1:bv(48),21:'META'},loads={hex(G+0x6fd4):(add('META',0x20),'CAP',64)});cert('reuse_test_accepts_exactly_capacity_at_least48',g,[neq(g.branches[0]['condition'],'(bvuge CAP #x0000000000000030)')]);keep('helper_reuse_guard',g)
 g=make('helper_reset',{21:'META'});cert('post_retirement_reset_clears_metadata_data_used_capacity',g,[neq(st(g,j)['address'],add('META',off))for j,off in enumerate([0x18,0x20,0x10])]+[neq(row['value'],bv(0))for row in g.stores]);keep('helper_reset',g)
 g=make('helper_heap_args',{1:'REQUEST'});cert('metadata_heap_request_forwards_reserve_bytes_raw_flags31004',g,[neq(g.get('x0'),bv(0xfffffe0007f94f99)),neq(g.get('x1'),'REQUEST'),neq(g.get('w2'),bv(0x31004,32)),neq(g.get('x3'),bv(0))]);keep('helper_heap_args',g)
 g=make('helper_heap_publish',{0:'DATA',21:'META',22:'REQUEST'});cert('successful_metadata_allocation_publishes_data_and_capacity',g,[neq(st(g)['address'],add('META',0x10)),neq(st(g)['value'],'DATA'),neq(st(g,1)['address'],add('META',0x20)),neq(st(g,1)['value'],'REQUEST')],['(distinct DATA #x0000000000000000)']);keep('helper_heap_publish',g)
 g=make('helper_reset_used',{21:'META',20:'OBJ'},loads={hex(G+0x7040):(add('OBJ',0x90),'META',64)});cert('helper_resets_used_count_and_reloads_owner_metadata',g,[neq(st(g)['address'],add('META',0x18)),neq(st(g)['value'],bv(0)),neq(g.get('x21'),'META')]);keep('helper_reset_used',g)
 g=make('helper_creator_arg',{1:'REQUEST'});cert('metadata_creator_receives_reserved_byte_count',g,[neq(g.get('x0'),'REQUEST')]);keep('helper_creator_arg',g)
 g=make('helper_owner_publish',{21:'META',20:'OBJ'});cert('lazy_helper_publishes_only_descriptor90_at_this_site',g,[neq(st(g)['address'],add('OBJ',0x90)),neq(st(g)['value'],'META'),neq(g.branches[0]['condition'],'(= META #x0000000000000000)')]);keep('helper_owner_publish',g)
 g=make('helper_append_existing',{21:'META'},loads={hex(G+0x7080):(add('META',0x10),'DATA',64),hex(G+0x7088):(add('META',0x18),'USED',64)})
 cert('existing_data_record_append_is_used_plus48_with_overflow_guard',g,[neq(g.get('x22'),add('USED',48)),neq(g.branches[1]['condition'],'(not (bvult (bvadd USED #x0000000000000030) USED))')],['(distinct DATA #x0000000000000000)']);keep('helper_append_existing',g)
 g=make('helper_append_empty');cert('empty_record_append_requests48_without_overflow',g,[neq(g.get('x22'),bv(48)),g.branches[0]['condition']]);keep('helper_append_empty',g)
 g=make('helper_append_capacity',{21:'META',1:'DATA',22:bv(48)},loads={hex(G+0x70a4):(add('META',0x20),48,64)});cert('fresh48_byte_capacity_skips_resize_for_first_record',g,['(not '+g.branches[1]['condition']+')'],['(distinct DATA #x0000000000000000)']);keep('helper_append_capacity',g)
 g=make('helper_resize_args',{1:'DATA',2:'CAP',22:'NEW'});cert('resize_boundary_carries_old_data_capacity_new_size_and_raw_flags',g,[neq(g.get('x0'),bv(0xfffffe0007f94f99)),neq(g.get('x1'),'DATA'),neq(g.get('x2'),'CAP'),neq(g.get('x3'),'NEW'),neq(g.get('w4'),bv(0x31004,32)),neq(g.get('x5'),bv(0))]);keep('helper_resize_args',g)
 g=make('helper_resize_publish',{0:'DATA',21:'META',22:'NEW'});cert('admitted_resize_publishes_data_capacity_and_used_size',g,[neq(st(g,j)['address'],add('META',off))for j,off in enumerate([0x10,0x20,0x18])]+[neq(st(g)['value'],'DATA'),neq(st(g,1)['value'],'NEW'),neq(st(g,2)['value'],'NEW')],['(distinct DATA #x0000000000000000)']);keep('helper_resize_publish',g)
 g=make('creator_heap_args',{0:'META',19:'REQUEST'});cert('creator_heap_request_retains_object_and_requested_reserve',g,[neq(g.get('x0'),bv(0xfffffe0007f94f99)),neq(g.get('x20'),'META'),neq(g.get('x1'),'REQUEST'),neq(g.get('w2'),bv(0x31004,32)),neq(g.get('x3'),bv(0))]);keep('creator_heap_args',g)
 g=make('creator_publish',{0:'DATA',20:'META',19:'REQUEST'});cert('successful_creator_returns_metadata_with_data_capacity_and_used0',g,[neq(st(g,j)['address'],add('META',off))for j,off in enumerate([0x10,0x20,0x18])]+[neq(st(g)['value'],'DATA'),neq(st(g,1)['value'],'REQUEST'),neq(st(g,2)['value'],bv(0)),neq(g.get('x0'),'META')],['(distinct DATA #x0000000000000000)']);keep('creator_publish',g)
 def maximum(a,b):return '(ite (bvugt '+a+' '+b+') '+a+' '+b+')'
 def minimum(a,b):return '(ite (bvult '+a+' '+b+') '+a+' '+b+')'
 new_align=maximum('ALIGN','OLDALIGN');new_bits=minimum('BITS','OLDBITS')
 solve('merged_alignment_is_unsigned_maximum_and_never_decreases','(assert (or (bvult '+new_align+' OLDALIGN) (bvult '+new_align+' ALIGN)))')
 solve('merged_address_bits_are_unsigned_minimum_and_never_increase','(assert (or (bvugt '+new_bits+' OLDBITS) (bvugt '+new_bits+' BITS)))')
 solve('merging_same_specification_twice_is_idempotent','(assert (or '+neq(maximum('ALIGN',new_align),new_align)+' '+neq(minimum('BITS',new_bits),new_bits)+'))')
 solve('two_specification_merges_commute_for_stable_record_epochs','(assert (or '+neq(maximum('NEW',new_align),maximum('ALIGN',maximum('NEW','OLDALIGN')))+' '+neq(minimum('BITS2',new_bits),minimum('BITS',minimum('BITS2','OLDBITS')))+'))')
 solve('fresh_metadata0_alignment_and64_bits_specialize_to_request_alignment','(assert (or '+neq(maximum('ALIGN',bv(0)),'ALIGN')+' '+neq(minimum(bv(64,8),bv(64,8)),bv(64,8))+'))')
 solve('64_bit_request_preserves_any_existing_limit_at_most64','(assert (bvule OLDBITS #x40))\n(assert '+neq(minimum(bv(64,8),'OLDBITS'),'OLDBITS')+')')
 # Selected method graph has only private-frame stores and two metadata stores.
 graph=s['selected_operation_graph'];assert graph==selected_graph(s['functions']['dma_operation']);nodes=set(graph['sites']);incoming={n:0 for n in sorted(nodes)};outgoing={n:[]for n in sorted(nodes)}
 for e in graph['edges']:incoming[e['to']]+=1;outgoing[e['from']].append(e['to'])
 todo=[n for n,d in incoming.items()if d==0];order=[]
 while todo:
  n=todo.pop();order.append(n)
  for child in outgoing[n]:
   incoming[child]-=1
   if incoming[child]==0:todo.append(child)
 assert set(order)==nodes and len(graph['ordinary_return_call_frontiers'])==1 and len(graph['return_instructions'])==1
 ordinary=[i for i in graph['store_instructions']if'[sp,'not in i['operands']];assert [(i['ea'],i['operands'])for i in ordinary]==[(hex(G+0x6730),'w9, [x8, #0x2c]'),(hex(G+0x6748),'x9, [x8, #8]')]
 disjoint=['(bvuge (bvsub DATA OBJ) #x00000000000000e8)','(bvuge (bvsub OBJ DATA) #x0000000000000030)'];bad=[]
 for off,width in [(8,8),(0x2c,1)]:
  for protected,pwidth in [(0x50,8),(0x60,8),(0xb8,8),(0xc0,8),(0xe0,1)]:bad.append('(and (bvult BYTEIX '+bv(width)+') (bvult USED '+bv(pwidth)+') (= '+add(add('DATA',off),'BYTEIX')+' '+add(add('OBJ',protected),'USED')+'))')
 solve('disjoint_metadata_updates_exclude_capacity_length_range_backing_and_getter_flag',''.join('(assert '+x+')\n'for x in disjoint)+'(assert (or '+' '.join(bad)+'))')
 # Original override sites are tied to the three fresh source branch certificates.
 overrides={hex(G+0x6628):('original_selector_takes_signed_greater_branch_to_case_dispatch',True),hex(G+0x6684):('original_case3_comparison_takes_operation4000000_target',True),hex(G+0x6710):('exact40_byte_request_passes_original_unsigned_size_guard',False)}
 assert {a:v[1]for a,v in overrides.items()}==graph['selected_branch_overrides']and all(any(p['name']==name and p['result']=='unsat'for p in pp)for name,_ in overrides.values())
 prior=json.loads(read(ROOT/'buffer_construction_flow_checks.json'));row=next(p for p in prior['proofs']if p['name']=='physical_mask0_options13_preserve_requested_alignment');r=subprocess.run([SOLVER,'-in'],input=row['query'],text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({'name':'replayed_constructor_mask0_alignment_and_zero_mask','query':row['query'],'result':'unsat','replayed_query':True,'original_query_sha256':hashlib.sha256(row['query'].encode()).hexdigest()})
 sem={'source_models':{n:g.record_full()for n,g in models.items()},'read_bindings':bindings,'operation_u32':0x4000000,'specification_bytes':40,'metadata_record_bytes':48,'source_specification_alignment_offset':0,'source_specification_address_bits_offset':0x14,'metadata_alignment_offset':8,'metadata_address_bits_offset':0x2c,'metadata_initialization_written_bytes':38,'metadata_initialization_unwritten_byte_offsets':untouched,'selected_graph_topological_sites':order,'fresh_branch_override_proofs':overrides,'fast_path_alignment_formula':'unsigned_max(old64,requested64)','fast_path_address_bits_formula':'unsigned_min(old8,requested8)','fast_path_explicit_field_noninterference_under_disjointness_proved':True,'fresh_metadata_specialization_alignment':'requested64','fresh_metadata_specialization_address_bits':64,'local_method_graph_closed_for_selected_operation_and_size':True,'helper_and_lower_call_effects_fully_proved':False,'actual_allocation_capacity_proved':False,'allocation_zeroing_proved':False,'complete_constructor_path_proved':False,'native_mapping_transfer_or_transaction_proved':False,'Mach_port_emissions':0,'source_only_no_CPU_execution':True}
 sem['source_instruction_instances_translated']=sum(len(g.sites)for g in models.values());sem['distinct_source_instruction_sites_translated']=len({pc for g in models.values()for pc in g.sites});return pp,sem
def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('request_vector_zeroing',lambda t:next(i for i in t['fragments']['request_zero']['instructions']if i['mnemonic']=='stp').__setitem__('operands','q0, q0, [sp, #0x40]')),('wrong_limit_offset',lambda t:t['fragments']['bit_store']['instructions'][0].__setitem__('operands','w9, [x8, #0x2d]')),('wrong_alignment_width',lambda t:t['fragments']['alignment_store']['instructions'][1].__setitem__('operands','w9, [x8, #8]')),('removed_lazy_edge',lambda t:t['selected_operation_graph']['edges'].pop()),('SDK_layout_assertion',lambda t:t['SDK_context'].__setitem__('probe_source',t['SDK_context']['probe_source'].replace('==40','==48'))),('invent_native',lambda t:t.__setitem__('target_executed',True))];rows=[]
 for n,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;rows.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return rows
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);actual={pc for m in sem['source_models'].values()for pc in m['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']};assert actual==expected,(actual-expected,expected-actual)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'source_instruction_instances_translated':sem['source_instruction_instances_translated'],'distinct_source_instruction_sites_translated':sem['distinct_source_instruction_sites_translated'],'metadata_bytes_touched':38,'metadata_bytes_fully_defined_without_old_contents':37,'metadata_unwritten_bytes':10,'predecessor_queries_replayed':1,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'DMA_mapping_constraints_proved':True,'complete_operation_proved':False,**{n:False for n in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
