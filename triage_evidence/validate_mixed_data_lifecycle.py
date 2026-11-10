#!/usr/bin/env python3
"""Static MixedData construction,field-publication and retirement certificates."""
import copy,json,re,shutil,subprocess,hashlib
from recover_mixed_data_lifecycle import ROOT,P,SCOPE,FLAGS,DEPS,build,G,META,TYPE,VT as INSTANCE_VT,MVT as META_VT
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_buffer_construction_flow import ConstructionSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
NAMES={n:64 for n in ['OBJ','METAIN','CLASSNAME','SUPER','CAP','RESERVE','DATA','SIGNED_OBJECT','SIGNED_META','VT','OLDDEBUG','BYTEIX','RESULT64']};NAMES.update(SIZEWORD=32,OLDCOUNT=32,REFERENCE16=16,OLDBYTE=8)
BASE_DECL=set(re.findall(r'\(declare-fun (\w+) ',DECL));DECLARED=BASE_DECL|set(NAMES)
def add(a,b):return '(bvadd '+a+' '+(bv(b)if isinstance(b,int)else b)+')'
def modifier(a,d):return '(bvor (bvand '+a+' #x0000ffffffffffff) '+bv(d<<48)+')'
class MixedSSA(ConstructionSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.atomic_inputs={};self.atomic_events=[];self.signing_events=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   m=i['mnemonic'];p=split(i['operands'])
   if m in ['bti','nop','ret','retab','retaa']:self.sites.append(i['ea'])
   elif m=='ldrh':
    value,bits=self.supplied_loads[i['ea']];assert bits==16;self.reads.append({'site':i['ea'],'address':self.address(p[1]),'width_bits':16,'input':value});self.put(p[0],'((_ zero_extend 16) '+value+')');self.sites.append(i['ea'])
   elif m=='pacda':
    value='SIGNED_META'if self.namespace.startswith('metaclass_install')else'SIGNED_OBJECT';self.signing_events.append({'site':i['ea'],'unsigned_value':self.get(p[0]),'modifier':self.get(p[1]),'symbolic_result':value,'scope':'Symbolic authenticator result;no target instruction,key or PAC validity is evaluated.'});self.put(p[0],value);self.sites.append(i['ea'])
   elif m=='ldadd':
    w=32 if p[0].startswith('w')else 64;address=self.address(p[2]);delta=self.get(p[0],w);old,bits=self.atomic_inputs[i['ea']];assert bits==w;new='(bvadd '+old+' '+delta+')';self.reads.append({'site':i['ea'],'address':address,'width_bits':w,'input':old});self.stores.append({'site':i['ea'],'address':address,'width_bits':w,'value':new});self.put(p[1],old);self.atomic_events.append({'site':i['ea'],'address':address,'width_bits':w,'old':old,'delta':delta,'new':new,'scope':'Original atomic-add operand relation only;no native atomic memory action or concurrency outcome.'});self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return {**super().record_full(),'symbolic_pointer_signing':self.signing_events,'atomic_add_relations':self.atomic_events}
def certificates(s):
 pp=[];models={};bounds={};bindings=[];extra=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in NAMES.items()if n not in BASE_DECL)
 def solve(n,body,more='',result='unsat'):
  q='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL+extra+more+body+'\n(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.returncode,r.stdout[:1800],r.stderr);pp.append({'name':n,'query':q,'result':result,'static_scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,conditions=()):
  solve(n,g.prefix()+''.join('(assert '+c+')\n'for c in conditions)+'(assert (or '+' '.join(bounds[g.namespace]+terms)+'))',''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items()if n not in DECLARED))
 def make(n,regs=None,loads=None):
  g=MixedSSA(n,regs);bb=[];loads=loads or{}
  for i in s['fragments'][n]['instructions']:
   if i['ea']in loads:
    address,v,w=loads[i['ea']];v=bv(v,w)if isinstance(v,int)else v
    if i['mnemonic']=='ldadd':g.atomic_inputs[i['ea']]=(v,w)
    else:g.supplied_loads[i['ea']]=(v,w)
    if re.fullmatch(r'[A-Za-z_]\w*',v)and v not in DECLARED:g.decl[v]=w
   g.run({'instructions':[i]},int(i['ea'],16)+4)
   if i['ea']in loads:
    address,v,w=loads[i['ea']];address=bv(address)if isinstance(address,int)else address;bb.append(neq(g.reads[-1]['address'],address));bindings.append({'phase':n,'site':i['ea'],'source_address':g.reads[-1]['address'],'expected_address':address,'width_bits':w})
  models[n]=g;bounds[g.namespace]=bb;return g
 def st(g,j=0):return g.stores[j]
 g=make('metaclass_args');cert('MixedData_registration_literal_superclass_and40_byte_instance_size',g,[neq(g.get('x0'),bv(META)),neq(g.get('x1'),bv(0xfffffe00070de463)),neq(g.get('x2'),bv(0xfffffe000cb5bfc0)),neq(g.get('w3'),bv(40,32))])
 g=make('base_meta_save',{0:'METAIN',1:'CLASSNAME'});cert('base_metaclass_constructor_saves_receiver_and_name',g,[neq(g.get('x19'),'METAIN'),neq(g.get('x20'),'CLASSNAME')])
 g=make('base_meta_fields',{0:'METAIN',19:'METAIN',2:'SUPER',3:bv(40)});cert('base_metaclass_publishes_size40_count0_and_superclass_pointer',g,[neq(st(g,j)['address'],add('METAIN',off))for j,off in enumerate([0x20,0x24,0x10])]+[neq(st(g)['value'],bv(40,32)),neq(st(g,1)['value'],bv(0,32)),neq(st(g,2)['value'],'SUPER')])
 g=make('base_meta_name',{0:'RESULT64',19:'METAIN',20:'CLASSNAME'});cert('base_metaclass_publishes_name_after_auxiliary_allocation',g,[neq(st(g)['address'],add('METAIN',8)),neq(st(g)['value'],'RESULT64'),neq(st(g,1)['address'],add('METAIN',0x18)),neq(st(g,1)['value'],'CLASSNAME')])
 g=make('base_meta_return',{19:'METAIN'});cert('ordinary_base_metaclass_return_preserves_receiver_identity',g,[neq(g.get('x0'),'METAIN')])
 g=make('metaclass_install',{0:bv(META)});cert('initializer_signs_nominal_MixedData_metaclass_vptr_and_stores_at_global',g,[neq(g.signing_events[0]['unsigned_value'],bv(META_VT)),neq(g.signing_events[0]['modifier'],modifier(bv(META),0xcda1)),neq(st(g)['address'],bv(META)),neq(st(g)['value'],'SIGNED_META')])
 criterion='(bvuge (bvand SIZEWORD #x00fffff8) #x00000028)'
 for n in ['alloc_selector','delete_selector']:
  pc=G+(0x9918 if n=='alloc_selector'else 0x98b0);g=make(n,loads={hex(pc):(TYPE+0x2c,'SIZEWORD',32)});cert(n+'_same_unsigned_masked_size_criterion',g,[neq(g.branches[0]['condition'],criterion)]);cert(n+'_source_size40_selects_typed_branch',g,['(not '+g.branches[0]['condition']+')'],['(= SIZEWORD #x00000028)'])
 g=make('alloc_fallback');cert('object_fallback_requests40_bytes_flags41004',g,[neq(g.get('x0'),bv(0xfffffe0007f36938)),neq(g.get('w1'),bv(40,32)),neq(g.get('w2'),bv(0x41004,32)),neq(g.get('x3'),bv(0))])
 g=make('alloc_typed');cert('object_typed_request_uses_matching_descriptor_and_flags4',g,[neq(g.get('x0'),bv(TYPE)),neq(g.get('w1'),bv(4,32))])
 g=make('alloc_debug',loads={hex(G+0x9964):(0xfffffe000cb5b638,'OLDDEBUG',64)});cert('allocation_debug_accounting_adds40_mod64',g,[neq(st(g)['address'],bv(0xfffffe000cb5b638)),neq(st(g)['value'],add('OLDDEBUG',40))])
 g=make('alloc_fields',{0:'OBJ'});assert len(g.stores)==5
 cert('owner_constructor_vptr_reference_word_and_three_zero_fields',g,[neq(g.signing_events[0]['unsigned_value'],bv(INSTANCE_VT)),neq(g.signing_events[0]['modifier'],modifier('OBJ',0xcda1))]+[neq(row['address'],add('OBJ',off))for row,off in zip(g.stores,[8,0,0x18,0x20,0x10])]+[neq(st(g)['value'],bv(1,32)),neq(st(g,1)['value'],'SIGNED_OBJECT')]+[neq(st(g,j)['value'],bv(0))for j in [2,3,4]])
 initialized=g;address=add('OBJ','BYTEIX');value='OLDBYTE'
 for row in g.stores:
  for j in range(row['width_bits']//8):value='(ite (= '+address+' '+add(row['address'],j)+') ((_ extract '+str(j*8+7)+' '+str(j*8)+') '+row['value']+') '+value+')'
 expected='(ite (bvult BYTEIX #x0000000000000008) ((_ extract 7 0) (bvlshr SIGNED_OBJECT (bvmul BYTEIX #x0000000000000008))) (ite (= BYTEIX #x0000000000000008) #x01 (ite (and (bvuge BYTEIX #x000000000000000c) (bvult BYTEIX #x0000000000000010)) OLDBYTE #x00)))';solve('all40_owner_bytes_explicit_fields_and_four_unwritten_padding_bytes',g.prefix()+'(assert (bvult BYTEIX #x0000000000000028))\n(assert '+neq(value,expected)+')')
 g=make('get_meta');cert('instance_getMetaClass_returns_source_metaclass_global',g,[neq(g.get('x0'),bv(META))])
 allocslot=next(p for p in s['nominal_slots']if p['role']=='metaclass_alloc')
 g=make('creator_dispatch',loads={hex(G+0x73c0):(int(allocslot['slot'],16),int(allocslot['target'],16),64)});cert('creator_metaclass_dispatch_resolves_exact_source_allocator',g,[neq(g.get('x0'),bv(META)),neq(g.get('x8'),bv(G+0x9908))],['(= VT '+bv(META_VT)+')'])
 g=make('creator_fresh_read',{0:'OBJ'},loads={hex(G+0x73d0):(add('OBJ',0x10),0,64)});cert('constructed_owner_zero_data_selects_new_storage_branch',g,[g.branches[0]['condition'],'(not '+g.branches[1]['condition']+')'],['(distinct OBJ #x0000000000000000)'])
 # Original byte-store/load join at the same full64 owner field.
 parts=[]
 for off in reversed(range(8)):
  a=add('OBJ',0x10+off);v='OLDBYTE'
  for row in initialized.stores:
   for j in range(row['width_bits']//8):v='(ite (= '+a+' '+add(row['address'],j)+') ((_ extract '+str(j*8+7)+' '+str(j*8)+') '+row['value']+') '+v+')'
  parts.append(v)
 word=parts[0]
 for p in parts[1:]:word='(concat '+word+' '+p+')'
 solve('constructed_owner_data_store_joins_creator_zero64_load',initialized.prefix()+'(assert '+neq(word,bv(0))+')')
 g=make('creator_fresh_gate',{19:bv(48)});cert('reserve48_passes_creator_fresh_reserve_guards',g,[b['condition']for b in g.branches])
 g=make('creator_heap_args',{0:'OBJ',19:bv(48)});cert('fresh_owner_separately_requests48_record_bytes_flags31004',g,[neq(g.get('x20'),'OBJ'),neq(g.get('x0'),bv(0xfffffe0007f94f99)),neq(g.get('x1'),bv(48)),neq(g.get('w2'),bv(0x31004,32)),neq(g.get('x3'),bv(0))])
 g=make('creator_publish',{0:'DATA',20:'OBJ',19:bv(48)});cert('admitted_record_allocation_publishes_pointer_capacity48_and_used0',g,[neq(st(g,j)['address'],add('OBJ',off))for j,off in enumerate([0x10,0x20,0x18])]+[neq(st(g)['value'],'DATA'),neq(st(g,1)['value'],bv(48)),neq(st(g,2)['value'],bv(0)),neq(g.get('x0'),'OBJ')],['(distinct DATA #x0000000000000000)'])
 g=make('retain_count_read',{0:'OBJ'},loads={'0xfffffe000c445234':(add('OBJ',8),'REFERENCE16',16)});cert('inherited_getRetainCount_consumes_only_low16_of_initialized32_bit_word',g,[neq(g.get('x0'),'((_ zero_extend 48) REFERENCE16)')]);cert('constructed_reference_word1_specializes_getter_to1',g,[neq(g.get('x0'),bv(1))],['(= REFERENCE16 #x0001)'])
 g=make('free_args',{0:'OBJ'},loads={hex(G+0x9804):(add('OBJ',0x10),'DATA',64),hex(G+0x9808):(add('OBJ',0x20),'CAP',64)});cert('free_requests_data_retirement_with_current_capacity_and_data_heap_selector',g,[neq(g.get('x0'),bv(0xfffffe0007f94f99)),neq(g.get('x1'),'DATA'),neq(g.get('x2'),'CAP'),neq(g.get('x19'),'OBJ')])
 g=make('free_clear',{19:'OBJ'});cert('after_data_retirement_free_clears_all_three_payload_fields',g,[neq(st(g,j)['address'],add('OBJ',off))for j,off in enumerate([0x18,0x20,0x10])]+[neq(row['value'],bv(0))for row in g.stores])
 getslot=next(p for p in s['nominal_slots']if p['role']=='instance_get_meta');delslot=next(p for p in s['nominal_slots']if p['role']=='instance_delete')
 g=make('free_get_meta',{19:'OBJ'},loads={hex(G+0x983c):(int(getslot['slot'],16),int(getslot['target'],16),64)});cert('free_requests_nominal_getMetaClass_after_field_reset',g,[neq(g.get('x0'),'OBJ'),neq(g.get('x8'),bv(G+0x9884))],['(= VT '+bv(INSTANCE_VT)+')'])
 g=make('free_instance_gate',{0:bv(META)});cert('nominal_getMetaClass_result_selects_instanceDestructed_call',g,[g.branches[0]['condition']])
 g=make('free_delete_dispatch',{19:'OBJ',20:modifier('OBJ',0xcda1)},loads={hex(G+0x985c):(int(delslot['slot'],16),int(delslot['target'],16),64)});cert('free_tail_deletion_dispatch_targets_the_private_deleting_destructor',g,[neq(g.get('x0'),'OBJ'),neq(g.get('x16'),bv(G+0x9894)),neq(g.get('x1'),bv(INSTANCE_VT+8))],['(= VT '+bv(INSTANCE_VT)+')'])
 g=make('free_delete_modifier',{1:bv(INSTANCE_VT+8)});cert('tail_deletion_modifier_carries_original_slot_and_diversity56b7',g,[neq(g.get('x17'),modifier(bv(INSTANCE_VT+8),0x56b7))])
 g=make('delete_poison',{0:'OBJ'});cert('deleting_destructor_invalidates_first_word_and_preserves_object_operand',g,[neq(st(g)['address'],'OBJ'),neq(st(g)['value'],bv(-1)),neq(g.get('x1'),'OBJ')])
 g=make('delete_fallback',{1:'OBJ'});cert('fallback_object_retirement_requests40_bytes_in_object_heap',g,[neq(g.get('x0'),bv(0xfffffe0007f36938)),neq(g.get('x1'),'OBJ'),neq(g.get('w2'),bv(40,32))])
 g=make('delete_typed',{1:'OBJ'});cert('typed_object_retirement_uses_the_allocation_descriptor',g,[neq(g.get('x0'),bv(TYPE)),neq(g.get('x1'),'OBJ')])
 g=make('delete_debug',loads={hex(G+0x98ec):(0xfffffe000cb5b638,'OLDDEBUG',64)});cert('deletion_debug_accounting_adds_negative40_mod64',g,[neq(st(g)['address'],bv(0xfffffe000cb5b638)),neq(st(g)['value'],'(bvsub OLDDEBUG #x0000000000000028)')])
 g=make('invalidate',{0:'OBJ'});cert('plain_destructor_invalidates_first_word_without_payload_retirement',g,[neq(st(g)['address'],'OBJ'),neq(st(g)['value'],bv(-1))]);assert len(g.stores)==1
 g=make('class_count_add',{8:bv(1)},loads={hex(G+0x99a0):(META+0x24,'OLDCOUNT',32)});cert('metaclass_instance_count_add1_uses_old_value_for_parent_gate',g,[neq(st(g)['address'],bv(META+0x24)),neq(st(g)['value'],'(bvadd OLDCOUNT #x00000001)'),neq(g.get('w10'),'OLDCOUNT'),neq(g.branches[0]['condition'],'(distinct OLDCOUNT #x00000000)')])
 g=make('class_count_parent',{9:bv(META)},loads={hex(G+0x99a8):(META+0x10,0xfffffe000cb5bfc0,64)});cert('zero_previous_instance_count_reaches_registered_OSObject_parent',g,['(not '+g.branches[0]['condition']+')',neq(g.get('x9'),bv(0xfffffe000cb5bfc0))])
 g=make('class_count_sub',{0:bv(META)},loads={'0xfffffe000c443530':(META+0x24,'OLDCOUNT',32)});cert('instanceDestructed_adds_negative1_and_tests_old_count1',g,[neq(st(g)['address'],bv(META+0x24)),neq(st(g)['value'],'(bvsub OLDCOUNT #x00000001)'),neq(g.branches[0]['condition'],'(distinct OLDCOUNT #x00000001)')])
 g=make('destroy_parent',{19:bv(META)},loads={'0xfffffe000c44353c':(META+0x10,0xfffffe000cb5bfc0,64)});cert('last_instance_parent_request_uses_registered_OSObject_metaclass',g,[g.branches[0]['condition'],neq(g.get('x0'),bv(0xfffffe000cb5bfc0))])
 solve('declared_paired_size_accounting_operands_cancel_mod64','(assert '+neq('(bvsub (bvadd OLDDEBUG #x0000000000000028) #x0000000000000028)','OLDDEBUG')+')')
 solve('declared_paired_instance_count_operands_cancel_mod32','(assert '+neq('(bvsub (bvadd OLDCOUNT #x00000001) #x00000001)','OLDCOUNT')+')')
 # Complete source census for the normal-return receiver preservation cuts.
 assert next(i for i in s['functions']['base_meta_ctor']['instructions']if i['ea']=='0xfffffe000c441edc')['operands']=='x20, x1'
 assert s['functions']['allocator']['instructions'][-1]['mnemonic']=='retab'
 assert all(not(i['operands'].startswith(('x0,','w0,'))and i['mnemonic']not in ['str','stur','stp','cmp','cbz','cbnz'])for i in s['functions']['allocator']['instructions']if G+0x9958<=int(i['ea'],16)<G+0x99b8)
 assert [p['slot']for p in s['initializer_array']['selected']]==['0xfffffe0007f95d10']and s['initializer_array']['selected_index']==56
 assert s['typed_descriptor']['size_u32']==40 and s['strings']['allocation_site_name']['text']=='site.'+s['strings']['registered_class_name']['text']
 prior=json.loads(read(ROOT/'dma_map_constraints_checks.json'));replay=['fresh48_byte_capacity_skips_resize_for_first_record','fresh_metadata0_alignment_and64_bits_specialize_to_request_alignment']
 for n in replay:
  row=next(p for p in prior['proofs']if p['name']==n);r=subprocess.run([SOLVER,'-in'],input=row['query'],text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({'name':'replayed_'+n,'query':row['query'],'result':'unsat','replayed_query':True,'original_query_sha256':hashlib.sha256(row['query'].encode()).hexdigest()})
 sem={'source_models':{n:g.record_full()for n,g in models.items()},'read_bindings':bindings,'registered_class_name':'_IOMemoryDescriptorMixedData','registered_superclass_metaclass':'0xfffffe000cb5bfc0','owner_size_bytes':40,'data_record_request_bytes':48,'owner_explicit_payload_zero_bytes':24,'owner_unwritten_padding_offsets':[12,13,14,15],'reference_word_initial_width_bits':32,'retain_count_getter_width_bits':16,'nominal_instance_vptr':hex(INSTANCE_VT),'nominal_metaclass_vptr':hex(META_VT),'source_construction_chain_identified':True,'owner_three_zero_fields_independent_of_allocator_zeroing':True,'fresh_owner_selects_fresh_record_allocation_under_stable_fields':True,'source_retirement_operand_pairing_proved':True,'native_allocation_or_reference_balance_proved':False,'backing_record_48_zeroing_proved':False,'complete_constructor_or_transaction_proved':False,'Mach_port_emissions':0,'source_only_no_CPU_execution':True}
 sem['source_instruction_instances_translated']=sum(len(g.sites)for g in models.values());sem['distinct_source_instruction_sites_translated']=len({pc for g in models.values()for pc in g.sites});return pp,sem
def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('registered_class_name',lambda t:t['strings']['registered_class_name'].__setitem__('text','OSData')),('instance_size',lambda t:t['typed_descriptor'].__setitem__('size_u32',48)),('missing_zero_store',lambda t:t['fragments']['alloc_fields']['instructions'].pop()),('wrong_free_capacity',lambda t:t['fragments']['free_args']['instructions'][2].__setitem__('operands','x2, [x0, #0x18]')),('wrong_retain_width',lambda t:t['fragments']['retain_count_read']['instructions'][0].__setitem__('mnemonic','ldr')),('invent_native',lambda t:t.__setitem__('target_executed',True))];rows=[]
 for n,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;rows.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return rows
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);actual={pc for m in sem['source_models'].values()for pc in m['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']};assert actual==expected,(actual-expected,expected-actual)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'source_instruction_instances_translated':sem['source_instruction_instances_translated'],'distinct_source_instruction_sites_translated':sem['distinct_source_instruction_sites_translated'],'symbolic_PACDA_sites':sum(len(m['symbolic_pointer_signing'])for m in sem['source_models'].values()),'atomic_add_relations':sum(len(m['atomic_add_relations'])for m in sem['source_models'].values()),'owner_explicit_payload_zero_bytes':24,'owner_unwritten_padding_bytes':4,'predecessor_queries_replayed':2,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'MixedData_construction_and_retirement_interfaces_proved':True,'complete_operation_proved':False,**{n:False for n in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
