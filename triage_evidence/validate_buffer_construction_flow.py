#!/usr/bin/env python3
"""Static component equations for original buffer construction and preparation."""
import copy,json,re,shutil,subprocess,hashlib
from recover_buffer_construction_flow import ROOT,P,SCOPE,FLAGS,DEPS,build,C,G,F
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_core_stack_delta_abi import DeltaSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
NAMES={n:64 for n in ['OBJ','TASK','ALIGN','PAGE','RANGE','BYTES','CAP','LENGTH','HEAP','MAPPER_PTR','PARAM','VT','RESULT','NEWLEN']};NAMES.update(SHIFT=32,IFLAGS=32,TYPE=32,MAPPER=32)
BASE_DECL=set(re.findall(r'\(declare-fun (\w+) ',DECL));DECLARED=BASE_DECL|set(NAMES)
def add(a,b):return '(bvadd '+a+' '+(bv(b)if isinstance(b,int)else b)+')'
class ConstructionSSA(DeltaSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.branches=[]
 def compare(self,a,b,w,cmn=False):
  super().compare(a,b,w,cmn);self.flags.update(ls='(not '+self.flags['hi']+')',hs='(not '+self.flags['lo']+')',cs='(not '+self.flags['lo']+')',cc=self.flags['lo'])
  if not cmn:self.flags.update(gt='(bvsgt '+a+' '+b+')',le='(bvsle '+a+' '+b+')')
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   m=i['mnemonic'];p=split(i['operands'])
   if m=='b'or m.startswith('b.')or m in ['cbz','cbnz','tbz','tbnz']:
    if m=='b':test='true';target=int(p[0][1:],0)
    elif m.startswith('b.'):test=self.flags[m[2:]];target=int(p[0][1:],0)
    elif m in ['cbz','cbnz']:
     w=32 if p[0].startswith('w')else 64;test='(= '+self.get(p[0],w)+' '+bv(0,w)+')';test='(not '+test+')'if m=='cbnz'else test;target=int(p[1][1:],0)
    else:
     w=32 if p[0].startswith('w')else 64;test='(= (bvand '+self.get(p[0],w)+' '+bv(1<<int(p[1][1:],0),w)+') '+bv(0,w)+')';test='(not '+test+')'if m=='tbnz'else test;target=int(p[2][1:],0)
    self.branches.append({'site':i['ea'],'mnemonic':m,'condition':test,'target':hex(target),'fallthrough':hex(pc+4),'scope':'Static predicate only;no branch or target executes. Subsequent fragment instructions require their declared selected-path premise.'});self.sites.append(i['ea'])
   elif m in ['adds','subs']:
    w=32 if p[0].startswith('w')else 64;a=self.get(p[1],w);b=self.operand(p[2],w,p[3]if len(p)>3 else None);v='('+('bvadd'if m=='adds'else'bvsub')+' '+a+' '+b+')';carry='(bvult '+v+' '+a+')'if m=='adds'else'(not (bvult '+a+' '+b+'))';zero='(= '+v+' '+bv(0,w)+')';self.put(p[0],v);self.flags={'eq':zero,'ne':'(not '+zero+')','hs':carry,'cs':carry,'lo':'(not '+carry+')','cc':'(not '+carry+')','hi':'(and '+carry+' (not '+zero+'))','ls':'(or (not '+carry+') '+zero+')'};self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return {**super().record_full(),'static_branch_predicates':self.branches}
def certificates(s):
 pp=[];models={};bounds={};read_bindings=[];extra=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in NAMES.items()if n not in BASE_DECL)
 def solve(n,body,more='',result='unsat'):
  q='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL+extra+more+body+'\n(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.returncode,r.stdout[:2000],r.stderr);pp.append({'name':n,'query':q,'result':result,'static_scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,conditions=(),result='unsat'):
  solve(n,g.prefix()+''.join('(assert '+c+')\n'for c in conditions)+'(assert (or '+' '.join(bounds.get(g.namespace,[])+terms)+'))',''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items()if n not in DECLARED),result)
 def make(n,regs=None,presets=None,loads=None):
  g=ConstructionSSA(n,regs,presets);bb=[];loads=loads or{}
  for i in s['fragments'][n]['instructions']:
   if i['ea']in loads:
    a,v,w=loads[i['ea']];v=bv(v,w)if isinstance(v,int)else v;g.supplied_loads[i['ea']]=(v,w)
    if re.fullmatch(r'[A-Za-z_]\w*',v)and v not in DECLARED:g.decl[v]=w
   g.run({'instructions':[i]},int(i['ea'],16)+4)
   if i['ea']in loads:
    a,v,w=loads[i['ea']];a=bv(a)if isinstance(a,int)else a;bb.append(neq(g.reads[-1]['address'],a));read_bindings.append({'phase':n,'site':i['ea'],'source_address':g.reads[-1]['address'],'expected_address':a,'width_bits':w})
  models[n]=g;bounds[g.namespace]=bb;return g
 def st(g,j=0):return g.stores[j]
 def call_slot(n,off,loads=None,regs=None,presets=None):
  target=next(p for p in s['nominal_slots']if p['offset_bytes']==off);loads=loads or{};f=s['fragments'][n];pc=next(i['ea']for i in f['instructions']if i['mnemonic']=='ldr'and i['operands'].startswith('x8, [x16]'));loads[pc]=(int(target['slot'],16),int(target['target'],16),64);g=make(n,regs,presets,loads);return g,target
 # Original caller and factory retain full-width task,size and alignment.
 g=make('caller_factory',loads={hex(F+0x80a8):(0xfffffe000847c608,0xfffffe0007f8b0a0,64),hex(F+0x80ac):(0xfffffe0007f8b0a0,'TASK',64),hex(F+0x80b4):(0xfffffe000847c5b0,0xfffffe0007e6d9c0,64),hex(F+0x80b8):(0xfffffe0007e6d9c0,'SHIFT',32)})
 alignment='((_ sign_extend 32) (bvshl #x00000001 (bvand SHIFT #x0000001f)))'
 cert('caller_requests_kernel_task_options13_capacity14000_and_runtime_alignment',g,[neq(g.get('x0'),'TASK'),neq(g.get('w1'),bv(0x13,32)),neq(g.get('x2'),bv(81920)),neq(g.get('x3'),alignment)])
 g=make('factory_args',{0:'OBJ',22:'TASK',21:bv(0x13),20:bv(81920),19:'ALIGN'});cert('factory_forwards_constructor_size_and_alignment_with_physical_mask0',g,[neq(g.get('x0'),'OBJ'),neq(g.get('x1'),'TASK'),neq(g.get('x2'),bv(0x13)),neq(g.get('x3'),bv(81920)),neq(g.get('x4'),'ALIGN'),neq(g.get('x5'),bv(0))])
 g=make('buffer_entry',{0:'OBJ',1:'TASK',2:bv(0x13),3:bv(81920)});cert('constructor_publishes_requested_capacity_and_raw_options',g,[neq(st(g)['address'],add('OBJ',0xd0)),neq(st(g)['value'],bv(0x13,32)),neq(st(g,1)['address'],add('OBJ',0xc0)),neq(st(g,1)['value'],bv(81920)),neq(g.get('x21'),bv(81920)),neq(g.get('x19'),'OBJ')])
 g=make('old_range_gate',{20:'TASK',2:bv(0x13)});cert('preexisting_range_rejects_options13_at_entry_gate',g,[neq(g.get('w0'),bv(0,32)),neq(g.branches[-1]['condition'],'true')])
 g=make('new_range',{0:'RANGE',19:'OBJ'},loads={hex(C+0x4c7c):(add('OBJ',0x60),'RANGE',64)});cert('new_typed_range_pair_is_published_and_zeroed',g,[neq(st(g)['address'],add('OBJ',0x60)),neq(st(g)['value'],'RANGE'),neq(st(g,1)['address'],'RANGE'),neq(st(g,1)['value'],bv(0)),neq(st(g,2)['address'],add('RANGE',8)),neq(st(g,2)['value'],bv(0))])
 g=make('mapper_bool',{8:'MAPPER_PTR'});cert('mapper_presence_is_canonical32_bit_boolean',g,[neq(g.get('w10'),'(ite (= MAPPER_PTR #x0000000000000000) #x00000000 #x00000001)')])
 g=make('alignment',{28:bv(0xfffffe000cb5b000),5:bv(0),4:'ALIGN',2:bv(0x13)},loads={hex(C+0x4cf0):(0xfffffe000cb5b840,'PAGE',64)});cert('physical_mask0_options13_preserve_requested_alignment',g,[neq(g.get('x3'),'ALIGN'),neq(g.get('x8'),bv(0)),neq(g.get('x9'),'PAGE'),neq(g.flags['lo'],'(bvult ALIGN PAGE)')])
 g=make('round_size',{21:bv(81920)});cert('fixed_capacity_is_unchanged_by_literal16KiB_rounding',g,[neq(g.get('x21'),bv(81920)),g.branches[0]['condition']])
 g=make('buffer_flags',{2:bv(0x13),3:'ALIGN',9:'PAGE',19:'OBJ',21:bv(81920)},loads={hex(C+0x4d64):(add('OBJ',0xc0),81920,64)});cert('effective_options_and_recorded_alignment_remain13_and_requested_value',g,[neq(g.get('w26'),bv(0x13,32)),neq(st(g)['address'],add('OBJ',0xc8)),neq(st(g)['value'],'ALIGN'),neq(g.branches[-1]['condition'],'(bvult (bvadd #x0000000000014000 ALIGN) #x0000000000014000)')])
 g=make('task_gate',{20:'TASK'},loads={hex(C+0x4d80):(0xfffffe0007f8b0a0,'TASK',64)});cert('kernel_task_request_passes_identity_gate',g,[g.branches[0]['condition']])
 g=make('allocation_flags',{2:bv(0x13)});cert('range_options_keep_only_direction_bits3',g,[neq(g.get('w23'),bv(3,32))])
 g=make('allocation_choice',{26:bv(0x13),23:bv(3),10:z('MAPPER'),3:'ALIGN',9:'PAGE',8:bv(0),19:'OBJ'},loads={hex(C+0x4e24):(add('OBJ',0xe0),'IFLAGS',32)})
 cert('allocation_choice_is_alignment_or_absent_mapper_under_clear_guard_flag',g,[neq(g.get('w25'),bv(0,32)),neq(g.get('w4'),'(bvxor MAPPER #x00000001)'),g.branches[0]['condition'],neq(g.branches[1]['condition'],'(bvugt ALIGN PAGE)'),g.branches[2]['condition'],neq(g.branches[3]['condition'],'(distinct MAPPER #x00000001)')],['(bvule MAPPER #x00000001)'])
 g=make('ordinary_args',{20:'TASK',22:'HEAP',21:bv(81920),3:'ALIGN'});cert('ordinary_allocation_prefix_uses81920_and_raw1004_flags',g,[neq(g.get('x0'),'HEAP'),neq(g.get('x1'),bv(81920)),neq(g.get('x8'),bv(0x1004))],['(distinct TASK #x0000000000000000)'])
 g=make('aligned_args',{0:'HEAP',1:bv(81920),3:'ALIGN',8:bv(0x1004)});cert('aligned_backend_arguments',g,[neq(g.get('x0'),'HEAP'),neq(g.get('x1'),bv(81920)),neq(g.get('x2'),'ALIGN'),neq(g.get('x3'),bv(0x1004))])
 g=make('byte_args',{0:'HEAP',1:bv(81920),8:bv(0x1004)});cert('byte_backend_arguments',g,[neq(g.get('x2'),bv(0x1004))])
 g=make('contiguous_args',{20:'TASK',22:'HEAP',21:bv(81920),3:'ALIGN'});cert('contiguous_backend_arguments_have_zero_physical_mask_and_no_task_mapping',g,[neq(g.get('x0'),'HEAP'),neq(g.get('x1'),bv(81920)),neq(g.get('x2'),bv(0)),neq(g.get('x3'),'ALIGN'),neq(g.get('x5'),bv(0))],['(distinct TASK #x0000000000000000)'])
 g=make('buffer_publish',{0:'BYTES',19:'OBJ',23:bv(3)});cert('nonnull_backend_result_is_published_before_base_options11b',g,[neq(st(g)['address'],add('OBJ',0xb8)),neq(st(g)['value'],'BYTES'),neq(g.branches[0]['condition'],'(= BYTES #x0000000000000000)'),neq(g.get('w22'),bv(0x11b,32))],['(distinct BYTES #x0000000000000000)'])
 g=make('mapping_gate',{26:bv(0x13)});cert('options13_select_skip_extra_mapping_branch',g,['(not '+g.branches[0]['condition']+')'])
 g=make('skip_mapping');cert('mapping_task_local_is_reset_to_zero',g,[neq(g.get('x21'),bv(0))])
 g=make('range_publish',{19:'OBJ',20:'TASK',22:bv(0x11b)},loads={hex(C+0x5064):(add('OBJ',0xb8),'BYTES',64),hex(C+0x5068):(add('OBJ',0x60),'RANGE',64),hex(C+0x5070):(add('OBJ',0xc0),81920,64),hex(C+0x5074):(add('OBJ',0x60),'RANGE',64),hex(C+0x507c):(add('OBJ',0x60),'RANGE',64),hex(C+0x5084):(0xfffffe0007f8b0a0,'TASK',64)})
 cert('single_range_publishes_byte_address_capacity_and_base_initializer_ABI',g,[neq(st(g)['address'],'RANGE'),neq(st(g)['value'],'BYTES'),neq(st(g,1)['address'],add('RANGE',8)),neq(st(g,1)['value'],bv(81920)),neq(g.get('x0'),'OBJ'),neq(g.get('x1'),'RANGE'),neq(g.get('w2'),bv(1,32)),neq(g.get('w3'),bv(0,32)),neq(g.get('x4'),'TASK'),neq(g.get('w5'),bv(0x11b,32)),neq(g.get('x6'),bv(0))])
 g,target=call_slot('dma_call',0x150,{hex(C+0x50ac):(add('OBJ',0xe0),'IFLAGS',32)},{19:'OBJ'});cert('post_base_DMA_operation_uses4000000_and40_byte_request',g,[neq(st(g)['address'],add('OBJ',0xe0)),neq(st(g)['value'],'(bvor IFLAGS #x00000008)'),neq(g.get('x0'),'OBJ'),neq(g.get('w1'),bv(0x4000000,32)),neq(g.get('x2'),add('K',0x28)),neq(g.get('w3'),bv(40,32)),neq(g.get('x8'),bv(int(target['target'],16)))],['(= VT '+bv(0xfffffe0007f85d80)+')'])
 g,target=call_slot('final_length',0x2f0,{hex(C+0x5234):(add('OBJ',0xc0),81920,64)},{19:'OBJ',20:'(bvor (bvand OBJ #x0000ffffffffffff) #xcda1000000000000)'});cert('final_constructor_call_requests_nominal_setLength_of_capacity',g,[neq(g.get('x0'),'OBJ'),neq(g.get('x1'),bv(81920)),neq(g.get('x8'),bv(int(target['target'],16)))],['(= VT '+bv(0xfffffe0007f85d80)+')'])
 g=make('base_flags',{5:bv(0x11b)});cert('base_initializer_preserves11b_type10_and_prepare_bit',g,[neq(g.get('w27'),bv(0x11b,32))])
 g=make('base_publish',{27:bv(0x11b),19:'OBJ',4:'TASK'});cert('base_initializer_records_type10_and_task',g,[neq(st(g)['address'],add('OBJ',0x20)),neq(st(g)['value'],bv(0x11b,32)),neq(st(g,1)['address'],add('OBJ',0x70)),neq(st(g,1)['value'],'TASK')])
 g=make('borrow_ranges',{22:'RANGE',19:'OBJ'}, {0x28:(bv(1),64)});cert('base_bit8_branch_borrows_original_single_range',g,[neq(st(g)['address'],add('OBJ',0x60)),neq(st(g)['value'],'RANGE'),neq(g.get('x21'),bv(1))])
 g=make('base_iteration_length',{20:bv(0),25:bv(81920),26:bv(0x10)});cert('single_range_accumulates81920_without_overflow',g,[neq(g.get('x20'),bv(81920)),g.branches[0]['condition']])
 g=make('base_length',{20:bv(81920),28:'RESULT',19:'OBJ'});cert('base_single_range_length_is_published',g,[neq(st(g)['address'],add('OBJ',0x50)),neq(st(g)['value'],bv(81920))])
 g=make('base_prepare_gate',{19:'OBJ'},loads={hex(G+0x7e90):(add('OBJ',0x20),0x11b,32)});cert('base_type11b_skips_bit16_helper',g,['(not '+g.branches[0]['condition']+')'])
 g=make('base_prepare_bit3',{8:bv(0x11b)});cert('base_type11b_selects_prepare_request',g,[g.branches[0]['condition']])
 g,target=call_slot('base_prepare_call',0x218,regs={19:'OBJ'});cert('base_constructor_requests_nominal_prepare0',g,[neq(g.get('x0'),'OBJ'),neq(g.get('w1'),bv(0,32)),neq(g.get('x8'),bv(int(target['target'],16)))],['(= VT '+bv(0xfffffe0007f85d80)+')'])
 g=make('base_success');cert('base_success_returns_canonical_true',g,[neq(g.get('w0'),bv(1,32))])
 g=make('length_gate',{0:'OBJ',1:'NEWLEN'},loads={hex(C+0x4bc0):(add('OBJ',0xc0),'CAP',64)});cert('setLength_has_unsigned_capacity_guard',g,[neq(g.branches[0]['condition'],'(bvugt NEWLEN CAP)')])
 g=make('length_publish',{0:'OBJ',1:'NEWLEN'},loads={hex(C+0x4bd0):(add('OBJ',0x60),'RANGE',64)});cert('admitted_setLength_updates_length_and_range_without_changing_capacity',g,[neq(st(g)['address'],add('OBJ',0x50)),neq(st(g)['value'],'NEWLEN'),neq(st(g,1)['address'],add('RANGE',8)),neq(st(g,1)['value'],'NEWLEN')])
 g=make('capacity_read',{0:'OBJ'},loads={hex(C+0x4b9c):(add('OBJ',0xc0),'CAP',64)});cert('getCapacity_returns_full64_bit_capacity',g,[neq(g.get('x0'),'CAP')])
 g=make('getter_indirect',{0:'OBJ'},loads={hex(C+0x4b84):(add('OBJ',0x60),'RANGE',64),hex(C+0x4b88):('RANGE','BYTES',64)});cert('type10_getter_returns_first_range_address_without_capacity_check',g,[neq(g.get('x0'),'BYTES')])
 g=make('getter_flags',{0:'OBJ'},loads={hex(C+0x4b64):(add('OBJ',0xe0),'FLAG8',8),hex(C+0x4b6c):(add('OBJ',0x20),0x11b,32)});cert('getter_bit6_guard_and_type10_indirect_branch',g,[neq(g.branches[0]['condition'],'(distinct (bvand ((_ zero_extend 24) FLAG8) #x00000040) #x00000000)'),'(not '+g.branches[1]['condition']+')'])
 g=make('bare_metadata',{0:'OBJ'});cert('bare_constructor_initializes_only_named_metadata_fields',g,[neq(st(g)['address'],add('OBJ',8)),neq(st(g)['value'],bv(1,32)),neq(st(g,1)['address'],add('OBJ',0x18)),neq(st(g,1)['value'],bv(0)),neq(st(g,2)['address'],add('OBJ',0x90)),neq(st(g,2)['value'],bv(0))])
 g=make('dma_selector',{1:bv(0x4000000)});cert('DMA_operation4000000_selects_case3',g,[neq(g.get('w8'),bv(3,32)),'(not '+g.flags['gt']+')'])
 # Field/root noninterference,capacity and initialization counter obligations.
 sf=s['derived_field_literal_stores'];assert [(i['ea'],i['operands'])for i in sf if '#0xc0]'in i['operands']]==[(hex(C+0x4c14),'x3, [x0, #0xc0]')]
 assert [(i['ea'],i['operands'])for i in sf if '#0xd0]'in i['operands']]==[(hex(C+0x4c10),'w2, [x0, #0xd0]')]
 bare=s['store_call_censuses']['bare_constructor']['stores'];assert len(bare)==4 and [i['operands']for i in bare]==['w8, [x0, #8]','xzr, [x0, #0x18]','xzr, [x0, #0x90]','x16, [x0]']
 solve('capacity_exceeds_private4096_byte_fill_count','(assert (bvugt #x0000000000001000 #x0000000000014000))')
 solve('capacity_equals20_fill_spans_and5_literal16KiB_units','(assert (or '+neq('(bvmul #x0000000000000014 #x0000000000001000)',bv(81920))+' '+neq('(bvmul #x0000000000000005 #x0000000000004000)',bv(81920))+'))')
 solve('local_flag_OR1_OR8_updates_preserve_bit6','(assert '+neq('((_ extract 6 6) (bvor IFLAGS #x00000009))','((_ extract 6 6) IFLAGS)')+')')
 solve('request_alignment_depends_only_on_shift_low5_bits','(assert '+neq(alignment,'((_ sign_extend 32) (bvshl #x00000001 ((_ zero_extend 27) ((_ extract 4 0) SHIFT))))')+')')
 witnesses=[]
 for sh in range(32):
  w=1<<sh;a=w if w<1<<31 else w-(1<<32);witnesses.append({'shift_low5':sh,'argument_u64':hex(a&((1<<64)-1)),'signed64_value':a,'source_formula_not_native':True})
 solve('inherited_flag_bit6_clear_is_an_additional_getter_premise','(assert (= IFLAGS #x00000040))\n(assert (distinct (bvand (bvor IFLAGS #x00000009) #x00000040) #x00000000))',result='sat')
 prior=json.loads(read(ROOT/'inner_write_frontier_checks.json'));row=next(p for p in prior['proofs']if p['name']=='scratch_cell80_receives_address_of_global_buffer_pointer');r=subprocess.run([SOLVER,'-in'],input=row['query'],text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({'name':'replayed_inner_scratch_global_join','query':row['query'],'result':'unsat','replayed_query':True,'original_query_sha256':hashlib.sha256(row['query'].encode()).hexdigest()})
 sem={'source_models':{n:g.record_full()for n,g in models.items()},'read_bindings':read_bindings,'requested_capacity_bytes':81920,'source_capacity_field_offset':0xc0,'source_length_field_offset':0x50,'original_range_pointer_field_offset':0x60,'raw_constructor_options':0x13,'base_initializer_options':0x11b,'base_recorded_options':0x11b,'raw_DMA_operation':0x4000000,'DMA_request_bytes':40,'prepare_request_sites':['0xfffffe000c537ed0','0xfffffe000a508108'],'alignment_formula':'sign_extend64(1U << (runtime_shift32 &31))','alignment_argument_values':witnesses,'alignment_runtime_value_known':False,'actual_allocation_capacity_proved':False,'allocation_zeroing_proved':False,'complete_constructor_path_proved':False,'all_callee_field_noninterference_proved':False,'native_prepare_count_or_balance_proved':False,'getter_nonnull_for_actual_initialized_objects_proved':False,'native_frame_or_transaction_proved':False,'Mach_port_emissions':0,'source_only_no_CPU_execution':True}
 sem['source_instruction_instances_translated']=sum(len(g.sites)for g in models.values());sem['distinct_source_instruction_sites_translated']=len({pc for g in models.values()for pc in g.sites});return pp,sem
def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('capacity_store',lambda t:next(i for i in t['fragments']['buffer_entry']['instructions']if i['ea']==hex(C+0x4c14)).__setitem__('operands','x3, [x0, #0xc8]')),('range_length',lambda t:next(i for i in t['fragments']['range_publish']['instructions']if i['ea']==hex(C+0x5078)).__setitem__('operands','x8, [x9]')),('prepare_slot',lambda t:t['nominal_slots'][1].__setitem__('target','0x0')),('getter_guard',lambda t:t['fragments']['getter_flags']['instructions'][1].__setitem__('operands','w8, #5, #0xfffffe000c524b90')),('missing_derived_store',lambda t:t['derived_field_literal_stores'].pop()),('invent_native',lambda t:t.__setitem__('target_executed',True))];rows=[]
 for n,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;rows.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return rows
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);actual={pc for m in sem['source_models'].values()for pc in m['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']};assert actual==expected,(actual-expected,expected-actual)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'source_instruction_instances_translated':sem['source_instruction_instances_translated'],'distinct_source_instruction_sites_translated':sem['distinct_source_instruction_sites_translated'],'static_branch_predicates':sum(len(m['static_branch_predicates'])for m in sem['source_models'].values()),'alignment_formula_values':32,'predecessor_queries_replayed':1,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'buffer_construction_components_proved':True,'complete_operation_proved':False,**{n:False for n in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
