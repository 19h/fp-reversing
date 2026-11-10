#!/usr/bin/env python3
"""Static seed/header/delta ABI proofs;source equations only,no target execution."""
import copy,json,re,hashlib,shutil,subprocess
from recover_core_stack_delta_abi import ROOT,P,SCOPE,FLAGS,DEPS,build,POOL,TABLE,qword
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_context_descriptor_task_flow import FlowSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq
from validate_daemon_list_output import split
from validate_daemon_reader_container_origins import lut
SOLVER=shutil.which('z3');assert SOLVER
NAMES={n:64 for n in['CELL','REC','SEED','HEADER','RESULT','VALUE64','D0','D1','D2']};NAMES.update(POST=32,VALUE=32)
BASE=set(re.findall(r'\(declare-fun (\w+) ',DECL));DECLARED=BASE|set(NAMES)
def add(x,v):return'(bvadd '+x+' '+(bv(v)if isinstance(v,int)else v)+')'
class DeltaSSA(FlowSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.probe_reads=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   p=split(i['operands'])
   if i['mnemonic']=='ldrb'and p[0]=='wzr':
    row={'site':i['ea'],'address':self.address(p[1]),'width_bits':8,'input':'arbitrary readable probe byte;discarded','architectural_destination':'WZR'};self.reads.append(row);self.probe_reads.append(row);self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'discarded_probe_reads':self.probe_reads}
def certificates(s):
 pp=[];models={};bounds={};cuts=[];bindings=[];fs=s['fragments'];rules={r['name']:r for r in s['bank_rules']};luts=''.join(lut('SD'+n,bytes.fromhex(b['bytes']))for n,b in s['banks'].items());extra=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in NAMES.items()if n not in BASE)
 def solve(n,body,more='',result='unsat'):
  q='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL+extra+more+body+'\n(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-core-stack-delta-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.returncode,r.stdout[:1800],r.stderr);pp.append({'name':n,'query':q,'result':result,'static_scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,conditions=(),result='unsat'):
  solve(n,g.prefix()+''.join('(assert '+c+')\n'for c in conditions)+'(assert (or '+' '.join(terms)+'))',luts+''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items()if n not in DECLARED),result)
 def fresh(n,r=None,presets=None):return DeltaSSA(n,r,presets)
 def span(n,g,data=None,banks=None,cut=None):
  data=data or{};banks=banks or{};cut=cut or{};bb=[]
  for i in fs[n]['instructions']:
   pc=int(i['ea'],16)
   if pc in data:
    a,v,w=data[pc];v=bv(v,w)if isinstance(v,int)else v;g.supplied_loads[i['ea']]=(v,w)
    if re.fullmatch(r'[A-Za-z_]\w*',v)and v not in DECLARED:g.decl[v]=w
   if pc in banks:
    name=banks[pc];a=g.address(split(i['operands'])[1]);base=int(s['banks'][name]['address'],16);ix='((_ extract 7 0) (bvsub '+a+' '+bv(base)+'))';bb.append(neq(a,add(bv(base),'((_ zero_extend 56) '+ix+')')));g.supplied_loads[i['ea']]=('(LUT_SD'+name+' '+ix+')',8)
   g.run({'instructions':[i]},pc+4)
   if pc in data:
    a,v,w=data[pc];a=bv(a)if isinstance(a,int)else a;bb.append(neq(g.reads[-1]['address'],a));bindings.append({'phase':n,'site':i['ea'],'address':g.reads[-1]['address'],'expected_address':a,'width_bits':w,'value':g.reads[-1]['input']})
   if pc in cut:
    reg,rn=cut[pc];value=int(rules[rn]['constant'],16);cert(n+'_fresh_bank_'+rn,g,bb+[neq(g.get(reg),bv(value,32))]);cuts.append({'phase':n,'site':i['ea'],'register':reg,'original_expression':g.get(reg),'constant':value,'proof':pp[-1]['name']});g.put(reg,bv(value,32))
  models[n]=g;bounds[n]=bb;return g
 def pool(pc,off):return(pc,(POOL+off,qword(POOL+off),64))
 def rule(pc,n):r=rules[n];return(pc,(int(r['slot'],16),int(r['original_pointer']['target'],16),64))
 def st(g,pc):return next(r for r in g.stores if r['site']==hex(pc))
 E_L=int(s['banks']['EL']['address'],16);E_R=int(s['banks']['ER']['address'],16);D_L=int(s['banks']['DL']['address'],16);D_R=int(s['banks']['DR']['address'],16);A_L=int(s['banks']['AL']['address'],16);A_R=int(s['banks']['AR']['address'],16);SEED_ADDR=0xfffffe000ccc30c8
 for n,pc,off,reg,target,foff in [('root_EL',0xfffffe000a6352e8,0xc08,27,E_L,None),('root_ER',0xfffffe000a635300,0x158,13,E_R,0xa58),('root_DL',0xfffffe000a6353f8,0x4f0,11,D_L,0xa10),('root_DR',0xfffffe000a635414,0x578,12,D_R,0xa18)]:
  g=span(n,fresh(n,{28:bv(POOL)}),dict([pool(pc,off)]));terms=bounds[n]+[neq(g.get('x'+str(reg)),bv(target))]
  if foff is not None:terms +=[neq(g.stores[-1]['address'],add('K',foff)),neq(g.stores[-1]['value'],bv(target))]
  cert(n+'_literal_pool_root_and_frame_publication',g,terms)
 g=span('save_EL',fresh('save_EL',{27:bv(E_L)}));cert('EL_saved_to_framea50',g,[neq(g.stores[0]['address'],add('K',0xa50)),neq(g.stores[0]['value'],bv(E_L))])
 g=span('seed_selector',fresh('seed_selector',{3:bv(E_L),25:bv(E_R),11:'((_ zero_extend 56) ((_ extract 7 0) VALUE))',10:z('VALUE')}),banks={0xfffffe000a63658c:'EL',0xfffffe000a636598:'ER'});cert('seed_root_byte_bank_cancels_all_selector_words',g,bounds['seed_selector']+[neq(g.get('w16'),bv(0x95,32))]);g.put('w16',bv(0x95,32));g.put('x28',bv(POOL));g=span('seed_publication',g,dict([rule(0xfffffe000a636650,'SEED_ROOT')]));cert('frame868_publishes_mutable_seed_address',g,bounds['seed_publication']+[neq(g.stores[-1]['address'],add('K',0x868)),neq(g.stores[-1]['value'],bv(SEED_ADDR))])
 g=span('caller0_roots',fresh('caller0_roots',{8:z('VALUE')},{0xa10:(bv(D_L),64),0xa18:(bv(D_R),64)}),banks={0xfffffe000a63cbf8:'DL',0xfffffe000a63cc08:'DR'});cert('caller0_local_bank_roots_and_ef_key',g,bounds['caller0_roots']+[neq(g.get('x22'),bv(D_L)),neq(g.get('x26'),bv(D_R)),neq(g.get('w28'),bv(0xef,32))])
 caller_models=[]
 for j,off,pc,bankpair,cutpc,rn,rec_reg in [(0,0xc30,0xfffffe000a63cd38,'D',0xfffffe000a63cd2c,'CALL_D',20),(1,0xc20,0xfffffe000a6439d4,'A',0xfffffe000a6439c8,'CALL_A',24),(2,0xc28,0xfffffe000a644064,'D',0xfffffe000a644058,'CALL_D',20)]:
  rr={rec_reg:'REC',22:bv(D_L),26:bv(D_R),28:bv(0xef)}if j==0 else{rec_reg:'REC'};presets={0x868:(bv(SEED_ADDR),64),0xa60:(bv(TABLE),64),0x9f8:(bv(A_L),64),0x9f0:(bv(A_R),64),0xa10:(bv(D_L),64),0xa18:(bv(D_R),64)}
  loadpc=[0xfffffe000a63ccf4,0xfffffe000a643970,0xfffffe000a644000][j];banks=[{0xfffffe000a63cd1c:'DL',0xfffffe000a63cd24:'DR'},{0xfffffe000a6439b0:'AL',0xfffffe000a6439c0:'AR'},{0xfffffe000a644040:'DL',0xfffffe000a644050:'DR'}][j]
  g=span('caller'+str(j),fresh('caller'+str(j),rr,presets),{loadpc:(SEED_ADDR,'SEED',64),**dict([rule(pc,rn)])},banks,{cutpc:('w8',rn)})
  cert('caller'+str(j)+'_seed_snapshot_cell_and_adapter_ABI',g,bounds['caller'+str(j)]+[neq(g.stores[0]['address'],add('K',off)),neq(g.stores[0]['value'],'SEED'),neq(g.get('x0'),'REC'),neq(g.get('x1'),add('K',off)),neq(g.get('x8'),bv(0xfffffe000a688ebc)),neq(g.get('x17'),bv(0x7787))]);caller_models.append(g)
 # Complete adapter arithmetic before its first call,with independent controller snapshots.
 data={0xfffffe000a688edc:(0xfffffe000ccc3348,'C0',32),0xfffffe000a688ee4:(0xfffffe000ccc32f8,'C1',32),0xfffffe000a688f48:(0xfffffe000ccc3348,'Q0',64),0xfffffe000a688f84:(0xfffffe000ccc32f8,'Q1',64),0xfffffe000a688fac:('CELL','SEED',64),0xfffffe000a688fbc:(0xfffffe000ccc3348,'C2',32),**dict([rule(0xfffffe000a688f44,'CTRL'),pool(0xfffffe000a688f58,0xb70),pool(0xfffffe000a688f6c,0xa10),rule(0xfffffe000a688f80,'SHARED'),pool(0xfffffe000a688fcc,0x458),pool(0xfffffe000a688fe0,0x638),rule(0xfffffe000a688ff8,'SEED_UPDATE')])}
 g=span('adapter_prefix',fresh('adapter',{0:'REC',1:'CELL',29:add('K',0x30)}),data,{0xfffffe000a688f18:'TL',0xfffffe000a688f2c:'TR',0xfffffe000a688f60:'AL',0xfffffe000a688f70:'AR',0xfffffe000a688fd4:'FL',0xfffffe000a688fe8:'FR'},{0xfffffe000a688f34:('w8','CTRL'),0xfffffe000a688f78:('w9','SHARED'),0xfffffe000a688ff0:('w8','SEED_UPDATE')})
 PWORD='(bvadd (bvmul SEED #x0000000000002e95) #x0000000000000001)';ALLOC='(bvadd (bvand (bvlshr '+PWORD+' #x0000000000000038) #x00000000000000f0) #x0000000000000010)'
 cert('adapter_captures_seed_updates_global_and_derives_private_allocation',g,bounds['adapter_prefix']+[neq(g.get('x21'),'SEED'),neq(g.get('x19'),'CELL'),neq(st(g,0xfffffe000a688ffc)['address'],bv(SEED_ADDR)),neq(st(g,0xfffffe000a688ffc)['value'],PWORD),neq(g.get('x8'),ALLOC),neq(g.get('x9'),ALLOC),neq(g.get('x0'),'REC')])
 cert('private_allocation_is16_to256_and_aligned16',g,['(bvult '+g.get('x8')+' #x0000000000000010)','(bvugt '+g.get('x8')+' #x0000000000000100)',neq('(bvand '+g.get('x8')+' #x000000000000000f)',bv(0))])
 cert('seed_affine_update_flips_parity_and_never_equals_snapshot',g,['(= '+st(g,0xfffffe000a688ffc)['value']+' SEED)',neq('((_ extract 0 0) '+st(g,0xfffffe000a688ffc)['value']+')','(bvxor ((_ extract 0 0) SEED) #b1)')])
 inverse=pow(0x2e95,-1,1<<64);solve('seed_update_is_bijective_mod64','(assert '+neq('(bvmul (bvsub '+PWORD+' #x0000000000000001) '+bv(inverse)+')','SEED')+')')
 allocation_witnesses=[]
 for n in range(16):
  seed=(((n<<60)-1)*inverse)&((1<<64)-1);p=(seed*0x2e95+1)&((1<<64)-1);a=((p>>56)&0xf0)+16;assert a==16*(n+1);allocation_witnesses.append({'seed_u64':hex(seed),'published_word_u64':hex(p),'private_allocation_bytes':a,'abstract_not_native':True})
 g=span('adapter_probe_args',g,{0xfffffe000a689018:(0xfffffe000847c618,0xfffffe000a5a1cc4,64)});cert('adapter_probe_target_and_private_size_inputs',g,bounds['adapter_probe_args']+[neq(g.get('x8'),ALLOC),neq(g.get('x9'),ALLOC),neq(g.get('x0'),'REC')])
 g=span('probe_small_prefix',g);cert('bounded_allocation_selects_original_probe_no_loop_branch',g,['(not '+g.flags['lo']+')',neq(g.get('x0'),'REC'),neq(g.get('x8'),ALLOC),neq(g.get('x9'),ALLOC)])
 g=span('probe_small_read',g);cert('probe_one_discarded_read_preserves_record_and_size',g,[neq(g.probe_reads[-1]['address'],'(bvsub K '+ALLOC+')'),neq(g.get('x0'),'REC'),neq(g.get('x8'),ALLOC),neq(g.get('x9'),ALLOC),neq(g.get('sp'),'K')])
 g=span('adapter_header_init',g);H='(bvsub K '+ALLOC+')';cert('adapter_initializes_header_at_private_sp_to_seed_minus100',g,[neq(g.get('x20'),H),neq(g.get('sp'),H),neq(st(g,0xfffffe000a689030)['address'],H),neq(st(g,0xfffffe000a689030)['value'],'(bvsub SEED #x0000000000000100)')])
 data={0xfffffe000a689034:(0xfffffe000ccc3348,'C3',32),0xfffffe000a689038:(0xfffffe000ccc32f8,'C4',32),0xfffffe000a68906c:(0xfffffe000ccc3348,'C5',32),0xfffffe000a689070:(0xfffffe000ccc32f8,'C6',32),**dict([pool(0xfffffe000a689048,0x840),pool(0xfffffe000a689058,0xbb8),rule(0xfffffe000a6890a0,'TABLE'),rule(0xfffffe000a6890a8,'INNER')])}
 g=span('adapter_inner_call',g,data,{0xfffffe000a689050:'TL',0xfffffe000a68905c:'TR',0xfffffe000a689084:'TL',0xfffffe000a689090:'TR'},{0xfffffe000a689064:('w8','INNER'),0xfffffe000a689098:('w9','TABLE')});cert('adapter_calls_inner_with_original_record_and_header',g,bounds['adapter_inner_call']+[neq(g.get('x0'),'REC'),neq(g.get('x1'),H),neq(g.get('x8'),bv(0xfffffe000a687ee0)),neq(g.get('x17'),bv(0x6a0f))])
 g.put('x0','RESULT');g=span('adapter_output',g,{0xfffffe000a6890b8:(H,'POST',32)});DELTA='(bvshl ((_ zero_extend 48) ((_ extract 15 0) (bvsub POST ((_ extract 31 0) SEED)))) #x0000000000000004)';OUT=st(g,0xfffffe000a6890c4)['value']
 cert('adapter_output_exact_delta_word_and_independent_return_register',g,bounds['adapter_output']+[neq(st(g,0xfffffe000a6890c4)['address'],'CELL'),neq(OUT,DELTA),neq(g.get('x0'),'RESULT')])
 cert('actual_adapter_delta_is_aligned_and_at_mostffff0',g,[neq('(bvand '+OUT+' #x000000000000000f)',bv(0)),'(bvugt '+OUT+' #x00000000000ffff0)'])
 cert('zero_delta_iff_final_header_low16_equals_snapshot_low16',g,[neq('(= '+OUT+' #x0000000000000000)','(= ((_ extract 15 0) POST) ((_ extract 15 0) SEED))')])
 cert('preserving_header_low16_is_sufficient_without_preserving_full_word',g,[neq(OUT,bv(0))],['(= ((_ extract 15 0) POST) ((_ extract 15 0) SEED))'])
 cert('negative16_prior_control_is_outside_adapter_return_domain',g,['(= '+OUT+' #xfffffffffffffff0)'])
 cert('changed_header_low16_can_produce_nonzero16_delta',g,['(= '+OUT+' #x0000000000000010)'],['(= POST (bvadd ((_ extract 31 0) SEED) #x00000001))'],result='sat')
 cert('upper_header_bits_can_change_while_delta_remains_zero',g,['(= '+OUT+' #x0000000000000000)'],['(= POST (bvxor ((_ extract 31 0) SEED) #xffff0000))'],result='sat')
 g=span('adapter_restore_SP',g);cert('adapter_resets_own_sp_independently_of_exported_delta',g,[neq(g.get('sp'),add('K',0x10)),neq(g.get('x0'),'RESULT')]);solve('adapter_final_literal_writeback_restores_entry_sp','(assert '+neq(add(add('K',0x10),0x30),add('K',0x40))+')')
 data={0xfffffe000a687f30:(0xfffffe000ccc7740,'IC0',32),0xfffffe000a687f38:(0xfffffe000ccc32f8,'IC1',32),0xfffffe000a687f8c:(0xfffffe000ccc7740,'IQ0',64),0xfffffe000a687fd0:(0xfffffe000ccc32f8,'IQ1',64),0xfffffe000a687ff0:('HEADER','(bvsub SEED #x0000000000000100)',64),**dict([rule(0xfffffe000a687f88,'INNER_CTRL'),pool(0xfffffe000a687f9c,0xc08),pool(0xfffffe000a687fb4,0x158),rule(0xfffffe000a687fcc,'INNER_SHARED')])}
 g=span('inner_prefix',fresh('inner_prefix',{0:'REC',1:'HEADER'}),data,{0xfffffe000a687f54:'EL',0xfffffe000a687f68:'ER',0xfffffe000a687fa8:'EL',0xfffffe000a687fbc:'ER'},{0xfffffe000a687f78:('w10','INNER_CTRL'),0xfffffe000a687fc4:('w11','INNER_SHARED')})
 cert('complete_inner_arithmetic_prefix_global_targets_and_header_restoration',g,bounds['inner_prefix']+[neq(st(g,0xfffffe000a687fe8)['address'],bv(0xfffffe000ccc7740)),neq(st(g,0xfffffe000a687fec)['address'],bv(0xfffffe000ccc32f8)),neq(st(g,0xfffffe000a687ff8)['address'],'HEADER'),neq(st(g,0xfffffe000a687ff8)['value'],'SEED'),neq(g.get('x0'),'REC'),neq(g.get('x1'),'HEADER')])
 g=span('inner_header_restore',fresh('inner_header_restore',{1:'HEADER'}),{0xfffffe000a687ff0:('HEADER','VALUE64',64)});cert('inner_entry_adds100_to_header_before_dispatch',g,bounds['inner_header_restore']+[neq(g.stores[0]['address'],'HEADER'),neq(g.stores[0]['value'],add('VALUE64',0x100))]);cert('initialized_header_is_restored_to_seed_at_inner_entry',g,[neq(g.stores[0]['value'],'SEED')],['(= VALUE64 (bvsub SEED #x0000000000000100))'])
 F_L=int(s['banks']['FL']['address'],16);F_R=int(s['banks']['FR']['address'],16)
 data={0xfffffe000a688188:(POOL+0x458,qword(POOL+0x458),64),0xfffffe000a6881a4:(POOL+0x638,qword(POOL+0x638),64),**dict([rule(0xfffffe000a6881c8,'HW')])}
 g=span('inner_first_call',fresh('inner_first_call',{1:'HEADER',27:bv(TABLE),26:bv(0xfffffe000ccc7740),28:bv(0xfffffe000ccc32f8),20:bv(0xa41a4d891208c018),24:bv(0x4d08a3fb)}),data,{0xfffffe000a688198:'FL',0xfffffe000a6881b0:'FR'},{0xfffffe000a6881c0:('w8','HW')});cert('inner_first_call_resolves_hardware_initializer_not_header_api',g,bounds['inner_first_call']+[neq(g.get('x8'),bv(0xfffffe000a508030)),neq(g.get('x1'),'HEADER'),neq(g.get('x17'),bv(0x327a))])
 for j,off in enumerate([0xc30,0xc20,0xc28]):
  g=span('return'+str(j),fresh('return'+str(j),presets={off:('D'+str(j),64)}));cert('caller'+str(j)+'_adds_exported_delta_after_adapter_returns',g,[neq(g.get('sp'),add('K','D'+str(j)))])
 conditions=['(bvule '+n+' #x00000000000ffff0)'for n in['D0','D1','D2']];solve('three_bounded_adapter_deltas_sum_zero_iff_each_zero',''.join('(assert '+c+')\n'for c in conditions)+'(assert '+neq('(= (bvadd D0 D1 D2) #x0000000000000000)','(and (= D0 #x0000000000000000) (= D1 #x0000000000000000) (= D2 #x0000000000000000))')+')')
 solve('three_visit_delta_sum_is_bounded_without_modular_wrap',''.join('(assert '+c+')\n'for c in conditions)+'(assert (bvugt (bvadd D0 D1 D2) #x00000000002fffd0))')
 solve('inner_entry_restoration_alone_does_not_prove_final_header_preservation','(assert (= VALUE64 SEED))\n(assert (= POST (bvadd ((_ extract 31 0) VALUE64) #x00000001)))\n(assert (distinct ((_ extract 15 0) POST) ((_ extract 15 0) SEED)))',result='sat')
 sem={'source_models':{n:g.record_full()for n,g in models.items()},'source_instruction_instances_translated':sum(len(g.sites)for g in models.values()),'distinct_source_instruction_sites_translated':len({pc for g in models.values()for pc in g.sites}),'fresh_bank_cuts':cuts,'read_bindings':bindings,'adapter_target':'0xfffffe000a688ebc','inner_target':'0xfffffe000a687ee0','seed_address':hex(SEED_ADDR),'allocation_bytes_min':16,'allocation_bytes_max':256,'allocation_witnesses':allocation_witnesses,'seed_affine_inverse_mod64':hex(inverse),'delta_bytes_min':0,'delta_bytes_max':0xffff0,'delta_alignment_bytes':16,'delta_zero_iff':'low16(final header)==low16(captured seed)','inner_entry_restores_seed':True,'full_inner_header_preservation_proved':False,'all_actual_deltas_proved_zero':False,'three_visit_nonzero_cancellation_excluded':True,'native_frame_or_transaction_proved':False,'Mach_port_emissions':0,'source_only_no_CPU_execution':True}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('wrong_adapter',lambda t:t['bank_rules'][0].__setitem__('target','0x0')),('seed_update_multiplier',lambda t:next(i for i in t['fragments']['adapter_prefix']['instructions']if i['ea']=='0xfffffe000a688fb0').__setitem__('operands','w9, #0')),('header_restore',lambda t:t['fragments']['inner_header_restore']['instructions'][1].__setitem__('operands','x10, x10, #0')),('delta_shift',lambda t:t['fragments']['adapter_output']['instructions'][2].__setitem__('operands','x8, x8, #3, #0x10')),('probe_read',lambda t:t['fragments']['probe_small_read']['instructions'][1].__setitem__('operands','w0, [x10]')),('invent_native',lambda t:t.__setitem__('target_executed',True))];rows=[]
 for n,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;rows.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return rows

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);actual={pc for m in sem['source_models'].values()for pc in m['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']};assert actual==expected,(actual-expected,expected-actual)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'source_instruction_instances_translated':sem['source_instruction_instances_translated'],'distinct_source_instruction_sites_translated':sem['distinct_source_instruction_sites_translated'],'fresh_bank_cuts':len(sem['fresh_bank_cuts']),'allocation_size_witnesses':16,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'core_seed_header_delta_ABI_proved':True,'complete_operation_proved':False,**{n:False for n in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
