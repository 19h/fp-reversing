#!/usr/bin/env python3
"""Source equations for context/task descriptor joins;no CPU or target APIs run."""
import copy,hashlib,json,re,shutil,subprocess
from recover_context_descriptor_task_flow import ROOT,P,SCOPE,FLAGS,DEPS,build,POOL,TABLE,qword
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_userclient_context_lifecycle import LifecycleSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq
from validate_daemon_list_output import split
from validate_daemon_reader_container_origins import lut
SOLVER=shutil.which('z3');assert SOLVER
NAMES={n:64 for n in['UC','CTX','TASK','REC','OBJ','CELL','BUF','ADDRESS','LENGTH','STAGING','HEAD','CODE','VT','OLD','ENCODED','RESULT','CTRL0','CTRL1','FRAMEOBJ','RECORD0','FIELD28','FIELD30','D0','D1','D2','R0','R1','R2','R3','SCRATCH']};NAMES.update(MODE=32,PHASE=32,WORD=32)
BASE_DECLARED=set(re.findall(r'\(declare-fun (\w+) ',DECL));DECLARED=BASE_DECLARED|set(NAMES)
def add(x,n):return'(bvadd '+x+' '+(bv(n)if isinstance(n,int)else n)+')'
class FlowSSA(LifecycleSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   p=split(i['operands']);m=i['mnemonic']
   if m=='ubfiz':
    w=32 if p[0].startswith('w')else 64;ls,bits=int(p[2][1:],0),int(p[3][1:],0);self.put(p[0],'(bvshl (bvand '+self.get(p[1],w)+' '+bv((1<<bits)-1,w)+') '+bv(ls,w)+')');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
 def address(self,mem):return super().address(mem)
def certificates(s):
 proofs=[];models={};bounds={};cuts=[];bindings=[];fs=s['fragments'];rules={r['name']:r for r in s['bank_rules']};luts=''.join(lut('DF'+n,bytes.fromhex(b['bytes']))for n,b in s['banks'].items());extra=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in NAMES.items()if n not in BASE_DECLARED)
 def solve(name,body,more='',result='unsat',logic='QF_BV'):
  q='(set-option :timeout 45000)\n(set-logic '+logic+')\n'+DECL+extra+more+body+'\n'+('(check-sat)\n'if logic=='QF_AUFBV'else'(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n');r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-context-descriptor-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.returncode,r.stdout[:1400],r.stderr);proofs.append({'name':name,'query':q,'result':result,'static_scope':SCOPE});print(name,result,flush=True)
 def cert(n,g,terms,conditions=(),result='unsat'):
  solve(n,g.prefix()+''.join('(assert '+c+')\n'for c in conditions)+'(assert (or '+' '.join(terms)+'))',luts+''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items()if n not in DECLARED),result)
 def fresh(n,r=None,presets=None):return FlowSSA(n,r,presets)
 def span(n,g,data=None,bank=None,cut=None):
  data=data or{};bank=bank or{};cut=cut or{};bb=[]
  for i in fs[n]['instructions']:
   pc=int(i['ea'],16)
   if pc in data:
    row=data[pc];pair=isinstance(row,list);entries=row if pair else[row];values=[]
    for expected,value,w in entries:
     value=bv(value,w)if isinstance(value,int)else value;values.append((value,w))
     if re.fullmatch(r'[A-Za-z_]\w*',value)and value not in DECLARED:g.decl[value]=w
    g.supplied_loads[i['ea']]=values if pair else values[0]
   if pc in bank:
    name=bank[pc];a=g.address(split(i['operands'])[1]);base=int(s['banks'][name]['address'],16);ix='((_ extract 7 0) (bvsub '+a+' '+bv(base)+'))';bb.append(neq(a,add(bv(base),'((_ zero_extend 56) '+ix+')')));g.supplied_loads[i['ea']]=('(LUT_DF'+name+' '+ix+')',8)
   before=len(g.reads);g.run({'instructions':[i]},pc+4)
   if pc in data:
    entries=data[pc]if isinstance(data[pc],list)else[data[pc]];new=g.reads[before:];assert len(new)==len(entries)
    for rd,(expected,_,_)in zip(new,entries):
     e=bv(expected)if isinstance(expected,int)else expected;bb.append(neq(rd['address'],e));bindings.append({'phase':n,'site':i['ea'],'original_address':rd['address'],'expected_address':e,'width_bits':rd['width_bits'],'value':rd['input']})
   if pc in cut:
    reg,rn=cut[pc];c=int(rules[rn]['constant'],16);cert(n+'_fresh_bank_'+rn,g,bb+[neq(g.get(reg),bv(c,32))]);cuts.append({'phase':n,'site':i['ea'],'register':reg,'source_expression':g.get(reg),'constant':c,'proof':proofs[-1]['name']});g.put(reg,bv(c,32))
  models[n]=g;bounds[n]=bb;return g
 def st(g,pc,index=0):return[r for r in g.stores if r['site']==hex(pc)][index]
 def rule(pc,n):r=rules[n];return(pc,(int(r['slot'],16),int(r['target'],16),64))
 g=span('user_ABI',fresh('user_ABI',{0:'UC',1:'REC',2:'OBJ'}),{0xfffffe000a504058:('REC','ADDRESS',64),0xfffffe000a50405c:(add('REC',8),'WORD',32),0xfffffe000a504060:[(add('UC',0xe0),'TASK',64),(add('UC',0xe8),'CTX',64)],0xfffffe000a504064:(add('UC',0xd8),'RESULT',64),0xfffffe000a504068:('RESULT','OLD',64),0xfffffe000a504080:(add('VT',0xa20),0xfffffe000a505198,64)})
 cert('selector26_exact_context_and_task_are_separate_provider_arguments',g,bounds['user_ABI']+[neq(g.get('x0'),'RESULT'),neq(g.get('x1'),'ADDRESS'),neq(g.get('x2'),z('WORD')),neq(g.get('x3'),'CTX'),neq(g.get('x4'),'TASK')])
 g=span('provider_entry',fresh('provider_entry',{1:'ADDRESS',2:z('WORD'),3:'CTX',4:'TASK'}));cert('provider_entry_saves_context_and_forwards_user_task_to_outer_descriptor',g,[neq(g.get('x21'),'CTX'),neq(g.get('x22'),z('WORD')),neq(g.get('x0'),'ADDRESS'),neq(g.get('x1'),z('WORD')),neq(g.get('w2'),bv(3,32)),neq(g.get('x3'),'TASK')])
 g=span('provider_core',fresh('provider_core',{21:'CTX',22:z('WORD'),24:'STAGING'}));cert('provider_core_receives_staging_extent_and_context_without_separate_task',g,[neq(g.get('x0'),'STAGING'),neq(g.get('x1'),z('WORD')),neq(g.get('x2'),'CTX')])
 g=span('core_save',fresh('core_save',{0:'STAGING',1:'LENGTH',2:'CTX'}));cert('core_saves_context_extent_and_staging_at_distinct_offsets',g,[neq(st(g,0xfffffe000a63524c)['address'],add('K',0x738)),neq(st(g,0xfffffe000a63524c)['value'],'CTX'),neq(st(g,0xfffffe000a635250)['address'],add('K',0x878)),neq(st(g,0xfffffe000a635250)['value'],'LENGTH'),neq(st(g,0xfffffe000a635254)['address'],add('K',0x8f8)),neq(st(g,0xfffffe000a635254)['value'],'STAGING')])
 for n,reg,off,base,want in [('root_TL',22,0x840,POOL,'TL'),('root_TR',23,0xbb8,POOL,'TR')]:
  f=fs[n];pc=int(f['start'],16);g=span(n,fresh(n,{28:bv(POOL)}),{pc:(POOL+off,int(s['banks'][want]['address'],16),64)});cert(n+'_original_pool_load',g,bounds[n]+[neq(g.get('x'+str(reg)),bv(int(s['banks'][want]['address'],16)))])
 tl=int(s['banks']['TL']['address'],16);tr=int(s['banks']['TR']['address'],16);fl=int(s['banks']['FL']['address'],16);fr=int(s['banks']['FR']['address'],16)
 g=span('root_FLFR',fresh('root_FLFR',{28:bv(POOL)}),{0xfffffe000a63665c:(POOL+0x458,qword(POOL+0x458),64),0xfffffe000a636664:(POOL+0x638,qword(POOL+0x638),64)});cert('original_F_bank_roots_from_pool_biases',g,bounds['root_FLFR']+[neq(g.get('x21'),bv(fl)),neq(g.get('x10'),bv(fr))])
 for n,regs,expected in [('save_TL',{28:bv(tl)},[(0xa48,tl)]),('save_TR',{23:bv(tr)},[(0xa40,tr)]),('save_FLFR',{21:bv(fl),10:bv(fr)},[(0xa00,fl),(0xa20,fr)])]:
  g=span(n,fresh(n,regs));cert(n+'_literal_frame_publication',g,[v for row,(off,value)in zip(g.stores,expected)for v in[neq(row['address'],add('K',off)),neq(row['value'],bv(value))]])
 g=span('mode_variable',fresh('mode_variable',{12:z('PHASE'),7:bv(TABLE)},{0x738:('CTX',64)}),{0xfffffe000a63c830:(add('CTX',8),'MODE',32),0xfffffe000a63c850:(add(bv(TABLE),'(bvshl ((_ sign_extend 32) (bvor PHASE (ite (= MODE (bvsub (bvand (bvadd PHASE #xf6499962) #x09b660ef) #x000000e6)) (bvxor (bvsub PHASE #x000005ae) #x000000e5) #x00000000))) #x0000000000000003)'),'CODE',64)})
 cert('first_mode_gate_exact_phase_dependent_comparison_and_index',g,bounds['mode_variable']+[neq(g.get('x17'),bv(0x1fcb))])
 g=span('mode_one',fresh('mode_one',{7:bv(TABLE)},{0x738:('CTX',64)}),{0xfffffe000a642e50:(add('CTX',8),'MODE',32),0xfffffe000a642e6c:(add(bv(TABLE),'((_ zero_extend 32) (bvmul (ite (= MODE #x00000001) #x000008f3 #x00000916) #x00000008))'),'CODE',64)})
 cert('second_mode_gate_tests_one_and_selects_exact_two_slots',g,bounds['mode_one']+[neq(g.get('x17'),bv(0x991b))])
 g=span('context_alias',fresh('context_alias',{0:'OBJ',11:'OLD'},{0x738:('CTX',64)}));cert('context_pointer_is_published_as_internal_record_first_qword',g,[neq(g.stores[0]['address'],'OBJ'),neq(g.stores[0]['value'],'CTX')])
 g=span('task_save',fresh('task_save',presets={0x738:('CTX',64)}),{0xfffffe000a647d98:(add('CTX',16),'TASK',64)});cert('context_task64_is_saved_at_frame9d0',g,bounds['task_save']+[neq(g.stores[0]['address'],add('K',0x9d0)),neq(g.stores[0]['value'],'TASK')])
 g=span('task_relay',fresh('task_relay',{22:'OBJ'},{0x9d0:('TASK',64)}));cert('preserved_task_scratch_is_copied_to_object2e0',g,[neq(g.stores[0]['address'],add('OBJ',0x2e0)),neq(g.stores[0]['value'],'TASK')])
 g=span('sample_record',fresh('sample_record',{25:'REC',20:bv(tr),26:bv(tl)},{0x738:('CTX',64)}),{0xfffffe000a64b34c:(add('CTX',16),'TASK',64)});cert('sample_record_receives_task64_at_offset38',g,bounds['sample_record']+[neq(st(g,0xfffffe000a64b434,1)['address'],add('REC',0x38)),neq(st(g,0xfffffe000a64b434,1)['value'],'TASK')])
 g.save(0xa60,bv(TABLE),64,'canonical table/frame epoch premise');g=span('sample_call',g,dict([rule(0xfffffe000a64b48c,'SAMPLE')]),{0xfffffe000a64b46c:'TL',0xfffffe000a64b478:'TR'},{0xfffffe000a64b480:('w8','SAMPLE')});cert('sample_task_record_call_selects_original_coordinator',g,bounds['sample_call']+[neq(g.get('x0'),'REC'),neq(g.get('x8'),bv(0xfffffe000a6247a4)),neq(g.get('x17'),bv(0x6353))])
 g=span('second_record',fresh('second_record',{24:'REC'},{0x738:('CTX',64)}),{0xfffffe000a65156c:(add('CTX',16),'TASK',64)});cert('second_record_receives_task64_at_offset10',g,bounds['second_record']+[neq(st(g,0xfffffe000a651668,1)['address'],add('REC',0x10)),neq(st(g,0xfffffe000a651668,1)['value'],'TASK')])
 g.save(0xa00,bv(fl),64,'proved pool-root value with frame/root stability premise');g.save(0xa20,bv(fr),64,'proved pool-root value with frame/root stability premise');g.put('x7',bv(TABLE));g=span('second_call',g,dict([rule(0xfffffe000a651708,'SECOND')]),{0xfffffe000a6516e4:'FL',0xfffffe000a6516f4:'FR'},{0xfffffe000a651700:('w8','SECOND')});cert('second_task_record_call_selects_original_consumer',g,bounds['second_call']+[neq(g.get('x0'),'REC'),neq(g.get('x8'),bv(0xfffffe000a61c404)),neq(g.get('x17'),bv(0x1e46))])
 g=span('coordinator_task_save',fresh('coordinator_task_save',{27:'REC',29:add('K',0x130)}),{0xfffffe000a624900:(add('REC',0x38),'TASK',64)});cert('coordinator_reads_and_saves_same_task_word',g,bounds['coordinator_task_save']+[neq(g.stores[0]['address'],add('K',0xa0)),neq(g.stores[0]['value'],'TASK')])
 g=span('coordinator_task_call',fresh('coordinator_task_call',{29:add('K',0x130)}),{0xfffffe000a624b38:(add('K',0xc0),'ADDRESS',64),0xfffffe000a624b3c:(add('K',0xa0),'TASK',64)});cert('coordinator_sample_size_creation_receives_task_in_x2',g,bounds['coordinator_task_call']+[neq(g.get('x2'),'TASK'),neq(g.get('x0'),'ADDRESS'),neq(g.get('x17'),bv(0x942c))])
 g=span('second_task_call',fresh('second_task_call',{19:'REC',29:add('K',0x160),26:bv(TABLE),25:'ADDRESS',20:'ENCODED'}),{0xfffffe000a61c84c:(add('REC',0x10),'TASK',64),0xfffffe000a61c850:[(add('K',0xf0),'CTRL0',64),(add('K',0xf8),'CTRL1',64)],0xfffffe000a61c888:(0xfffffe00084723f0,qword(0xfffffe00084723f0),64),0xfffffe000a61c8a4:(0xfffffe0008472478,qword(0xfffffe0008472478),64),**dict([rule(0xfffffe000a61c8c4,'FACTORY')])},{0xfffffe000a61c898:'DL',0xfffffe000a61c8b0:'DR'},{0xfffffe000a61c8bc:('w8','FACTORY')});cert('second_consumer_forwards_task64_to_exact_samples_factory',g,bounds['second_task_call']+[neq(g.get('x2'),'TASK'),neq(g.get('x0'),'ADDRESS'),neq(g.get('x1'),'(bvxor ENCODED #xd26b7d290a2e6311)'),neq(g.get('x8'),bv(0xfffffe000a509980))])
 for label,options in [('sample_sizes_ABI',2),('samples_ABI',3)]:
  g=span(label,fresh(label,{0:'ADDRESS',1:'LENGTH',2:'TASK'}));cert(label+'_full_width_task_and_raw_options_to_withAddressRange',g,[neq(g.get('x0'),'ADDRESS'),neq(g.get('x1'),'LENGTH'),neq(g.get('x3'),'TASK'),neq(g.get('w2'),bv(options,32))])
 for label,glob in [('sample_sizes_publish',0xfffffe000ccc7858),('samples_publish',0xfffffe000ccc7860)]:
  g=span(label,fresh(label,{0:'RESULT'}));cert(label+'_global_descriptor_and_raw_status',g,[neq(g.stores[0]['address'],bv(glob)),neq(g.stores[0]['value'],'RESULT'),neq(g.get('w0'),'(ite (= RESULT #x0000000000000000) #xffff5bd4 #x00000000)')])
 g=span('head',fresh('head',{2:'OBJ',7:bv(TABLE)},{0x738:('CTX',64)}),{0xfffffe000a65ed5c:('CTX','HEAD',64)});cert('core_head_read_publishes_context_and_head_as_separate_fields',g,[neq(g.stores[0]['address'],add('OBJ',0x118)),neq(g.stores[0]['value'],'CTX'),neq(g.stores[1]['address'],add('OBJ',0x410)),neq(g.stores[1]['value'],'HEAD')]+[v for v in bounds['head']if'CODE'not in v])
 for j,off in enumerate([0xc30,0xc20,0xc28]):
  name='delta'+str(j);g=span(name,fresh(name,presets={off:('D'+str(j),64)}));cert(name+'_original_return_updates_sp_by_raw_cell',g,[neq(g.get('sp'),add('K','D'+str(j)))]);cert(name+'_old_context_cell_address_reused_iff_delta_zero',g,[neq('(= '+add(g.get('sp'),0x738)+' '+add('K',0x738)+')','(= D'+str(j)+' #x0000000000000000)')])
 solve('conditional_three_delta_composition_restores_entry_slot_iff_sum_zero','(assert '+neq('(= '+add(add(add(add('K','D0'),'D1'),'D2'),0x738)+' '+add('K',0x738)+')','(= (bvadd D0 D1 D2) #x0000000000000000)')+')')
 solve('nonzero_private_delta_changes_saved_context_read_address','(assert (= D0 #x0000000000000010))\n(assert (distinct '+add(add('K','D0'),0x738)+' '+add('K',0x738)+'))',result='sat')
 solve('nonzero_individual_deltas_can_cancel_without_proving_source_path','(assert (= D0 #x0000000000000010))\n(assert (= D1 #xfffffffffffffff0))\n(assert (= D2 #x0000000000000000))\n(assert (= (bvadd D0 D1 D2) #x0000000000000000))',result='sat')
 solve('u32_scratch_reuse_can_change_a_previously_saved_task_word','(assert (distinct (concat ((_ extract 63 32) TASK) WORD) TASK))',result='sat')
 # Exact byte representation joins task into both carrier fields;no native
 # object/lifetime or arbitrary-memory-access behavior is supplied.
 for off in[0x38,0x10]:
  body='';last='MEM'
  for j in range(8):
   n='TM'+str(j);body+='(define-fun '+n+' () (Array (_ BitVec 64) (_ BitVec 8)) (store '+last+' '+add('REC',off+j)+' ((_ extract '+str(8*j+7)+' '+str(8*j)+') TASK)))\n';last=n
  values=['(select '+last+' '+add('REC',off+j)+')'for j in reversed(range(8))];v=values[0]
  for x in values[1:]:v='(concat '+v+' '+x+')'
  solve('task64_byte_store_load_join_record'+hex(off)[2:],body+'(assert '+neq(v,'TASK')+')','(declare-fun MEM () (Array (_ BitVec 64) (_ BitVec 8)))\n',logic='QF_AUFBV')
 prior=json.loads(read(ROOT/'userclient_context_lifecycle_checks.json'))
 for n in ['initializer_success_publishes_raw_task_zero_provider_and_live_byte','start_exact_provider_cell_mode_and_task_ABI','context_success_exact24_byte_head_mode_task_and_cell_publication']:
  row=next(r for r in prior['proofs']if r['name']==n);r=subprocess.run([SOLVER,'-in'],input=row['query'],text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';proofs.append({'name':'replayed_'+n,'query':row['query'],'result':'unsat','original_query_sha256':hashlib.sha256(row['query'].encode()).hexdigest(),'replayed_query':True})
 prior=json.loads(read(ROOT/'sample_descriptor_proofs.json'));row=next(r for r in prior['proofs']if r['name']=='task_type_bits');q=read(ROOT/row['file']);assert hashlib.sha256(q.encode()).hexdigest()==row['sha256'];r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';proofs.append({'name':'replayed_descriptor_task_type_bits','query':q,'result':'unsat','original_query_sha256':row['sha256'],'replayed_query':True})
 sem={'source_models':{n:g.record_full()for n,g in models.items()},'source_instruction_instances_translated':sum(len(g.sites)for g in models.values()),'distinct_source_instruction_sites_translated':len({pc for g in models.values()for pc in g.sites}),'fresh_bank_cuts':cuts,'read_bindings':bindings,'selector':26,'core_context_frame_offset':0x738,'context_mode_offset':8,'context_task_offset':16,'sample_record_task_offset':0x38,'second_record_task_offset':0x10,'sample_task_target':'0xfffffe000a6247a4','second_task_target':'0xfffffe000a61c404','second_factory_target':'0xfffffe000a509980','factory_task_argument':'X3 kernel task pointer64','literal_context_reload_census_complete_for_stated_pattern':True,'all_aliases_or_control_paths_proved':False,'private_delta_values_proved_zero':False,'task_reference_balance_proved':False,'global_descriptor_serialization_proved':False,'native_connection_or_mapping_proved':False,'Mach_port_emissions':0,'all_accepted_queries_exclude_errors_and_unknown':True}
 return proofs,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('context_task_field',lambda t:next(i for i in t['fragments']['task_save']['instructions']if i['ea']=='0xfffffe000a647d98').__setitem__('operands','x8, [x8, #8]')),('missing_census_reload',lambda t:t['context_census']['raw_mask_reload_sites'].pop()),('factory_task_width',lambda t:t['fragments']['samples_ABI']['instructions'][0].__setitem__('operands','w3, w2')),('wrong_bank',lambda t:t['banks']['TL'].__setitem__('bytes','00'+t['banks']['TL']['bytes'][2:])),('delta_cell',lambda t:t['fragments']['delta0']['instructions'][1].__setitem__('operands','x9, [sp, #0xc20]')),('wrong_target',lambda t:t['bank_rules'][1].__setitem__('target','0x0')),('invent_native',lambda t:t.__setitem__('target_executed',True))];rows=[]
 for n,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;rows.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return rows

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);actual={pc for m in sem['source_models'].values()for pc in m['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']};assert actual==expected,(actual-expected,expected-actual)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'source_instruction_instances_translated':sem['source_instruction_instances_translated'],'distinct_source_instruction_sites_translated':sem['distinct_source_instruction_sites_translated'],'fresh_bank_cuts':len(sem['fresh_bank_cuts']),'predecessor_queries_replayed':4,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'typed_context_to_descriptor_task_flow_proved':True,'complete_operation_proved':False,**{n:False for n in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
