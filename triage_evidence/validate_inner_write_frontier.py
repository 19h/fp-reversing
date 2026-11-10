#!/usr/bin/env python3
"""Static call-selector,frame,fill-CFG and hardware argument certificates."""
import copy,json,re,shutil,subprocess,hashlib
from recover_inner_write_frontier import ROOT,P,SCOPE,FLAGS,DEPS,build,POOL,TABLE,qword,BASE
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_core_stack_delta_abi import DeltaSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq
from validate_daemon_list_output import split
from validate_daemon_reader_container_origins import lut
SOLVER=shutil.which('z3');assert SOLVER
NAMES={n:64 for n in ['REC','PARAM','SRC','DST','COUNT','OFFSET','INDIRECT','STATE','IV','HEADER','BYTEIX','HV']};NAMES.update(MODE=8,MODE32=32,SEL=32)
BASE_DECL=set(re.findall(r'\(declare-fun (\w+) ',DECL));DECLARED=BASE_DECL|set(NAMES)
def add(a,b):return '(bvadd '+a+' '+(bv(b)if isinstance(b,int)else b)+')'
def fill_paths(f,start,end,reg):
 """Enumerate three loop-free source branch trees;retain symbolic conditions."""
 at={int(i['ea'],16):i for i in f['instructions']};todo=[(start,[],[],None)];rows=[]
 while todo:
  pc,conditions,sites,cmp=todo.pop()
  if pc==end:rows.append({'conditions':conditions,'store_sites':sites,'store_count':len(sites)});continue
  i=at[pc];m=i['mnemonic'];p=split(i['operands'])
  if m=='cmp':assert p[0]==reg;todo.append((pc+4,conditions,sites,int(p[1][1:],0)))
  elif m in ['str','strb']:
   assert p[1]=='[x0]'and (len(p)==2 or p[2]in ['#1','#8']);todo.append((pc+4,conditions,sites+[i['ea']],cmp))
  elif m=='b':todo.append((int(p[0][1:],0),conditions,sites,cmp))
  elif m.startswith('b.')or m in ['cbz','cbnz']:
   if m in ['cbz','cbnz']:assert p[0]==reg;test='(= SEL #x00000000)';test='(not '+test+')'if m=='cbnz'else test;target=int(p[1][1:],0)
   else:
    assert cmp is not None;op={'b.eq':'=','b.ne':'distinct','b.gt':'bvsgt'}[m];test='('+op+' SEL '+bv(cmp,32)+')';target=int(p[0][1:],0)
   todo.append((target,conditions+[test],sites,cmp));todo.append((pc+4,conditions+['(not '+test+')'],sites,cmp))
  elif m=='ret':rows.append({'conditions':conditions,'store_sites':sites,'store_count':len(sites)})
  else:raise AssertionError((hex(pc),m,p))
 assert len(rows)==8;return rows
def certificates(s):
 proofs=[];models={};bindings=[];cuts=[];fs=s['fragments'];luts=''.join(lut('IW'+n,bytes.fromhex(b['bytes']))for n,b in s['banks'].items());extra=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in NAMES.items()if n not in BASE_DECL)
 def solve(n,body,more='',result='unsat'):
  q='(set-option :timeout 45000)\n(set-logic QF_BV)\n'+DECL+extra+more+body+'\n(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.returncode,r.stdout[:1800],r.stderr);proofs.append({'name':n,'query':q,'result':result,'static_scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms):solve(n,g.prefix()+'(assert (or '+' '.join(terms)+'))',luts+''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items()if n not in DECLARED))
 def simple(n,regs=None,presets=None,loads=None):
  g=DeltaSSA(n,regs,presets,loads);g.run(fs[n],int(fs[n]['end'],16));models[n]=g;return g
 bank=lambda n:bv(int(s['banks'][n]['address'],16))
 fixed={0x826c:(add('K',0x98),168),0x8360:(add('K',0x98),16),0x83c0:(add('K',0xc0),32),0x8450:(add('K',0x98),16),0x8510:(add('K',0xc0),32),0x858c:(add('K',0x140),16),0x8ccc:(add('K',0x140),16)}
 for r in s['bank_rules']:
  n=r['name'];site=int(r['call_site'],16)-BASE;pair=r['pair'];presets={0x18:(bank('FR'),64),0x38:(bank('FL'),64),0x40:(bank('TL'),64),0x48:(bank('TR'),64),0x20:(bank('EL'),64),0x60:(bank('ER'),64),0x68:('SRC',64),0x78:('DST',64),0x80:('INDIRECT',64)}
  regs={27:bv(TABLE),29:add('K',0x1b0),25:'PARAM',0:'DST',1:'SRC',2:'COUNT',19:'COUNT'}
  if site==0x826c:regs.update({21:bank('EL'),11:bank('ER')})
  if site==0x8360:regs.update({10:bank('EL'),20:add('K',0x94)})
  if site==0x83c0:regs[20]=add('K',0x94)
  if site==0x8450:regs[11]=add('K',0x94)
  if site==0x89cc:regs[19]='OFFSET'
  if site==0x8ae4:regs[11]='OFFSET'
  if site==0x8bc0:regs[21]='COUNT'
  g=DeltaSSA(n,regs,presets);terms=[];data={};lb,rb=r['byte_load_sites'];cut=r['cut_site'];table=r['table_load_site']
  if site==0x81dc:data.update({hex(BASE+0x8188):(POOL+0x458,qword(POOL+0x458),64),hex(BASE+0x81a4):(POOL+0x638,qword(POOL+0x638),64)})
  if site==0x8ccc:data.update({hex(BASE+0x8c8c):(POOL+0xf50,qword(POOL+0xf50),64),hex(BASE+0x8ca0):(POOL+0xf20,qword(POOL+0xf20),64)})
  if site==0x8e80:data.update({hex(BASE+0x8e4c):(POOL+0x4f0,qword(POOL+0x4f0),64),hex(BASE+0x8e60):(POOL+0x578,qword(POOL+0x578),64)})
  data[table]=(int(r['slot'],16),int(r['target'],16),64)
  if site==0x87cc:data[hex(BASE+0x87ac)]=('INDIRECT','DST',64)
  if site==0x8bc0:data[hex(BASE+0x8b9c)]=('PARAM','MODE',8)
  for i in fs[n]['instructions']:
   pc=int(i['ea'],16);p=split(i['operands'])
   if i['ea']in [lb,rb]:
    bn=pair+('L'if i['ea']==lb else'R');address=g.address(p[1]);ba=int(s['banks'][bn]['address'],16);ix='((_ extract 7 0) (bvsub '+address+' '+bv(ba)+'))';terms.append(neq(address,add(bv(ba),'((_ zero_extend 56) '+ix+')')));g.supplied_loads[i['ea']]=('(LUT_IW'+bn+' '+ix+')',8)
   if i['ea']in data:
    a,v,w=data[i['ea']];g.supplied_loads[i['ea']]=(bv(v,w)if isinstance(v,int)else v,w)
   g.run({'instructions':[i]},pc+4)
   if i['ea']in data:
    a,v,w=data[i['ea']];a=bv(a)if isinstance(a,int)else a;terms.append(neq(g.reads[-1]['address'],a));bindings.append({'phase':n,'site':i['ea'],'expected_address':a,'source_address':g.reads[-1]['address'],'width_bits':w})
   if i['ea']==cut:
    reg=p[0];value=int(r['constant'],16);cert(n+'_fresh_original_bank_selection',g,terms+[neq(g.get(reg),bv(value,32))]);cuts.append({'phase':n,'site':i['ea'],'register':reg,'expression':g.get(reg),'constant_u32':value});g.put(reg,bv(value,32))
  tt=terms+[neq(g.get(r['target_register']),bv(int(r['target'],16))),neq(g.get('x17'),bv(int(r['diversity'],16)))]
  if site in fixed:
   dst,count=fixed[site];tt +=[neq(g.get('x0'),dst),neq(g.get('x2'),bv(count))]
  if site in [0x826c,0x87cc]:tt +=[neq(g.get('x1'),bv(0)),neq(g.get('x2'),bv(168 if site==0x826c else 4096))]
  if site in [0x8360,0x8450]:tt.append(neq(g.get('x1'),add('PARAM',2)))
  if site in [0x83c0,0x8510]:tt.append(neq(g.get('x1'),add('PARAM',0x39)))
  if site==0x858c:tt.append(neq(g.get('x1'),add('PARAM',0x12)))
  if site==0x8608:tt +=[neq(g.get('x0'),'DST'),neq(g.get('x1'),'SRC'),neq(g.get('x2'),'COUNT')]
  if site==0x89cc:tt +=[neq(g.get('x0'),add('DST','OFFSET')),neq(g.get('x1'),add('SRC','OFFSET'))]
  if site==0x8ae4:tt +=[neq(g.get('x0'),'DST'),neq(g.get('x1'),add('SRC','((_ zero_extend 32) ((_ extract 31 0) OFFSET))')),neq(g.get('x2'),'COUNT')]
  if site==0x8bc0:tt +=[neq(g.get('x0'),add('K',0x94)),neq(g.get('x1'),add('K',0x140)),neq(g.get('x2'),'COUNT'),neq(g.get('w3'),'((_ zero_extend 24) MODE)')]
  cert(n+'_nominal_target_and_local_arguments',g,tt);models[n]=g
 g=DeltaSSA('scratch_root',{22:bv(POOL)}, {0x38:(bank('FL'),64),0x18:(bank('FR'),64)});r=s['scratch_root_selection'];terms=[]
 for i in fs['scratch_root']['instructions']:
  pc=int(i['ea'],16)
  if pc in [BASE+0x8720,BASE+0x8730]:
   bn='FL'if pc==BASE+0x8720 else'FR';address=g.address(split(i['operands'])[1]);ba=int(s['banks'][bn]['address'],16);ix='((_ extract 7 0) (bvsub '+address+' '+bv(ba)+'))';terms.append(neq(address,add(bv(ba),'((_ zero_extend 56) '+ix+')')));g.supplied_loads[i['ea']]=('(LUT_IW'+bn+' '+ix+')',8)
  if pc==BASE+0x8740:g.supplied_loads[i['ea']]=(bv(int(r['original_pointer']['target'],16)),64)
  g.run({'instructions':[i]},pc+4)
  if pc==BASE+0x8738:
   cert('scratch_root_fresh_original_bank_selection',g,terms+[neq(g.get('w9'),bv(0xdf,32))]);cuts.append({'phase':'scratch_root','site':i['ea'],'register':'w9','expression':g.get('w9'),'constant_u32':0xdf});g.put('w9',bv(0xdf,32))
 cert('scratch_cell80_receives_address_of_global_buffer_pointer',g,terms+[neq(g.reads[-1]['address'],bv(int(r['slot'],16))),neq(g.stores[0]['address'],add('K',0x80)),neq(g.stores[0]['value'],bv(0xfffffe000ccc7848))]);models['scratch_root']=g
 assert [r['ea']for r in s['direct_stores']if r['class']=='private_frame'and r['relative_half_open_extent'][0]<0x88 and 0x80<r['relative_half_open_extent'][1]]==['0xfffffe000a688118','0xfffffe000a688748']
 # Source-exact arguments which precede two selector fragments.
 g=simple('late_copy_args',{24:'OFFSET',21:'COUNT',8:'HV'}, {0x78:('DST',64),0x80:('INDIRECT',64)},{hex(BASE+0x8e0c):('SRC',64)})
 cert('late_copy_uses_dereferenced_scratch_not_saved_input_cell',g,[neq(g.get('x0'),add('DST','((_ zero_extend 32) ((_ extract 31 0) OFFSET))')),neq(g.get('x1'),add('SRC','((_ zero_extend 32) ((_ extract 31 0) COUNT))')),neq(g.get('x2'),'((_ zero_extend 32) ((_ extract 31 0) HV))'),neq(g.reads[-1]['address'],'INDIRECT')])
 g=simple('scratch_copy_args',{21:'OFFSET'}, {0x80:('INDIRECT',64)},{hex(BASE+0x8a74):('DST',64)})
 cert('scratch_copy_destination_is_dereferenced_scratch_plus_u32_offset',g,[neq(g.get('x0'),add('DST','((_ zero_extend 32) ((_ extract 31 0) OFFSET))')),neq(g.reads[-1]['address'],'INDIRECT')])
 g=simple('record_inputs',{0:'REC'},{},{hex(BASE+0x804c):('PARAM',64),hex(BASE+0x8050):('SRC',64),hex(BASE+0x8054):('DST',64)})
 cert('record_parameter_input_and_output_fields_are_separate64_bit_roots',g,[neq(g.reads[j]['address'],add('REC',off))for j,off in enumerate([0x18,0,0x10,0x20])]+[neq(g.get('x25'),'PARAM'),neq(g.get('x15'),'SRC'),neq(g.get('x16'),'DST')])
 g=simple('record_save',{0:'REC'});cert('original_record_is_published_to_frame28',g,[neq(g.stores[0]['address'],add('K',0x28)),neq(g.stores[0]['value'],'REC')])
 g=simple('status_reload',presets={0x28:('REC',64)});cert('status_predecessor_reloads_original_record_conditionally',g,[neq(g.get('x0'),'REC')])
 g=simple('status_store',{0:'REC'});cert('status_site_writes_only_record8_to11',g,[neq(g.stores[0]['address'],add('REC',8))]);assert g.stores[0]['width_bits']==32
 g=simple('private_state_root');cert('alternate_state_view_is_frame94',g,[neq(g.get('x11'),add('K',0x94))])
 g=simple('hardware_ABI',{0:'STATE',1:'IV',2:'COUNT',3:z('MODE32')},{},{'0xfffffe000a5084a8':('REC',64),'0xfffffe000a5084b0':('DST',64),'0xfffffe000a5084b8':('HEADER',64)})
 cert('hardware_adapter_truncates_count_and_forwards_IV_state_and_shared_buffer',g,[neq(g.reads[0]['address'],bv(0xfffffe000ccceb08)),neq(g.reads[1]['address'],bv(0xfffffe000ccceb10)),neq(g.get('x0'),'REC'),neq(g.get('x1'),'DST'),neq(g.get('x2'),'DST'),neq(g.get('x3'),'((_ zero_extend 32) ((_ extract 31 0) COUNT))'),neq(g.get('x4'),'IV'),neq(g.get('w5'),'(bvxor MODE32 #x00000001)'),neq(g.get('x6'),'STATE'),neq(g.get('x7'),bv(0))]+[neq(st['value'],bv(0,st['width_bits']))for st in g.stores]);assert len(g.stores)==3
 assert [(i['ea'],i['mnemonic'],i['operands'])for i in s['SP_FP_writes']]==[('0xfffffe000a687ee4','sub','sp, sp, #0x1c0'),('0xfffffe000a687f00','add','x29, sp, #0x1b0'),('0xfffffe000a688800','ldp','x29, x30, [sp, #0x1b0]'),('0xfffffe000a688818','add','sp, sp, #0x1c0')]
 bad=[]
 for st in s['direct_stores']:
  if st['class']=='private_frame':
   lo,hi=st['relative_half_open_extent'];bad.append('(and (bvult BYTEIX '+bv(hi-lo)+') (bvult HV '+bv(2)+') (= '+add(add('K',lo),'BYTEIX')+' '+add(add('K',0x1c0),'HV')+'))')
 solve('all36_literal_frame_store_extents_exclude_header_low2_under_frame_epoch','(assert (or '+' '.join(bad)+'))')
 bad=[]
 for dst,count in fixed.values():bad.append('(and (bvult BYTEIX '+bv(count)+') (bvult HV '+bv(2)+') (= '+add(dst,'BYTEIX')+' '+add(add('K',0x1c0),'HV')+'))')
 solve('all7_private_destination_call_extents_exclude_header_low2','(assert (or '+' '.join(bad)+'))')
 # Source branch trees count the alignment prefix,Duff-loop first pass and tail.
 f=s['functions']['fill'];paths={};starts=[('prefix',0xfffffe000a687d78,0xfffffe000a687dd4,'w8'),('qword_first_pass',0xfffffe000a687dfc,0xfffffe000a687e60,'x11'),('tail',0xfffffe000a687e6c,0xfffffe000a687ec8,'x8')]
 for n,a,e,reg in starts:
  rows=fill_paths(f,a,e,reg);paths[n]=rows;expected='(ite (= SEL #x00000000) #x00000008 SEL)'if n=='qword_first_pass'else'SEL';terms=[]
  for row in rows:terms.append('(and '+' '.join(row['conditions']+[neq(bv(row['store_count'],32),expected)])+')')
  solve('fill_'+n+'_all_symbolic_paths_store_exact_count','(assert (bvule SEL #x00000007))\n(assert (or '+' '.join(terms)+'))')
 # All fill memory writes advance only the original destination by their widths.
 fii=f['instructions'];ss=[i for i in fii if i['mnemonic']in ['str','strb']];assert len(ss)==22
 assert all(split(i['operands'])[1]=='[x0]'for i in ss)and all(i['mnemonic']not in ['bl','blraa','blr','braa']for i in fii)
 assert [i for i in fii if split(i['operands'])[0]=='x0'and i['mnemonic']not in ['str','strb']]==[]
 assert all(i['operands'].startswith('w1,')for i in ss if i['mnemonic']=='strb')and all(i['operands'].startswith('x9,')for i in ss if i['mnemonic']=='str')
 assert [(i['mnemonic'],i['operands'])for i in fii[1:5]]==[('neg','w8, w0'),('and','x8, x8, #7'),('cmp','x2, x8'),('csel','x8, x2, x8, lo')]
 fat={int(i['ea'],16):i for i in fii}
 for a,m,o in [(0xfffffe000a687dd4,'sub','x8, x2, x8'),(0xfffffe000a687dd8,'cmp','x8, #8'),(0xfffffe000a687ddc,'b.lo','#0xfffffe000a687e68'),(0xfffffe000a687e60,'subs','x10, x10, #1'),(0xfffffe000a687e64,'b.ne','#0xfffffe000a687e40'),(0xfffffe000a687e68,'and','x8, x8, #7')]:assert fat[a]['mnemonic']==m and fat[a]['operands']==o
 assert all(split(i['operands'])[2:]==(['#8']if i['mnemonic']=='str'else []if i['ea']=='0xfffffe000a687ec4'else ['#1'])for i in ss)
 assert [(i['mnemonic'],i['operands'])for i in fii if 0xfffffe000a687de0<=int(i['ea'],16)<=0xfffffe000a687df8]==[('mov','w9, w1'),('mov','x10, #0x101010101010101'),('mul','x9, x9, x10'),('lsr','x10, x8, #3'),('add','x10, x10, #7'),('lsr','x10, x10, #3'),('ubfx','x11, x8, #3, #3')]
 align='(bvand (bvneg DST) #x0000000000000007)';pref='(ite (bvult COUNT '+align+') COUNT '+align+')';rem='(bvsub COUNT '+pref+')';q='(bvlshr '+rem+' #x0000000000000003)';r='(bvand '+rem+' #x0000000000000007)';cycles='(bvlshr (bvadd '+q+' #x0000000000000007) #x0000000000000003)';first='(ite (= (bvand '+q+' #x0000000000000007) #x0000000000000000) #x0000000000000008 (bvand '+q+' #x0000000000000007))'
 solve('fill_alignment_prefix_and_remaining_count_do_not_underflow','(assert (or (bvugt '+pref+' COUNT) (bvugt '+pref+' #x0000000000000007)))')
 solve('fill_qword_Duff_loop_counts_exactly_q_words','(assert (distinct '+q+' #x0000000000000000))\n(assert (or (= '+cycles+' #x0000000000000000) '+neq(add(first,'(bvmul (bvsub '+cycles+' #x0000000000000001) #x0000000000000008)'),q)+'))')
 solve('fill_total_written_bytes_equal_original_count','(assert '+neq(add(add(pref,'(bvmul '+q+' #x0000000000000008)'),r),'COUNT')+')')
 solve('fill_zero_argument_produces_zero_byte_and_qword_pattern','(assert '+neq('(bvmul ((_ zero_extend 32) #x00000000) #x0101010101010101)',bv(0))+')')
 prior=json.loads(read(ROOT/'core_stack_delta_abi_checks.json'))
 for n in ['complete_inner_arithmetic_prefix_global_targets_and_header_restoration','zero_delta_iff_final_header_low16_equals_snapshot_low16']:
  row=next(p for p in prior['proofs']if p['name']==n);proc=subprocess.run([SOLVER,'-in'],input=row['query'],text=True,capture_output=True,timeout=50);assert not proc.returncode and not proc.stderr and proc.stdout.strip()=='unsat';proofs.append({'name':'replayed_'+n,'query':row['query'],'result':'unsat','original_query_sha256':hashlib.sha256(row['query'].encode()).hexdigest(),'replayed_query':True})
 sem={'source_models':{n:g.record_full()for n,g in models.items()},'read_bindings':bindings,'fresh_bank_cuts':cuts,'fill_symbolic_branch_paths':paths,'scratch_global_pointer_address':'0xfffffe000ccc7848','scratch_cell80_has_two_phase_distinct_literal_writers':True,'zero_fill_footprint_proved_under_valid_nonwrapping_destination':True,'copy_footprint_is_external_callee_contract':True,'private_destination_calls':7,'external_copy_calls':4,'external_fill_calls':1,'hardware_calls':2,'full_inner_header_preservation_proved':False,'all_actual_deltas_proved_zero':False,'nominal_inner_CFG_closed':False,'diversity_equality_sufficient_for_CFG_closure':False,'status_record_root_requires_reaching_frame28_reload':True,'external_range_and_provider_effects_proved':False,'native_frame_or_transaction_proved':False,'Mach_port_emissions':0,'source_only_no_CPU_execution':True}
 sem['source_instruction_instances_translated']=sum(len(g.sites)for g in models.values());sem['distinct_source_instruction_sites_translated']=len({pc for g in models.values()for pc in g.sites});return proofs,sem
def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('wrong_copy_target',lambda t:t['bank_rules'][2].__setitem__('target','0x0')),('missing_store',lambda t:t['direct_stores'].pop()),('lost_external_discriminator_target',lambda t:t['matching_diversity_entries']['0x678'].pop()),('truncated_count_width',lambda t:next(i for i in t['fragments']['hardware_ABI']['instructions']if i['ea']=='0xfffffe000a5084b4').__setitem__('operands','x8, x2')),('fill_byte_step',lambda t:next(i for i in t['functions']['fill']['instructions']if i['ea']=='0xfffffe000a687db8').__setitem__('operands','w1, [x0], #2')),('invent_native',lambda t:t.__setitem__('target_executed',True))];rows=[]
 for n,fn in cases:
  t=copy.deepcopy(s);fn(t);assert t!=original;rows.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return rows
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);actual={pc for m in sem['source_models'].values()for pc in m['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']};assert actual==expected
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'source_instruction_instances_translated':sem['source_instruction_instances_translated'],'distinct_source_instruction_sites_translated':sem['distinct_source_instruction_sites_translated'],'fresh_bank_cuts':len(sem['fresh_bank_cuts']),'fill_symbolic_branch_paths':sum(map(len,sem['fill_symbolic_branch_paths'].values())),'predecessor_queries_replayed':2,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json']+DEPS},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'inner_write_frontier_established':True,'complete_operation_proved':False,**{n:False for n in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
