#!/usr/bin/env python3
"""Source-pinned48-step expansion,bounded lookup geometry and state-parametric words."""
import copy,json,re,shutil,subprocess,collections
from types import SimpleNamespace
from recover_daemon_mode_one_secondary_word_extension import ROOT,P,SCOPE,FLAGS,DEPS,PDF,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_checkpoint import PostSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq
from validate_daemon_list_output import split
from daemon_mode_one_handoff_tools import CandidateDAG
from validate_daemon_mode_one_record_word_extension import sigma
from validate_daemon_mode_one_secondary_word_import import dependency_bounds
SOLVER=shutil.which('z3');assert SOLVER
WORD_READ_PCS=[0x100c5044c,0x100c50460,0x100c504b0,0x100c504e8,0x100c50d20,0x100c50d64,0x100c50e48,0x100c50e64]
READ_BASES=[143,213,156,226,72,81,0,9]
WRITE_BASES=[88,16,158,228]
STREAM_BASES=[0,72,142,212]
BANKS={'SUM':(72,328),'XOR':(333,589),'DEC':(659,675),'CARRY':(677,933),'ENC':(936,952)}
FAMILY_PROPOSALS={'ENC': [4307881788, 4307881824, 4307881864, 4307881896, 4307882180, 4307882256, 4307882420, 4307882456, 4307882500, 4307882608, 4307882736, 4307882880, 4307882932, 4307882960, 4307883104, 4307883172], 'SUM': [4307883328, 4307883552, 4307883592, 4307883824, 4307883868, 4307883924, 4307884056, 4307884104, 4307884144, 4307884304, 4307884352, 4307884400, 4307884620, 4307884736, 4307884760, 4307884964, 4307885024, 4307885044, 4307885300, 4307885324, 4307885376, 4307885520], 'CARRY': [4307883400, 4307883668, 4307883716, 4307883972, 4307884024, 4307884224, 4307884272, 4307884504, 4307884556, 4307884840, 4307884896, 4307885172, 4307885196, 4307885540], 'XOR': [4307883452, 4307885808, 4307886052, 4307886056, 4307886428, 4307886432, 4307886492, 4307886540, 4307886672], 'DEC': [4307886760, 4307886796, 4307886820, 4307886852, 4307886960, 4307887032, 4307887168, 4307887184]}
SIGMA_ROWS=[('input0_sigma0',0x100c50528,22,0,0,0xdde224a2,0x093330d9),('input2_sigma1',0x100c5055c,12,2,1,0x415e95aa,0x6080035f),('input1_sigma0',0x100c50594,4,1,0,0,0xa88ddd29),('input3_sigma1',0x100c505ac,1,3,1,0,0x63524e89)]
class ExtensionSSA(PostSSA):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.snapshots={};self.eons=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='eon':
    p=split(i['operands']);assert len(p)==3 and p[0].startswith('w');self.put(p[0],'(bvxor '+self.get(p[1],32)+' (bvnot '+self.get(p[2],32)+'))');self.sites.append(i['ea']);self.eons.append({'site':i['ea'],'width_bits':32,'operation':'Rn XOR NOT(Rm);no shift'})
   else:super().run({'instructions':[i]},pc+4)
   if pc in{r[1]for r in SIGMA_ROWS}:self.snapshots[i['ea']]={str(reg):self.get('w'+str(reg))for reg in range(31)}
  return self
 def record_full(self):return{**super().record_full(),'sigma_source_snapshots':self.snapshots,'EON_lowerings':self.eons}
def model(s,name,zero_words=False):
 f=s['fragments']['loop'];bb=[i for i in f['instructions']if i['mnemonic']=='ldrb'];assert len(bb)==69
 loads={hex(pc):(bv(0,32)if zero_words else'WORD'+str(j),32)for j,pc in enumerate(WORD_READ_PCS)};loads.update({i['ea']:('RB'+str(j),8)for j,i in enumerate(bb)});loads['0x100c52698']=('CFN',64)
 regs={1:bv(0xe525982b),2:bv(0x7293),3:bv(286),4:z('(bvadd #x5f521b8d IX)'),12:z('(bvmul IX #x000000f1)'),14:bv(241),15:z('(bvadd #x00000879 (bvmul IX #x000000f1))'),20:z('(bvadd #x00000df2 (bvmul IX #x000000f1))'),22:z('(bvadd #x0000d6a4 (bvmul IX #x000000f1))'),23:z('(bvsub #x0000002f IX)'),24:z('(bvadd #x0000d4c2 (bvmul IX #x000000f1))'),21:frame(0x8b0),27:frame(0xc80)}
 presets={0x740:('TABLE',64),0x750:(frame(0xc80),64),0x758:(frame(0x8b0),64),0x6a8:(bv(286,32),32),0x6bc:(bv(0x1ef1,32),32),0x6b0:('ENCODEDZERO',32),0x738:('STATEA',32),0x730:('STATEB',32)}
 g=ExtensionSSA(name,regs,presets=presets,loads=loads);g.decl.update(CFN=64,ENCODEDZERO=32,STATEA=32,STATEB=32,**{'WORD'+str(j):32 for j in range(8)},**{'RB'+str(j):8 for j in range(69)});g.run(f,int(f['instructions'][-1]['ea'],16));return g

def remainder_candidates(g):
 d=CandidateDAG()
 for n,w in g.decl.items():d.alias[n]=d.intern(('sym',n),w)
 d.defs(g.prefix());inverse={}
 for name,node in d.alias.items():inverse.setdefault(node,name)
 out=[]
 def kind(x):return d.nodes[x][0][0]
 proposal={hex(pc):family for family,pcs in FAMILY_PROPOSALS.items()for pc in pcs};assert len(proposal)==69
 for r in g.reads:
  if r['width_bits']!=8:continue
  index=d.index(r['address']);short=kind(index)=='extract'
  if short:assert d.nodes[index][0][2:]==(15,0);index=d.nodes[index][0][1]
  k,w=d.nodes[index];assert k[0]=='bvsub'and w==32;n,product=k[1:];kp,_=d.nodes[product];assert kp[0]=='bvmul'and any(d.const(v)==962 for v in kp[1:]);q=next(v for v in kp[1:]if d.const(v)!=962)
  if kind(q)=='extract':assert d.nodes[q][0][2:]==(31,0);q=d.nodes[q][0][1]
  kq,_=d.nodes[q];assert kq[0]=='bvlshr';prod,shift=kq[1:];km,pw=d.nodes[prod];assert km[0]=='bvmul'and pw==64;cc=[v for v in km[1:]if d.const(v)is not None];assert len(cc)==1;coef=d.const(cc[0]);arg=next(v for v in km[1:]if v!=cc[0]);assert kind(arg)=='zext';arg=d.nodes[arg][0][1];input_shift=0
  if arg!=n:ka,aw=d.nodes[arg];assert ka[0]=='bvlshr'and ka[1]==n;input_shift=d.const(ka[2])
  shift=d.const(shift);assert(coef,shift,input_shift)in[(0x441fef,32,0),(0x883fddf1,40,1)]
  out.append({'site':r['site'],'original_address':r['address'],'numerator_source_ref':inverse[n],'coefficient':coef,'shift':shift,'input_shift':input_shift,'product_width':64,'extract_low16':short,'candidate_family':proposal[r['site']],'family_proved':coef==0x441fef,'candidate_method':'Typed DAG proposes shapes;original source-SMT and independent integer lemmas supply certificates. Full29 fixed-family proposals are expressly refuted under the broad component inputs.'})
 assert len(out)==69 and sum(r['coefficient']==0x441fef for r in out)==40;return out

def frame_value(m,off,w):
 parts=[m['final_frame_bytes'][str(off+j)][0]for j in reversed(range(w//8))];v=parts[0]
 for part in parts[1:]:v='(concat '+v+' '+part+')'
 return v
def add(values):
 v=values[0]
 for a in values[1:]:v='(bvadd '+v+' '+a+')'
 return v

def certificates(s):
 pp=[];models={};fs=s['fragments'];domain=['(bvult IX #x00000030)']
 def solve(name,g=None,terms=(),cc=(),result='unsat',integer=False,body='',extra=''):
  q='(set-option :timeout 45000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+(''if integer else DECL)+extra
  if g is not None:q+=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
  q+=body+''.join('(assert '+v+')\n'for v in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat)\n'if integer else'(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';p=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not p.returncode and not p.stderr and p.stdout.strip()==result,(name,p.stdout[:1600],p.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def replay(name,selected):
  c=json.loads(read(ROOT/(name+'_checks.json')));assert c['all_checks_pass'];rows=[r for r in c['proofs']if selected(r)];assert rows
  for row in rows:
   p=subprocess.run([SOLVER,'-in'],input=row['query'],text=True,capture_output=True,timeout=50);assert not p.returncode and not p.stderr,(name,row['name'],p.stdout[:1600],p.stderr)
   assert p.stdout.strip()=='unsat'if row['result']=='unsat'else row['result']=='sat'and p.stdout.startswith('sat\n'),(row['name'],p.stdout[:1600]);pp.append({**row,'name':'replayed_'+name+'_'+row['name'],'replayed_query':True})
  print('replayed',name,len(rows),flush=True);return c,len(rows)
 old,n=replay('daemon_mode_one_secondary_word_import',lambda p:not p.get('replayed_query',False));assert n==10
 other,n2=replay('daemon_mode_one_record_word_extension',lambda p:p['name']in['sigma0_unmasked_pair','sigma1_unmasked_pair','sigma0_masked_word','sigma1_masked_word']);assert n2==4
 pm=old['semantics']['source_models']['post_import_chained_to_quad3'];rr=pm['final_registers'];expected={1:0xe525982b,2:0x7293,3:286,4:0x5f521b8d,12:0,14:241,15:0x879,20:0xdf2,22:0xd6a4,23:47,24:0xd4c2};pd=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in pm['declarations'].items())
 solve('actual_parent_full_initial_control_ABI_and_saved_roots',terms=[neq(rr[str(k)],bv(v))for k,v in expected.items()]+[neq(rr['21'],frame(0x8b0)),neq(rr['27'],frame(0xc80)),neq(frame_value(pm,0x750,64),frame(0xc80)),neq(frame_value(pm,0x758,64),frame(0x8b0)),neq(frame_value(pm,0x6a8,32),bv(286,32)),neq(frame_value(pm,0x6bc,32),bv(0x1ef1,32))],cc=['(= QUAD #x00000003)'],body=pm['source_SSA'],extra=pd)
 g=model(s,'extension');models['loop']=g;rf={r['site']for r in g.frame_reads};sf={r['site']for r in g.frame_writes};reads=[r for r in g.reads if r['width_bits']==32 and r['site']not in rf];stores=[r for r in g.stores if r['site']not in sf]
 assert(len(g.sites),len(g.reads),len(g.frame_reads),len(g.stores),len(g.frame_writes),len(g.initial),len(g.cuts))==(2244,169,91,27,23,0,0);assert len(reads)==8 and len(stores)==4 and len(g.eons)==1
 def addr(label):return '(bvadd '+frame(0xc80)+' ((_ zero_extend 32) (bvshl (bvurem (bvmul (bvadd IX '+bv(label,32)+') #x000000f1) #x0000011e) #x00000002)))'
 solve('all_eight_original_word_addresses',g,[neq(r['address'],addr(b))for r,b in zip(reads,READ_BASES)],cc=domain)
 solve('all_four_original_word_store_addresses',g,[neq(r['address'],addr(b))for r,b in zip(stores,WRITE_BASES)],cc=domain)
 terms=[neq(g.get('x1'),bv(0xe525982b)),neq(g.get('x2'),bv(0x7293)),neq(g.get('x3'),bv(286)),neq(g.get('w4'),'(bvadd #x5f521b8e IX)'),neq(g.get('x14'),bv(241)),neq(g.get('w12'),'(bvmul (bvadd IX #x00000001) #x000000f1)'),neq(g.get('w23'),'(bvsub #x0000002e IX)'),neq(g.get('x21'),frame(0x8b0)),neq(g.get('x27'),frame(0xc80)),neq(g.get('x17'),bv(0x5b22)),neq(next(r for r in g.reads if r['site']=='0x100c52698')['address'],'(ite (= IX #x0000002f) '+at(0xa529)+' '+at(0x1ef1)+')')]
 terms +=[neq(g.get('w'+str(j)),'(bvadd '+bv(base,32)+' (bvmul (bvadd IX #x00000001) #x000000f1))')for j,base in[(15,0x879),(20,0xdf2),(22,0xd6a4),(24,0xd4c2)]]
 terms +=[neq(g.loadframe(0x748,32),'(bvmul IX #x000000f1)'),neq(g.loadframe(0x710,32),'(bvsub #x0000002f IX)'),neq(g.loadframe(0x6a8,32),bv(286,32)),neq(g.loadframe(0x6bc,32),bv(0x1ef1,32))]
 solve('closing_counter_biases_roots_and_repeat_exit',g,terms,cc=domain)
 sr={r['site']:r for r in g.stores};lr={r['site']:r for r in g.reads};solve('all23_literal_frame_stores_and91_frame_reads',g,[neq(sr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_writes]+[neq(lr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_reads])
 solve('finite48_step_progress_and_last_countdown_underflow',terms=['(bvule (bvadd IX #x00000001) IX)','(bvugt (bvadd IX #x00000001) #x00000030)','(distinct (= (bvsub #x0000002f IX) #x00000000) (= IX #x0000002f))','(and (= IX #x0000002f) (distinct (bvsub #x0000002e IX) #xffffffff))'],cc=domain)
 sigma_records=[]
 for name,pc,reg,word,which,mask,outmask in SIGMA_ROWS:
  arg='WORD'+str(word);arg='(bvxor '+arg+' '+bv(mask,32)+')'if mask else arg;want='(bvxor '+sigma(arg,which)+' '+bv(outmask,32)+')';actual=g.snapshots[hex(pc)][str(reg)];solve(name+'_exact_source_identity',g,[neq(actual,want)]);sigma_records.append({'name':name,'site':hex(pc),'output_register':'W'+str(reg),'input':'WORD'+str(word),'sigma':which,'input_XOR_mask':hex(mask),'output_XOR_mask':hex(outmask),'actual_source_expression':actual,'standard_expression':want})
 byte_rows=remainder_candidates(g);short=[r for r in byte_rows if r['coefficient']==0x441fef];long=[r for r in byte_rows if r['coefficient']!=0x441fef]
 solve('all40_short_form_numerators_at_most759849',g,['(bvugt '+r['numerator_source_ref']+' '+bv(759849,32)+')'for r in short])
 shapes=[]
 for r in byte_rows:
  n=r['numerator_source_ref'];arg=n if not r['input_shift']else'(bvlshr '+n+' '+bv(r['input_shift'],32)+')';rem='(bvsub '+n+' (bvmul ((_ extract 31 0) (bvlshr (bvmul ((_ zero_extend 32) '+arg+') '+bv(r['coefficient'])+') '+bv(r['shift'])+')) #x000003c2))'
  if r['extract_low16']:rem='((_ zero_extend 16) ((_ extract 15 0) '+rem+'))'
  shapes.append(neq(r['original_address'],'(bvadd '+frame(0x8b0)+' ((_ zero_extend 32) '+rem+'))'))
 solve('all69_original_primary_byte_remainder_shapes',g,shapes)
 family_terms=[]
 for r in short:
  lo,hi=BANKS[r['candidate_family']];n=r['numerator_source_ref'];family_terms +=['(bvult '+n+' '+bv(lo*799,32)+')','(bvugt '+n+' '+bv((hi-1)*799,32)+')','(distinct (bvurem '+n+' #x0000031f) #x00000000)']
 solve('forty_sites_have_proved_initialized_bank_membership',g,family_terms)
 full_family_terms=[]
 for r in long:
  n=r['numerator_source_ref'];j='(bvurem (bvmul (bvurem '+n+' #x000003c2) '+bv(pow(799,-1,962),32)+') #x000003c2)';lo,hi=BANKS[r['candidate_family']];full_family_terms +=['(bvult '+j+' '+bv(lo,32)+')','(bvuge '+j+' '+bv(hi,32)+')']
 solve('remaining29_sampled_fixed_bank_assignment_has_component_counterexample',g,full_family_terms,cc=domain,result='sat')
 math=[]
 for label,coef,shift,half,limit in[('small',0x441fef,32,False,759849),('full',0x883fddf1,40,True,0xffffffff)]:
  arg='(div N 2)'if half else'N';quot='(div (* '+arg+' '+str(coef)+') '+str(1<<shift)+')';cc=['(and (<= 0 N) (<= N '+str(limit)+'))'];extra='(declare-fun N () Int)\n'
  solve(label+'_integer_reciprocal_equals_div962',integer=True,extra=extra,cc=cc,terms=['(distinct '+quot+' (div N 962))'])
  solve(label+'_integer_product_msub_widths_and_remainder',integer=True,extra=extra,cc=cc,terms=['(> (* '+arg+' '+str(coef)+') '+str(2**64-1)+')','(> '+quot+' '+str(2**32-1)+')','(> (* '+quot+' 962) N)','(> (* '+quot+' 962) '+str(2**32-1)+')','(< (- N (* '+quot+' 962)) 0)','(>= (- N (* '+quot+' 962)) 962)'])
  math.append({'label':label,'coefficient':hex(coef),'output_shift':shift,'input_div2':half,'numerator_max':limit,'maximum_product':(limit//2 if half else limit)*coef,'remainder_domain':[0,961],'u64_product_u32_msub_proved':True})
 solve('low16_extract_preserves_remainders_below962',terms=['(distinct ((_ zero_extend 16) ((_ extract 15 0) VALUE)) VALUE)'],cc=['(bvule VALUE #x000003c1)'])
 extra='(declare-fun A32 () (_ BitVec 32))\n(declare-fun B32 () (_ BitVec 32))\n'
 solve('EON32_boolean_complement_identity',extra=extra,terms=[neq('(bvxor A32 (bvnot B32))','(bvnot (bvxor A32 B32))')])
 solve('CNEG_NE_is_inverted_CSNEG_EQ_alias',extra=extra,terms=[neq('(ite (distinct (bvand A32 B32) #x00000000) (bvneg A32) A32)','(ite (= (bvand A32 B32) #x00000000) A32 (bvneg A32))')])
 # This second translation specializes only named array-word values to zero.
 # Its first store defines the exact component-state bias,not a native sample.
 zero=model(s,'zero_words',True);models['zero_word_bias_specialization']=zero;zstores=[r for r in zero.stores if r['site']not in{v['site']for v in zero.frame_writes}];bias=zstores[0]['value'];bias_dependencies=dependency_bounds(SimpleNamespace(decl={**zero.decl,'IX':32},defs=zero.defs),zstores[:1])[0]['syntactic_input_upper_bound'];assert bias_dependencies==['STATEA','Z25','Z5']
 desired=add([sigma('WORD1',0),sigma('WORD3',1),'WORD4','WORD5',bias]);solve('stream72_exact_state_parametric_additive_word_dependence',g,[neq(stores[0]['value'],desired)],body=zero.prefix())
 second=add([sigma('(bvxor WORD0 #xdde224a2)',0),sigma('(bvxor WORD2 #x415e95aa)',1),'WORD6','WORD7','(bvsub '+zstores[1]['value']+' '+add([sigma('#xdde224a2',0),sigma('#x415e95aa',1)])+')']);solve('analogous_stream0_additive_proposal_is_false',g,[neq(stores[1]['value'],second)],body=zero.prefix(),cc=domain,result='sat')
 # Candidate constants came from an all-zero abstract parent valuation.
 # SAT refutes the four-pair conjunction,not every individual relation.
 pm=old['semantics']['source_models']['import_words'];parent_rows=old['semantics']['iteration_ledger'][0]['word_store_ledger'];values={r['coordinate_label']:r['value']for r in parent_rows};pd=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in pm['declarations'].items());pair_records=[]
 for base,other,masks in[(0,142,[0xeed9f885,0x1f717798,0x1ad3488c,0xa58a8afc]),(72,212,[0x9fe2d299,0x9fe2d299,0x39aca50a,0x7fdad914])]:
  terms=[neq('(bvxor '+values[base+j]+' '+values[other+j]+')',bv(masks[j],32))for j in range(4)];solve('sampled_constant_XOR_pair_group_'+str(base)+'_'+str(other)+'_is_false',terms=terms,cc=['(= QUAD #x00000000)'],result='sat',body=pm['source_SSA'],extra=pd);pair_records.append({'bases':[base,other],'sampled_masks':[hex(v)for v in masks],'scope':'SAT refutes the simultaneous four-pair constant-XOR proposal in the broad parent component model;no native reachability or individual-pair classification follows.'})
 known={base+j for base in STREAM_BASES for j in range(16)};initial=set(known);ledger=[];written=set()
 for ix in range(48):
  labels=[ix+b for b in READ_BASES];new=[ix+b for b in WRITE_BASES];assert set(labels)<=known and len(set(new))==4 and not set(new)&known;rows=[]
  for label,row in zip(new,stores):
   off=0xc80+4*(241*label%286);assert not written&set(range(off,off+4));written.update(range(off,off+4));rows.append({'site':row['site'],'coordinate_label':label,'slot':241*label%286,'frame_offset':off})
  ledger.append({'IX':ix,'conventional_position_t':16+ix,'incoming_countdown':47-ix,'outgoing_countdown_u32':(46-ix)&0xffffffff,'read_labels':labels,'word_stores':rows,'known_words_before':len(known),'repeat':ix<47});known.update(new)
 assert len(known)==256 and known=={base+j for base in STREAM_BASES for j in range(64)}and len(written)==768 and max(written)==0x10f7
 initial_bytes={0xc80+4*(241*label%286)+j for label in initial for j in range(4)};assert len(initial_bytes)==256 and not initial_bytes&written and len(initial_bytes|written)==1024
 fw={r['frame_offset']+j for r in g.frame_writes for j in range(r['width_bits']//8)};assert len(fw)==76 and not fw&(written|initial_bytes)and max(fw)==0x74b
 protected=[(0x350,8),(0x358,8),(0x360,8),(0x368,16),(0x380,16),(0x4e4,4),(0x6a8,4),(0x6b0,4),(0x6bc,4),(0x740,8),(0x750,16),(0x768,296),(0x8b0,962),(0x1100,1),(0x1150,1),(0x1210,8)]
 assert all(not(fw|written)&set(range(off,off+n))for off,n in protected)
 after=ExtensionSSA('after',g.r);after.defs=list(g.defs);after.decl=dict(g.decl);after.byte_cells=dict(g.byte_cells);after.decl['CTX4E4']=32;after.save(0x4e4,'CTX4E4',32,'explicit next-prefix context input');after.run(fs['after'],int(fs['after']['end'],16));models['exit_prefix']=after;assert len(after.sites)==7 and len(after.reads)==1 and len(after.stores)==1 and not after.initial
 V='(bvadd (bvadd CTX4E4 '+g.get('w7')+') #xaeff9d92)';solve('exit_prefix_low32_reset_and_F4e4_register_handoff',after,[neq(after.loadframe(0x748,32),bv(0,32)),neq(after.get('w3'),V),neq(after.get('w8'),'(bvlshr '+V+' #x0000001c)')],cc=['(= IX #x0000002f)'])
 solve('exit_prefix_original_one_store_and_new_context_load',after,[neq(after.stores[0]['address'],frame(0x748)),neq(after.reads[0]['address'],frame(0x4e4))])
 solve('abstract48_iteration_component_domain_nonempty',cc=domain,result='sat')
 assert set(g.sites)|set(after.sites)=={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'}
 assert(sum(r['width_bits']//8 for r in g.reads),sum(r['width_bits']//8 for r in g.stores))==(729,108)
 sem={'source_models':{name:m.record_full()for name,m in models.items()},'source_nonbranch_sites_translated':2251,'selected_traversal_nonbranch_instances':48*2244+7,'parent_direct_queries_replayed':10,'analogous_record_sigma_queries_replayed':4,'initial_control_GPRs_at_IX0':expected,'initial_other_GPRs':'Unrestricted u64;word loads are eight independent u32 inputs and lookup loads are69 independent u8 inputs.','scalar_premises':{'F6a8':286,'F6bc':'0x1ef1','F6b0':'arbitraryu32 ENCODEDZERO','F738':'arbitraryu32 STATEA','F730':'arbitraryu32 STATEB'},'iteration_domain':'0<=IX<48;logical t=IX+16','iterations':48,'incoming_W23':'47-IX','outgoing_W23':'46-IX mod2^32;0xffffffff at final exit','incoming_W12':'241*IX','outgoing_W12':'241*(IX+1)','root_X27':'F+0xc80','root_X21':'F+0x8b0','coordinate':'D(j)=F+0xc80+4*((241*j)mod286)','stream_bases':STREAM_BASES,'read_label_offsets':READ_BASES,'write_label_offsets':WRITE_BASES,'word_read_source_ledger':reads,'word_store_source_ledger':stores,'iteration_coverage_ledger':ledger,'initial_known_words':sorted(initial),'final_known_words':sorted(known),'initial_word_bytes':256,'new_word_stores':192,'new_word_bytes':768,'final_populated_words':256,'final_populated_word_bytes':1024,'unclaimed_grid_slots':30,'native_grid_allocation_extent_proved':False,'new_secondary_last_written_byte':'F+0x10f7','grid_domain_end_exclusive':'F+0x10f8','gap_before_F1100_view_bytes':8,'primary_byte_sites':69,'primary_byte_reads_total':3312,'primary_byte_offset_bounds':[0,961],'primary_byte_bounds_need_lookup_codomain_premises':False,'byte_read_ledger':byte_rows,'short_reciprocal_sites':40,'short_source_numerator_bound':759849,'full_reciprocal_sites':29,'reciprocal_integer_certificates':math,'forty_proved_bank_counts':dict(collections.Counter(r['candidate_family']for r in short)),'remaining29_sample_family_assignment_proved':False,'all69_membership_in_initialized800_cells_proved':False,'pre_mutation_numeric_tables_current_validity_proved':False,'current_table_byte_values_proved':False,'sigma_identities':sigma_records,'sigma0':'ROR32(x,7) XOR ROR32(x,18) XOR SHR32(x,3)','sigma1':'ROR32(x,17) XOR ROR32(x,19) XOR SHR32(x,10)','primary_standard_reference':s['standard_reference'],'state_parametric_stream72_recurrence':'S72[t]=sigma0(S212[t-15])+sigma1(S212[t-2])+S72[t-16]+S72[t-7]+Theta mod2^32','Theta_definition':'First original store value in zero_word_bias_specialization,with eight word inputs zero and identical component entry state.','Theta_source_ref':bias,'Theta_syntactic_input_upper_bound':bias_dependencies,'Theta_constant_or_linear_proved':False,'first_stream_additive_source_expression':desired,'second_stream_additive_candidate_proved':False,'second_stream_rejected_expression':second,'parent_constant_XOR_pair_negative_controls':pair_records,'whole_decoded_standard_schedule_proved':False,'whole_hash_algorithm_identified':False,'per_iteration_loads':169,'per_iteration_stores':27,'per_iteration_read_bytes':729,'per_iteration_store_bytes':108,'private_frame_store_effects':23,'private_frame_store_bytes':92,'private_frame_distinct_written_bytes':76,'private_frame_store_ledger':g.frame_writes,'frame_epoch_stores':{hex(off):[r for r in g.frame_writes if r['frame_offset']==off]for off in[0x748,0x710,0x738,0x730,0x6f0,0x6e8]},'protected_ranges':[{'offset':off,'size_bytes':n}for off,n in protected],'loop_loads_total':8112,'loop_stores_total':1296,'loop_read_bytes_total':34992,'loop_store_bytes_total':5184,'loop_distinct_written_bytes':844,'exit_prefix_loads':1,'exit_prefix_stores':1,'exit_prefix_read_bytes':4,'exit_prefix_store_bytes':4,'loop_and_prefix_loads':8113,'loop_and_prefix_stores':1297,'loop_and_prefix_read_bytes':34996,'loop_and_prefix_store_bytes':5188,'loop_and_prefix_distinct_written_bytes':844,'frame_F748_epoch':'Loop:241*IX u32;next prefix clears only its low32 bits.','frame_F710_epoch':'Saved incoming countdown47-IX;not the returned underflowed W23.','frame_F738_and_F730':'Opaque evolving u32 component state;not established as counters,constant masks or linear encodings.','exit_slot':'0xa529','exit_target':'0x100c2c25c','repeat_slot':'0x1ef1','repeat_target':'0x100c503c8','control_diversity':'0x5b22','exit_prefix_new_input':'u32[F+0x4e4]=CTX4E4;producer/owner/meaning unknown in this increment.','exit_prefix_W3':'u32(CTX4E4+incoming W7+0xaeff9d92)','exit_prefix_W8':'exit_prefix_W3 SHR28','remaining_exit_block_instructions_untranslated':s['exit_block_census']['source_instructions']-7,'source_value_cuts':0,'computed_address_normalizations':0,'initial_unprescribed_frame_inputs':0,'LOCAL_pointer_dereferences':0,'Mach_port_emissions':0,'new_IDA_access':False,'native_reachability_proved':False,'native_mapping_proved':False,'native_ownership_proved':False,'successful_output_proved':False,'daemon_kext_pairing_proved':False,'native_claim':False,'excluded_exploration':'An initial dual-translation query placed zero-source definitions before declarations and was strictly rejected;the accepted order declares shared inputs before both source prefixes. An initial translator lacked EON;the local EON32 lowering and original encoding are now explicit. An initial exploratory duplicate IX declaration was rejected despite a following SAT token;accepted queries reject all errors/unknown/timeouts. Coarse numerator bounds and zero-valuation bank proposals were candidates only. A raw-numerator family range proposal for all69 and the remaining29 logical fixed-family proposal returned SAT;only the40 independently proved assignments are claimed. An all-zero-derived XOR/linear state-bias fit and an F738-derived constant-mask hypothesis returned SAT and are not semantic assumptions. Sampled pair-XOR proposals and the analogous second-stream additive proposal are expressly refuted in the retained query set. No native inputs or observations arise from these abstract controls.'}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['loop'].__setitem__('bytes','00'+q['fragments']['loop']['bytes'][2:])),('wrong_repeat_target',lambda q:q['branch_edges'][0].__setitem__('target','0x0')),('wrong_exit_target',lambda q:q['branch_edges'][1].__setitem__('target','0x0')),('wrong_EON_width',lambda q:q['EON_decode_checks'][0].__setitem__('width_bits',64)),('wrong_CNEG_condition',lambda q:q['CNEG_decode_checks'][0].__setitem__('alias_condition','EQ')),('wrong_bitfield_width',lambda q:q['bitfield_decode_checks'][0].__setitem__('source_count',0)),('wrong_standard_hash',lambda q:q['standard_reference'].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[];original=build()
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert q!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':2251,'selected_traversal_nonbranch_instances':107719,'iterations':48,'word_read_operations':384,'new_word_stores':192,'new_word_bytes':768,'final_populated_words':256,'final_populated_word_bytes':1024,'unclaimed_grid_slots':30,'primary_byte_reads_bounded':69,'primary_byte_reads_total':3312,'short_reciprocal_sites':40,'full_reciprocal_sites':29,'short_numerator_upper_bound':759849,'proved_bank_membership_sites':40,'proved_SUM_sites':11,'proved_CARRY_sites':3,'proved_XOR_sites':3,'proved_ENC_sites':15,'proved_DEC_sites':8,'source_sigma_identities':4,'state_parametric_additive_streams':1,'rejected_second_additive_streams':1,'rejected_pair_XOR_groups':2,'per_iteration_loads':169,'per_iteration_stores':27,'per_iteration_read_bytes':729,'per_iteration_store_bytes':108,'private_frame_stores':23,'private_frame_distinct_written_bytes':76,'loop_and_prefix_loads':8113,'loop_and_prefix_stores':1297,'loop_and_prefix_read_bytes':34996,'loop_and_prefix_store_bytes':5188,'loop_and_prefix_distinct_written_bytes':844,'source_value_cuts':0,'computed_address_normalizations':0,'initial_unprescribed_frame_inputs':0,'primary_standard_bytes':833315,'rejected_alterations':len(aa)}
 assert sem['selected_traversal_nonbranch_instances']==counts['selected_traversal_nonbranch_instances']
 deps=[P+'_source.json','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_lookup_algebra.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','validate_daemon_mode_one_word_schedule.py','validate_daemon_mode_one_secondary_word_import.py','validate_daemon_mode_one_record_word_extension.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{name:sha(ROOT/name)for name in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'secondary_word_extension_geometry_bounds_sigma_and_state_dependence_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
