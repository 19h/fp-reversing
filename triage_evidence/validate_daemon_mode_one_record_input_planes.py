#!/usr/bin/env python3
"""Source-proved short-input byte codec,paired-plane loop and long handoff."""
import copy,json,re,subprocess,shutil
from recover_daemon_mode_one_record_input_planes import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_mode_one_handoff_tools import FrameSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,at,frame
from validate_daemon_mode_one_record_join import EXTRA as PARENT_EXTRA
from validate_daemon_constructor_lookup import KEYS
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=PARENT_EXTRA+'(declare-fun IDX () (_ BitVec 32))\n(declare-fun PBUF () (_ BitVec 64))\n(declare-fun MASK () (_ BitVec 64))\n'
UU=[(0xbd700+866*j)%961 for j in range(64)]
VV=[(0xaed96+866*j)%961 for j in range(64)]
def lookup(values,arg):
 value=bv(values[-1],32)
 for j in range(len(values)-2,-1,-1):value=f'(ite (= {arg} {bv(j,32)}) {bv(values[j],32)} {value})'
 return value
def certificates(s):
 pp=[];models={};fs=s['fragments'];cuts=[]
 def solve(name,body,result='unsat',cc=(),integer=False,arrays=False,extra=''):
  query='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_ABV'if arrays else'QF_BV')+')\n'+('(declare-fun XI () Int)\n'if integer else DECL+EXTRA)+extra+body+'\n'+''.join('(assert '+c+')\n'for c in cc)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=20)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':query,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def pre(g):return ''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
 def cert(name,g,terms,cc=()):solve(name,pre(g)+'(assert (or '+' '.join(terms)+'))',cc=cc)
 def rd(g,pc):return next(v for v in g.reads if v['site']==hex(pc))
 def run(g,name,a=None,end=None):
  f=fs[name];g.run({'instructions':[v for v in f['instructions']if a is None or int(v['ea'],16)>=a]},end or int(f['instructions'][-1]['ea'],16));return g
 def chained(name,g,regs=None,loads=None):
  out=FrameSSA(name,{**g.r,**(regs or{})},loads=loads);out.defs=list(g.defs);out.decl=dict(g.decl);out.byte_cells=dict(g.byte_cells);out.loaded=g.loaded;return out
 from recover_daemon_mode_one_record_join import build as previous_build
 from validate_daemon_mode_one_record_join import certificates as previous_certificates
 old=previous_build();assert old==json.loads(read(ROOT/DEPS[0]));prior=json.loads(read(ROOT/DEPS[1]));bp,bs=previous_certificates(old)
 assert bp==prior['proofs']and json.loads(json.dumps(bs))==prior['semantics'];pp.extend({**p,'name':'replayed_join_'+p['name'],'replayed_query':True}for p in bp)
 pm=bs['source_model']
 def saved(off,w=32):
  parts=[pm['final_frame_bytes'][off+j][0]for j in reversed(range(w//8))];value=parts[0]
  for part in parts[1:]:value=f'(concat {value} {part})'
  return value
 decl=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in pm['declarations'].items())
 solve('actual_join_supplies_both_successor_control_fields',decl+pm['source_SSA']+'(assert (or '+neq(saved(0x620),bv(0x3c0d,32))+' '+neq(saved(0x18),bv(0xb5e1,32))+' '+neq(saved(0x598),bv(0x81112185,32))+'))')
 common={0x620:(bv(0x3c0d,32),32),0x18:(bv(0xb5e1,32),32),0x598:(bv(0x81112185,32),32),0x728:('COUNT',32),0x740:('TABLE',64),0x748:('PBUF',64),0x750:(frame(0xd10),64),0x4d8:(bv(0x7f3081c2),64)}
 initial={4:bv(0x39c7500a),6:bv(0x53921748),8:bv(0x7f3081c2)}
 short=FrameSSA('short',initial,presets=common,loads={'0x100c4a208':('FN',64)});run(short,'short');models['short']=short
 short_domain=['(bvult COUNT #x00000040)']
 cert('short_setup_zero_partition_saved_phase_and_buffer',short,[neq(rd(short,0x100c4a208)['address'],f'(ite (= COUNT #x00000000) {at(0x3c0d)} {at(0x782c)})'),neq(short.loadframe(0x6f8,32),bv(0x4719,32)),neq(short.get('w9'),'(bvadd COUNT #x39c7500a)'),neq(short.get('x3'),'PBUF'),neq(short.get('w16'),bv(0xbdf3fb52,32)),neq(short.get('w30'),bv(961,32))],short_domain);assert len(short.stores)==len(short.frame_writes)==1
 setup=chained('short_loop_seed',short,loads={'0x100c65c04':('FN',64)});run(setup,'setup');models['setup']=setup
 key_registers=[0,1,2,3,4,5,6,7,19,20,21,22,23,25,26,28,30]
 constants={0:0xb47faaf81a732f68,1:0x1161e26185a1560e,2:0x080da9f5faed7516,4:KEYS[0],5:0xa7bebfcf1750d389,6:0x4923,7:0xb6dc5654307e7f72,19:0x9bc794aef0c360b0,20:0x005af3a82df0ce0c,21:0x95a858ee5d7b24cb,22:0xe4a7beffdf1f71f3,23:0x99e54358178f9594,25:0xb325064bf33d6f30,26:0x00144db9b1af6b57,28:0x378f295de186c160,30:961}
 cert('nonzero_short_seed_stride_counter_and_codec_constants',setup,[neq(setup.get('x'+str(k)),bv(v))for k,v in constants.items()]+[neq(setup.get('x3'),'PBUF'),neq(setup.loadframe(0x730,32),bv(866,32)),neq(setup.loadframe(0x738,32),bv(0x80cf7e3e,32)),neq(setup.loadframe(0x6f8,32),bv(0x4719,32)),neq(setup.get('x8'),bv(0x7f3081c2)),neq(rd(setup,0x100c65c04)['address'],at(0xa1ce))]);assert len(setup.stores)==len(setup.frame_writes)==3
 loads={'0x100dc1278':('B0',8),'0x100dc1290':('B1',8),'0x100dc14c0':('B2',8),'0x100dc1508':('FN',64)}
 def part(label,a,end,regs):
  g=chained(label,setup,{8:z('(bvadd IDX #x7f3081c2)')},loads);run(g,'loop',end=a);g.r.update(regs);run(g,'loop',a,end);models[label]=g;return g
 # The actual source seed equals the established address-keyed codec seed.
 seed=part('codec_seed',0x100dc10e8,0x100dc1314,{13:'A'})
 B='(bvadd ((_ rotate_right 8) (bvand A #xfffffffffffffff8)) #x622c5d3364e5d59f)';X=f'(bvxor {B} #xa7bebfcf1750d389)';Y=f'(bvxor {B} #xb6dc5654307e7f72)'
 cert('source_byte_codec_seed',seed,[neq(seed.get('x17'),f'((_ rotate_right 8) {X})'),neq(seed.get('x16'),Y)])
 rounds=[]
 specs=[(0,0x100dc1314,0x100dc1320,{17:'((_ rotate_right 8) U)',16:'V'},17,16,False),(1,0x100dc1320,0x100dc1340,{17:'U',16:'V'},17,16,False),(2,0x100dc1340,0x100dc1360,{17:'U',16:'V'},17,16,False),(3,0x100dc1364,0x100dc13b4,{17:'U',16:'V'},15,16,True),(4,0x100dc13b4,0x100dc1400,{15:f'(bvxor U {bv(KEYS[3])})',16:'V'},15,16,True),(5,0x100dc1400,0x100dc145c,{15:f'(bvxor U {bv(KEYS[4])})',17:f'(bvxor U {bv(KEYS[4])})',16:'V'},17,16,True),(6,0x100dc145c,0x100dc148c,{15:f'(bvxor U {bv(KEYS[5])})',17:f'(bvxor U {bv(KEYS[5])})',16:'V'},15,None,False)]
 for j,a,end,regs,xreg,yreg,encoded in specs:
  g=part('codec_round'+str(j+1),a,end,regs);F=f'(bvxor (bvadd ((_ rotate_right 8) U) V) {bv(KEYS[j])})';terms=[neq(g.get('x'+str(xreg)),f'(bvxor {F} {bv(KEYS[j])})'if encoded else F)]
  if yreg is not None:terms.append(neq(g.get('x'+str(yreg)),f'(bvxor ((_ rotate_left 3) V) {F})'))
  if j in [4,5]:terms.append(neq(f'(bvshl {g.get("x15")} #x0000000000000038)',f'(bvshl {g.get("x17")} #x0000000000000038)'))
  cert('source_byte_codec_round'+str(j+1),g,terms);rounds.append({'round':j+1,'start':hex(a),'end':hex(end),'key_u64':hex(KEYS[j]),'source_input_bindings':regs,'source_X_output_register':xreg,'source_X_is_key_xored':encoded,'source_Y_output_register':yreg,'low_byte_alias_checked':j in[4,5]})
 extract=part('codec_byte_extract',0x100dc146c,0x100dc14cc,{13:'A',15:f'(bvxor U {bv(KEYS[6])})'})
 shift='(bvshl (bvand A #x0000000000000007) #x0000000000000003)'
 cert('source_final_address_byte_selection',extract,[neq('((_ extract 7 0) '+extract.get('w13')+')',f'(bvxor ((_ extract 7 0) (bvlshr U {shift})) B2)')])
 # Two source reciprocal shapes plus128 finite numerator/remainder cases
 # justify the exact scratch-address replacements in the full iteration.
 groups=[(0x100dc1118,0x100dc11b0,15,15,0xbd700,UU),(0x100dc1188,0x100dc1208,14,14,0xaed96,VV)]
 address_cases=[]
 for a,end,num,out,base,bank in groups:
  g=part('remainder_shape_'+hex(a),a,end,{num:z('VALUE'),28:bv(0x8864298f),30:bv(961)})
  quotient='((_ extract 31 0) (bvlshr (bvmul ((_ zero_extend 32) VALUE) #x000000008864298f) #x0000000000000029))'
  cert('source_scratch_remainder_shape_'+hex(a),g,[neq(g.get('w'+str(out)),f'(bvsub VALUE (bvmul {quotient} #x000003c1))')])
  rows=[]
  for j in range(64):
   n=base+866*j;q=(n*0x8864298f)>>41;assert q==n//961 and n-q*961==bank[j];rows.append({'index':j,'numerator':n,'quotient':q,'offset':bank[j]})
  address_cases.append({'start':hex(a),'end':hex(end),'base':hex(base),'cases':rows})
 g=chained('whole_short_iteration',setup,{8:z('(bvadd IDX #x7f3081c2)')},loads);cc=['(bvult IDX COUNT)','(bvult COUNT #x00000040)'];starts={a:(num,base)for a,end,num,out,base,bank in groups};ends={end-4:(out,bank,a)for a,end,num,out,base,bank in groups}
 for i in fs['loop']['instructions'][:-1]:
  pc=int(i['ea'],16)
  if pc in starts:
   num,base=starts[pc];cert('actual_loop_numerator_'+hex(pc),g,[neq(g.get('w'+str(num)),f'(bvadd {bv(base,32)} (bvmul IDX #x00000362))'),neq(g.get('w28'),bv(0x8864298f,32)),neq(g.get('w30'),bv(961,32))],cc)
  run(g,'loop',pc,pc+4)
  if pc in ends:
   out,bank,a=ends[pc];value=lookup(bank,'IDX');cuts.append({'site':i['ea'],'register':'w'+str(out),'original_expression':g.get('w'+str(out)),'replacement':value,'justification':'source reciprocal shape,actual numerator/coefficient binding and all64 finite address cases','shape_start':hex(a)});g.put('w'+str(out),value)
  if pc==0x100dc1488:
   cuts.append({'site':i['ea'],'register':'x15','original_expression':g.get('x15'),'replacement':'MASK','actual_value':'canonical seven-round mask word at PBUF+IDX','justification':'universal source seed,seven encoded round contracts and low-byte aliases;actual incoming constants and their loop restoration are separately certified'});g.put('x15','MASK')
 models['whole_loop']=g;maskshift='(bvshl (bvand (bvadd PBUF ((_ zero_extend 32) IDX)) #x0000000000000007) #x0000000000000003)';maskbyte=f'((_ extract 7 0) (bvlshr MASK {maskshift}))'
 ptr=lambda bank:f'(bvadd {frame(0xd10)} {z(lookup(bank,"IDX"))})'
 cert('whole_short_loop_addresses_stores_counter_control_and_constants',g,[neq(rd(g,0x100dc1278)['address'],ptr(UU)),neq(rd(g,0x100dc1290)['address'],'(bvadd PBUF ((_ zero_extend 32) IDX))'),neq(rd(g,0x100dc14c0)['address'],ptr(VV)),neq(g.stores[0]['address'],ptr(UU)),neq(g.stores[1]['address'],ptr(VV)),neq(g.stores[0]['value'],'(bvxor B1 B0)'),neq(g.stores[1]['value'],f'(bvxor {maskbyte} B2)'),neq(g.get('w8'),'(bvadd IDX #x7f3081c3)'),neq(rd(g,0x100dc1508)['address'],f'(ite (bvult (bvadd IDX #x00000001) COUNT) {at(0xa1ce)} {at(0x3c0d)})'),neq(g.get('w9'),'(bvadd COUNT #x39c7500a)'),neq(g.get('w16'),bv(0xbdf3fb52,32))]+[neq(g.get('x'+str(k)),bv(v))for k,v in constants.items()]+[neq(g.get('x3'),'PBUF')],cc);assert len(g.stores)==2 and all(r['width_bits']==8 for r in g.stores)and not g.frame_writes
 solve('short_loop_strict_next_index_and_final_partition','(assert (or (bvule (bvadd IDX #x00000001) IDX) (bvugt (bvadd IDX #x00000001) COUNT) (distinct (bvult (bvadd IDX #x00000001) COUNT) (distinct (bvadd IDX #x00000001) COUNT))))',cc=cc)
 mem='(declare-fun MEM () (Array (_ BitVec 64) (_ BitVec 8)))\n(define-fun WRITTEN () (Array (_ BitVec 64) (_ BitVec 8)) (store (store MEM U (bvxor (select MEM U) B1)) V (bvxor (select MEM V) B3)))\n'
 solve('coherent_two_plane_update_and_unchanged_other_cells','(assert (or (distinct (bvxor (select WRITTEN U) (select WRITTEN V)) (bvxor (bvxor B1 B3) #xe9)) (and (distinct O U) (distinct O V) (distinct (select WRITTEN O) (select MEM O)))))',cc=['(distinct U V)','(= (bvxor (select MEM U) (select MEM V)) #xe9)'],arrays=True,extra=mem)
 # The long route has no record read in this prelude. The joining fields
 # prove its equality selector;other frame epochs may select the other slot.
 long=FrameSSA('long',initial,presets=common,loads={'0x100c50398':('FN',64)});run(long,'long');models['long']=long
 cert('long_joining_fields_select_equality_edge_and_new_state_spill',long,[neq(rd(long,0x100c50398)['address'],at(0xb5e5)),neq(long.get('w19'),bv(0x4923,32)),neq(long.get('w11'),bv(0xb5e1,32)),neq(long.stores[0]['address'],frame(0x6c8))]);assert len(long.stores)==len(long.frame_writes)==1
 handoff=chained('long_handoff',long,loads={'0x100c6ef78':('FN',64)});run(handoff,'long_setup');models['long_setup']=handoff
 cert('long_handoff_new_frame_epoch_and_plane_initializer_ABI',handoff,[neq(rd(handoff,0x100c6ef78)['address'],at(0x6317)),neq(handoff.loadframe(0x18,32),bv(0x53921748,32)),neq(handoff.loadframe(0x2cc,32),bv(0x0c392ed3,32)),neq(handoff.get('x8'),bv(0x7f3081c2)),neq(handoff.get('w23'),bv(0xc8,32)),neq(handoff.get('w22'),bv(0x5c,32)),neq(handoff.get('w21'),bv(0x74,32)),neq(handoff.get('w27'),bv(0x16,32)),neq(handoff.get('w1'),long.loadframe(0x6c8,32))]);assert len(handoff.stores)==len(handoff.frame_writes)==2
 for name,count in [('zero',0),('one',1),('max_short',63),('first_long',64),('max',0xffffffff)]:solve(name+'_COUNT_domain','(assert (= COUNT '+bv(count,32)+'))'+('\n(assert (= IDX '+bv(count-1,32)+'))'if count in[1,63]else''),result='sat')
 cells=[0xd10+x for x in UU+VV];assert len(cells)==len(set(cells))==128
 retained={0xd10+(base+866*j)%961 for base,n in [(0x77086,256),(0x368c4,256),(0,256),(0x73704,16),(0x6e272,16)]for j in range(n)};assert len(retained)==800 and not retained&set(cells)
 protected={off+j for off,w in[(0x728,4),(0x740,8),(0x748,8),(0x750,8),(0x768,296),(0x1210,8)]for j in range(w)};assert not set(cells)&protected
 frame_ledger=[]
 for label in ['short','setup','long','long_setup']:
  m=models[label];cert(label+'_all_word_stores_have_original_private_addresses',m,[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip(m.stores,m.frame_writes)])
  frame_ledger.extend({'routine':label,**r}for r in m.frame_writes)
 assert not{r['frame_offset']+j for r in frame_ledger for j in range(r['width_bits']//8)}&(retained|protected|set(cells))
 records={n:m.record_full()for n,m in models.items()};actual={pc for m in records.values()for pc in m['source_sites']};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 sem={'source_models':records,'source_nonbranch_sites_translated':len(actual),'codec_round_keys_u64':[hex(v)for v in KEYS],'codec_round_contracts':rounds,'codec_seed':'B=ror64(A AND~7,8)+622c5d3364e5d59f;X=B XORa7bebfcf1750d389;Y=B XORb6dc5654307e7f72','codec_round':'Xnew=(ror64(X,8)+Y)XORkey;Ynew=rol64(Y,3)XORXnew;only Xnew is needed after round7','codec_byte':'u8(X7 >> (8*(A AND7)))','source_cuts':cuts,'finite_address_cases':address_cases,'plane0_offsets':UU,'plane1_offsets':VV,'short_input_byte_read':'PBUF+IDX,0<=IDX<COUNT<64','short_plane0_update':'U[IDX]=old_U[IDX] XOR raw_record_byte','short_plane1_update':'V[IDX]=old_V[IDX] XOR mask(PBUF+IDX)','paired_decoded_relation':'U[i]XORV[i]=decoded_record_byte[i]XORe9 for i<COUNT;equals e9 for COUNT<=i<64','zero_padded_decoded_block_relation':'U XOR V XOR e9 is the64-byte decoded record prefix followed by64-COUNT zero bytes','short_zero_target':'0x100c74750','short_nonzero_setup':'0x100c65bdc','short_loop_target':'0x100dc10d4','short_loop_final_target':'0x100c74750','short_iteration_count':'COUNT when COUNT!=0;zero bypass otherwise','short_max_iterations':63,'short_source_reads_integer':'COUNT','short_plane_byte_reads_integer':'2*COUNT','short_plane_byte_stores_integer':'2*COUNT','with_four_earlier_passes_record_reads_integer':'5*COUNT on the short route;earlier header adds4 reads','plane63_always_untouched_on_short_route':True,'short_saved_counter_cell_F6f8':'0x4719','short_nonzero_F730_stride':866,'short_nonzero_F738_counter_bias':'0x80cf7e3e','short_zero_preserves_old_F730_and_F738':True,'long_context_F18_before':'0xb5e1','long_context_F18_after':'0x53921748','long_joining_selector':'0xb5e5','long_other_epoch_selector':'0xb5e1->0x100dc22c4;excluded by current joining control fields','long_handoff_target':'0x100c88438','long_prelude_record_byte_reads':0,'long_compact_state_function_proved':False,'long_F6c8_state_spill_then_W1_reload_proved':True,'source_frame_store_ledger':frame_ledger,'retained_arithmetic_codebook_cells':800,'saved_roots_workspace_and_budget_preserved':True,'native_buffer_frame_disjointness_is_a_premise':True,'whole_algorithm_identified':False,'successful_output_publication_proved':False,'native_reachability_proved':False,'Mach_port_emissions':0,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['loop'].__setitem__('bytes','00'+q['fragments']['loop']['bytes'][2:])),('wrong_record_read',lambda q:q['fragments']['loop']['instructions'][0].__setitem__('operands','w11, [sp, #0x738]')),('wrong_zero_target',lambda q:q['branch_edges'][0].__setitem__('target','0x0')),('wrong_long_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('wrong_parent_hash',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(v['result']=='unsat'for v in pp),'queries_sat':sum(v['result']=='sat'for v in pp),'predecessor_queries_replayed':sum(v.get('replayed_query',False)for v in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'codec_seed_certificates':1,'codec_round_certificates':7,'codec_byte_extract_certificates':1,'scratch_address_cases':128,'plane_cells_bounded':128,'short_max_iterations':63,'arithmetic_and_codebook_cells_retained':800,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','recover_daemon_mode_one_record_join.py','validate_daemon_mode_one_record_join.py','validate_daemon_constructor_lookup.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'record_short_input_planes_and_long_handoff_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
