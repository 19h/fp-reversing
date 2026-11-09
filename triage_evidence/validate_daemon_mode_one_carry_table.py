#!/usr/bin/env python3
"""Source SSA, bounded integer identities and exhaustive table algebra.

No target instructions, CPU emulator, API or IPC requests are executed.
"""
import copy,json,shutil,subprocess
from recover_daemon_mode_one_carry_table import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_inverse_tables import Engine as Parent,A,B,C,frame,at,lut
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
START=0xa8575b74
D=[(137774+757*j)%963 for j in range(256)]
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec 32))\n'for n in['IDX','ARG'])
class Engine(Parent):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='subs':
    p=split(i['operands']);w=32 if p[0].startswith('w')else 64;a=self.get(p[1],w);b=self.operand(p[2],w,p[3]if len(p)>3 else None)
    self.compare(a,b,w);self.put(p[0],f'(bvsub {a} {b})');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def fresh(label,r=None,loads=None):
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=Engine(rr,loads,namespace=label+'_');g.declarations='';return g
def certificates(s):
 proofs=[];tr={};finite={};f=s['fragments']['carry']
 def solve(n,body,cc=(),integer=False,result='unsat'):
  q='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+('(declare-fun XI () Int)\n'if integer else DECL+EXTRA)+body+'\n'+''.join('(assert '+v+')\n'for v in cc)+'(check-sat)\n'
  p=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if p.returncode or p.stderr or p.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-carry-failed-query.smt2').write_text(q)
  assert p.returncode==0 and not p.stderr and p.stdout.strip()==result,(n,p.stdout,p.stderr)
  proofs.append({'name':n,'query':q,'result':result,'scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,cc=()):solve(n,prefix(g)+'(assert (or '+' '.join(terms)+'))',cc)
 def part(n,a,b,r=None,loads=None,fragment='carry'):
  ff=s['fragments'][fragment];ii=[i for i in ff['instructions']if a<=int(i['ea'],16)<b];g=fresh(n,r,loads);g.run({'instructions':ii},b);tr[n]=g.record();return g
 seed=part('shuffle_phase_seed',0x100dbfc3c,0x100dbfc54,{4:bv(0x8d87)},fragment='shuffle_seed')
 cert('shuffle_phase_is_d781bff7',seed,[neq(seed.get('w23'),'#xd781bff7')])
 tail=part('shuffle_exit_seed',0x100dc0220,0x100dc02a4,{23:seed.get('x23')},fragment='shuffle_exit');tail.defs=list(seed.defs)+tail.defs
 cert('shuffle_initializes_carry_count_and_phase',tail,[neq(tail.get('w4'),'#x00000000'),neq(tail.get('w8'),'#x0000c25d')])
 sum_tail=part('sum_writer_exit_seed',0x100c07388,0x100c07394,{4:bv(0),8:bv(0xc25d)},fragment='sum_writer')
 cert('sum_writer_sets_second_loop_base',sum_tail,[neq(sum_tail.get('w5'),bv(START,32)),neq(sum_tail.get('w4'),'#x00000000'),neq(sum_tail.get('w8'),'#x0000c25d')])
 loads={'0x100c18e94':('B1',8),'0x100c18e98':('B0',8),'0x100c18f7c':('B2',8),'0x100c18fc0':('B3',8),'0x100c19004':('TABLE',64),'0x100c19008':('FN',64)}
 g=fresh('carry',{4:z('IDX'),5:z(f'(bvadd IDX {bv(START,32)})'),8:bv(0xc25d),21:frame(0xd00),23:bv(0x100f715a0)},loads)
 cc=['(bvult IDX #x00000100)','(bvuge B0 #xd0)','(bvult B0 #xe0)','(bvuge B1 #xd0)','(bvult B1 #xe0)']
 solve('selected_abstract_domain_nonempty','',cc,result='sat')
 snap={}
 for i in f['instructions'][:-1]:
  pc=int(i['ea'],16);g.run({'instructions':[i]},pc+4)
  if pc in[0x100c18e98,0x100c18f58,0x100c18f78,0x100c18f8c,0x100c18fa4,0x100c18fb0]:snap[pc]=(dict(g.r),list(g.defs),list(g.reads),list(g.stores))
 tr['carry_full_source']=g.record()
 def upto(pc):
  rr,dd,reads,stores=snap[pc];o=copy.copy(g);o.r=rr;o.defs=dd;o.reads=reads;o.stores=stores;return o
 def rd(o,pc):return next(v for v in o.reads if v['site']==hex(pc))
 inputs=upto(0x100c18e98)
 cert('inverse_table_low_and_high_read_addresses',inputs,[neq(rd(inputs,0x100c18e98)['address'],f'(bvadd {frame(0xd00)} {z(lut(B,"(bvand IDX #x0000000f)"))})'),neq(rd(inputs,0x100c18e94)['address'],f'(bvadd {frame(0xd00)} {z(lut(B,"(bvlshr IDX #x00000004)"))})')],cc)
 key='(bvxor (concat ((_ extract 3 0) (bvxor B1 #xd4)) ((_ extract 3 0) (bvxor B0 #xd4))) #x7a)'
 mixer=upto(0x100c18f58);cert('obfuscated_mixer_is_packed_inverse_nibbles_xor7a',mixer,[neq(mixer.get('w17'),f'((_ zero_extend 24) {key})')],cc)
 # These shape certificates preserve the exact source reciprocal arithmetic;
 # exhaustive bounded checks below establish its division/address meaning.
 op=part('operation_remainder_shape',0x100c18f5c,0x100c18f80,{17:z('ARG'),23:bv(0x100f715a0)},loads={'0x100c18f7c':('B2',8)})
 n='(bvmul ARG #x0000020f)';q=f'((_ extract 31 0) (bvlshr (bvmul {z(n)} #x0000000000456c7a) #x0000000000000020))';r=f'(bvsub {n} (bvmul {q} #x000003b0))'
 cert('source_fixed_data_remainder_shape',op,[neq(rd(op,0x100c18f7c)['address'],f'(bvadd {bv(0x100f715a0)} {z(r)})')])
 dec=part('operation_byte_decoder',0x100c18f80,0x100c18fc4,{17:z('B2',8),13:bv(757),16:bv(963),21:frame(0xd00)},loads={'0x100c18fc0':('B3',8)})
 y='((_ zero_extend 24) B2)';v=f'(bvor (bvxor (bvor #x0000005a (bvlshr {y} #x00000007)) (bvlshr {y} #x00000004)) #x00000020)';n=f'(bvmul {v} #x000002f5)';q=f'((_ extract 31 0) (bvlshr (bvmul {z(n)} #x0000000000440dd3) #x0000000000000020))';r=f'(bvsub {n} (bvmul {q} #x000003c3))'
 cert('source_forward_table_decoder_and_remainder_shape',dec,[neq(rd(dec,0x100c18fc0)['address'],f'(bvadd {frame(0xd00)} {z(r)})')])
 out=g.stores[0];n='(bvadd #x00021a2e (bvmul IDX #x000002f5))';q=f'((_ extract 31 0) (bvlshr (bvmul {z(n)} #x00000000440dd2cf) #x0000000000000028))';rem=f'(bvsub {n} (bvmul {q} #x000003c3))'
 cert('source_output_address_byte_counter_and_control',g,[neq(out['address'],f'(bvadd {frame(0xd00)} {z(rem)})'),neq(out['value'],'(bvxor #x94 (bvshl B3 #x04))'),neq(g.get('w4'),'(bvadd IDX #x00000001)'),neq(g.get('w5'),f'(bvadd IDX {bv(START+1,32)})'),neq(g.get('x21'),frame(0xd00)),neq(g.get('x23'),bv(0x100f715a0)),neq(g.get('w8'),'#x0000c25d'),neq(rd(g,0x100c19004)['address'],frame(0x740)),neq(rd(g,0x100c19008)['address'],f'(ite (= IDX #x000000ff) {at(0xc25d)} {at(0xc262)})'),neq(g.get('x17'),bv(0x4177))],cc)
 for d,m,shift,limit in[(944,0x456c7a,32,527*255),(963,0x440dd3,32,127*757),(963,0x440dd2cf,40,137774+757*255),(1926,0x0440dd2d,37,32*757),(963,0x2207,23,12869+757*15)]:
  solve(f'exact_bounded_reciprocal_{d}_{shift}',f'(assert (distinct (div (* XI {m}) {1<<shift}) (div XI {d})))',['(<= 0 XI)',f'(<= XI {limit})'],integer=True)
 raw=bytes.fromhex(s['operation_data']['bytes']);rows=[];op2=[];index_cases=[];decode_cases=[]
 for i in range(256):
  n=527*i;q=(n*0x456c7a)>>32;r=n-q*944;assert r==n%944
  index_cases.append({'packed_argument':i,'numerator':n,'quotient':q,'offset':r})
  v=((0x5a|(i>>7))^(i>>4))|0x20;n=v*757;q=(n*0x440dd3)>>32;r=n-q*963
  assert 112<=v<128 and r==A[v-112]
  decode_cases.append({'byte':i,'forward_index':v-112,'offset':r})
  t=i;lo=t&15;hi=t>>4;n=(hi+17)*757;q=(n*0x0440dd2d)>>37;r=n-q*1926;r=r if r<963 else r-963
  assert r==B[hi]and((12869+757*lo)-(((12869+757*lo)*0x2207)>>23)*963)==B[lo]
  n=((START+t)*757+0x35b0ac2a)&0xffffffff;assert n==137774+757*t and n-((n*0x440dd2cf)>>40)*963==D[t]
  packed=t^0x7a;y=raw[(527*packed)%944];k=(((0x5a|(y>>7))^(y>>4))|0x20)-112;assert 0<=k<16
  op2.append(k);rows.append({'logical_pair':t,'packed_argument':packed,'fixed_data_offset':(527*packed)%944,'fixed_data_byte':y,'decoded_label':k})
 # Independently re-decode the first operation from the original944 B bank.
 op1=[]
 for t in range(256):
  y=raw[(342023+527*(t^0x34))%944];v=y^(y>>1)^(0xe8|(y>>5))^0xac;assert 0<=v<16;op1.append(v)
 rank=[sum(op2[a+16*b]==4 for b in range(16))for a in range(16)];assert sorted(rank)==list(range(16))
 labels=[rank.index(j)for j in range(16)]
 assert labels[0]==9 and labels[1]==4
 for a in range(16):
  for b in range(16):
   t=labels[a]+16*labels[b];assert rank[op1[t]]==(a+b)%16 and rank[op2[t]]==(a+b)//16
 assert len(set(A+B+C+D))==16+16+256+256
 protected=[*range(0x720,0x724),*range(0x728,0x72c),*range(0x730,0x734),*range(0x748,0x74c),*range(0x1210,0x1218),*range(0x438,0x440),*range(0x570,0x588),*range(0x738,0x748)]
 assert not {0xd00+j for j in D}&set(protected)
 assert len(g.stores)==1 and all(v['width_bits']==8 for v in g.stores)
 for v in s['branch_edges']:assert v['fixup']['target']==(0x100c9589c if v['index']=='0xc25d'else 0x100c18e20)
 old=json.loads(read(ROOT/'daemon_mode_one_inverse_tables_checks.json'));assert old['all_checks_pass']and old['complete_semantic_chain_proved']and not old['complete_operation_proved']
 assert op1==old['semantics']['operation256']
 selected={'table_bank_codec_is_constant208','table_operation_root_slot','table_inverse_inputs_output_lookup_scatter_and_control','second_shuffle_table_writer_seed','inverse_reads_A_and_writes_B_with_original_index','reset_restores_identity_A_without_touching_B'}
 replayed=[]
 for p in old['proofs']:
  if p['name']not in selected:continue
  v=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not v.returncode and not v.stderr and v.stdout.strip()==p['result']=='unsat'
  proofs.append({**p,'name':'replayed_'+p['name'],'replayed_query':True});replayed.append(p['name']);print('replayed_'+p['name'],'unsat',flush=True)
 assert set(replayed)==selected
 finite={'operation_lookup_cases':rows,'reciprocal_cases':index_cases,'decoder_cases':decode_cases,'input_and_destination_cases':256,'label_rank':rank,'natural_labels':labels,'sum_operation256':op1,'carry_operation256':op2,'sum_pairs_checked':256,'carry_pairs_checked':256,'combined_integer_identity_pairs_checked':256,'A_offsets':A,'B_offsets':B,'C_offsets':C,'D_offsets':D,'meaningful_scratch_bytes':544,'all_regions_pairwise_disjoint':True,'protected_frame_offsets':protected,'D_dynamic_byte_writes':256,'counter_initial':0,'counter_exit':256,'repeat_target':'0x100c18e20','exit_target':'0x100c9589c','composition':{'R':'pi composed with natural_labels','C':'C[R(a)+16*R(b)]=d4 XOR R((a+b) mod16)','D':'D[R(a)+16*R(b)]=d4 XOR (R(floor((a+b)/16))<<4)','combined':'a+b = decoded_sum +16*decoded_carry','native_claim':False}}
 return proofs,tr,finite
def verify(s):return s==build()
def alterations(s):
 cases=[('wrong_source_byte',lambda q:q['fragments']['carry'].__setitem__('bytes','00'+q['fragments']['carry']['bytes'][2:])),('wrong_fixed_data',lambda q:q['operation_data'].__setitem__('bytes','00'*944)),('wrong_branch_target',lambda q:q['branch_edges'][0]['fixup'].__setitem__('target',0)),('invent_native_execution',lambda q:q.__setitem__('target_executed',True))];rows=[]
 for n,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);rows.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return rows
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,sem=certificates(s);aa=alterations(s)
 actual=set(tr['carry_full_source']['source_sites']);expected={i['ea']for i in s['fragments']['carry']['instructions']if i['mnemonic']!='braa'};assert actual==expected
 counts={**s['verified_source_counts'],'new_routine_nonbranch_sites_translated':len(actual),'untranslated_new_routine_sites':len(expected-actual),'queries_unsat':sum(q['result']=='unsat'for q in pp),'queries_sat':sum(q['result']=='sat'for q in pp),'replayed_queries_unsat':sum(q.get('replayed_query',False)for q in pp),'fixed_data_cases':256,'decoder_cases':256,'sum_and_carry_pairs':256,'meaningful_scratch_bytes':544,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','validate_daemon_mode_one_inverse_tables.py','validate_daemon_mode_one_scatter.py','validate_daemon_list_output.py','validate_daemon_existing_scalar_reader.py','daemon_mode_one_inverse_tables_checks.json']},'proofs':pp,'translations':tr,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_sum_carry_contract_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
