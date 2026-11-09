#!/usr/bin/env python3
"""SSA and finite algebra for XOR and the changing digit-map ABI."""
import copy,json,subprocess,shutil
from recover_daemon_mode_one_digit_maps import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_carry_table import fresh,START
from validate_daemon_mode_one_inverse_tables import A,B,C,frame,at,lut
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
SOLVER=shutil.which('z3');assert SOLVER
EXTRA='(declare-fun IDX () (_ BitVec 32))\n'
D=[(137774+757*j)%963 for j in range(256)]
Q=[(0x51518+757*j)%963 for j in range(256)]
U=[(757*j)%963 for j in range(16)]
def source_certificates(s):
 pp=[];tr={};models={};fs=s['fragments']
 def solve(n,body,cc=(),integer=False,result='unsat'):
  query='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+('(declare-fun XI () Int)\n'if integer else DECL+EXTRA)+body+'\n'+''.join('(assert '+v+')\n'for v in cc)+'(check-sat)\n'
  r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-digit-failed.smt2').write_text(query)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.stdout,r.stderr)
  pp.append({'name':n,'query':query,'result':result,'scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,cc=()):solve(n,prefix(g)+'(assert (or '+' '.join(terms)+'))',cc)
 def run(name,r,loads):
  g=fresh(name,r,loads);sn={}
  for i in fs[name]['instructions'][:-1]:
   g.run({'instructions':[i]},int(i['ea'],16)+4);sn[i['ea']]=(dict(g.r),list(g.defs),list(g.reads),list(g.stores))
  tr[name]=g.record();models[name]=g
  def cut(pc):
   rr,dd,rd,st=sn[hex(pc)];o=copy.copy(g);o.r=rr;o.defs=dd;o.reads=rd;o.stores=st;return o
  return g,cut
 def rd(g,pc):return next(v for v in g.reads if v['site']==hex(pc))
 def registers(g,constants):return[neq(g.get('w'+str(k)),bv(v,32))for k,v in constants.items()]
 def remainder(n,m,shift,d):
  q=f'((_ extract 31 0) (bvlshr (bvmul {z(n)} {bv(m)}) {bv(shift)}))'
  return f'(bvsub {n} (bvmul {q} {bv(d,32)}))'
 loads={'0x100c18e94':('B1',8),'0x100c18e98':('B0',8),'0x100c18f7c':('B2',8),'0x100c18fc0':('B3',8),'0x100c19004':('TABLE',64),'0x100c19008':('FN',64)}
 seed,_=run('carry_seed',{4:bv(255),5:bv(START+255),8:bv(0xc25d),21:frame(0xd00),23:bv(0x100f715a0)},loads)
 xc={0:0x456c7a,2:944,3:0x440dd3,6:0x440dd2cf,10:0,11:0xa648,12:527,13:757,14:12869,15:0x2207,16:963}
 cert('carry_exit_binds_xor_writer_live_constants',seed,registers(seed,xc)+[neq(seed.get('x21'),frame(0xd00)),neq(seed.get('x23'),bv(0x100f715a0))])
 rr={k:bv(v)for k,v in xc.items()};rr.update({10:z('IDX'),21:frame(0xd00),23:bv(0x100f715a0)})
 loads={'0x100c958f4':('B0',8),'0x100c958f8':('B1',8),'0x100c95924':('B2',8),'0x100c95960':('B3',8),'0x100c9597c':('TABLE',64),'0x100c95980':('FN',64)}
 g,cut=run('xor',rr,loads);cc=['(bvult IDX #x00000100)','(bvuge B0 #xd0)','(bvult B0 #xe0)','(bvuge B1 #xd0)','(bvult B1 #xe0)','(bvuge B2 #x50)','(bvult B2 #x60)']
 solve('xor_abstract_domain_nonempty','',cc,result='sat')
 cert('xor_reads_both_inverse_nibbles',cut(0x100c958f8),[neq(rd(g,0x100c958f4)['address'],f'(bvadd {frame(0xd00)} {z(lut(B,"(bvand IDX #x0000000f)"))})'),neq(rd(g,0x100c958f8)['address'],f'(bvadd {frame(0xd00)} {z(lut(B,"(bvlshr IDX #x00000004)"))})')],cc)
 key='(bvxor (concat ((_ extract 3 0) (bvxor B1 #xd4)) ((_ extract 3 0) (bvxor B0 #xd4))) #x06)'
 cert('xor_packs_inverse_nibbles_xor06',cut(0x100c95910),[neq(cut(0x100c95910).get('w17'),f'((_ zero_extend 24) {key})')],cc)
 n=f'(bvadd #x00026367 (bvmul ((_ zero_extend 24) {key}) #x0000020f))';r=remainder(n,0x456c7a,32,944)
 cert('xor_fixed_data_address_shape',cut(0x100c95924),[neq(rd(g,0x100c95924)['address'],f'(bvadd {bv(0x100f715a0)} {z(r)})')],cc)
 n='(bvadd #x00014b30 (bvmul ((_ zero_extend 24) (bvxor B2 #x5e)) #x000002f5))';r=remainder(n,0x440dd3,32,963)
 cert('xor_forward_permutation_read_shape',cut(0x100c95960),[neq(rd(g,0x100c95960)['address'],f'(bvadd {frame(0xd00)} {z(r)})')],cc)
 n='(bvadd #x00051518 (bvmul IDX #x000002f5))';r=remainder(n,0x440dd2cf,40,963)
 cert('xor_destination_byte_and_loop_control',g,[neq(g.stores[0]['address'],f'(bvadd {frame(0xd00)} {z(r)})'),neq(g.stores[0]['value'],'B3'),neq(g.get('w10'),'(bvadd IDX #x00000001)'),neq(g.get('w1'),'#x00000000'),neq(g.get('w4'),'#xa79db846'),neq(g.get('w8'),'#x0000a659'),neq(rd(g,0x100c9597c)['address'],frame(0x740)),neq(rd(g,0x100c95980)['address'],f'(ite (= IDX #x000000ff) {at(0xa659)} {at(0xa648)})'),neq(g.get('x21'),frame(0xd00)),neq(g.get('x23'),bv(0x100f715a0))]+registers(g,{k:v for k,v in xc.items()if k!=10}),cc)
 rr={4:z('(bvadd IDX #xa79db846)'),1:z('IDX'),8:bv(0xa659),21:frame(0xd00),23:bv(0x100f715a0)}
 loads={'0x100c6ff44':('B0',8),'0x100c6ffa8':('B1',8),'0x100c6ffd4':('TABLE',64),'0x100c6ffd8':('FN',64)}
 g,cut=run('decoder',rr,loads);cc=['(bvult IDX #x00000010)','(bvuge B0 #xd0)','(bvult B0 #xe0)']
 solve('decoder_abstract_domain_nonempty','',cc,result='sat')
 cert('decoder_reads_old_inverse_table_despite_high_numerator_bits',cut(0x100c6ff44),[neq(rd(g,0x100c6ff44)['address'],f'(bvadd {frame(0xd00)} {z(lut(B,"IDX"))})')],cc)
 n='(bvadd #x00022ff0 (bvmul ((_ zero_extend 24) (bvxor B0 #xd1)) #x0000020f))';r=remainder(n,0x22b63cbf,39,944)
 cert('decoder_fixed_data_address_shape',cut(0x100c6ffa8),[neq(rd(g,0x100c6ffa8)['address'],f'(bvadd {bv(0x100f715a0)} {z(r)})')],cc)
 dc={0:944,10:757,11:0x2207,12:963,13:0,14:0x4def,15:527,16:0x22b63cbf}
 cert('decoder_byte_destination_counter_and_next_seed',g,[neq(g.stores[0]['address'],f'(bvadd {frame(0xd00)} {z(lut(U,"IDX"))})'),neq(g.stores[0]['value'],'(bvxor (bvxor B0 #x49) B1)'),neq(g.get('w4'),'(bvadd IDX #xa79db847)'),neq(g.get('w1'),'(bvadd IDX #x00000001)'),neq(g.get('w8'),'#x0000a659'),neq(rd(g,0x100c6ffd4)['address'],frame(0x740)),neq(rd(g,0x100c6ffd8)['address'],f'(ite (= IDX #x0000000f) {at(0xb395)} {at(0xa659)})'),neq(g.get('x21'),frame(0xd00)),neq(g.get('x23'),bv(0x100f715a0))]+registers(g,dc),cc)
 rr={k:bv(v)for k,v in dc.items()};rr.update({13:z('IDX'),21:frame(0xd00),23:bv(0x100f715a0)})
 loads={'0x100d1798c':('B0',8),'0x100d179f0':('B1',8),'0x100d17a18':('TABLE',64),'0x100d17a1c':('FN',64)}
 g,cut=run('relabel',rr,loads);cc=['(bvult IDX #x00000010)']
 solve('relabel_abstract_domain_nonempty','',cc,result='sat')
 n='(bvadd #x0004f627 (bvmul (bvxor IDX #x00000007) #x0000020f))';r=remainder(n,0x22b63cbf,39,944)
 cert('relabel_fixed_data_address_shape',cut(0x100d1798c),[neq(rd(g,0x100d1798c)['address'],f'(bvadd {bv(0x100f715a0)} {z(r)})')],cc)
 mask='(bvxor (bvand (bvsub (bvxor IDX #x0000000d) (bvxor IDX #x00000041)) #x000000ff) #x00000052)'
 arg=f'(bvxor ((_ zero_extend 24) B0) {mask})';n=f'(bvadd #x00014b30 (bvmul {arg} #x000002f5))';r=remainder(n,0x440dd2cf,40,963)
 cert('relabel_reads_forward_permutation_with_decoded_digit_label',cut(0x100d179f0),[neq(rd(g,0x100d179f0)['address'],f'(bvadd {frame(0xd00)} {z(r)})')],cc)
 cert('relabel_overwrites_inverse_cells_and_exits_after16',g,[neq(g.stores[0]['address'],f'(bvadd {frame(0xd00)} {z(lut(B,"IDX"))})'),neq(g.stores[0]['value'],'B1'),neq(g.get('w13'),'(bvadd IDX #x00000001)'),neq(rd(g,0x100d17a18)['address'],frame(0x740)),neq(rd(g,0x100d17a1c)['address'],f'(ite (= IDX #x0000000f) {at(0x4def)} {at(0x4e26)})'),neq(g.get('x21'),frame(0xd00)),neq(g.get('x23'),bv(0x100f715a0))],cc)
 # Generic source product/shift expressions above are linked to exact
 # bounded integer identities here;finite rows below bind original bytes.
 for name,d,m,shift,limit in [('op32',944,0x456c7a,32,500000),('op39',944,0x22b63cbf,39,500000),('scratch32',963,0x440dd3,32,100000),('scratch40',963,0x440dd2cf,40,4294967295),('scratch23',963,0x2207,23,65535)]:
  solve('exact_bounded_reciprocal_'+name,f'(assert (distinct (div (* XI {m}) {1<<shift}) (div XI {d})))',['(<= 0 XI)',f'(<= XI {limit})'],integer=True)
 return pp,tr,models
def finite(s):
 raw=bytes.fromhex(s['operation_data']['bytes']);old=json.loads(read(ROOT/'daemon_mode_one_carry_table_checks.json'));rank=old['semantics']['label_rank'];M=old['semantics']['natural_labels']
 assert sorted(rank)==sorted(M)==list(range(16))and all(rank[M[j]]==j for j in range(16))
 xx=[];xorop=[]
 for t in range(256):
  n=0x26367+527*(t^6);q=(n*0x456c7a)>>32;r=n-q*944;assert r==n%944;y=raw[r];v=y^0x5e;assert 0<=v<16
  a=84784+757*v;assert a-((a*0x440dd3)>>32)*963==A[v]
  nout=0x51518+757*t;assert nout-((nout*0x440dd2cf)>>40)*963==Q[t]
  xorop.append(v);xx.append({'logical_pair':t,'fixed_numerator':n,'fixed_offset':r,'fixed_byte':y,'decoded_label':v,'Q_offset':Q[t]})
  assert ((0xd4^(t&15))^(0xd4^((t>>4)<<4)))==((t&15)|((t>>4)<<4))
 for a in range(16):
  for b in range(16):
   assert rank[xorop[M[a]+16*M[b]]]==a^b
   sumv=rank[old['semantics']['sum_operation256'][M[a]+16*M[b]]];carry=rank[old['semantics']['carry_operation256'][M[a]+16*M[b]]];assert a+b==sumv+16*carry
 dec=[];rel=[]
 for j in range(16):
  n=((0xa79db846+j)*757+0x4b47)&0xffffffff;low=n&65535;q=((low*0x2207)&0xffffffff)>>23;r=(n-q*963)&65535;assert low==12869+757*j and r==B[j]
  b=0xd4^j;n=0x22ff0+527*(b^0xd1);q=(n*0x22b63cbf)>>39;r=n-q*944;assert r==n%944;y=raw[r];value=b^0x49^y;assert value==0xd4^rank[j]
  out=757*j;q=(((out&65535)*0x2207)&0xffffffff)>>23;assert(out-q*963)&65535==U[j]
  dec.append({'inverse_label':j,'fixed_numerator':n,'fixed_offset':r,'fixed_byte':y,'decoded_E_rank':value,'U_offset':U[j]})
  n=0x4f627+527*(j^7);q=(n*0x22b63cbf)>>39;r=n-q*944;assert r==n%944;y=raw[r];mask=(((j^0xd)-(j^0x41))&255)^0x52;label=y^mask;assert label==M[j]
  n=84784+757*label;assert n-((n*0x440dd2cf)>>40)*963==A[label]
  out=12869+757*j;q=(((out&65535)*0x2207)&0xffffffff)>>23;assert(out-q*963)&65535==B[j]
  rel.append({'digit':j,'fixed_numerator':n,'fixed_offset':r,'fixed_byte':y,'mask':mask,'decoded_M_label':label,'B_offset':B[j]})
 assert len(set(A+B+C+D+Q+U))==816
 protected=old['semantics']['protected_frame_offsets'];assert not{0xd00+j for j in A+B+C+D+Q+U}&set(protected)
 return {'natural_labels':M,'label_rank':rank,'xor_operation256':xorop,'xor_fixed_cases':xx,'inverse_digit_map_cases':dec,'forward_digit_map_cases':rel,'xor_pairs_checked':256,'sum_carry_pairs_rechecked':256,'packed_byte_encoding_pairs':256,'decoder_cases':16,'relabel_cases':16,'region_offsets':{'A':A,'B':B,'C':C,'D':D,'Q':Q,'U':U},'meaningful_scratch_bytes':816,'regions_pairwise_disjoint':True,'protected_frame_offsets':protected,'dynamic_byte_writes':{'xor':256,'decoder':16,'relabel':16},'B_lifecycle':{'before':'E(pi_inverse(j))','read_by':'xor and decoder','overwritten_after_U_complete':'E(R(j))','inverse_relation_after':'U[R(j)]=E(j)'},'composition':{'R':'pi composed with M','Q':'Q[R(a)+16*R(b)]=E(R(a XOR b))','U':'U[t]=E(R_inverse(t))','B_after':'B[j]=E(R(j))','C_XOR_D':'C[x+16*y] XOR D[x+16*y] packs the encoded sum label in low nibble and encoded carry label in high nibble','native_claim':False},'next_target':'0x100daee68'}
def verify(s):return s==build()
def alterations(s):
 changes=[('wrong_source_byte',lambda q:q['fragments']['decoder'].__setitem__('bytes','00'+q['fragments']['decoder']['bytes'][2:])),('wrong_fixed_data',lambda q:q['operation_data'].__setitem__('bytes','00'*944)),('wrong_relabel_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('invent_native_execution',lambda q:q.__setitem__('target_executed',True))];rows=[]
 for n,fn in changes:
  q=copy.deepcopy(s);fn(q);assert not verify(q);rows.append({'name':n,'rejected_by_fresh_original_source_comparison':True})
 return rows
def certificates(s):
 pp,tr,models=source_certificates(s);sem=finite(s)
 parent=json.loads(read(ROOT/'daemon_mode_one_carry_table_checks.json'));assert parent['all_checks_pass']and parent['local_sum_carry_contract_proved']and not parent['complete_operation_proved']
 for proof in parent['proofs']:
  if proof['result']!='unsat':continue
  r=subprocess.run([SOLVER,'-in'],input=proof['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat'
  pp.append({**proof,'name':'replayed_carry_'+proof['name'],'replayed_query':True});print('replayed_carry_'+proof['name'],'unsat',flush=True)
 assert all(len(models[n].stores)==1 and models[n].stores[0]['width_bits']==8 for n in['xor','decoder','relabel'])
 return pp,tr,sem
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,sem=certificates(s);aa=alterations(s)
 actual={pc for t in tr.values()for pc in t['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 counts={**s['verified_source_counts'],'distinct_nonbranch_sites_translated':len(actual),'new_nonbranch_sites_translated':sum(len(tr[n]['source_sites'])for n in['xor','decoder','relabel']),'untranslated_source_sites':len(expected-actual),'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'replayed_queries_unsat':sum(p.get('replayed_query',False)for p in pp),'xor_pairs_checked':256,'sum_carry_pairs_rechecked':256,'packed_encoding_pairs':256,'decoder_cases':16,'relabel_cases':16,'meaningful_scratch_bytes':816,'dynamic_byte_writes':288,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_carry_table.py','validate_daemon_mode_one_inverse_tables.py','validate_daemon_mode_one_scatter.py','validate_daemon_list_output.py','validate_daemon_existing_scalar_reader.py','daemon_mode_one_carry_table_checks.json']
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'translations':tr,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_xor_and_digit_maps_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
