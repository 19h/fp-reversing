#!/usr/bin/env python3
"""Universal source SSA and compositional reduction of the two-bank combiner."""
import copy,json,subprocess,shutil
from recover_daemon_mode_one_bank_combine import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_carry_table import Engine as Parent
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
from validate_daemon_mode_one_inverse_tables import frame,at
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec 32))\n'for n in ['A'+str(j)for j in range(4)]+['S'+str(j)for j in range(4)])
def add(*xs):
 e=xs[0]
 for x in xs[1:]:e=f'(bvadd {e} {x})'
 return e
def sub(a,b):return f'(bvsub {a} {b})'
def xo(a,b):return f'(bvxor {a} {b})'
class Engine(Parent):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='bfi':
    p=split(i['operands']);w=32 if p[0].startswith('w')else 64;l,n=int(p[2][1:],0),int(p[3][1:],0);mask=((1<<n)-1)<<l
    self.put(p[0],f'(bvor (bvand {self.get(p[0],w)} {bv(~mask,w)}) (bvshl (bvand {self.get(p[1],w)} {bv((1<<n)-1,w)}) {bv(l,w)}))');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def fresh(label,r=None,loads=None):
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=Engine(rr,loads,namespace=label+'_');g.declarations='';return g
def certificates(s):
 pp=[];tr={};cuts=[];fs=s['fragments']
 def solve(n,body,cc=(),result='unsat'):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+body+'\n'+''.join('(assert '+c+')\n'for c in cc)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-combine-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.stdout,r.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,cc=()):solve(n,prefix(g)+'(assert (or '+' '.join(terms)+'))',cc)
 def run(n,r=None,loads=None,a=None,end=None,label=None):
  f=fs[n];label=label or n;a=a or int(f['start'],16);end=end or int(f['instructions'][-1]['ea'],16);g=fresh(label,r,loads);g.run({'instructions':[i for i in f['instructions']if a<=int(i['ea'],16)<end]},end);tr[label]=g.record();return g
 bank={10:z('A0'),5:z('A1'),25:z('A2'),30:z(add('A3','#xad732488')),13:z('S0'),11:z('S1'),3:z('S2'),26:z('S3')}
 init=run('initializer',{15:bv(0x4923),2:z('VALUE'),**bank},{'0x100dda8e0':('TABLE',64),'0x100dda8e4':('FN',64)})
 seed={0:0,4:0x528cdb78,8:1,20:0x4cdb,22:0xad732488}
 cert('initializer_binds_combine_constants_and_bank_coordinates',init,[neq(init.get('w'+str(k)),bv(v,32))for k,v in seed.items()]+[neq(init.get('x'+str(k)),v)for k,v in bank.items()]+[neq(init.get('x21'),frame(0x8348)),neq(next(v for v in init.reads if v['site']=='0x100dda8e4')['address'],at(0x6284))])
 circuit=run('combine',{16:z('VALUE')},a=0x100bdba84,end=0x100bdbbf8,label='unary_carry_circuit')
 unary=xo(add('VALUE','#x6891e1c7'),'#x08156cbf')
 cert('parallel_carry_circuit_is_add_then_xor',circuit,[neq(circuit.get('w1'),unary)])
 masked=run('combine',{12:z('VALUE'),1:z('A0')},a=0x100bdbc00,end=0x100bdbc58,label='masked_addition')
 binary=add(xo(add('VALUE','#x01fe06c9'),'#x59259907'),xo('A0','#x08156cbf'))
 cert('masked_boolean_sum_is_two_encoded_operands_added',masked,[neq(masked.get('w12'),binary)])
 rr={k:bv(v)for k,v in seed.items()};rr.update(bank);rr[21]=frame(0x8348)
 g=fresh('full_combine',rr,{'0x100bdbcac':('TABLE',64),'0x100bdbcb0':('FN',64)});vinput=None;uinput=None;binput=None
 for i in fs['combine']['instructions'][:-1]:
  pc=int(i['ea'],16)
  if pc==0x100bdba84:vinput=g.get('w16')
  if pc==0x100bdbc00:uinput=g.get('w12');binput=g.get('w1')
  g.run({'instructions':[i]},pc+4)
  if pc==0x100bdbbf4:
   assert vinput;replacement=xo(add(vinput,'#x6891e1c7'),'#x08156cbf');cuts.append({'site':i['ea'],'register':'w1','original_value':g.get('w1'),'replacement':replacement,'universal_lemma':'parallel_carry_circuit_is_add_then_xor','source_fragment':'combine','source_span':['0x100bdba84','0x100bdbbf8'],'input_binding':{'VALUE':vinput}});g.put('w1',replacement)
  if pc==0x100bdbc54:
   assert uinput and binput;replacement=add(xo(add(uinput,'#x01fe06c9'),'#x59259907'),xo(binput,'#x08156cbf'));cuts.append({'site':i['ea'],'register':'w12','original_value':g.get('w12'),'replacement':replacement,'universal_lemma':'masked_boolean_sum_is_two_encoded_operands_added','source_fragment':'combine','source_span':['0x100bdbc00','0x100bdbc58'],'input_binding':{'VALUE':uinput,'A0':binput}});g.put('w12',replacement)
 tr['combine_full_source']=g.record()
 m=xo('A3','A1');n=xo('S1','S3');T=lambda x:xo(add(x,'#x01fe06c9'),'#x59259907')
 common=lambda a,c,x:add(T(x),x,sub(c,a),'#x144c3fb2')
 outputs={12:common('A0','A2',m),19:common('S0','S2',n),5:add('A2',m,'#xd06c2258'),0:add('S2',n,'#x2dc65bfe'),7:add(sub('S2','S3'),'#xf8afc709'),11:add('A3',m,'#x1368083a'),2:add('S3',n,'#x351694f5'),4:add(sub('S2','S0'),n,'#xf768929f'),14:add(sub('S2','S0'),n,'#x144c3fb2'),1:xo(add(sub('A2','A0'),m,'#x144c3fb2'),'#x08156cbf'),16:'#x000017d8',3:'#x000266d8',6:sub('S2','S3'),15:add(sub('A2','A3'),'#x528cdb78')}
 for k,v in outputs.items():cert('compact_output_W'+str(k),g,[neq(g.get('w'+str(k)),v)])
 rd=lambda pc:next(v for v in g.reads if v['site']==hex(pc))
 cert('combiner_store_roots_and_private_continuation',g,[neq(g.stores[0]['address'],frame(0x448)),neq(g.stores[0]['value'],'#x00000000'),neq(rd(0x100bdbcac)['address'],frame(0x740)),neq(rd(0x100bdbcb0)['address'],at(0x4cf9)),neq(g.get('x17'),bv(0x74b2)),neq(g.get('x21'),frame(0x8348)),neq(g.get('w13'),'S0'),neq(g.get('w25'),'A2'),neq(g.get('w30'),add('A3','#xad732488'))])
 solve('arbitrary_eight_word_bank_domain_nonempty','',result='sat')
 assert len(g.stores)==1 and g.stores[0]['width_bits']==32
 regions=json.loads(read(ROOT/'daemon_mode_one_digit_maps_checks.json'))['semantics']['region_offsets'];scratch={0xd00+x for vv in regions.values()for x in vv};assert len(scratch)==816 and not scratch&set(range(0x448,0x44c))
 protected=set(range(0x450,0x460))|set(range(0x738,0x748))|set(range(0x750,0x754))|set(range(0x1210,0x1218));assert not protected&set(range(0x448,0x44c))
 sem={'arithmetic':'All operations modulo2^32;XOR is bitwise','unary_source_function':'F(x)=u32(x+6891e1c7) XOR08156cbf','masked_source_function':'G(u,v)=u32(((u+01fe06c9) XOR59259907)+(v XOR08156cbf))','input_banks':{'first':['W10=A','W5=B','W25=C','W30=D+ad732488'],'second':['W13=E','W11=F','W3=G','W26=H']},'compact_outputs_SMT':{str(k):v for k,v in outputs.items()},'shared_output_function':'T(x)=u32(x+01fe06c9) XOR59259907;Q(a,b,c,d)=u32(T(d XOR b)+(d XOR b)+c-a+144c3fb2);W12=Q(A,B,C,D),W19=Q(E,F,G,H)','live_source_cuts':cuts,'one_store':{'site':'0x100bdba34','frame_offset':'0x448','width_bytes':4,'value':0},'saved_view_preserved':'X21=F+0x8348;no dereference here','scratch_cells_preserved':816,'next_target':'0x100dab3d0','native_claim':False}
 return pp,tr,sem
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_circuit_byte',lambda q:q['fragments']['combine'].__setitem__('bytes','00'+q['fragments']['combine']['bytes'][2:])),('wrong_initializer_phase',lambda q:q['fragments']['initializer']['instructions'][0].__setitem__('operands','w20, w15, #0x3b9')),('wrong_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];rows=[]
 for n,fn in ops:
  q=copy.deepcopy(s);fn(q);assert not verify(q);rows.append({'name':n,'rejected_by_fresh_original_source_comparison':True})
 return rows
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,sem=certificates(s);aa=alterations(s);actual={pc for v in tr.values()for pc in v['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 counts={**s['verified_source_counts'],'distinct_nonbranch_sites_translated':len(actual),'new_nonbranch_sites_translated':len(tr['combine_full_source']['source_sites']),'untranslated_source_sites':len(expected-actual),'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'universal_circuit_identities':2,'proved_live_cuts':len(sem['live_source_cuts']),'compact_register_outputs':len(sem['compact_outputs_SMT']),'scratch_cells_preserved':816,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_carry_table.py','validate_daemon_mode_one_inverse_tables.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','daemon_mode_one_digit_maps_checks.json']
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'translations':tr,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_two_bank_combination_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
