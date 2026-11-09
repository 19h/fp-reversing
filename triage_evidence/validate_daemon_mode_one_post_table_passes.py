#!/usr/bin/env python3
"""Source certificates for the post-table size/read/state-handoff contracts."""
import copy,json,subprocess,shutil
from recover_daemon_mode_one_post_table_passes import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_carry_table import Engine as Parent
from validate_daemon_mode_one_inverse_tables import frame,at
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec 32))\n'for n in ['IDX']+['A'+str(j)for j in range(4)]+['S'+str(j)for j in range(4)])
class Engine(Parent):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='neg':
    p=split(i['operands']);self.put(p[0],f'(bvneg {self.get(p[1],32)})');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def certificates(s):
 pp=[];tr={};sem={};models={}
 def solve(n,body,cc=(),result='unsat',integer=False):
  q='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+('(declare-fun XI () Int)\n'if integer else DECL+EXTRA)+body+'\n'+''.join('(assert '+v+')\n'for v in cc)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-post-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.stdout,r.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,cc=()):solve(n,prefix(g)+'(assert (or '+' '.join(terms)+'))',cc)
 def run(n,r=None,loads=None,a=None,end=None,label=None):
  label=label or n;f=s['fragments'][n];a=a or int(f['start'],16);end=end or(int(f['instructions'][-1]['ea'],16)if f['instructions'][-1]['mnemonic']=='braa'else int(f['end'],16));rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=Engine(rr,loads,namespace=label+'_');g.declarations='';g.run({'instructions':[i for i in f['instructions']if a<=int(i['ea'],16)<end]},end);tr[label]=g.record();models[label]=g;return g
 def rd(g,pc):return next(v for v in g.reads if v['site']==hex(pc))
 def st(g,pc):return next(v for v in g.stores if v['site']==hex(pc))
 def regs(g,rr):return[neq(g.get('w'+str(k)),bv(v,32))for k,v in rr.items()]
 size=run('size_decode',{20:z('(bvadd (bvmul VALUE #x4fabe741) #x1d89a59c)')})
 cert('saved_size_decoder_has_exact_zero_preimage',size,[neq('(= '+size.get('w13')+' #x16f293c0)','(= VALUE #x00000000)')])
 cert('LEN32_saved_decoder_value',size,[neq(size.get('w13'),'#x16f293e0')],['(= VALUE #x00000020)'])
 solve('saved_decoder_is_not_global_normalized_length',prefix(size)+'(assert '+neq(size.get('w13'),'(bvadd VALUE #x16f293c0)')+')',result='sat')
 ss=run('size_save',{13:z('VALUE')});src=run('source_save',{30:'BUF'})
 cert('saved_size_word_publication',ss,[neq(ss.stores[0]['address'],frame(0x750)),neq(ss.stores[0]['value'],'VALUE')]);cert('saved_source_pointer_publication',src,[neq(src.stores[0]['address'],frame(0x458)),neq(src.stores[0]['value'],'BUF')])
 seed=run('relabel_seed',{0:bv(944),10:bv(757),11:bv(0x2207),12:bv(963),13:bv(15),14:bv(0x4def),15:bv(527),16:bv(0x22b63cbf),21:frame(0xd00),23:bv(0x100f715a0)},{'0x100d1798c':('B0',8),'0x100d179f0':('B1',8),'0x100d17a18':('TABLE',64),'0x100d17a1c':('FN',64)})
 cert('digit_map_exit_binds_gate_phase',seed,[neq(seed.get('w1'),'#x0000a0c1'),neq(seed.get('w8'),'#x0000000d'),neq(seed.get('x23'),bv(0x100f715a0))])
 gate=run('gate',{1:bv(0xa0c1),8:bv(13),23:bv(0x100f715a0)},{'0x100daee74':('VALUE',32),'0x100daeea0':('TABLE',64),'0x100daeea4':('FN',64)})
 gc={26:0x20420872,25:0x9b092801,10:0x2fc893f3,5:0x47e362f4,30:0xcdb52cfa,13:0x2fc893f3,3:0x9b092801,11:0x47e362f4,12:0x663b,15:0x4923}
 cert('post_table_gate_size_partition_roots_and_seeds',gate,[neq(st(gate,0x100daee68)['address'],frame(0x450)),neq(st(gate,0x100daee68)['value'],bv(0x100f715a0)),neq(rd(gate,0x100daee74)['address'],frame(0x750)),neq(rd(gate,0x100daeea4)['address'],f'(ite (= VALUE #x16f293c0) {at(0xa0c1)} {at(0xa0cc)})')]+regs(gate,gc))
 setup=run('setup',{12:bv(0x663b),15:bv(0x4923),2:z('VALUE'),25:bv(0x9b092801)},{'0x100bd6c2c':('TABLE',64),'0x100bd6c30':('FN',64)})
 fc={0:0x8980,2:0x36,5:0xca0ce743,8:0,10:0x2fc893f3,12:0xad53e765,13:0xd83d9e9b,14:0x20420872,15:0xd83d9e7c,16:0xd83d9e7b,4:0xc6386678,6:0x7dd64931,7:0xff00ff01,19:0x8229b6ce,20:0xd7fb8d7f,21:0x026e5a70,22:0x64e5a5f1,23:0xcccd66fa,24:0x9c116f52,25:0x9b092801,26:0x23,27:0x663b,28:0x4861eac7}
 cert('LEN32_first_pass_seed_and_reused_word_cell',setup,regs(setup,fc)+[neq(setup.get('x9'),'TABLE'),neq(st(setup,0x100bd6c80)['address'],frame(0x748)),neq(st(setup,0x100bd6c80)['value'],'#x000087c8'),neq(rd(setup,0x100bd6c30)['address'],at(0x663b))],['(= VALUE #x16f293e0)'])
 rr={k:bv(v)for k,v in fc.items()};rr.update({8:z('IDX'),12:z('(bvadd IDX #xad53e765)'),15:z('(bvadd IDX #xd83d9e7c)'),9:'TABLE',10:z('A0'),5:z('A1'),25:z('A2'),14:z('A3')})
 ll={'0x100d77c20':('BUF',64),'0x100d77c24':('B0',8),'0x100d77d24':('FN',64)};domain=['(bvult IDX #x00000020)']
 first=run('first',rr,ll)
 cert('first_pass_reads_same32_bytes_and_control',first,[neq(rd(first,0x100d77c20)['address'],frame(0x458)),neq(rd(first,0x100d77c24)['address'],'(bvadd BUF ((_ zero_extend 32) IDX))'),neq(rd(first,0x100d77d24)['address'],f'(ite (bvult IDX #x0000001f) {at(0x8980)} {at(0x89a3)})'),neq(first.get('w8'),'IDX'),neq(first.get('w12'),'(bvadd IDX #xad53e765)'),neq(first.get('w15'),'(bvadd IDX #xd83d9e7c)'),neq(first.get('x9'),'TABLE')],domain)
 inj=run('first',rr,ll,end=0x100d77c60,label='first_injection')
 zfirst='(bvadd (bvsub (bvmul (bvadd ((_ zero_extend 24) B0) IDX) #x0d1586fd) A1) #xed2cd9c2)'
 cert('first_byte_injection_compact_word',inj,[neq(inj.get('w5'),zfirst)],domain)
 advance=run('advance',{9:'TABLE',27:bv(0x663b),30:z('VALUE'),28:bv(0x4861eac7),8:z('IDX'),12:z('(bvadd IDX #xad53e765)'),15:z('(bvadd IDX #xd83d9e7c)')},{'0x100d77864':('FN',64)})
 cert('first_pass_advance_returns_and_increments',advance,[neq(advance.get('w5'),'(bvadd VALUE #x4861eac7)'),neq(advance.get('w8'),'(bvadd IDX #x00000001)'),neq(advance.get('w12'),'(bvadd IDX #xad53e766)'),neq(advance.get('w15'),'(bvadd IDX #xd83d9e7d)'),neq(rd(advance,0x100d77864)['address'],at(0x663b))],domain)
 kept={10:z('A0'),5:z('A1'),25:z('A2'),14:z('A3')}
 between=run('between',{9:'TABLE',**kept},{'0x100d64a04':(bv(0x87c8,32),32),'0x100d64a14':('VALUE',32),'0x100d64a74':('FN',64),'0x100d64b18':('BUF',64)})
 sc={0:0x17774fb2,1:0x17774f93,2:0x17774f92,11:0x47e362f4,19:0x9b092801,4:0x20420872,13:0x2fc893f3,12:0x20ffb251,15:0,6:0x0d1586fd,16:0x87c6,23:0x9c116f53,24:0x06ae69f1,22:0x94c61e16,26:0xca630f0b,27:0xc6386678,28:0x4a630f0f,30:0x909b7583,8:0x4ccd66fa}
 cert('between_pass_reseeds_and_preserves_first_bank',between,regs(between,sc)+[neq(between.get('w'+str(k)),f'A{j}')for j,k in enumerate([10,5,25,14])]+[neq(between.get('x21'),'BUF'),neq(rd(between,0x100d64b18)['address'],frame(0x458)),neq(rd(between,0x100d64a74)['address'],at(0x87c8)),neq(st(between,0x100d64ad0)['address'],frame(0x748)),neq(st(between,0x100d64ad0)['value'],'#x00004923')],['(= VALUE #x16f293e0)'])
 rr={k:bv(v)for k,v in sc.items()};rr.update({15:z('IDX'),12:z('(bvadd IDX #x20ffb251)'),1:z('(bvadd IDX #x17774f93)'),21:'BUF',13:z('A0'),11:z('A1'),19:z('A2'),4:z('A3')})
 ll={'0x100bf2de4':('B0',8),'0x100bf2f1c':('TABLE',64),'0x100bf2f20':('FN',64)};second=run('second',rr,ll)
 cert('second_pass_reads_same32_bytes_and_control',second,[neq(rd(second,0x100bf2de4)['address'],'(bvadd BUF ((_ zero_extend 32) IDX))'),neq(rd(second,0x100bf2f20)['address'],f'(ite (bvult IDX #x0000001f) {at(0x87c8)} {at(0x87c6)})'),neq(second.get('w15'),'(bvadd IDX #x00000001)'),neq(second.get('w12'),'(bvadd IDX #x20ffb252)'),neq(second.get('w1'),'(bvadd IDX #x17774f94)'),neq(second.get('x21'),'BUF')]+[neq(second.get('x'+str(k)),'Z'+str(k))for k in[10,5,25,14]],domain)
 inj=run('second',rr,ll,end=0x100bf2e18,label='second_injection');zsecond='(bvadd (bvsub (bvmul (bvadd ((_ zero_extend 24) B0) IDX) #x0d1586fd) A1) #x6b035573)'
 cert('second_byte_injection_compact_word',inj,[neq(inj.get('w11'),zsecond)],domain)
 solve('source_byte_index_domain_nonempty','',domain,result='sat')
 q='((_ extract 31 0) (bvlshr (bvmul ((_ zero_extend 32) VALUE) #x00000000ff00ff01) #x0000000000000028))';red=f'(bvsub (bvsub VALUE (bvmul {q} #x00000101)) VALUE)'
 reduction=run('first',{5:z('VALUE'),17:z('(bvsub VALUE #x7b682142)'),6:bv(0x7dd64931),7:bv(0xff00ff01),19:bv(0x8229b6ce),20:bv(0xd7fb8d7f),21:bv(0x026e5a70)},a=0x100d77c60,end=0x100d77c8c,label='first_reduction')
 cert('first_source_reduction_is_remainder_minus_word',reduction,[neq(reduction.get('w17'),red)])
 reduction=run('second',{11:z('VALUE')},a=0x100bf2e18,end=0x100bf2e34,label='second_reduction')
 cert('second_source_reduction_is_remainder_minus_word',reduction,[neq(reduction.get('w11'),red)])
 solve('exact_unsigned_quotient257','(assert (distinct (div (* XI 4278255361) 1099511627776) (div XI 257)))',['(<= 0 XI)','(< XI 4294967296)'],integer=True)
 hand=run('handoff',{14:z('A3'),4:z('S3'),19:z('S2')},{'0x100dac020':(bv(0x4923,32),32),'0x100dac034':('TABLE',64),'0x100dac038':('FN',64),'0x100dac044':('VALUE',32)})
 cert('source_banks_reconverge_at_shared_initializer',hand,[neq(hand.get('w30'),'(bvadd A3 #xad732488)'),neq(hand.get('x26'),z('S3')),neq(hand.get('x3'),z('S2')),neq(hand.get('w2'),'VALUE'),neq(hand.get('w15'),'#x00004923'),neq(rd(hand,0x100dac038)['address'],at(0x8ad6))])
 keep={10:z('A0'),5:z('A1'),25:z('A2'),30:z('A3'),13:z('S0'),11:z('S1'),3:z('S2'),26:z('S3')}
 init=run('initializer',{15:bv(0x4923),2:z('VALUE'),**keep},{'0x100dda8e0':('TABLE',64),'0x100dda8e4':('FN',64)})
 literals=[];ii=s['fragments']['initializer']['instructions'];terms=[]
 for j,i in enumerate(ii):
  if i['mnemonic']!='str':continue
  row=st(init,int(i['ea'],16));off=int(i['operands'].split('#')[1].strip(']'),0);width=row['width_bits'];terms.append(neq(row['address'],frame(off)))
  if off in[0x434,0x44c,0x568]:continue
  lo,hi=ii[j-2:j];assert lo['mnemonic']=='mov'and hi['mnemonic']=='movk'and 'lsl #16'in hi['operands'];value=int(split(lo['operands'])[1][1:],0)|(int(split(hi['operands'])[1][1:],0)<<16);assert width==32;terms.append(neq(row['value'],bv(value,32)));literals.append({'site':i['ea'],'frame_offset':hex(off),'value_u32':hex(value)})
 assert len(literals)==32 and len(init.stores)==35
 cert('initializer_exact_literal_stores_live_banks_and_next_target',init,terms+[neq(init.get('x'+str(k)),v)for k,v in keep.items()]+[neq(st(init,0x100ddaa8c)['value'],frame(0x8348)),neq(rd(init,0x100dda8e4)['address'],at(0x6284)),neq(init.get('w22'),'#xad732488')])
 cert('initializer_LEN32_computed_words',init,[neq(st(init,0x100dda880)['value'],'#xec2864b6'),neq(st(init,0x100ddaa88)['value'],'#x3874e8e9')],['(= VALUE #x16f293e0)'])
 writebytes=[]
 for n in['gate','setup','between','initializer']:
  for row in models[n].stores:
   # Every address was source-certified against its fixed frame offset.
   pc=int(row['site'],16);ins=next(i for i in s['fragments'][n]['instructions']if int(i['ea'],16)==pc);off=int(ins['operands'].split('#')[1].strip(']'),0);writebytes.extend(range(off,off+row['width_bits']//8))
 old=json.loads(read(ROOT/'daemon_mode_one_digit_maps_checks.json'));regions=old['semantics']['region_offsets'];scratch={0xd00+x for v in regions.values()for x in v};assert len(scratch)==816
 protected=set(range(0x458,0x460))|set(range(0x750,0x754))|set(range(0x738,0x748))|set(range(0x1210,0x1218));assert not set(writebytes)&(protected|scratch)
 # Earlier table writes lie in T+[0,962];the earlier source-pass ledger has
 # one saved-size publication and one SRC publication,then disjoint stores.
 prior=json.loads(read(ROOT/'daemon_mode_one_source_passes_source.json'))
 later=[r for r in prior['frame_store_ledger']if r['site']not in['0x100d5e010','0x100d5e38c']]
 assert all(not set(range(r['frame_offset'],r['frame_offset']+r['width_bytes']))&(set(range(0x750,0x754))|set(range(0x458,0x460)))for r in later)
 solve('scratch_domain_disjoint_from_saved_source_size_roots','(assert (or '+' '.join(f'(= (bvadd K #x0000000000000d00 O) {frame(p)})'for p in protected)+'))',['(bvult O #x00000000000003c3)'])
 selected={'LEN32_entry_selects_source_seed_and_two_local_views','second_pass_reseeds_same_words_and_preserves_first_bank','second_pass_control_reads32_bytes_in_order'};parent=json.loads(read(ROOT/'daemon_mode_one_source_passes_checks.json'));replayed=[]
 for proof in parent['proofs']:
  if proof['name']not in selected:continue
  r=subprocess.run([SOLVER,'-in'],input=proof['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**proof,'name':'replayed_'+proof['name'],'replayed_query':True});replayed.append(proof['name'])
 assert set(replayed)==selected
 sem={'selected_source':'OBJ+0x18,32 B,via saved F+0x458','size_zero_preimage':'saved_word==16f293c0 iff LEN==0;decoder is not globally LEN+16f293c0','LEN32_saved_word':'0x16f293e0','new_source_reads':64,'distinct_source_offsets':list(range(32)),'first_injection':'Z=u32((byte+j)*0d1586fd -B +ed2cd9c2)','second_injection':'Z=u32((byte+j)*0d1586fd -B +6b035573)','shared_reduction':'u32((Z mod257)-Z)','pass_equivalence_proved':False,'state_SSA':{n:{'definitions':models[n].prefix(),'outputs':{str(k):models[n].get('w'+str(k))for k in ks}}for n,ks in[('first',[10,5,25,14,30]),('second',[13,11,19,4])]},'first_bank_survives_second_in':[10,5,25,14],'initializer_bank_ABI':{'first':['W10','W5','W25','W30=prior W14+ad732488'],'second':['W13','W11','W3=prior W19','W26=prior W4']},'F748_lifecycle':['old shuffle seed word','87c8 first-pass private phase','4923 after between-pass setup'],'literal_words':literals,'initializer_store_count':35,'initializer_unwritten_word_in_literal_span':'F+0x424','initializer_computed_LEN32_words':{'0x434':'0xec2864b6','0x44c':'0x3874e8e9'},'initializer_saved_view':{'cell':'F+0x568','value':'F+0x8348','native_extent_unknown':True},'post_table_write_offsets':sorted(set(writebytes)),'scratch_cells_preserved':816,'protected_frame_offsets':sorted(protected),'next_index':'0x6284','next_target':next(e['target']for e in s['branch_edges']if e['fragment']=='initializer'),'native_claim':False}
 return pp,tr,sem
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_size_source',lambda q:q['fragments']['size_decode'].__setitem__('bytes','00'+q['fragments']['size_decode']['bytes'][2:])),('wrong_source_load',lambda q:q['fragments']['first']['instructions'][2].__setitem__('operands','w17, [x11]')),('wrong_branch',lambda q:q['branch_edges'][0].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];rows=[]
 for name,fn in ops:
  q=copy.deepcopy(s);fn(q);assert not verify(q);rows.append({'name':name,'rejected_by_fresh_original_source_comparison':True})
 return rows
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,sem=certificates(s);aa=alterations(s);actual={pc for t in tr.values()for pc in t['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 counts={**s['verified_source_counts'],'distinct_nonbranch_sites_translated':len(actual),'untranslated_source_sites':len(expected-actual),'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'replayed_queries_unsat':sum(p.get('replayed_query',False)for p in pp),'new_source_reads':64,'distinct_source_offsets':32,'literal_words':32,'initializer_store_count':35,'scratch_cells_preserved':816,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_carry_table.py','validate_daemon_mode_one_inverse_tables.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','daemon_mode_one_digit_maps_checks.json','daemon_mode_one_source_passes_checks.json']
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'translations':tr,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_size_source_handoff_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
