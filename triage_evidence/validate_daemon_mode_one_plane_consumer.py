#!/usr/bin/env python3
"""Four-round plane gather,word scatter and coherent frame-forwarding proofs."""
import copy,json,re,shutil,subprocess,functools
from recover_daemon_mode_one_plane_consumer import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_source_absorption import Engine as Parent
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
from validate_daemon_mode_one_inverse_tables import frame,at
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=''.join(f'(declare-fun J{j} () (_ BitVec 32))\n'for j in range(8))+''.join(f'(declare-fun B{j} () (_ BitVec 8))\n'for j in range(4,32))
PHASE=f'(bvmul {z("IX")} {bv(0x2f50)})'
REG_COORD={23:0x7648,24:0x793d,22:0x14b30,6:0x1511a,30:0x14e25,4:0x1540f,19:0x8511,27:0x8806,21:0x8afb,10:0x15704,16:0x159f9,2:0x15cee,15:0x15fe3}
OUTPUT_BASES=[0,204,135,67,1,205,136,68,2,206,137,69,3,207,138,70]
BYTE_BASES=[40,41,42,43,112,114,113,115,44,45,46,47,116,118,117,119,48,49,50,51,120,121,122,123,52,53,54,55,125,124,126,127]
class Engine(Parent):
 def __init__(self,*args,frame_cells=None,**kw):
  super().__init__(*args,**kw);self.frame_cells=None if frame_cells is None else dict(frame_cells);self.frame_reads=[];self.frame_writes=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   m=i['mnemonic'];p=split(i['operands']);w=32 if p[0].startswith('w')else 64;off=None
   if self.frame_cells is not None and m in['ldr','str']:
    q=re.fullmatch(r'\[sp, #(0x[0-9a-f]+)\]',p[1]);off=int(q[1],16)if q else None
    if off is not None and m=='ldr':
     value,bits,origin=self.frame_cells[off];assert bits==w,(i,bits,w);self.loads[i['ea']]=(value,bits);self.frame_reads.append({'site':i['ea'],'frame_offset':off,'width_bits':bits,'value':value,'origin':origin})
   if m=='umulh':
    a=f'((_ zero_extend 64) {self.get(p[1],64)})';b=f'((_ zero_extend 64) {self.get(p[2],64)})';self.put(p[0],f'((_ extract 127 64) (bvmul {a} {b}))');self.sites.append(i['ea'])
   elif m=='ubfx':
    l,n=int(p[2][1:],0),int(p[3][1:],0);assert 0<n and l+n<=w;self.put(p[0],f'(bvand (bvlshr {self.get(p[1],w)} {bv(l,w)}) {bv((1<<n)-1,w)})');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
   if off is not None and m=='str':
    row=self.stores[-1]
    for a,(_,bits,_)in self.frame_cells.items():assert a==off or not(set(range(a,a+bits//8))&set(range(off,off+w//8))),(i,a,bits)
    self.frame_cells[off]=(row['value'],w,i['ea']);self.frame_writes.append({'site':i['ea'],'frame_offset':off,'width_bits':w,'value':row['value']})
  return self
def fresh(n,r=None,loads=None,frame_cells=None):
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=Engine(rr,loads,namespace=n+'_',frame_cells=frame_cells);g.declarations='';return g
def certificates(s,diagnostic=False):
 pp=[];tr={};cuts=[];fs=s['fragments'];cc=['(bvult IX #x00000004)']
 def solve(n,body,conditions=(),result='unsat'):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+body+'\n'+''.join('(assert '+c+')\n'for c in conditions)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-plane-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.stdout,r.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,conditions=()):solve(n,prefix(g)+'(assert (or '+' '.join(terms)+'))',conditions)
 def part(n,r=None,loads=None,a=None,end=None,label=None,frame_cells=None):
  f=fs[n];a=a or int(f['start'],16);end=end or(int(f['instructions'][-1]['ea'],16)if f['instructions'][-1]['mnemonic']=='braa'else int(f['end'],16));g=fresh(label or n,r,loads,frame_cells);g.run({'instructions':[i for i in f['instructions']if a<=int(i['ea'],16)<end]},end);tr[label or n]=g.record();return g
 views=part('views');cert('original_local_word_and_byte_view_roots',views,[neq(q['address'],frame(off))for q,off in zip(views.stores,[0x758,0x738])]+[neq(views.stores[0]['value'],frame(0x8b0)),neq(views.stores[1]['value'],frame(0xd00))])
 init=part('initializer',{15:bv(0x4923),2:bv(0x16f293e0)},{'0x100dda8e0':('TABLE',64),'0x100dda8e4':('FN',64)})
 cert('original_saved_biased_view_is_frame_plus8348',init,[neq(init.stores[-1]['address'],frame(0x568)),neq(init.stores[-1]['value'],frame(0x8348))])
 seed=part('seed',loads={'0x100a763e0':('#x00004923',32),'0x100a763e8':('TABLE',64),'0x100a763f0':('CONT',64),'0x100a7650c':('J7',32),'0x100a76510':('J5',32),'0x100a76514':('J6',32)})
 cert('first_round_counter_coordinate_and_state_register_seed',seed,[neq(seed.get('x'+str(k)),bv(v))for k,v in REG_COORD.items()]+[neq(seed.get('x7'),bv(0)),neq(seed.get('w3'),'#x000003f0'),neq(seed.get('w20'),'#x00000033'),neq(seed.get('x28'),bv(0x881ba59da4055115)),neq(seed.get('w26'),'J7'),neq(seed.get('w0'),'J5'),neq(seed.get('w25'),'J6')])
 local_loads={'0x100b4f82c':('B0',8),'0x100b4f864':('U',64),'0x100b4f87c':('V',64)}
 hidden=part('loop',{12:z('VALUE'),21:z('(bvadd VALUE #xa3e88c8f)')},local_loads,a=0x100b4f80c,end=0x100b4f87c,label='hidden_byte_index')
 cert('hidden_index_combines_complementary_byte_masks_to_d0',hidden,[neq(hidden.get('w1'),'#x000000d0')])
 div=part('loop',{22:z('VALUE')},{'0x100b4f9f4':('B0',8),'0x100b4f9f8':('U',64)},a=0x100b4f9a0,end=0x100b4fa18,label='hidden_divisor')
 cert('masked_complementary_divisor_is963_for_all_input_words',div,[neq(div.get('w19'),'#x000003c3'),neq(div.get('w23'),'(bvadd ((_ extract 31 0) U) #x000168c2)')])
 last=part('loop',{21:z('VALUE'),4:z('(bvand SIZE #x00000043)'),19:z('(bvxor (bvand SIZE #x00000043) #x00000043)')},a=0x100b4ffec,end=0x100b4fff4,label='last_word_index')
 cert('final_word_scatter_mask_pair_adds43',last,[neq(last.get('w4'),'(bvadd VALUE #x00000043)')])
 prior=json.loads(read(ROOT/'daemon_mode_one_source_absorption_checks.json'));assert prior['all_checks_pass']and prior['local_LEN32_source_absorption_proved']
 cells={}
 for row in prior['semantics']['handoff_store_ledger']:
  off,w,value=row['frame_offset'],row['width_bytes'],int(row['value'],16)
  expr=f'(bvadd {bv(value)} {PHASE})'if w==8 else bv(value,32)
  if off==0x6d8:expr='(bvmul IX #x00000004)'
  cells[off]=(expr,w*8,'recorded round-entry schedule')
 for off,expr,bits in[(0x568,frame(0x8348),64),(0x738,frame(0xd00),64),(0x758,frame(0x8b0),64),(0x740,'TABLE',64)]+[(off,'J'+str(j),32)for j,off in enumerate([0x6c0,0x6c4,0x6c8,0x6bc,0x748])]:cells[off]=(expr,bits,'saved root or incoming state word')
 rr={k:f'(bvadd {bv(v)} {PHASE})'for k,v in REG_COORD.items()};rr.update({7:PHASE,3:z('(bvsub #x000003f0 (bvmul IX #x00000010))'),20:z('(bvadd #x00000033 (bvmul IX #x00000010))'),28:bv(0x881ba59da4055115),0:z('J5'),25:z('J6'),26:z('J7')})
 loads={i['ea']:('B'+str(j),8)for j,i in enumerate(i for i in fs['loop']['instructions']if i['mnemonic']=='ldrb')};loads['0x100b50168']=('CONT',64)
 g=fresh('whole_round',rr,loads,frame_cells=cells);cut_points={0x100b4f878:('w1','#x000000d0','hidden_index_combines_complementary_byte_masks_to_d0'),0x100b4fa14:('w19','#x000003c3','masked_complementary_divisor_is963_for_all_input_words'),0x100b4fff0:('w4','(bvadd (bvmul IX #x00000004) #x00000043)','final_word_scatter_mask_pair_adds43')}
 bindings={}
 for i in fs['loop']['instructions'][:-1]:
  pc=int(i['ea'],16)
  if pc==0x100b4f80c:
   bindings['hidden_byte']={'VALUE':g.get('w12')};cert('hidden_byte_lemma_actual_live_input_binding',g,[neq(g.get('w21'),f'(bvadd {g.get("w12")} #xa3e88c8f)')],cc)
  if pc==0x100b4f9a0:bindings['hidden_divisor']={'VALUE':g.get('w22')}
  if pc==0x100b4ffec:
   bindings['last_word']={'VALUE':g.get('w21'),'SIZE':g.get('w12')};cert('last_word_lemma_actual_live_input_bindings',g,[neq(g.get('w4'),f'(bvand {g.get("w12")} #x00000043)'),neq(g.get('w19'),f'(bvxor (bvand {g.get("w12")} #x00000043) #x00000043)'),neq(g.get('w21'),'(bvmul IX #x00000004)')],cc)
  g.run({'instructions':[i]},pc+4)
  if pc in cut_points:
   reg,replacement,lemma=cut_points[pc];key={0x100b4f878:'hidden_byte',0x100b4fa14:'hidden_divisor',0x100b4fff0:'last_word'}[pc];cuts.append({'site':i['ea'],'register':reg,'original_value':g.get(reg),'replacement':replacement,'universal_lemma':lemma,'input_bindings':bindings[key]});g.put(reg,replacement)
 tr['whole_round_source']=g.record()
 if diagnostic:
  __import__('pathlib').Path('/tmp/fp-plane-model.json').write_text(json.dumps({'SSA':g.prefix(),'reads':g.reads,'stores':g.stores,'frame_reads':g.frame_reads,'frame_writes':g.frame_writes,'registers':g.r,'frame_cells':g.frame_cells}));return pp,tr,{}
 byte_reads=[r for r in g.reads if r['width_bits']==8];frame_sites={r['site']for r in g.frame_writes};outputs=[r for r in g.stores if r['site']not in frame_sites];assert len(byte_reads)==32 and len(outputs)==16 and len(g.frame_writes)==40
 want_byte=lambda base:f'(bvadd {frame(0xd00)} {z(f"(bvurem (bvmul (bvadd (bvmul IX #x00000010) {bv(base,32)}) #x000002f5) #x000003c3)")})'
 want_word=lambda base:f'(bvadd {frame(0x8b0)} {z(f"(bvmul (bvurem (bvmul (bvadd (bvmul IX #x00000004) {bv(base,32)}) #x0000002f) #x00000111) #x00000004)")})'
 # Four residue cases are an exhaustive selected-domain proof,not a trace sample.
 for round_index in range(4):
  domain=cc+[f'(= IX {bv(round_index,32)})']
  cert('all32_plane_gather_addresses_round'+str(round_index),g,[neq(r['address'],want_byte(base))for r,base in zip(byte_reads,BYTE_BASES)],domain)
  cert('all16_local_word_scatter_addresses_round'+str(round_index),g,[neq(r['address'],want_word(base))for r,base in zip(outputs,OUTPUT_BASES)],domain)
 invariant=[neq(g.get('x'+str(k)),f'(bvadd {bv(v+0x2f50)} {PHASE})')for k,v in REG_COORD.items()]
 invariant +=[neq(g.get('x7'),f'(bvadd {PHASE} {bv(0x2f50)})'),neq(g.get('w3'),'(bvsub #x000003e0 (bvmul IX #x00000010))'),neq(g.get('w20'),'(bvadd #x00000043 (bvmul IX #x00000010))'),neq(g.get('x28'),bv(0x881ba59da4055115)),neq(g.frame_cells[0x6d8][0],'(bvadd (bvmul IX #x00000004) #x00000004)')]
 for row in prior['semantics']['handoff_store_ledger']:
  if row['width_bytes']==8:invariant.append(neq(g.frame_cells[row['frame_offset']][0],f'(bvadd {bv(int(row["value"],16)+0x2f50)} {PHASE})'))
 branch=next(r for r in g.reads if r['site']=='0x100b50168')
 invariant +=[neq(branch['address'],f'(ite (= IX #x00000003) {at(0x8049)} {at(0x803e)})'),neq(g.get('x17'),bv(0x505b))]
 cert('round_schedule_counter_roots_and_repeat_exit_induction',g,invariant,cc)
 # Every fixed frame access has a concrete SP-relative address;loads use the
 # latest same-width source store or an explicit round-entry premise.
 cert('all40_frame_stores_have_exact_literal_addresses',g,[neq(next(r for r in g.stores if r['site']==v['site'])['address'],frame(v['frame_offset']))for v in g.frame_writes],cc)
 cert('all_literal_frame_load_addresses_match_forwarding_ledger',g,[neq(next(r for r in g.reads if r['site']==v['site'])['address'],frame(v['frame_offset']))for v in g.frame_reads],cc)
 definitions={}
 for line in g.defs:
  m=re.fullmatch(r'\(define-fun (\S+) \(\) \(_ BitVec \d+\) (.*)\)',line);assert m;definitions[m[1]]=m[2]
 symbols={'J'+str(j)for j in range(8)}|{'B'+str(j)for j in range(32)}|{'IX','K','TABLE','CONT'}|{'Z'+str(j)for j in range(31)}
 @functools.lru_cache(None)
 def dependencies(expr):
  result=set()
  for token in re.findall(r'[A-Za-z_][A-Za-z0-9_]*',expr):
   if token in definitions:result.update(dependencies(definitions[token]))
   elif token in symbols:result.add(token)
  return frozenset(result)
 next_state={**{'J'+str(j):g.frame_cells[off][0]for j,off in enumerate([0x6c0,0x6c4,0x6c8,0x6bc,0x748])},'J5':g.get('w0'),'J6':g.get('w25'),'J7':g.get('w26')}
 dep_rows=[]
 for label,expr in[('word'+str(j),r['value'])for j,r in enumerate(outputs)]+list(next_state.items()):
  dep=dependencies(expr);assert dep<={'J'+str(j)for j in range(8)}|{'B'+str(j)for j in range(32)},(label,dep)
  planes=sorted({0 if BYTE_BASES[int(t[1:])]<112 else 1 for t in dep if t.startswith('B')});dep_rows.append({'output':label,'dependencies':sorted(dep),'local_byte_planes':planes})
 state_families=[['J0','J1','J2','J6'],['J3','J4','J5','J7']]
 for family in state_families:
  for name in family:assert dependencies(next_state[name])<=set(family)
 read_layout=[];word_layout=[]
 for j in range(4):
  for r,base in zip(byte_reads,BYTE_BASES):
   index=base+16*j;read_layout.append({'round':j,'site':r['site'],'symbol':r['input'],'logical_index':index,'physical_offset':757*index%963,'plane':0 if base<112 else 1})
  for k,(r,base)in enumerate(zip(outputs,OUTPUT_BASES)):
   index=(47*(4*j+base))%273;word_layout.append({'round':j,'word':k,'site':r['site'],'logical_index_before47_permutation':4*j+base,'word_slot':index,'frame_offset':0x8b0+4*index,'width_bytes':4})
 assert {r['logical_index']for r in read_layout}==set(range(40,104))|set(range(112,176))and len({r['physical_offset']for r in read_layout})==128
 output_bytes={r['frame_offset']+k for r in word_layout for k in range(4)};assert len(output_bytes)==256
 frame_bytes={r['frame_offset']+k for r in g.frame_writes for k in range(r['width_bits']//8)}
 assert not output_bytes&frame_bytes and max(output_bytes)<0xd00 and max(frame_bytes)<0x8b0
 assert not(output_bytes|frame_bytes)&set(range(0xd00,0xd00+963))
 protected=set(range(0x438,0x440))|set(range(0x450,0x460))|set(range(0x568,0x588))|set(range(0x738,0x748))|set(range(0x758,0x760))|set(range(0x1210,0x1218));assert not(output_bytes|frame_bytes)&protected
 previous_source=json.loads(read(ROOT/'daemon_mode_one_source_absorption_source.json'))
 from recover_daemon_mode_one_source_absorption import build as previous_build
 assert previous_build()==previous_source
 replay={'post_loop_frame_schedule_and_three_materialized_word_reloads','LEN32_repeats31_times_then_joins','both_original_loop_values_are_local_XOR_updates'};done=set()
 for p in prior['proofs']:
  if p['name']not in replay:continue
  r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_'+p['name'],'replayed_query':True});done.add(p['name']);print('replayed_'+p['name'],'unsat',flush=True)
 assert done==replay
 solve('four_round_abstract_domain_nonempty','',cc,result='sat')
 sem={'rounds':4,'round_counter_frame_offset':0x6d8,'round_counter':'4*r,r=0..3','coordinate_step_bytes':0x2f50,'coordinate_step_identity':'0x2f50=16*757','source_byte_gather_layout':read_layout,'source_byte_bases':BYTE_BASES,'source_value_SSA':g.prefix(),'source_store_ledger':g.stores,'source_reads':g.reads,'frame_forwarded_reads':g.frame_reads,'frame_store_ledger':g.frame_writes,'computed_address_cuts':cuts,'output_word_layout':word_layout,'output_word_bases':OUTPUT_BASES,'output_address_rule':'F+0x8b0+4*((47*(4*r+b)) mod273)','word_output_root':'F+0x8b0 saved at F+0x758','biased_byte_view':'F+0x8348 saved at F+0x568;bias cancels in actual state-byte addresses','byte_read_address_rule':'F+0xd00+((757*(16*r+b)) mod963)','state_entry_word_bindings':{'J'+str(j):name for j,name in enumerate(['u32 F+0x6c0','u32 F+0x6c4','u32 F+0x6c8','u32 F+0x6bc','u32 F+0x748','W0','W25','W26'])},'state_exit_words_SMT':next_state,'state_and_output_dependency_certificates':dep_rows,'round_word_store_values_SMT':[r['value']for r in outputs],'byte_read_operations':128,'distinct_plane_bytes_read':128,'word_store_operations':64,'distinct_output_bytes_written':256,'output_min_frame_offset':min(output_bytes),'output_max_frame_offset_inclusive':max(output_bytes),'frame_store_operations_per_round':len(g.frame_writes),'frame_store_bytes_per_round':sum(r['width_bits']//8 for r in g.frame_writes),'frame_bytes_written_distinct':len(frame_bytes),'scratch_bytes_preserved':963,'live_arithmetic_cells_preserved':800,'arithmetic_table_byte_reads':0,'direct_source_byte_reads':0,'image_byte_reads':0,'preserved_frame_byte_offsets':sorted(protected),'repeat_target':'0x100b4ef4c','exit_target':'0x100d76e6c','compact_full_transform_proved':False,'caller_output_publication_proved':False,'native_claim':False}
 sem['state_word_families']=state_families;sem['local_plane_bytes_absent_from_carried_state']=True;sem['round_index_absent_from_word_values']=True
 sem['loop_read_bytes_per_round']=sum(r['width_bits']//8 for r in g.reads);sem['loop_store_bytes_per_round']=sum(r['width_bits']//8 for r in g.stores)
 sem['complete_loop_unique_bytes_written']=len(output_bytes|frame_bytes);sem['frame_reads_forwarded_from_current_round_stores']=sum(r['origin'].startswith('0x')for r in g.frame_reads)
 return pp,tr,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('wrong_source_byte',lambda q:q['fragments']['loop'].__setitem__('bytes','00'+q['fragments']['loop']['bytes'][2:])),('wrong_plane_load',lambda q:q['fragments']['loop']['instructions'][67].__setitem__('operands','w1, [sp]')),('wrong_view_root',lambda q:q['fragments']['views']['instructions'][1].__setitem__('operands','x9, x8, #0x24')),('wrong_target',lambda q:q['branch_edges'][2].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for n,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':n,'rejected_by_fresh_original_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,sem=certificates(s);aa=alterations(s);actual={pc for t in tr.values()for pc in t['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 counts={**s['verified_source_counts'],'distinct_nonbranch_sites_translated':len(actual),'untranslated_source_sites':len(expected-actual),'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'replayed_queries_unsat':sum(p.get('replayed_query',False)for p in pp),'source_certified_address_cuts':len(sem['computed_address_cuts']),'rounds':4,'plane_byte_reads':128,'word_store_operations':64,'distinct_output_bytes':256,'carried_state_words':8,'state_output_dependency_certificates':len(sem['state_and_output_dependency_certificates']),'scratch_bytes_preserved':963,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_source_absorption.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','daemon_mode_one_source_absorption_checks.json','daemon_mode_one_digit_maps_checks.json']
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'translations':tr,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_four_round_plane_consumer_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
