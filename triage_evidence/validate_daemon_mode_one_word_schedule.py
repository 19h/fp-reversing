#!/usr/bin/env python3
"""Source-pinned word-grid read/write contracts for indices16 through63."""
import copy,json,re,subprocess,shutil
from recover_daemon_mode_one_word_schedule import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_plane_consumer import Engine as Parent
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
from validate_daemon_mode_one_inverse_tables import frame,at
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=''.join(f'(declare-fun B{j} () (_ BitVec 8))\n'for j in range(4,69))+''.join(f'(declare-fun WORD{j} () (_ BitVec 32))\n'for j in range(8))
READ_OFFSETS=[-15,-2,189,202,119,128,51,60]
WRITE_BASES=[135,67,0,204]
class Engine(Parent):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='cneg':
    p=split(i['operands']);w=32 if p[0].startswith('w')else 64;self.put(p[0],f'(ite {self.flags[p[2]]} (bvneg {self.get(p[1],w)}) {self.get(p[1],w)})');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def fresh(n,r=None,loads=None,cells=None):
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=Engine(rr,loads,namespace=n+'_',frame_cells=cells);g.declarations='';return g
def certificates(s):
 pp=[];tr={};fs=s['fragments'];cc=['(bvuge IX #x00000010)','(bvult IX #x00000040)']
 def solve(n,body,conditions=(),result='unsat'):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+body+'\n'+''.join('(assert '+c+')\n'for c in conditions)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-schedule-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(n,r.stdout,r.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,conditions=()):solve(n,prefix(g)+'(assert (or '+' '.join(terms)+'))',conditions)
 def part(n,r=None,loads=None,a=None,end=None,label=None):
  f=fs[n];a=a or int(f['start'],16);end=end or(int(f['instructions'][-1]['ea'],16)if f['instructions'][-1]['mnemonic']=='braa'else int(f['end'],16));g=fresh(label or n,r,loads);g.run({'instructions':[i for i in f['instructions']if a<=int(i['ea'],16)<end]},end);tr[label or n]=g.record();return g
 views=part('views');cert('original_word_view_and_scratch_roots',views,[neq(v['address'],frame(off))for v,off in zip(views.stores,[0x758,0x738])]+[neq(views.stores[0]['value'],frame(0x8b0)),neq(views.stores[1]['value'],frame(0xd00))])
 seed=part('seed',loads={'0x100d76e78':('B0',8),'0x100d76e84':('TABLE',64),'0x100d76e88':('#x0000b8d8',32),'0x100d76e8c':('CONT',64),'0x100d76ed0':(frame(0x8b0),64),'0x100d76ed8':('VALUE',32),'0x100d76edc':('PL',32),'0x100d76ee0':('TAG',32),'0x100d76ee8':('SIZE',32)})
 rd=lambda g,pc:next(v for v in g.reads if v['site']==hex(pc))
 stores={int(v['address'].split('#x')[-1].split(')')[0],16):v for v in seed.stores}
 cert('seed_counter_codecs_map0_and_next_loop',seed,[neq(seed.get('w14'),'#x00000010'),neq(seed.get('w12'),'#x00000292'),neq(seed.get('w5'),'#x2dbe0883'),neq(seed.get('w1'),'#x0000002f'),neq(seed.get('w16'),'#x0000e01f'),neq(seed.get('w24'),'#x00000111'),neq(seed.get('x13'),frame(0x8b0)),neq(rd(seed,0x100d76e78)['address'],frame(0xd00+(757*17)%963)),neq(stores[0x598]['value'],'#x00009033'),neq(stores[0x6cc]['value'],'#xd241f7ac'),neq(stores[0x6d8]['value'],'(bvshl ((_ zero_extend 24) B0) #x00000004)'),neq(rd(seed,0x100d76e8c)['address'],at(0xb8d8))])
 lemma=part('loop',{19:z('VALUE'),1:bv(47)},a=0x100bde130,end=0x100bde13c,label='masked_destination_index')
 cert('masked_word_destination_pair_is_constant47',lemma,[neq(lemma.get('w11'),'#x0000002f')])
 rr={14:z('IX'),12:z('(bvmul (bvsub IX #x00000002) #x0000002f)'),5:z('(bvadd #x2dbe0883 (bvmul (bvsub IX #x00000010) #x0000002f))'),1:bv(47),16:bv(0xe01f),24:bv(273),13:frame(0x8b0)}
 cells={off:(expr,w,'iteration entry premise')for off,expr,w in[(0x6cc,'#xd241f7ac',32),(0x748,'VALUE',32),(0x758,frame(0x8b0),64),(0x738,frame(0xd00),64),(0x6d8,'SIZE',32),(0x618,'#x0000b8d8',32),(0x740,'TABLE',64)]}
 loads={};b=word=0
 for i in fs['loop']['instructions']:
  if i['mnemonic']=='ldrb':loads[i['ea']]=('B'+str(b),8);b+=1
  elif i['mnemonic']=='ldr'and'[sp,'not in i['operands']:
   loads[i['ea']]=('WORD'+str(word),32)if i['operands'].startswith('w')else('CONT',64);word+=i['operands'].startswith('w')
 assert b==69 and word==8
 g=fresh('whole_iteration',rr,loads,cells);cuts=[];binding=None
 for i in fs['loop']['instructions'][:-1]:
  pc=int(i['ea'],16)
  if pc==0x100bde130:
   binding={'VALUE':g.get('w19')};cert('masked_word_destination_actual_live_constant',g,[neq(g.get('w1'),'#x0000002f')],cc)
  g.run({'instructions':[i]},pc+4)
  if pc==0x100bde138:cuts.append({'site':i['ea'],'register':'w11','original_value':g.get('w11'),'replacement':'#x0000002f','universal_lemma':'masked_word_destination_pair_is_constant47','input_binding':binding});g.put('w11','#x0000002f')
 tr['whole_iteration_source']=g.record();frame_read_sites={v['site']for v in g.frame_reads};frame_store_sites={v['site']for v in g.frame_writes};reads=[r for r in g.reads if r['site']not in frame_read_sites and r['width_bits']==32];outputs=[r for r in g.stores if r['site']not in frame_store_sites];assert len(reads)==8 and len(outputs)==4 and len(g.frame_writes)==17
 def address(offset):return f'(bvadd {frame(0x8b0)} {z(f"(bvmul (bvurem (bvmul (bvadd IX {bv(offset,32)}) #x0000002f) #x00000111) #x00000004)")})'
 cert('all_eight_backward_word_read_addresses',g,[neq(row['address'],address(offset))for row,offset in zip(reads,READ_OFFSETS)],cc)
 cert('all_four_new_word_store_addresses',g,[neq(row['address'],address(base))for row,base in zip(outputs,WRITE_BASES)],cc)
 branch=rd(g,0x100bde288)
 cert('iteration48_counter_codecs_roots_and_repeat_exit',g,[neq(g.get('w14'),'(bvadd IX #x00000001)'),neq(g.get('w12'),'(bvmul (bvsub IX #x00000001) #x0000002f)'),neq(g.get('w5'),'(bvadd #x2dbe0883 (bvmul (bvsub IX #x0000000f) #x0000002f))'),neq(g.get('x13'),frame(0x8b0)),neq(g.get('w1'),'#x0000002f'),neq(g.get('w16'),'#x0000e01f'),neq(g.get('w24'),'#x00000111'),neq(g.get('x17'),bv(0x4a5b)),neq(branch['address'],f'(ite (= IX #x0000003f) {at(0xb8d9)} {at(0xb8d8)})')],cc)
 cert('all_literal_frame_store_addresses',g,[neq(next(r for r in g.stores if r['site']==v['site'])['address'],frame(v['frame_offset']))for v in g.frame_writes],cc)
 cert('all_literal_frame_load_addresses_and_joins',g,[neq(next(r for r in g.reads if r['site']==v['site'])['address'],frame(v['frame_offset']))for v in g.frame_reads],cc)
 prior=json.loads(read(ROOT/'daemon_mode_one_plane_consumer_checks.json'));assert prior['all_checks_pass']and prior['local_four_round_plane_consumer_proved']
 from recover_daemon_mode_one_plane_consumer import build as previous_build
 assert previous_build()==json.loads(read(ROOT/'daemon_mode_one_plane_consumer_source.json'))
 initial={r['logical_index_before47_permutation']for r in prior['semantics']['output_word_layout']};assert initial=={base+j for base in[0,67,135,204]for j in range(16)}
 assert not{0x618+j for j in range(4)}&{r['frame_offset']+j for r in prior['semantics']['frame_store_ledger']for j in range(r['width_bits']//8)}
 known=set(initial);ledger=[];written=set()
 for index in range(16,64):
  labels=[index+v for v in READ_OFFSETS];assert set(labels)<=known
  added=[index+b for b in WRITE_BASES];assert len(set(added))==4 and not set(added)&known and not set(added)&set(labels)
  rows=[]
  for label,row in zip(added,outputs):
   slot=47*label%273;off=0x8b0+4*slot;rows.append({'site':row['site'],'logical_label':label,'word_slot':slot,'frame_offset':off});written.update(range(off,off+4))
  ledger.append({'index':index,'word_read_labels':labels,'new_word_stores':rows,'known_words_before':len(known),'repeat':index<63});known.update(added)
 final={base+j for base in[0,67,135,204]for j in range(64)};assert known==final and len(known)==256 and len(written)==768
 initial_bytes={0x8b0+4*(47*n%273)+j for n in initial for j in range(4)};assert not initial_bytes&written and len(initial_bytes|written)==1024
 fb={r['frame_offset']+j for r in g.frame_writes for j in range(r['width_bits']//8)};assert len(fb)==56 and max(fb)<0x8b0 and max(written)==0xcf3 and not fb&written
 assert not(written|fb)&set(range(0xd00,0xd00+963))
 assert not(written|fb)&{off+j for off,w in[(0x438,8),(0x450,16),(0x568,32),(0x618,4),(0x6cc,4),(0x6d8,4),(0x738,16),(0x758,8),(0x1210,8)]for j in range(w)}
 replay={'original_local_word_and_byte_view_roots','round_schedule_counter_roots_and_repeat_exit_induction','replayed_post_loop_frame_schedule_and_three_materialized_word_reloads'};done=set()
 for p in prior['proofs']:
  if p['name']not in replay:continue
  r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_'+p['name'],'replayed_query':True});done.add(p['name']);print('replayed_'+p['name'],'unsat',flush=True)
 assert done==replay;solve('word_extension_abstract_domain_nonempty','',cc,result='sat')
 sem={'iterations':48,'index_domain':'16<=IX<64','stream_bases':[0,67,135,204],'word_read_offsets':READ_OFFSETS,'word_write_bases':WRITE_BASES,'address_rule':'F+0x8b0+4*((47*(IX+offset)) mod273)','initial_known_logical_words':sorted(initial),'final_known_logical_words':sorted(known),'iteration_coverage_ledger':ledger,'word_read_sites':reads,'word_store_sites':outputs,'source_SSA':g.prefix(),'source_reads':g.reads,'source_stores':g.stores,'frame_forwarded_reads':g.frame_reads,'frame_store_ledger':g.frame_writes,'computed_destination_cut':cuts,'byte_read_address_expressions':[r for r in g.reads if r['width_bits']==8],'byte_table_access_sites':69,'byte_table_accesses_total':69*48,'all_byte_table_addresses_bounded_to963_proved':False,'byte_table_semantics_proved':False,'excluded_diagnostic':'The combined universal69-address scratch-bound query returned unknown at the15000 ms limit;it is not an accepted certificate.','word_read_operations':384,'word_read_bytes':1536,'new_word_store_operations':192,'new_word_bytes_written':768,'complete_word_grid_words':256,'complete_word_grid_bytes':1024,'word_grid_slots':273,'unassigned_word_grid_slots':17,'new_word_min_frame_offset':min(written),'new_word_max_frame_offset_inclusive':max(written),'frame_store_sites':17,'frame_store_bytes_per_iteration':68,'frame_bytes_written_distinct':56,'scratch_bytes_preserved':963,'read_bytes_per_iteration':sum(r['width_bits']//8 for r in g.reads),'store_bytes_per_iteration':sum(r['width_bits']//8 for r in g.stores),'phase_cell_F6d8':'Saved map-B[0] byte shifted left4;retained,not a loop counter','counter_cell_F750':'Current logical index16..63,u32','unchanged_selector_cell_F618':'0xb8d8','repeat_target':'0x100bdc3b0','exit_target':'0x100c5917c','whole_algorithm_identified':False,'compact_recurrence_proved':False,'caller_publication_proved':False,'native_claim':False}
 return pp,tr,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('wrong_source_byte',lambda q:q['fragments']['loop'].__setitem__('bytes','00'+q['fragments']['loop']['bytes'][2:])),('wrong_word_load',lambda q:q['fragments']['loop']['instructions'][29].__setitem__('operands','w8, [sp]')),('wrong_view',lambda q:q['fragments']['views']['instructions'][1].__setitem__('operands','x9, x8, #0x24')),('wrong_exit',lambda q:q['branch_edges'][2].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for n,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,sem=certificates(s);aa=alterations(s);actual={pc for t in tr.values()for pc in t['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 counts={**s['verified_source_counts'],'distinct_nonbranch_sites_translated':len(actual),'untranslated_source_sites':len(expected-actual),'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'replayed_queries_unsat':sum(p.get('replayed_query',False)for p in pp),'iterations':48,'word_read_operations':384,'new_word_store_operations':192,'new_word_bytes':768,'complete_word_grid_words':256,'complete_word_grid_bytes':1024,'byte_table_access_sites_retained':69,'IDA_original_byte_spot_checks':3,'IDA_original_bytes_compared':192,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_plane_consumer.py','validate_daemon_mode_one_source_absorption.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','daemon_mode_one_plane_consumer_checks.json','daemon_mode_one_digit_maps_checks.json']
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'translations':tr,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'local_word_schedule_interface_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
