#!/usr/bin/env python3
"""Source certificates for two record-byte passes and sparse scratch writes."""
import copy,json,re,shutil,subprocess
from recover_daemon_mode_one_record_passes import ROOT,P,SCOPE,FLAGS,BLOCKS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_mode_one_handoff_tools import FrameSSA,CandidateDAG,parse
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,at,frame
from validate_daemon_mode_one_record_scan import EXTRA as PARENT_DECL
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=PARENT_DECL+''.join(f'(declare-fun {n} () (_ BitVec 32))\n'for n in ['IDX']+['S'+str(j)for j in range(4)]+['T'+str(j)for j in range(4)])
ADDR=[(0xbd700+0x362*j)%961 for j in range(16)]
def certificates(s):
 pp=[];models={};fs=s['fragments'];common={0x740:('TABLE',64),0x728:('COUNT',32),0x748:('PBUF',64),0x750:(frame(0xd10),64),0x730:(bv(0x4923,32),32)}
 def solve(name,body,result='unsat',conditions=(),integer=False):
  q='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+('(declare-fun XI () Int)\n'if integer else DECL+EXTRA)+body+'\n'+''.join('(assert '+v+')\n'for v in conditions)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-record-passes-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def pre(g):return ''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())+g.prefix()
 def cert(name,g,terms,conditions=()):solve(name,pre(g)+'(assert (or '+' '.join(terms)+'))',conditions=conditions)
 def rd(g,pc):return next(v for v in g.reads if v['site']==hex(pc))
 def run(g,name,a=None,end=None):
  f=fs[name];ii=[v for v in f['instructions']if a is None or int(v['ea'],16)>=a];g.run({'instructions':ii},end or int(f['instructions'][-1]['ea'],16));return g
 def chained(name,previous,overrides=None,loads=None):
  g=FrameSSA(name,{**previous.r,**(overrides or{})},presets=common,loads=loads);g.defs=list(previous.defs);g.decl=dict(previous.decl);g.loaded=previous.loaded;return g
 from recover_daemon_mode_one_record_scan import build as previous_build
 from validate_daemon_mode_one_record_scan import certificates as previous_certificates
 old=previous_build();assert old==json.loads(read(ROOT/DEPS[0]));prior=json.loads(read(ROOT/DEPS[1]));bp,bs=previous_certificates(old);assert bp==prior['proofs']and json.loads(json.dumps(bs))==prior['semantics']
 for p in bp:pp.append({**p,'name':'replayed_scan_'+p['name'],'replayed_query':True})
 pm=bs['source_models']['length_gate'];rr={int(k)if str(k).isdigit()else k:v for k,v in pm['final_registers'].items()};decl=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in pm['declarations'].items())
 solve('actual_selected_record_seed_inputs',decl+pm['source_SSA']+'(assert (or '+neq('((_ extract 31 0) '+rr[16]+')','COUNT')+' '+neq('((_ extract 31 0) '+rr[1]+')',bv(0x4923,32))+' '+neq('((_ extract 31 0) '+rr[2]+')',bv(0x4923,32))+' '+neq('((_ extract 31 0) '+rr[8]+')',bv(0xb8b1edac,32))+'))')
 seed=FrameSSA('first_seed',rr,presets=common,loads={'0x100d86400':('FN',64)});seed.defs=pm['source_SSA'].splitlines();seed.decl=dict(pm['declarations']);run(seed,'first_seed');models['first_seed']=seed
 first_constants={1:0x4923,5:0x497ff60c,6:0xb68009f3,7:0xffffd3fd,8:0xc9ce925b,12:0x528d39cf,13:0x34695a82,14:0x1649b14e,15:0xbfa31027,16:0x3773df7c,19:0xffffd3ef,20:0x4008,21:0x5ff8,22:0xad72a711,23:0xfbfad9b5,24:0xafa811b9,25:0xec522800,26:0xff00ff01,27:0xfd773292,30:0xf5616085}
 cert('first_pass_seed_and_original_edge',seed,[neq(seed.get('w'+str(k)),bv(v,32))for k,v in first_constants.items()]+[neq(seed.get('w9'),'(bvadd COUNT #x497ff60c)'),neq(rd(seed,0x100d86400)['address'],at(0x1f20))])
 first=chained('first',seed,{12:z('(bvadd IDX #x528d39cf)'),**{j:z('S'+str(k))for k,j in enumerate([13,14,15,16])}},loads={'0x100d8ac70':('B0',8),'0x100d8b148':('FN',64)});run(first,'first');models['first']=first
 pred='(bvult (bvadd IDX #x00000001) COUNT)';domain='(bvult IDX COUNT)'
 cert('first_pass_byte_counter_and_unsigned_control',first,[neq(rd(first,0x100d8ac70)['address'],f'(bvadd PBUF {z("IDX")})'),neq(first.get('w12'),'(bvadd IDX #x07cc0324)'),neq(first.get('w10'),bv(0x1f20,32)),neq(first.get('w11'),bv(0x5d1a,32)),neq(first.get('w28'),bv(0x4978bdec,32)),neq(rd(first,0x100d8b148)['address'],f'(ite {pred} {at(0xa927)} {at(0xa91b)})')])
 assert not first.stores
 repeat=chained('repeat',first,loads={'0x100bf6c7c':('FN',64)});run(repeat,'repeat');models['repeat']=repeat
 cert('first_repeat_restores_counter_and_carried_seed',repeat,[neq(repeat.get('w12'),'(bvadd IDX #x528d39d0)'),neq(repeat.get('w1'),bv(0x4923,32)),neq(repeat.get('w26'),bv(0xff00ff01,32)),neq(repeat.get('w16'),f'(bvadd {first.get("w0")} {first.get("w16")} #x7ec1f1d0)'),neq(rd(repeat,0x100bf6c7c)['address'],at(0x1f20))]+[neq(repeat.get('x'+str(j)),first.get('x'+str(j)))for j in [13,14,15]])
 assert not repeat.stores
 first_preserved=[5,6,7,8,9,19,20,21,22,23,24,25,27,30]
 for reg in first_preserved:
  for name in ['first','repeat']:
   assert not {prefix+str(reg)for prefix in ['x','w']}&set(s['register_write_sets'][name]),(reg,name)
 between=chained('between',first,loads={'0x100d03b50':('FN',64)});run(between,'between');models['between']=between
 second_constants={1:0,2:0x4c5b0000,3:0x6ed7,5:0x36c8e19b,6:0x3e9d4b08,7:0xc9371e65,8:0x4c5b2300,9:0xb8b1edac,10:0x713c7a3a,11:0x1649b14e,12:0x34695a82,19:0xfde77bff,25:0xd8e2155d,26:0x3022fea3,27:0x43867224,28:0x4978bdec}
 cert('between_passes_reseeds_second_bank_and_phase',between,[neq(between.get('w'+str(k)),bv(v,32))for k,v in second_constants.items()]+[neq(between.get('w4'),'(bvadd COUNT #xc9371e64)'),neq(between.get('x30'),'PBUF'),neq(between.loadframe(0x730,32),bv(0x4923,32)),neq(rd(between,0x100d03b50)['address'],at(0x5d1a))]+[neq(between.get('x'+str(j)),first.get('x'+str(j)))for j in [0,13,14,15,16]])
 assert len(between.stores)==1
 second=chained('second',between,{1:z('IDX'),6:z('(bvadd IDX #x3e9d4b08)'),7:z('(bvadd IDX #xc9371e65)'),**{j:z('T'+str(k))for k,j in enumerate([9,10,11,12])}},loads={'0x100dacfa8':('B0',8),'0x100dad2a8':('FN',64)});run(second,'second');models['second']=second
 cert('second_pass_byte_counter_and_unsigned_control',second,[neq(rd(second,0x100dacfa8)['address'],f'(bvadd PBUF {z("IDX")})'),neq(second.get('w1'),'(bvadd IDX #x00000001)'),neq(second.get('w6'),'(bvadd IDX #x3e9d4b09)'),neq(second.get('w7'),'(bvadd IDX #xc9371e66)'),neq(rd(second,0x100dad2a8)['address'],f'(ite {pred} {at(0x6ee2)} {at(0x6ed7)})')]+[neq(second.get('x'+str(j)),between.get('x'+str(j)))for j in [0,13,14,15,16,30]])
 assert not second.stores
 second_preserved=[2,3,4,5,8,19,25,26,27,28,30,0,13,14,15,16]
 for reg in second_preserved:assert not{prefix+str(reg)for prefix in ['x','w']}&set(s['register_write_sets']['second']),reg
 solve('ordered_pass_next_index_no_wrap_and_partition','(assert (or (bvule (bvadd IDX #x00000001) IDX) (bvugt (bvadd IDX #x00000001) COUNT) (distinct '+pred+' (distinct (bvadd IDX #x00000001) COUNT))))',conditions=[domain])
 # Both reciprocal implementations have separately captured source shapes.
 quotient='((_ extract 31 0) (bvlshr (bvmul ((_ zero_extend 32) VALUE) #x00000000ff00ff01) #x0000000000000028))'
 for name,a,b,reg,out in [('first',0x100d8ade8,0x100d8adfc,15,15),('second',0x100dad160,0x100dad17c,10,10)]:
  g=FrameSSA(name+'_reduce',{reg:z('VALUE'),26:bv(0xff00ff01)});run(g,name,a,b);models[name+'_reduce']=g
  cert(name+'_source_remainder257_added_to_input',g,[neq(g.get('w'+str(out)),f'(bvadd VALUE (bvsub VALUE (bvmul {quotient} #x00000101)))')])
 solve('reciprocal257_exact_unsigned32','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or (distinct (div (* XI 4278255361) 1099511627776) (div XI 257)) (>= (* XI 4278255361) 18446744073709551616) (>= (* 257 (div XI 257)) 4294967296)))',integer=True)
 solve('remainder257_exact_range','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or (< (- XI (* 257 (div XI 257))) 0) (> (- XI (* 257 (div XI 257))) 256)))',integer=True)
 restore=chained('restore',second,loads={'0x100b08904':('FN',64)});run(restore,'restore');models['restore']=restore
 cert('second_pass_exit_restores_scratch_and_first_state_word',restore,[neq(restore.get('w2'),bv(0x4923,32)),neq(restore.get('w8'),f'(bvadd {first.get("w0")} {first.get("w16")})'),neq(restore.get('x26'),frame(0xd10)),neq(rd(restore,0x100b08904)['address'],at(0x324a))]+[neq(restore.get('x'+str(j)),second.get('x'+str(j)))for j in [9,10,11,12,13,14,15]])
 assert not restore.stores
 # The zero-count route preserves the seed's X26; the nonzero route restores it.
 for name in ['decode','next','payload_gate','length_gate']:assert not {'x26','w26'}&set(old['register_write_sets'][name]),name
 sr={**rr,2:bv(0x4923),8:z('VALUE'),26:frame(0xd10),**{j:z('T'+str(k))for k,j in enumerate([9,10,11,12])},**{j:z('S'+str(k))for k,j in enumerate([13,14,15])}}
 scatter_seed=FrameSSA('scatter_seed',sr,presets=common,loads={'0x100bf2ac8':('FN',64)});scatter_seed.defs=pm['source_SSA'].splitlines();scatter_seed.decl=dict(pm['declarations']);run(scatter_seed,'scatter_seed');models['scatter_seed']=scatter_seed
 sc={0:0x25,1:0x2f1e,2:0x7e4ab0b3,3:15,4:0xbd700,5:961,7:0xc6e2f0ee,8:0x4757bfa0,21:0x005080a2,22:0x005080a1,23:0x47073f01,24:0x5c58fc80,25:0x4d,27:0x23,28:0xcfa97dc6,30:0x41060280}
 cert('common_scatter_seed_saves_word_and_preserves_banks',scatter_seed,[neq(scatter_seed.get('w'+str(k)),bv(v,32))for k,v in sc.items()]+[neq(scatter_seed.loadframe(0x730,32),'VALUE'),neq(scatter_seed.get('x26'),frame(0xd10)),neq(rd(scatter_seed,0x100bf2ac8)['address'],at(0x2f1e))]+[neq(scatter_seed.get('w'+str(j)),'T'+str(k))for k,j in enumerate([9,10,11,12])]+[neq(scatter_seed.get('w'+str(j)),'S'+str(k))for k,j in enumerate([13,14,15])])
 assert len(scatter_seed.stores)==1
 ledger=[]
 for j in range(16):
  g=chained('scatter'+str(j),scatter_seed,{2:bv(0x7e4ab0b3+j),3:bv(15-j),4:bv(0xbd700+0x362*j)},loads={'0x100c919e0':('FN',64)});run(g,'scatter');models['scatter'+str(j)]=g;assert len(g.stores)==1;row=g.stores[0];assert row['width_bits']==8
  d=CandidateDAG()
  for n,w in re.findall(r'\(declare-fun (\w+) \(\) \(_ BitVec (\d+)\)\)',DECL+EXTRA+pre(g).split('(define-fun',1)[0]):d.alias[n]=d.intern(('sym',n),int(w))
  d.defs(g.prefix());value=d.const(d.get(parse(row['value'])));assert value is not None and value==(0x74^j)
  cert('scatter_iteration_'+str(j),g,[neq(row['address'],frame(0xd10+ADDR[j])),neq(row['value'],bv(value,8)),neq(g.get('w2'),bv(0x7e4ab0b4+j,32)),neq(g.get('w3'),bv(14-j,32)),neq(g.get('w4'),bv(0xbda62+0x362*j,32)),neq(rd(g,0x100c919e0)['address'],at(0x2f3b if j==15 else 0x2f1e))]+[neq(g.get('x'+str(k)),scatter_seed.get('x'+str(k)))for k in [9,10,11,12,13,14,15]])
  ledger.append({'iteration':j,'offset_in_961_byte_view':ADDR[j],'frame_offset':0xd10+ADDR[j],'value_u8':value,'source_store':row['site'],'original_value_SMT':row['value']})
 assert len(set(ADDR))==16 and all(0<=x<961 for x in ADDR)
 assert (0x3773df7c-0x7ec1f1d0)%2**32==0xb8b1edac
 protected=set(range(0x2b8,0x2c8))|set(range(0x388,0x390))|set(range(0x728,0x72c))|set(range(0x738,0x73c))|set(range(0x748,0x758))|set(range(0x768,0xcf4))
 assert not {v['frame_offset']for v in ledger}&protected;assert all(0xd00<=v['frame_offset']<0x10c3 for v in ledger)
 old_scatter=[0xd00+(84784+757*j)%963 for j in range(16)];collision=sorted(set(old_scatter)&{v['frame_offset']for v in ledger})
 solve('nonzero_count_domain','(assert (distinct COUNT #x00000000))',result='sat')
 solve('largest_count_final_iteration_domain','(assert (= COUNT #xffffffff))\n(assert (= IDX #xfffffffe))\n(assert '+domain+')',result='sat')
 solve('zero_count_bypass_domain','(assert (= COUNT #x00000000))',result='sat')
 solve('wrong_signed_count_comparison_counterexample','(assert (distinct (bvult IDX COUNT) (bvslt IDX COUNT)))',result='sat')
 records={n:g.record_full()for n,g in models.items()};actual={pc for m in records.values()for pc in m['source_sites']};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 sem={'source_models':records,'source_nonbranch_sites_translated':len(actual),'first_loop_preserved_registers':first_preserved,'second_loop_preserved_registers':second_preserved,'first_counter_at_body_entry':'u32(IDX+0x528d39cf)','first_counter_after_body':'u32(IDX+0x07cc0324)','first_counter_after_repeat':'u32(IDX+0x528d39d0)','both_loop_continue_predicate':'u32(IDX+1)<COUNT, unsigned','source_byte_offsets':'0..COUNT-1 twice when COUNT!=0','total_record_byte_reads_integer':'2*COUNT','two_pass_final_state_equality_proved':False,'first_bank_after_last_body':['W13','W14','W15','u32(W0+W16),saved to F730'],'second_bank_after_second_pass':['W9','W10','W11','W12'],'first_initial_bank_words_u32':[first_constants[k]for k in [13,14,15,16]],'first_canonical_initial_bank_u32':[0x34695a82,0x1649b14e,0xbfa31027,0xb8b1edac],'first_D_entry_encoding':'W16=u32(D+0x7ec1f1d0)','first_D_output':'u32(W0+W16),re-encoded by repeat or saved without bias at final handoff','zero_COUNT_saved_word':'0xb8b1edac','second_initial_bank_words_u32':[second_constants[k]for k in [9,10,11,12]],'first_bank_preserved_through_second':True,'source_reduction':'u32(Z+(Z mod257))','scatter_base_frame_offset':0xd10,'scatter_address_domain_bytes':961,'scatter_numerator_start':0xbd700,'scatter_numerator_step':0x362,'scatter_store_ledger':ledger,'scatter_distinct_initialized_cells':16,'scatter_byte_form':'0x74 XOR j,0<=j<16','scatter_values_sorted':sorted(v['value_u8']for v in ledger),'scatter_all_stores_overlap_old963_byte_scratch':True,'overlap_with_old_sixteen_permutation_cells':collision,'new_workspace_contents_written':False,'word_view_contents_written':False,'Mach_port_emissions':0,'next_frontier':'0x100dcfa10','native_reachability_proved':False,'successful_output_publication_proved':False,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['first'].__setitem__('bytes','00'+q['fragments']['first']['bytes'][2:])),('read_offset',lambda q:q['fragments']['second']['instructions'][0].__setitem__('operands','w17, [x30, #1]')),('repeat_target',lambda q:q['branch_edges'][1].__setitem__('target','0x0')),('scratch_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(v['result']=='unsat'for v in pp),'queries_sat':sum(v['result']=='sat'for v in pp),'predecessor_queries_replayed':sum(v.get('replayed_query',False)for v in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'ordered_record_passes':2,'distinct_scatter_stores':16,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','daemon_word_round_tools.py','daemon_mode_one_handoff_tools.py','daemon_word_lookup_algebra.py','validate_daemon_mode_one_record_scan.py','recover_daemon_mode_one_record_scan.py']+DEPS;c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'record_byte_passes_and_scratch_handoff_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
