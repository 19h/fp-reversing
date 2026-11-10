#!/usr/bin/env python3
"""Exact twin-view copy contracts,nonzero count loops and initial even specialization."""
import copy,hashlib,json,shutil,subprocess
from recover_daemon_mode_one_even_view_import import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_checkpoint import PostSSA
from validate_daemon_mode_one_secondary_word_extension import frame_value
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq,low
from validate_daemon_list_output import split
SOLVER=shutil.which('z3');assert SOLVER
P0=0x4a62f57c;BIAS=0xf00f12f95e107577

def add(*xs):
 a=xs[0]
 for x in xs[1:]:a='(bvadd '+a+' '+x+')'
 return a

def remainder(n):
 q='((_ extract 31 0) (bvlshr (bvmul '+z('(bvlshr '+n+' #x00000001)')+' #x00000000883fddf1) #x0000000000000028))'
 return '(bvsub '+n+' (bvmul '+q+' #x000003c2))'

class MarkerSSA(PostSSA):
 def __init__(self,*a,forward=False,**kw):super().__init__(*a,**kw);self.forward=forward;self.original=[];self.numerator=None
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if pc==0x100c2aba8:self.numerator=self.get('w9')
   if pc in[0x100c2abc8,0x100c2abd0]:
    p=split(i['operands']);off=0x8b0+799*32%962;self.original.append({'site':i['ea'],'mnemonic':i['mnemonic'],'original_address':self.address(p[1]),'specialized_frame_offset':off})
    if self.forward:i={**i,'operands':p[0]+', [sp, #'+hex(off)+']'}
   super().run({'instructions':[i]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'original_byte_accesses':self.original,'numerator_source_ref':self.numerator,'byte_address_normalizations':2 if self.forward else 0,'normalization_domain':'LIMIT=32'if self.forward else None}

def certificates(s):
 pp=[];mm={};fs=s['fragments']
 def solve(name,g=None,terms=(),cc=(),result='unsat',integer=False,extra='',body=''):
  q='(set-option :timeout 45000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+(''if integer else DECL)+extra
  if g is not None:
   d=g['declarations']if isinstance(g,dict)else g.decl;q+=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in d.items())+(g['source_SSA']if isinstance(g,dict)else g.prefix())
  q+=body+''.join('(assert '+v+')\n'for v in cc)
  if terms:q+='(assert (or '+' '.join(terms)+'))\n'
  q+='(check-sat)\n'if integer else'(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout[:1600],r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def replay(prefix,names):
  c=json.loads(read(ROOT/(prefix+'_checks.json')));rows=[p for p in c['proofs']if p['name']in names];assert len(rows)==len(names)
  for p in rows:
   q=p['query'].replace('(set-option :timeout 15000)','(set-option :timeout 45000)');r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=50);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat',(prefix,p['name'],r.returncode,r.stdout[:1600],r.stderr);pp.append({**p,'query':q,'prior_query_sha256':hashlib.sha256(p['query'].encode()).hexdigest(),'timeout_budget_changed':q!=p['query'],'name':'replayed_'+prefix+'_'+p['name'],'replayed_query':True})
  print('replayed',prefix,len(rows),flush=True)
 replay('daemon_mode_one_secondary_reentry',['even_gate_exact_all_u32_threshold_and_preserved_pair','generalized_refresh_PSTATE_and_parity_control_handoff','odd_gate_exact_all_u32_threshold_and_saved_progress_word'])
 replay('daemon_mode_one_parity_state_adapters',['reciprocal481_half_u32_exact_floor_remainder_and_widths','even_register_and_pointer_representation_contract','even_setup_initial_zero_flag_selects_toggle'])
 replay('daemon_mode_one_workspace_state_install',['coherent_install_original_normalized_addresses','install_preserves_F758_table_root_and_TABLE'])
 replay('daemon_mode_one_word_xor_plane_refresh',['raw_word_full_mask_shift_counts_and_computed_fourth_read','coherent_word_numeric_XOR_contract_and_original_byte_address'])
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 def run(g,label):
  f=fs[label];g.run(f,int(f['instructions'][-1]['ea'],16));mm[label]=g;return g
 def frame_cert(name,g):
  rr={r['site']:r for r in g.reads};ss={r['site']:r for r in g.stores};solve(name+'_all_literal_frame_effect_addresses',g,[neq(rr[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_reads]+[neq(ss[r['site']]['address'],frame(r['frame_offset']))for r in g.frame_writes])
 old=json.loads(read(ROOT/'daemon_mode_one_secondary_reentry_checks.json'))['semantics']['source_models'];incoming=old['even'];R='(bvadd (bvsub (bvsub BWORD PSTATE) AWORD) #x29ee6c20)';R0='(bvadd (bvsub BWORD AWORD) #xdf8b76a4)'
 rr=incoming['final_registers'];branch=next(r for r in incoming['reads']if r['site']=='0x100d773ec')['address']
 solve('actual_even_gate_complete_entry_ABI_nonzero_partition_and_VIEW_preservation',incoming,[neq(low(rr['8']),'(bvsub (bvsub BWORD PSTATE) AWORD)'),neq(low(rr['9']),add(bv(0x6c054010,32),R)),neq(rr['13'],bv(0xa05a)),neq(rr['12'],bv(0x1e31)),neq(rr['0'],'Z0'),neq(rr['19'],z('PSTATE')),neq(rr['21'],frame(0x8b0)),neq(rr['7'],bv(0x883fddf1)),neq(rr['20'],bv(0xd6)),neq(rr['23'],bv(0xb3)),neq(branch,'(ite (= '+R+' #x00000000) '+at(0xc94e)+' '+at(0xc96f)+')')])
 install=json.loads(read(ROOT/'daemon_mode_one_workspace_state_install_checks.json'))['semantics']['source_models']['install'];ctx=json.loads(read(ROOT/'daemon_mode_one_parity_state_adapters_checks.json'))['semantics']['source_models']['even_setup'];CA=frame_value(ctx,0x4ac,32);CB=frame_value(ctx,0x4a4,32)
 solve('initializer_F300_plus_bias_is_private_F1150_view',install,[neq(add(frame_value(install,0x300,64),bv(BIAS)),frame(0x1150))])
 solve('even_context_two_view_roots_initial_count32_and_equal_base_position',ctx,[neq(add(frame_value(ctx,0x360,64),bv(BIAS)),frame(0x1150)),neq(frame_value(ctx,0x380,64),frame(0x1100)),neq(add('(bvsub '+CB+' '+CA+')','#xdf8b76a4'),bv(32,32)),neq(frame_value(ctx,0x4a8,32),CA)])
 solve('even_context_encoded_suffix_input96_and_word_XOR_gate',ctx,[neq(add(CB,'#x8cca81ed'),bv(96,32)),neq(frame_value(ctx,0x4b0,32),add(bv(P0,32),CA,bv(0x1e971aa1,32)))])
 # Entry and two per-iteration models quantify over every nonzero u32 LIMIT.
 delta='(bvsub LIMIT #x29ee6c20)';limit1=add('#x6c054010','LIMIT');limit2=add('#x9039fe79','LIMIT');idx='(bvadd PSTATE #xb59d0a84)';d={'PSTATE':32,'LIMIT':32,'VIEW0':64,'VIEW1':64,'SRCWORD':64,'SAVED24':32,'SAVED28':64}
 e=PostSSA('entry',{13:bv(0xa05a),2:z('PSTATE'),8:z(delta),9:z(limit1),19:z('PSTATE'),0:'VIEW1',7:bv(0x883fddf1),20:bv(0xd6),23:bv(0xb3),21:frame(0x8b0)},presets={0x740:('TABLE',64),0x360:('SRCWORD',64)},loads={'0x100daf000':('EFN',64)});e.decl.update(d,EFN=64);run(e,'entry');frame_cert('entry',e)
 ec={10:0,3:0x44009da2,2:0x2804a26f,11:0x9fd3,15:0x6f65,24:962,27:0x6c054010,28:0x3f89,17:0x62ce}
 solve('entry_actual_loop_constants_rebased_source_and_target',e,[neq(e.get('x'+str(j)),bv(v))for j,v in ec.items()]+[neq(e.get('w13'),add('PSTATE','#x719c6ce2')),neq(e.get('x12'),add('SRCWORD',bv(BIAS))),neq(e.get('w9'),limit1),neq(e.get('w8'),delta),neq(e.get('x19'),z('PSTATE')),neq(e.get('x0'),'VIEW1'),neq(rd(e,0x100daf000)['address'],at(0xa05a))])
 r1={0:'VIEW1',2:bv(0x2804a26f),3:z(add('#x44009da2','IX')),7:bv(0x883fddf1),8:z(delta),9:z(limit1),10:z('(bvmul IX #x0000031f)'),11:bv(0x9fd3),12:'VIEW0',13:z(add('PSTATE','#x719c6ce2')),15:bv(0x6f65),19:z('PSTATE'),20:bv(0xd6),21:frame(0x8b0),23:bv(0xb3),24:bv(962),27:bv(0x6c054010),28:bv(0x3f89)}
 a=PostSSA('first',r1,presets={0x740:('TABLE',64)},loads={'0x100d870b4':('BYTE0',8),'0x100d870f0':('AFN',64)});a.decl.update(d,BYTE0=8,AFN=64);run(a,'first');frame_cert('first',a)
 domain=['(distinct LIMIT #x00000000)','(bvult IX LIMIT)'];nextix='(bvadd IX #x00000001)';n1='(bvmul IX #x0000031f)';src1=add('VIEW0',z(add(idx,'IX')))
 solve('first_original_source_byte_address_value_and_reciprocal_destination_shape',a,[neq(rd(a,0x100d870b4)['address'],src1),neq(a.stores[0]['address'],add(frame(0x8b0),z(remainder(n1)))),neq(a.stores[0]['value'],'(bvxor BYTE0 #xf9)')])
 solve('first_exact_nonzero_limit_progress_repeat_exit_and_invariants',a,[neq(a.get('w3'),add('#x44009da2',nextix)),neq(a.get('w10'),'(bvmul '+nextix+' #x0000031f)'),neq(a.get('w9'),limit1),neq(a.get('w8'),delta),neq(a.get('w15'),bv(0x6f65,32)),neq(a.get('x19'),z('PSTATE')),neq(a.get('x0'),'VIEW1'),neq(rd(a,0x100d870f0)['address'],'(ite (bvult '+nextix+' LIMIT) '+at(0xa05a)+' '+at(0x9fd3)+')'),neq(a.get('x17'),bv(0x62ce))],cc=domain)
 b=PostSSA('between',{15:bv(0x6f65),8:z(delta),19:z('PSTATE'),0:'VIEW1',20:bv(0xd6),21:frame(0x8b0),23:bv(0xb3)},presets={0x740:('TABLE',64)},loads={'0x100cba55c':('BFN',64)});b.decl.update(d,BFN=64);run(b,'between');frame_cert('between',b)
 bc={9:0x966a,10:0x410,4:799,6:0x9039fe79,7:0x1a21,11:0x05513566,24:0xb04b3eb4,27:0x67919175,28:0xffffe591,30:0x8ae8c914,22:0x2f24,17:0x885e}
 solve('between_second_loop_initial_constants_same_limit_and_source_base',b,[neq(b.get('x'+str(j)),bv(v))for j,v in bc.items()]+[neq(b.get('w8'),limit2),neq(b.get('x2'),z('PSTATE')),neq(b.get('x0'),'VIEW1'),neq(rd(b,0x100cba55c)['address'],at(0x6f65))])
 r2={j:bv(v)for j,v in bc.items()if j not in[11,17]};r2.update({0:'VIEW1',2:z('PSTATE'),8:z(limit2),11:z(add('#x05513566','IX')),19:z('PSTATE'),20:bv(0xd6),21:frame(0x8b0),23:bv(0xb3)})
 c=PostSSA('second',r2,presets={0x740:('TABLE',64)},loads={'0x100b8e938':('BYTE1',8),'0x100b8e97c':('CFN',64)});c.decl.update(d,BYTE1=8,CFN=64);divisor=None
 for i in fs['second']['instructions'][:-1]:
  if i['mnemonic']=='udiv':divisor=c.get('w2')
  c.run({'instructions':[i]},int(i['ea'],16)+4)
 mm['second']=c;frame_cert('second',c);n2=add('(bvmul IX #x0000031f)',bv(799*593,32));q2='(bvudiv '+n2+' #x000003c2)';rem2='(bvsub '+n2+' (bvmul '+q2+' #x000003c2))'
 solve('second_source_byte_address_raw_value_UDIV962_and_destination_shape',c,[neq(rd(c,0x100b8e938)['address'],add('VIEW1',z(add(idx,'IX')))),neq(divisor,bv(962,32)),neq(c.stores[0]['address'],add(frame(0x8b0),z(rem2))),neq(c.stores[0]['value'],'BYTE1')])
 solve('second_same_nonzero_limit_progress_repeat_exit_and_restored_PSTATE',c,[neq(c.get('w11'),add('#x05513566',nextix)),neq(c.get('w8'),limit2),neq(c.get('x2'),z('PSTATE')),neq(c.get('w12'),bv(0x1e31,32)),neq(rd(c,0x100b8e97c)['address'],'(ite (bvult '+nextix+' LIMIT) '+at(0xb94e)+' '+at(0x966a)+')'),neq(c.get('x17'),bv(0xb9e1))],cc=domain)
 solve('unsigned_nonzero_iteration_domain_has_strict_progress_and_unique_last',terms=['(bvule '+nextix+' IX)','(distinct (= '+nextix+' LIMIT) (= IX (bvsub LIMIT #x00000001)))'],cc=domain,extra='(declare-fun LIMIT () (_ BitVec 32))\n')
 solve('UDIV962_integer_remainder_product_widths',integer=True,extra='(declare-fun N () Int)\n',cc=['(<= 0 N)','(<= N 4294967295)'],terms=['(< (- N (* 962 (div N 962))) 0)','(>= (- N (* 962 (div N 962))) 962)','(> (* 962 (div N 962)) N)','(> (div N 962) 4294967295)'])
 mp={0x740:('TABLE',64),0x4ac:('AWORD',32),0x4a4:(add('PSTATE','AWORD','LIMIT','#xd61193e0'),32),0x6f8:('SAVED24',32)}
 def marker(name,forward):
  q=MarkerSSA(name,{2:z('PSTATE'),12:bv(0x1e31),14:'SAVED28',20:bv(0xd6),21:frame(0x8b0),23:bv(0xb3)},presets={**mp,0x8b0+799*32%962:('MARKBYTE',8)},loads={'0x100c2abc8':('MARKBYTE',8),'0x100c2abd8':('MFN',64)},forward=forward);q.decl.update(PSTATE=32,LIMIT=32,AWORD=32,SAVED24=32,SAVED28=64,MARKBYTE=8,MFN=64);q.run(fs['marker'],int(fs['marker']['instructions'][-1]['ea'],16));mm[name]=q;return q
 raw=marker('raw_marker',False)
 solve('marker_original_numerator_equals799_times_LIMIT',raw,[neq(raw.numerator,'(bvmul LIMIT #x0000031f)')])
 solve('marker_original_addresses_use_exact_source_numerator_remainder',raw,[neq(r['original_address'],add(frame(0x8b0),z(remainder(raw.numerator))))for r in raw.original])
 solve('marker_exact_XOR_pair_restoration_and_return_controls',raw,[neq(raw.stores[0]['value'],'(bvxor MARKBYTE #x80)'),neq(raw.get('w10'),add('PSTATE','AWORD')),neq(raw.get('x28'),'SAVED28'),neq(raw.get('w24'),'SAVED24'),neq(rd(raw,0x100c2abd8)['address'],at(0x1e31))])
 mark=marker('marker',True);frame_cert('marker',mark);off=0x8b0+799*32%962
 solve('specialized32_marker_original_numerator_is25568',mark,[neq(mark.numerator,bv(799*32,32))],cc=['(= LIMIT #x00000020)'])
 solve('coherent_marker_original_addresses_use_exact_source_numerator',mark,[neq(r['original_address'],add(frame(0x8b0),z(remainder(mark.numerator))))for r in mark.original])
 solve('specialized32_marker_constant_reciprocal_remainder556',terms=[neq(remainder(bv(799*32,32)),bv(799*32%962,32))])
 solve('specialized32_marker_value_and_return_ABI',mark,[neq(mark.loadframe(off,8),'(bvxor MARKBYTE #x80)'),neq(mark.get('w2'),'PSTATE'),neq(mark.get('w10'),add('PSTATE','AWORD')),neq(mark.get('w8'),bv(0x4d20,32)),neq(mark.get('x28'),'SAVED28'),neq(mark.get('w24'),'SAVED24'),neq(mark.get('x17'),bv(0xe346))],cc=['(= LIMIT #x00000020)'])
 # Finite coordinate ledger composes the original remainder shapes with the
 # replayed exact reciprocal theorem and the direct UDIV integer theorem.
 ledger=[];written=set();reads=set()
 for j in range(32):
  n0=799*j;n1=799*(593+j);assert n0<2**32 and n1<2**32
  q=((n0//2)*0x883fddf1)>>40;assert q==n0//962
  dest=[0x8b0+n0%962,0x8b0+n1%962];source=[0x1150+j,0x1100+j];written.update(dest);reads.update(source);ledger.append({'j':j,'first_source_frame_offset':source[0],'second_source_frame_offset':source[1],'first_destination':dest[0],'second_destination':dest[1],'first_label':j,'second_label':593+j,'repeat':j<31})
 assert len(written)==len(reads)==64 and off not in written;written.add(off);assert len(written)==65 and not written&reads
 arithmetic={0x8b0+799*j%962 for lo,hi in[(72,328),(333,589),(659,675),(677,933),(936,952)]for j in range(lo,hi)};assert len(arithmetic)==800 and not written&arithmetic and not written&set(range(0xc80,0xc80+286*4))
 source_bytes=[0,0,3,0];assert (96*8)==0x300 and[0x300>>shift&255 for shift in[24,16,8,0]]==source_bytes
 assert[0x8b0+799*j%962 for j in[63,62,61,60]]==[0x9e9,0xa8c,0xb2f,0xbd2]
 for name in fs:assert set(mm[name].sites)=={i['ea']for i in fs[name]['instructions'][:-1]}
 assert sum(len(mm[n].sites)for n in fs)==143
 # A broad pair representation proposal is expressly not used as padding.
 refresh=old['refresh'];pairs=['(bvxor '+frame_value(refresh,0x8b0+799*j%962,8)+' '+frame_value(refresh,0x8b0+799*(593+j)%962,8)+')'for j in range(64)]
 solve('broad_refresh_pair_XOR_F9_zero_padding_proposal_is_false',refresh,[neq(v,'#xf9')for v in pairs],cc=['(= PSTATE #x4a62f57c)'],result='sat')
 solve('copied_pair_XOR_projection_exact_two_view_relation',terms=[neq('(bvxor (bvxor (bvxor B0 #xf9) B1) #xf9)','(bvxor B0 B1)')])
 solve('abstract_nonzero_loop_domain_nonempty',a,cc=domain,result='sat')
 effects={n:{'source_nonbranch_sites':len(mm[n].sites),'loads':len(mm[n].reads),'stores':len(mm[n].stores),'read_bytes':sum(r['width_bits']//8 for r in mm[n].reads),'store_bytes':sum(r['width_bits']//8 for r in mm[n].stores)}for n in fs}
 sem={'source_models':{n:g.record_full()for n,g in mm.items()},'incoming_even_source_model':incoming,'initial_even_context_source_model':ctx,'initializer_source_model':install,'source_nonbranch_sites_translated':143,'generic_count':'LIMIT=u32(BWORD-PSTATE-AWORD+0x29ee6c20);nonzero on entry','logical_iteration_domain':'0<=IX<LIMIT;LIMIT!=0','generic_iterations_per_loop':'LIMIT,assuming valid complete execution','source_index':'u32(PSTATE+0xb59d0a84+IX)','decoded_initial_position':'u32(PSTATE-0x4a62f57c);zero when PSTATE=P0','first_source_base':'u64[F360]+0xf00f12f95e107577','second_source_base':'preserved incoming X0','initial_even_source_bases':['F+0x1150','F+0x1100'],'initial_even_progression_premise':'PSTATE=0x4a62f57c','initial_even_count':32,'initial_even_encoded_suffix_input_plus_bias':96,'initial_even_suffix_XOR_mask':'0x00000300','suffix_mask_coordinate_order_C60_to_C63':source_bytes,'suffix_action':'XOR mask bytes,not an unconditional write of a decoded bit length','copied_pair_projection':'plane0[j] XOR plane1[j] XOR0xf9 = view1150[j] XOR view1100[j] for copied initial-even j0..31;analyst-defined projection,not a proved native decoder','first_copy_byte':'source byte XOR0xf9','second_copy_byte':'source byte unchanged','first_destination':'F+8b0+(u32(799*IX) mod962)','second_destination':'F+8b0+(u32(799*IX+473807) mod962)','marker_numerator':'u32(799*LIMIT)','specialized32_marker_frame_offset':off,'specialized_marker_composition':'Original coherent numerator=25568 under LIMIT32;both original coherent addresses use remainder of that exact source numerator;the independent constant reciprocal query proves remainder556. Congruence and substitution entail F+8b0+556=F+adc for both accesses. Generic marker formula likewise composes source-numerator and exact-address-shape equalities. No source value cut or unproved extra assumption is used.','specialized32_marker_label':32,'specialized32_marker_value':'previous byte XOR0x80','specialized32_copy_ledger':ledger,'specialized32_read_bytes_from_views':64,'specialized32_copy_stores':64,'specialized32_with_marker_distinct_bytes_written':65,'arithmetic_cells_preserved_in_specialized32_case':800,'specialized32_marker_address_normalizations':2,'source_value_cuts':0,'effect_counts':effects,'native_arrival_proved':False,'generic_count_at_most64_proved':False,'generic_plane_only_writes_proved':False,'source_view_native_owner_or_extent_proved':False,'whole_decoded_padding_proved':False,'whole_algorithm_identified':False,'native_output_proved':False,'daemon_kext_pairing_proved':False,'Mach_port_emissions':0,'new_IDA_access':False,'coherence_boundary':'Independent raw byte reads overapproximate native correlations. The specialized marker alone forwards its explicit arbitrary prior byte with two source-proved LIMIT32 normalizations. Stable nonwrapping mappings,view/root continuity and no outside writes remain premises.','entry_boundary':'The initial even-context source proves saved fields/roots and the32-count arithmetic when PSTATE=P0;its recorded setup flag is zero. Native arrival at this later flag/progression context is unproved. Later PSTATE values retain the generic nonzero-count contract and do not inherit32 automatically.','excluded_exploration':'Combined generic and specialized marker-numerator/address queries returned unknown at45000ms and is excluded;accepted numerator and original-address-shape certificates compose the same address claim by congruence. An original15000-ms predecessor replay failed strict expected-output matching;no result from that attempt is accepted. Selected predecessor propositions are replayed with45000-ms timeout budgets and original query hashes,without changing source assertions. An all-zero even-context valuation proposed32;the accepted source query proves it universally. An initial standalone progress query omitted its LIMIT declaration and was strictly rejected despite a trailing SAT token. A premature query requested absent F4a4 bytes from the initializer-only model and was rejected;the later common setup supplies this field. A broad refreshed-plane XOR-F9 zero-padding proposal returned SAT and is retained only as an abstract negative control,not a native counterexample or proof about the correlated32-byte context.'}
 return pp,sem

def verify(s):return s==build()
def alterations(s):
 original=build();cases=[('source_byte',lambda q:q['fragments']['first'].__setitem__('bytes','00'+q['fragments']['first']['bytes'][2:])),('repeat_target',lambda q:q['branch_edges'][1].__setitem__('target','0x0')),('exit_target',lambda q:q['branch_edges'][2].__setitem__('target','0x0')),('modifier',lambda q:q['branch_edges'][0].__setitem__('IA_diversity','0x0')),('UDIV_width',lambda q:next(r for r in q['ISA_decode_checks']if r['kind']=='udiv').__setitem__('width_bits',64)),('lineage_hash',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert q!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out

def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':143,'initial_even_iterations_per_loop':32,'initial_even_view_bytes_read':64,'initial_even_plane_bytes_copied':64,'initial_even_with_marker_distinct_bytes_written':65,'initial_even_arithmetic_cells_preserved':800,'marker_address_normalizations':2,'source_value_cuts':0,'suffix_mask_value':768,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','validate_daemon_existing_scalar_reader.py','validate_daemon_mode_one_secondary_word_extension.py','daemon_word_round_tools.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'two_view_copy_loops_even32_case_marker_and_suffix_components_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
