#!/usr/bin/env python3
"""Parameterized source proofs for position-aware full/short record absorption."""
import copy,json,re,subprocess,shutil
from recover_daemon_mode_one_record_reentry import ROOT,P,SCOPE,FLAGS,DEPS,BLOCKS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_join import JoinSSA
from validate_daemon_mode_one_record_long_planes import LongSSA,INDEXED
from validate_daemon_mode_one_record_long_prefix import PrefixSSA,DATA,emit,renamed,dependency_census
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq
from validate_daemon_list_output import split
from daemon_mode_one_handoff_tools import FrameSSA,parse
from validate_daemon_constructor_lookup import KEYS
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in[('COUNT',32),('POS',32),('IDX',32),('PBUF',64),('MASK',64),('FN_EXIT',64)])
REM='(bvsub COUNT POS)'
UU=[(0xbd700+866*j)%961 for j in range(64)];VV=[(0xaed96+866*j)%961 for j in range(64)]
DOMAIN=['(bvule POS COUNT)','(bvule POS #xffffffbf)'];SHORT=DOMAIN+['(bvult '+REM+' #x00000040)'];ITER=SHORT+['(bvult IDX '+REM+')'];FULL=DOMAIN+['(bvuge '+REM+' #x00000040)']
def lookup(values,arg):
 out=bv(values[-1],32)
 for j in reversed(range(len(values)-1)):out=f'(ite (= {arg} {bv(j,32)}) {bv(values[j],32)} {out})'
 return out

def certificates(s):
 pp=[];models={};cuts=[];overapproximations=[];fs=s['fragments']
 def solve(name,body,result='unsat',cc=(),extra='',values=None,integer=False):
  query='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+(''if integer else DECL+EXTRA)+extra+body+'\n'+''.join('(assert '+c+')\n'for c in cc)+'(check-sat)\n'
  if values is not None:query+='(get-value ('+' '.join(values)+'))\n'
  r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr,(name,r.stdout,r.stderr);record={'name':name,'query':query,'result':result,'scope':SCOPE}
  if values is None:assert r.stdout.strip()==result,(name,r.stdout)
  else:
   assert result=='sat'and r.stdout.startswith('sat\n'),(name,r.stdout);rows=parse(r.stdout[4:]);assert len(rows)==len(values);record['model_value_hex']=[row[-1]for row in rows];assert all(re.fullmatch('#x[0-9a-f]+',v)for v in record['model_value_hex'])
  pp.append(record);print(name,result,flush=True);return record
 def declarations(g):return''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items()if n not in['COUNT','POS','IDX','PBUF','MASK','FN_EXIT'])
 def cert(name,g,terms,cc=()):return solve(name,g.prefix()+'(assert (or '+' '.join(terms)+'))',cc=cc,extra=declarations(g))
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 def run(g,label):
  for v,w in g.supplied_loads.values():
   if re.fullmatch('[A-Z][A-Z0-9_]*',v)and v not in['FN','FN_EXIT','B0','B1','B2']:g.decl[v]=w
  f=fs[label];g.run(f,int(f['instructions'][-1]['ea'],16));assert not g.initial;return g
 def chained(old,name,cls=PrefixSSA,loads=None,regs=None):
  g=cls(name,{**old.r,**(regs or{})},loads=loads);g.defs=list(old.defs);g.decl=dict(old.decl);g.byte_cells=dict(old.byte_cells);g.loaded=old.loaded;return g
 def frame_cert(name,g,cc=()):
  sf={r['site']for r in g.frame_writes};rf={r['site']for r in g.frame_reads};reads=[r for r in g.reads if r['site']in rf];assert len(reads)==len(g.frame_reads)
  cert(name,g,[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip([r for r in g.stores if r['site']in sf],g.frame_writes)]+[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip(reads,g.frame_reads)],cc)
 # Fresh source recapture accompanies selected universal stage contracts.
 from recover_daemon_mode_one_record_rounds import build as previous_build
 assert previous_build()==json.loads(read(ROOT/'daemon_mode_one_record_rounds_source.json'))
 names={'setup_low32_reset_controls_preserved_inputs_and_dispatch','setup_all107_stores_and113_frame_reads','round_counter_epoch_exact64_repetition_and_dispatch','round_all94_stores_and114_frame_reads','round_two_initialized_grid_and_two_image_word_addresses','update_raw_COUNT_biased_position_predicate_and_two_targets','update_all163_stores_and50_frame_reads','repeat_initializer_target_and_explicit_outgoing_constants'}
 selections=[('daemon_mode_one_record_rounds_checks.json',names),('daemon_mode_one_record_word_gather_checks.json',None),('daemon_mode_one_record_word_extension_checks.json',{'all_eight_word_read_addresses','all_four_word_store_addresses','source_counter_registers_frame_epoch_and_repeat_exit','finite_next_index_and_last_iteration','all17_private_frame_stores_and70_frame_reads'}),('daemon_mode_one_record_input_planes_checks.json',{'source_byte_codec_seed','source_final_address_byte_selection','long_handoff_new_frame_epoch_and_plane_initializer_ABI','long_joining_fields_select_equality_edge_and_new_state_spill'}|{'source_byte_codec_round'+str(j)for j in range(1,8)}|{'source_scratch_remainder_shape_'+hex(a)for a in[0x100dc1118,0x100dc1188]})]
 replay_ledger=[]
 for file,wanted in selections:
  old=json.loads(read(ROOT/file));assert old['all_checks_pass'];chosen=[v for v in old['proofs']if(v['result']=='unsat'and not v.get('replayed_query',False))]if wanted is None else[v for v in old['proofs']if v['name']in wanted];assert wanted is None or{v['name']for v in chosen}==wanted
  for v in chosen:
   r=subprocess.run([SOLVER,'-in'],input=v['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**v,'name':'replayed_'+file[:-12]+'_'+v['name'],'replayed_query':True})
  replay_ledger.append({'checks':file,'sha256':sha(ROOT/file),'selected_queries':len(chosen),'all_queries_replayed':False})
 entry_frame={0x728:('COUNT',32),0x18:('(bvadd POS #x53921748)',32),0x2cc:('(bvadd POS #x0c392ed3)',32),0x740:('TABLE',64),0x748:('PBUF',64),0x750:(frame(0xd10),64),0x4d8:(bv(0x7f3081c2),64)}
 initial={19:bv(0x4923),8:bv(0x7f3081c2),23:bv(0xc8),22:bv(0x5c),21:bv(0x74),27:bv(0x16),24:bv(0x23)}
 args={'presets':entry_frame,'loads':{'0x100c8c55c':('INIT_FN',64)}}
 raw=run(JoinSSA('reentry_init',initial,**args),'initializer');assert not raw.initial;models['initializer_raw']=raw
 # Original indexed addresses remain universal with the new POS field.
 for pc,(off,num)in INDEXED.items():
  source=raw.prefix();record={'site':hex(pc),'frame_offset':off,'overapproximation':None}
  if num is not None:
   key='reentry_init_v'+str(num);lines=source.splitlines();hits=[line for line in lines if parse(line)[1]==key];assert len(hits)==1 and parse(hits[0])[3]==['_','BitVec','32'];source='\n'.join('(declare-fun '+key+' () (_ BitVec 32))'if line==hits[0]else line for line in lines)+'\n';record['overapproximation']={'symbol':key,'removed_definition':hits[0],'replacement':'Unconstrained u32;universal source overapproximation'}
  row=next(r for r in raw.stores if r['site']==hex(pc));record['original_address']=row['address'];solve('initializer_original_indexed_address_'+hex(pc),source+'(assert '+neq(row['address'],frame(off))+')',extra=declarations(raw));overapproximations.append(record)
 init=run(LongSSA('reentry_init',initial,**args),'initializer');assert init.prefix()==raw.prefix();models['initializer']=init
 cert('initializer_all27_literal_frame_aliases',init,[neq(r['original_address'],frame(r['frame_offset']))for r in init.alias_records]);frame_cert('initializer_all131_store_and_five_frame_read_addresses',init)
 cert('initializer_exact_modular_threshold_and_position_ABI',init,[neq(rd(init,0x100c8c55c)['address'],f'(ite (bvult COUNT (bvadd POS #x00000040)) {at(0xb1fc)} {at(0xb217)})'),neq(init.get('w6'),'(bvadd POS #x53921748)'),neq(init.get('w19'),'(bvadd POS #x53921748)'),neq(init.get('w4'),bv(0x39c7500a,32)),neq(init.get('x8'),bv(0x7f3081c2)),neq(init.loadframe(0x730,32),bv(0x67f0,32)),neq(init.loadframe(0x620,32),bv(0x3c0d,32)),neq(init.loadframe(0x738,32),bv(0x4923,32)),neq(init.get('x17'),bv(0x6307))])
 cert('initializer_remaining_length_partition_with_explicit_no_wrap',init,[neq(rd(init,0x100c8c55c)['address'],f'(ite (bvult {REM} #x00000040) {at(0xb1fc)} {at(0xb217)})')],DOMAIN)
 solve('modular_threshold_is_not_global_remaining_length_test','(assert (bvule POS COUNT))\n(assert (bvugt POS #xffffffbf))\n(assert (= (bvand POS #x0000003f) #x00000000))\n(assert (bvugt COUNT POS))\n(assert (distinct (bvult COUNT (bvadd POS #x00000040)) (bvult (bvsub COUNT POS) #x00000040)))',result='sat',values=['COUNT','POS'])
 short=run(chained(init,'shifted_short',FrameSSA,loads={'0x100c4a208':('SHORT_FN',64)}),'short');models['short']=short
 cert('short_remaining_zero_partition_and_shifted_threshold_word',short,[neq(rd(short,0x100c4a208)['address'],f'(ite (= COUNT POS) {at(0x3c0d)} {at(0x782c)})'),neq(short.get('w9'),f'(bvadd {REM} #x39c7500a)'),neq(short.loadframe(0x6f8,32),bv(0x4719,32)),neq(short.get('x3'),'PBUF'),neq(short.get('w16'),bv(0xbdf3fb52,32)),neq(short.get('w30'),bv(961,32))],SHORT);frame_cert('short_literal_frame_effects',short)
 seed=run(chained(short,'shifted_short_seed',FrameSSA,loads={'0x100c65c04':('SHORT_SEED_FN',64)}),'short_seed');models['short_seed']=seed
 constants={0:0xb47faaf81a732f68,1:0x1161e26185a1560e,2:0x080da9f5faed7516,4:KEYS[0],5:0xa7bebfcf1750d389,6:0x4923,7:0xb6dc5654307e7f72,19:0x9bc794aef0c360b0,20:0x005af3a82df0ce0c,21:0x95a858ee5d7b24cb,22:0xe4a7beffdf1f71f3,23:0x99e54358178f9594,25:0xb325064bf33d6f30,26:0x00144db9b1af6b57,28:0x378f295de186c160,30:961}
 cert('short_seed_codec_constants_and_fixed_local_plane_counters',seed,[neq(seed.get('x'+str(k)),bv(v))for k,v in constants.items()]+[neq(seed.get('x3'),'PBUF'),neq(seed.get('x8'),bv(0x7f3081c2)),neq(seed.get('w9'),f'(bvadd {REM} #x39c7500a)'),neq(seed.loadframe(0x730,32),bv(866,32)),neq(seed.loadframe(0x738,32),'(bvadd POS #x80cf7e3e)'),neq(rd(seed,0x100c65c04)['address'],at(0xa1ce))]);frame_cert('short_seed_literal_frame_effects',seed)
 loads={'0x100dc1278':('B0',8),'0x100dc1290':('B1',8),'0x100dc14c0':('B2',8),'0x100dc1508':('SHORT_LOOP_FN',64)}
 loop=chained(seed,'shifted_short_loop',FrameSSA,loads=loads,regs={8:z('(bvadd IDX #x7f3081c2)')})
 loop.decl['SHORT_LOOP_FN']=64
 groups=[(0x100dc1118,0x100dc11b0,15,15,0xbd700,UU),(0x100dc1188,0x100dc1208,14,14,0xaed96,VV)]
 starts={a:(num,base)for a,end,num,out,base,bank in groups};ends={end-4:(out,bank,a)for a,end,num,out,base,bank in groups};finite=[]
 for a,end,num,out,base,bank in groups:
  rows=[]
  for j in range(64):
   n=base+866*j;q=n*0x8864298f>>41;assert q==n//961 and n-q*961==bank[j];rows.append({'IDX':j,'numerator':n,'quotient':q,'remainder':bank[j]})
  finite.append({'start':hex(a),'end':hex(end),'cases':rows})
 A='(bvadd PBUF ((_ zero_extend 32) (bvadd POS IDX)))'
 for i in fs['short_loop']['instructions'][:-1]:
  pc=int(i['ea'],16)
  if pc==0x100dc10e8:cert('short_actual_shifted_address_supplies_universal_codec_seed',loop,[neq(loop.get('x13'),A)],ITER)
  if pc in starts:
   num,base=starts[pc];cert('short_live_local_plane_numerator_'+hex(pc),loop,[neq(loop.get('w'+str(num)),f'(bvadd {bv(base,32)} (bvmul IDX #x00000362))'),neq(loop.get('w28'),bv(0x8864298f,32)),neq(loop.get('w30'),bv(961,32))],ITER)
  loop.run({'instructions':[i]},pc+4)
  if pc in ends:
   out,bank,a=ends[pc];value=lookup(bank,'IDX');cuts.append({'site':i['ea'],'register':'w'+str(out),'original_expression':loop.get('w'+str(out)),'replacement':value,'justification':'Replayed universal reciprocal-shape query,fresh actual numerator/coefficient binding and all64 finite address cases','shape_start':hex(a)});loop.put('w'+str(out),value)
  if pc==0x100dc1488:
   cuts.append({'site':i['ea'],'register':'x15','original_expression':loop.get('x15'),'replacement':'MASK','actual_value':'Canonical seven-round mask word at PBUF+zero_extend32(POS+IDX)','justification':'Replayed universal source seed/seven encoded rounds/byte extraction;fresh shifted address binding and actual constant ABI/restoration.'});loop.put('x15','MASK')
 models['short_loop']=loop;ptr=lambda bank:f'(bvadd {frame(0xd10)} {z(lookup(bank,"IDX"))})';shift=f'(bvshl (bvand {A} #x0000000000000007) #x0000000000000003)';maskbyte=f'((_ extract 7 0) (bvlshr MASK {shift}))'
 cert('short_complete_shifted_record_local_planes_XOR_counter_and_dispatch',loop,[neq(rd(loop,0x100dc1278)['address'],ptr(UU)),neq(rd(loop,0x100dc1290)['address'],A),neq(rd(loop,0x100dc14c0)['address'],ptr(VV)),neq(loop.stores[0]['address'],ptr(UU)),neq(loop.stores[1]['address'],ptr(VV)),neq(loop.stores[0]['value'],'(bvxor B1 B0)'),neq(loop.stores[1]['value'],f'(bvxor {maskbyte} B2)'),neq(loop.get('w8'),'(bvadd IDX #x7f3081c3)'),neq(loop.get('w9'),f'(bvadd {REM} #x39c7500a)'),neq(loop.get('x3'),'PBUF'),neq(rd(loop,0x100dc1508)['address'],f'(ite (bvult (bvadd IDX #x00000001) {REM}) {at(0xa1ce)} {at(0x3c0d)})')]+[neq(loop.get('x'+str(k)),bv(v))for k,v in constants.items()],ITER)
 solve('short_next_index_stays_within_remainder_and_record','(assert (or (bvule (bvadd IDX #x00000001) IDX) (bvugt (bvadd IDX #x00000001) (bvsub COUNT POS)) (bvuge (bvadd POS IDX) COUNT) (bvult (bvadd POS IDX) POS)))',cc=ITER)
 solve('unshifted_short_record_address_has_abstract_counterexample','(assert (distinct (bvadd PBUF ((_ zero_extend 32) (bvadd POS IDX))) (bvadd PBUF ((_ zero_extend 32) IDX))))',cc=ITER+['(= POS #x00000040)'],result='sat')
 assert len(loop.stores)==2 and all(r['width_bits']==8 for r in loop.stores)and not loop.frame_writes
 # The full-block entry accepts arbitrary data words. Only the position
 # representations and documented phase/root inputs are fixed here.
 preset={**entry_frame,0x730:(bv(0x67f0,32),32)}
 fullseed=run(PrefixSSA('full_seed',{6:z('(bvadd POS #x53921748)')},presets=preset,loads={'0x100c9174c':('FULL_SEED_FN',64)}),'prefix_seed');models['prefix_seed']=fullseed
 old=json.loads(read(ROOT/'daemon_mode_one_record_long_prefix_checks.json'))['semantics'];cc={r['frame_offset']:int(r['constant_u32'],16)for r in old['seed39_constant_word_stores']};const=[r for r in fullseed.frame_writes if r['frame_offset']not in DATA];assert len(const)==len(cc)==39
 position_cells={0x530,0x52c,0x520,0x51c,0x518,0x514,0x510,0x50c,0x508,0x504,0x4f8,0x4f4,0x4f0,0x4ec,0x4e8};assert len(position_cells)==15 and position_cells<=set(cc)
 seed_layout=[{'frame_offset':r['frame_offset'],'site':r['site'],'first_entry_value':hex(cc[r['frame_offset']]),'parameterized_value':'u32(POS+'+hex(cc[r['frame_offset']])+')'if r['frame_offset']in position_cells else hex(cc[r['frame_offset']]),'depends_on_POS':r['frame_offset']in position_cells}for r in const]
 fixed={12:0,1:0x0cb55635,14:0x7d269bca,13:0xb2054,10:0x4923,16:0xc09be,0:0xb1cf2,23:0xc065c,2:0xb1990,3:0xc02fa,5:0xb162e,6:0xbff98,7:0xb12cc,20:0xbfc36,25:0xb0f6a,15:0x453a3898,19:0x0be7880c,24:866,4:0x8864298f,26:0x324a764c67af2e0e,21:0xa7bebfcf1750d389,22:0xb6dc5654307e7f72,17:0x373d}
 cert('full_seed_24_fixed15_position_words_and_register_ABI',fullseed,[neq(r['value'],f'(bvadd POS {bv(cc[r["frame_offset"]],32)})'if r['frame_offset']in position_cells else bv(cc[r['frame_offset']],32))for r in const]+[neq(fullseed.get('x'+str(k)),bv(v))for k,v in fixed.items()]+[neq(fullseed.get('w11'),'POS'),neq(fullseed.get('x30'),'PBUF'),neq(rd(fullseed,0x100c9174c)['address'],at(0x67f0))]);frame_cert('full_seed_all47_stores_and_three_frame_reads',fullseed)
 fullrounds=[];all_planes=set();record_offsets=[];g=fullseed
 prior_rounds=old['rounds']
 for q in range(4):
  g=run(chained(g,'full_loop'+str(q)),'prefix_loop');models['prefix_round'+str(q)]=g
  br=[r for r in g.reads if r['width_bits']==8];bt=[r for r in g.stores if r['width_bits']==8];assert len(br)==48 and len(bt)==32 and len(g.frame_writes)==64
  prior_reads={r['site']:r for r in prior_rounds[q]['address_ledger']if r['kind']=='read'};prior_stores={r['site']:r for r in prior_rounds[q]['address_ledger']if r['kind']=='store'};addresses=[]
  for row,kind,mapping in[(r,'read',prior_reads)for r in br]+[(r,'store',prior_stores)for r in bt]:
   p=mapping[row['site']];off=p['offset'];want=f'(bvadd PBUF ((_ zero_extend 32) (bvadd POS {bv(off,32)})))'if p['root']=='PBUF'else frame(off);addresses.append({'kind':kind,'site':row['site'],'original_address':row['address'],'expected':want,'root':p['root'],'local_offset':off})
  cert('full_round'+str(q)+'_all80_shifted_record_and_local_plane_addresses',g,[neq(r['original_address'],r['expected'])for r in addresses],FULL)
  live=[]
  for j in range(16):
   trip=addresses[3*j:3*j+3];idx=16*q+j;U=0xd10+866*(896+idx)%961;V=0xd10+866*(827+idx)%961
   assert sorted((r['root'],r['local_offset'])for r in trip)==sorted([('PBUF',idx),('K',U),('K',V)])and trip[2]['local_offset']==V
   assert[addresses[48+2*j]['local_offset'],addresses[49+2*j]['local_offset']]==[U,V]and not{U,V}&all_planes;all_planes.update([U,V]);record_offsets.append(idx)
   record=next(r for r,a in zip(br[3*j:3*j+3],trip)if a['root']=='PBUF');ur=next(r for r,a in zip(br[3*j:3*j+3],trip)if a['local_offset']==U);vr=br[3*j+2]
   assert int(ur['site'],16)<int(bt[2*j]['site'],16)and int(vr['site'],16)<int(bt[2*j+1]['site'],16)
   live.append({'local_index':idx,'record_offset':'POS+'+str(idx),'record_read':record,'U_read':ur,'V_read':vr,'U_store':bt[2*j],'V_store':bt[2*j+1],'U_offset':U,'V_offset':V})
  cert('full_round'+str(q)+'_all16_U_raw_XOR_updates',g,[neq(r['U_store']['value'],f'(bvxor {r["record_read"]["input"]} {r["U_read"]["input"]})')for r in live],FULL)
  defs=[parse(line)for line in g.prefix().splitlines()];names={d[1]for d in defs};guards=[d for d in defs if d[1].startswith('full_loop'+str(q)+'_')and isinstance(d[-1],list)and d[-1][0]=='ite'];assert len(guards)==6;guard=guards[0]
  def fixed_guard(value):return'\n'.join(emit([*d[:-1],['ite',value,*d[-1][2:]]])if d[1]==guard[1]else emit(d)for d in defs)+'\n'
  false=fixed_guard('false');true=renamed(fixed_guard('true'),names,'_true');first=bt[1]['value'];solve('full_round'+str(q)+'_CSEL_arms_same_first_V_byte',false+true+'(assert '+neq(first,renamed(first,names,'_true'))+')',cc=FULL,extra=declarations(g))
  assert all(not d for d in dependency_census(g.prefix(),{guard[1]},[r['value']for r in bt[3::2]]))
  zero={r['V_read']['input']:'#x00'for r in live};mask_source=renamed(false,names,'_mask',zero);mask_expr=[renamed(r['V_store']['value'],names,'_mask')for r in live]
  solve('full_round'+str(q)+'_all16_V_XOR_shifted_address_functions',false+mask_source+'(assert (or '+' '.join(neq(r['V_store']['value'],f'(bvxor {r["V_read"]["input"]} {mask})')for r,mask in zip(live,mask_expr))+'))',cc=FULL,extra=declarations(g))
  declared=set(re.findall(r'\(declare-fun (\w+) ',DECL+EXTRA))|set(g.decl);dependencies=dependency_census(mask_source,declared,mask_expr);assert dependencies==[['PBUF','POS']for _ in range(16)]
  frame_cert('full_round'+str(q)+'_all64_frame_stores_and131_frame_reads',g,FULL)
  cert('full_round'+str(q)+'_four_step_counter_phase_and_dispatch',g,[neq(rd(g,0x100c168f4)['address'],at(0x84f9 if q<3 else 0x84ef)),neq(g.get('x19'),bv(0x0be7880c+16*(q+1))),neq(g.loadframe(0x730,32),bv(0x2b22871b-0x3620*(q+1),32)),neq(g.loadframe(0x534,32),bv(0x84ef,32)),neq(g.get('x17'),bv(0xadd2))],FULL)
  fullrounds.append({'round':q,'address_ledger':addresses,'byte_updates':live,'first_CSEL_original_definition':emit(guard),'CSEL_equal_arm_certificate':'full_round'+str(q)+'_CSEL_arms_same_first_V_byte','other15_V_outputs_have_no_guard_dependency':True,'common_false_arm_SSA':false,'V_zero_input_mask_SSA':mask_source,'V_mask_expressions':mask_expr,'V_mask_declared_dependencies':dependencies})
 assert record_offsets==list(range(64))and len(all_planes)==128
 tail=run(chained(g,'full_exit',loads={'0x100dad2e8':('FN_EXIT',64)}),'prefix_exit');models['prefix_exit']=tail
 cert('full_exit_exact64_progress_word_gather_ABI_and_dispatch',tail,[neq(tail.loadframe(0x18,32),'(bvadd POS #x53921788)'),neq(tail.loadframe(0x2cc,32),'(bvadd POS #x0c392f13)'),neq(tail.get('w10'),bv(0x4923,32)),neq(tail.get('w11'),fullseed.loadframe(0x6cc,32)),neq(rd(tail,0x100dad2e8)['address'],at(0x8d10)),neq(tail.get('x8'),'FN_EXIT'),neq(tail.get('x17'),bv(0x26e7))],FULL);frame_cert('full_exit_two_stores_and_five_frame_reads',tail,FULL)
 solve('full_all64_record_offsets_stay_inside_COUNT','(declare-fun I () (_ BitVec 32))\n(assert (bvult I #x00000040))\n(assert (or (bvult (bvadd POS I) POS) (bvuge (bvadd POS I) COUNT) (bvugt (bvadd POS #x00000040) COUNT)))',cc=FULL)
 solve('cycle_update_predicate_is_COUNT_greater_current_position','(assert (distinct (bvugt COUNT (bvadd (bvadd POS #x53921748) #xac6de8b8)) (bvugt COUNT POS)))')
 # Source-certified intermediate stages preserve both biased position cells,
 # COUNT,roots and codebooks. Indexed word stores use their replayed domains.
 protected={off+j for off,n in[(0x18,4),(0x2cc,4),(0x560,8),(0x568,8),(0x580,8),(0x588,8),(0x728,4),(0x740,8),(0x748,8),(0x750,8),(0x758,8),(0x768,296),(0x1210,8)]for j in range(n)};cycle=[]
 for name in ['word_gather','word_extension','rounds']:
  file='daemon_mode_one_record_'+name+'_checks.json';c=json.loads(read(ROOT/file));assert c['all_checks_pass'];mm=c['semantics']['source_models'];rows=[]
  for label,m in mm.items():
   if name=='word_gather'and label in['biased_view','word_view']:continue
   for r in m.get('frame_writes',[]):assert not protected&set(range(r['frame_offset'],r['frame_offset']+r['width_bits']//8)),(name,label,r);rows.append(r)
  cycle.append({'checks':file,'sha256':sha(ROOT/file),'frame_store_instances_checked':len(rows),'COUNT_position_biases_roots_workspace_budget_preserved':True,'computed_word_store_domains':'Replayed original-source grid-address contracts;word stores remain below F+d10.','scratch_codebook_preservation':'Pinned source ledgers preserve the800 C/D/E/H/I cells;round update writes only the128 plane cells.'})
 retained={0xd10+(base+866*j)%961 for base,n in[(0x77086,256),(0x368c4,256),(0,256),(0x73704,16),(0x6e272,16)]for j in range(n)};planes={0xd10+v for v in UU+VV};assert len(retained)==800 and len(planes)==128 and not retained&planes and planes==all_planes
 preservation=[]
 for name,m in models.items():
  if name=='initializer_raw':continue
  written={r['frame_offset']+j for r in m.frame_writes for j in range(r['width_bits']//8)}
  if name.startswith('prefix_round'):assert not written&planes and not written&{off+j for off in DATA for j in range(4)}
  allowed_progress=set(range(0x18,0x1c))|set(range(0x2cc,0x2d0))if name=='prefix_exit'else set()
  assert not written&(protected-allowed_progress)and not written&retained,(name,sorted(written&protected))
  if name not in['initializer']:assert not(written|planes)&set(range(0x8b0,0xd10))
  preservation.append({'fragment':name,'source_loads':len(m.reads),'load_bytes':sum(r['width_bits']//8 for r in m.reads),'source_stores':len(m.stores),'store_bytes':sum(r['width_bits']//8 for r in m.stores),'distinct_literal_frame_bytes_written':len(written),'retained800_cells_and_saved_roots_preserved':True,'progress_cell_writes':name=='prefix_exit'})
 # Bounded mathematical induction composes the retained stage contracts.
 # Scalar/address coverage only;no decoded state recurrence or native proof.
 solve('outer_loop_quotient_remainder_and_exact_total_byte_coverage','(declare-fun C () Int)\n(assert (and (<= 0 C) (<= C 4294967232)))\n(define-fun Q () Int (div C 64))\n(define-fun R () Int (mod C 64))\n(assert (or (< Q 0) (< R 0) (>= R 64) (distinct (+ (* 64 Q) R) C) (> (* 64 Q) C) (and (> R 0) (> (* 64 Q) 4294967231)) (and (> R 0) (>= (+ (* 64 Q) 64) 4294967296))))',integer=True)
 solve('outer_full_step_and_suffix_guard_nonwrapping','(assert (bvule COUNT #xffffffc0))\n(assert (bvule POS COUNT))\n(assert (= (bvand POS #x0000003f) #x00000000))\n(assert (bvugt COUNT POS))\n(assert (or (bvugt POS #xffffffbf) (and (bvuge (bvsub COUNT POS) #x00000040) (or (bvule (bvadd POS #x00000040) POS) (bvugt (bvadd POS #x00000040) COUNT)))))')
 for label,pos,count in [('one_byte_suffix',64,65),('last_short_suffix',64,127),('next_full_block',64,128),('max_proved_exact_block_count',0xffffff80,0xffffffc0)]:solve(label+'_abstract_domain',f'(assert (= POS {bv(pos,32)}))\n(assert (= COUNT {bv(count,32)}))',result='sat')
 solve('outer_byte_intervals_partition_COUNT','(declare-fun C () Int)\n(declare-fun I () Int)\n(assert (and (<= 0 C) (<= C 4294967232) (<= 0 I) (< I C)))\n(define-fun Q () Int (div C 64))\n(define-fun R () Int (mod C 64))\n(define-fun B () Int (div I 64))\n(define-fun J () Int (mod I 64))\n(assert (or (and (< I (* 64 Q)) (or (< B 0) (>= B Q) (< J 0) (>= J 64) (distinct I (+ (* 64 B) J)))) (and (>= I (* 64 Q)) (or (< (- I (* 64 Q)) 0) (>= (- I (* 64 Q)) R)))))',integer=True)
 solve('distinct_full_block_byte_intervals_do_not_overlap','(declare-fun B1 () Int)\n(declare-fun B2 () Int)\n(declare-fun I1 () Int)\n(declare-fun I2 () Int)\n(assert (and (<= 0 B1) (< B1 B2) (<= 0 I1) (< I1 64) (<= 0 I2) (< I2 64)))\n(assert (= (+ (* 64 B1) I1) (+ (* 64 B2) I2)))',integer=True)
 # Branch-pointer inputs are separate symbols,not values from immutable
 # image data. Normalize the historical frontend's field name accordingly.
 records={n:m.record_full()for n,m in models.items()}
 for m in records.values():
  for r in m.get('external_reads',[]):
   if 'supplied_from_original_image'in r:r['component_input_supplied']=r.pop('supplied_from_original_image')
 declared=set(re.findall(r'\(declare-fun (\w+) ',DECL+EXTRA))|set(init.decl);plane_rows=[r for r in init.frame_writes if r['width_bits']==8];bank_deps=dependency_census(init.prefix(),declared,[r['value']for r in plane_rows]);banks=[{'Z0','Z6','Z9','Z10'},{'Z1','Z2','Z4','Z5'}];assert all(set(ds)in banks for ds in bank_deps)
 previous=json.loads(read(ROOT/'daemon_mode_one_record_rounds_checks.json'))['semantics'];old_planes={r['frame_offset']for r in previous['update_plane_store_ledger']};new_planes={r['frame_offset']for r in plane_rows};assert old_planes==new_planes and len(old_planes)==128
 assert not any(r['width_bits']==8 for r in previous['source_models']['repeat']['reads'])and not any(r['width_bits']==8 for r in init.reads)
 actual={pc for m in models.values()for pc in m.sites};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==9591
 init_planes=[r for r in init.frame_writes if r['width_bits']==8];assert len(init_planes)==128 and{r['frame_offset']for r in init_planes}==planes
 sem={'source_models':records,'source_nonbranch_sites_translated':9591,'source_cuts':cuts,'initializer_indexed_source_overapproximations':overapproximations,'predecessor_replay_ledger':replay_ledger,'position_symbol':'POS;u32 decoded control/progress coordinate,not a native owner','incoming_F18':'u32(POS+0x53921748)','incoming_F2cc':'u32(POS+0x0c392ed3)','initializer_exact_original_predicate':'COUNT < u32(POS+64)','remaining_length_equivalence_domain':'POS<=COUNT and POS<=0xffffffbf','positive_reentry_guard':'COUNT>POS','wraparound_negative_control_is_abstract':True,'native_acceptance_of_wraparound_case_proved':False,'initializer_plane_bytes_replaced':128,'initializer_plane_compact_functions_proved':False,'initializer_plane_value_dependency_upper_bounds':bank_deps,'initializer_two_register_banks':[[0,6,9,10],[1,2,4,5]],'positive_reentry_plane_bytes_overwritten_before_any_plane_read':128,'local_overwrite_before_read_is_not_native_observer_noninterference':True,'short_remaining_bytes':'COUNT-POS,under POS<=COUNT','short_zero_case':'Generic component bypass when COUNT=POS;positive re-entry guard excludes this case in the repeating cycle','short_record_address':'PBUF+zero_extend32(POS+IDX),0<=IDX<COUNT-POS<64','short_F738':'u32(POS+0x80cf7e3e);not the fixed first-entry constant','short_F730':'866;local plane stride','short_source_read_operations':'COUNT-POS','short_plane_read_operations':'2*(COUNT-POS)','short_plane_store_operations':'2*(COUNT-POS)','short_U_update':'old_U[IDX] XOR raw_record[POS+IDX]','short_V_update':'old_V[IDX] XOR canonical_address_mask(PBUF+POS+IDX)','short_mask_rounds':7,'short_mask_keys_u64':[hex(k)for k in KEYS],'short_plane0_offsets':UU,'short_plane1_offsets':VV,'short_remainder_address_cases':finite,'short_final_target':'0x100c74750','full_seed_control_coordinate_ledger':seed_layout,'full_seed_fixed_words':24,'full_seed_position_words':15,'independent_branch_pointer_symbols':True,'full_rounds':fullrounds,'full_body_iterations':4,'full_record_bytes':64,'full_record_offsets':[{'local_index':i,'record_offset':'POS+'+str(i)}for i in record_offsets],'full_plane_read_operations':128,'full_plane_store_operations':128,'full_plane_cells':128,'full_U_update':'old_U[i] XOR raw_record[POS+i],0<=i<64','full_V_update':'old_V[i] XOR source_address_function(PBUF,POS,i);canonical identity unproved','full_V_canonical_mask_identity_proved':False,'full_F18_after':'u32(POS+64+0x53921748)','full_F2cc_after':'u32(POS+64+0x0c392ed3)','full_next_target':'0x100b8ed9c','intermediate_cycle_preservation':cycle,'effect_and_preservation_ledger':preservation,'retained_codebook_cells':800,'plane_cells':128,'cycle_length_domain':'64<=COUNT<=0xffffffc0;first phase POS=0;every full step advances POS64;positive re-entry only whenCOUNT>POS','cycle_full_blocks':'floor(COUNT/64)','cycle_short_bytes':'COUNT mod64','cycle_record_address_coverage':'0..COUNT-1,once through these absorption sites,under the retained stage/mapping contracts','cycle_complete_decoded_state_recurrence_proved':False,'earlier_record_pass_reads_not_included_in_cycle_coverage':True,'entire_length_domain_proved':False,'whole_algorithm_identified':False,'source_frame_disjointness_is_a_premise':True,'native_buffer_extent_proved':False,'native_traversal_proved':False,'successful_output_proved':False,'daemon_kext_pairing_proved':False,'Mach_port_emissions':0,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['prefix_loop'].__setitem__('bytes','00'+q['fragments']['prefix_loop']['bytes'][2:])),('wrong_record_address',lambda q:next(i for i in q['fragments']['short_loop']['instructions']if i['ea']=='0x100dc1290').__setitem__('operands','w13, [x3]')),('wrong_prefix_step',lambda q:next(i for i in q['fragments']['prefix_exit']['instructions']if i['ea']=='0x100dad2cc').__setitem__('operands','w9, w9, #0x20')),('wrong_short_target',lambda q:q['branch_edges'][0].__setitem__('target','0x0')),('wrong_PAC',lambda q:q['branch_edges'][-1].__setitem__('IA_diversity','0x0')),('wrong_pair_offset',lambda q:q['pair_load_decode_checks'][0]['frame_offsets'].__setitem__(1,0x20)),('wrong_lineage',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':9591,'initializer_frame_aliases':27,'initializer_indexed_store_addresses':5,'initializer_universal_intermediate_overapproximations':4,'initializer_plane_stores':128,'short_parameterized_body_sites':271,'short_max_byte_reads':63,'short_finite_plane_address_cases':128,'short_source_cuts':3,'full_body_steps':4,'full_record_byte_reads':64,'full_plane_byte_reads':128,'full_plane_byte_stores':128,'full_original_byte_addresses_proved':320,'full_selected_instances_including_seed_exit':19194,'full_selected_instances_including_initializer':23368,'full_seed_state_words':8,'full_seed_control_coordinate_words':39,'full_seed_fixed_words':24,'full_seed_position_words':15,'full_CSEL_arm_equalities':4,'full_V_linearity_certificates':4,'retained_codebook_cells':800,'cycle_progress_preservation_stages':3,'cycle_max_COUNT_proved':0xffffffc0,'positive_reentry_overwritten_plane_bytes':128,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','recover_daemon_mode_one_record_rounds.py','validate_daemon_mode_one_record_join.py','validate_daemon_mode_one_record_long_planes.py','validate_daemon_mode_one_record_long_prefix.py','daemon_mode_one_handoff_tools.py','daemon_word_lookup_algebra.py','daemon_word_round_tools.py','validate_daemon_mode_one_word_schedule.py','validate_daemon_existing_scalar_reader.py','validate_daemon_constructor_inputs.py','validate_daemon_constructor_lookup.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'parameterized_short_full_absorption_and_bounded_cycle_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
