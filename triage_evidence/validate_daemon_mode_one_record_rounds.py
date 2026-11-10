#!/usr/bin/env python3
"""Source64-round ABI,complete byte containment and COUNT-controlled continuation."""
import copy,json,re,subprocess,shutil,math
from recover_daemon_mode_one_record_rounds import ROOT,P,SCOPE,FLAGS,DEPS,LINEAGE,BLOCKS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_join import JoinSSA
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,neq,at
from validate_daemon_list_output import split
from daemon_mode_one_handoff_tools import CandidateDAG,parse
from daemon_word_round_tools import lookup
SOLVER=shutil.which('z3');assert SOLVER
DATA=[0x444,0x448,0x44c,0x458,0x460,0x464,0x468,0x46c,0x470,0x474,0x478,0x47c,0x480,0x484,0x488,0x48c]
SPECIAL=['0x100af63b0','0x100af82f0','0x100af9a38','0x100afb40c','0x100afd304','0x100afdf04','0x100afe1b0']
def byte_candidates(g):
 d=CandidateDAG()
 for n,w in g.decl.items():d.alias[n]=d.intern(('sym',n),w)
 d.defs(g.prefix());inverse={}
 for name,node in d.alias.items():inverse.setdefault(node,name)
 defined_refs={parse(v)[1]for v in g.prefix().splitlines()};rows=[];special=[];frame_sites={r['site']for r in g.frame_reads}
 def kind(x):return d.nodes[x][0][0]
 for r in g.reads:
  if r['width_bits']!=8 or r['site']in frame_sites or r['site']in['0x100d8c1f0','0x100d8c200']:continue
  if r['site']in SPECIAL:special.append(r);continue
  ix=d.index(r['address']);short=kind(ix)=='extract'
  if short:assert d.nodes[ix][0][2:]==(15,0);ix=d.nodes[ix][0][1]
  k,w=d.nodes[ix];assert k[0]=='bvsub'and w==32;n,p=k[1:];kp,_=d.nodes[p];assert kp[0]=='bvmul'and any(d.const(v)==961 for v in kp[1:]);q=next(v for v in kp[1:]if d.const(v)!=961)
  if kind(q)=='extract':assert d.nodes[q][0][2:]==(31,0);q=d.nodes[q][0][1]
  kq,_=d.nodes[q];assert kq[0]=='bvlshr';prod,shift=kq[1:];km,pw=d.nodes[prod];assert km[0]=='bvmul'and pw==64;cs=[v for v in km[1:]if d.const(v)is not None];assert len(cs)==1;coef=d.const(cs[0]);arg=next(v for v in km[1:]if v!=cs[0]);assert kind(arg)=='zext'and d.nodes[arg][0][1]==n
  shift=d.const(shift);assert(coef,shift)in[(0x443215,32),(0x8864298f,41),(0x8864299,37)]
  ref=inverse[n];assert ref in defined_refs;rows.append({'site':r['site'],'original_address':r['address'],'numerator_source_ref':ref,'coefficient':coef,'shift':shift,'extract_low16':short,'candidate_is_not_a_proof':True})
 return rows,special

def certificates(s):
 pp=[];models={};cuts=[];shape_overapproximations=[];fs=s['fragments']
 def solve(name,body,result='unsat',extra='',integer=False):
  query='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+(''if integer else DECL)+extra+body+'\n(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=query,text=True,capture_output=True,timeout=20)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr)
  pp.append({'name':name,'query':query,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def decl(g):return''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())
 def cert(name,g,terms,domain=False):solve(name,g.prefix()+('(assert (bvult IX #x00000040))\n'if domain else'')+'(assert (or '+' '.join(terms)+'))',extra=decl(g))
 def rr(g,pc):return next(r for r in g.reads if r['site']==pc)
 def run(name,presets=None,loads=None):
  g=JoinSSA(name,{j:z('J'+str(j))for j in range(31)},presets=presets,loads=loads);g.decl.update({'J'+str(j):32 for j in range(31)});g.run(fs[name],int(fs[name]['instructions'][-1]['ea'],16));models[name]=g;return g
 def frame_cert(name,g):
  assert len(g.stores)==len(g.frame_writes)
  cert(name,g,[neq(r['address'],frame(fr['frame_offset']))for r,fr in zip(g.stores,g.frame_writes)]+[neq(rr(g,fr['site'])['address'],frame(fr['frame_offset']))for fr in g.frame_reads])
 # Refresh only the source contracts needed at this boundary.
 from recover_daemon_mode_one_record_word_extension import build as previous_build
 assert previous_build()==json.loads(read(ROOT/'daemon_mode_one_record_word_extension_source.json'))
 selections={'daemon_mode_one_record_word_extension_checks.json':{'all_eight_word_read_addresses','all_four_word_store_addresses','source_counter_registers_frame_epoch_and_repeat_exit','finite_next_index_and_last_iteration','all17_private_frame_stores_and70_frame_reads'},'daemon_mode_one_phase_handoff_checks.json':{'workspace_request_C0_chain_and_null_dispatch'},'daemon_mode_one_record_long_prefix_checks.json':{'exit_pair_reloads_biased64_advances_state_reload_and_target'}}
 for file,names in selections.items():
  old=json.loads(read(ROOT/file));assert old['all_checks_pass'];done=set()
  for p in old['proofs']:
   if p['name']not in names:continue
   r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_'+file[:-12]+'_'+p['name'],'replayed_query':True});done.add(p['name'])
  assert done==names
 prior=json.loads(read(ROOT/'daemon_mode_one_record_word_extension_checks.json'))['semantics']['source_models']['loop'];pd=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in prior['declarations'].items())
 solve('actual_incoming_u32_extensions_for_X22_X23_X24',prior['source_SSA']+'(assert (= IX #x0000002f))\n(assert (or '+' '.join(neq('((_ extract 63 32) '+prior['final_registers'][str(j)]+')',bv(0,32))for j in[22,23,24])+'))',extra=pd)
 prev=json.loads(read(ROOT/'daemon_mode_one_record_word_gather_checks.json'))['semantics']['source_models']['exit'];saved=next(r['value']for r in reversed(prev['frame_writes'])if r['frame_offset']==0x598);pd=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in prev['declarations'].items());solve('original_gather_exit_selector_F598_is5588',prev['source_SSA']+'(assert '+neq(saved,bv(0x5588,32))+')',extra=pd)
 # Fresh literal and normalized write census;computed historical byte/word
 # domains retain their pinned prior certificates,not an all-history replay.
 roots={off+j for off in[0x568,0x580,0x588]for j in range(8)};chronology=[]
 for name in LINEAGE:
  file='daemon_mode_one_record_'+name+'_checks.json';c=json.loads(read(ROOT/file));assert c['all_checks_pass'];sem=c['semantics'];mm=sem.get('source_models',{'single':sem.get('source_model',{})});rows=[]
  for model in mm.values():
   for row in model.get('frame_writes',[]):assert not roots&set(range(row['frame_offset'],row['frame_offset']+row['width_bits']//8)),(name,row);rows.append(row)
  source='daemon_mode_one_record_'+name+'_source.json';src=json.loads(read(ROOT/source));literal=[]
  for fragment in src['fragments'].values():
   for i in fragment['instructions']:
    if i['mnemonic']not in['str','strb','stp','stur']:continue
    p=split(i['operands']);m=re.fullmatch(r'\[sp(?:, #(0x[0-9a-f]+|[0-9]+))?\]',p[-1])
    if not m:continue
    off=int(m[1],0)if m[1]else 0;w=1 if i['mnemonic']=='strb'else(4 if p[0].startswith('w')else 8)*(2 if i['mnemonic']=='stp'else 1);assert not roots&set(range(off,off+w));literal.append(i['ea'])
  chronology.append({'source':source,'source_sha256':sha(ROOT/source),'checks':file,'checks_sha256':sha(ROOT/file),'normalized_frame_writes_checked':len(rows),'literal_store_sites_checked':len(literal),'saved_image_roots_and_CELL0_preserved':True,'historical_computed_store_domains':'Retained source-certified scratch/word domains;not all historical queries refreshed.'})
 # Only these two later stages follow the proved first-prefix bias update.
 control_tail=[]
 for name in ['word_gather','word_extension']:
  c=json.loads(read(ROOT/('daemon_mode_one_record_'+name+'_checks.json')));mm=c['semantics']['source_models'];rows=[r for m in mm.values()for r in m.get('frame_writes',[])]
  protected_bias={off+j for off in[0x18,0x2cc]for j in range(4)}
  assert all(not protected_bias&set(range(r['frame_offset'],r['frame_offset']+r['width_bits']//8))for r in rows)
  if name=='word_extension':assert all(not set(range(0x598,0x59c))&set(range(r['frame_offset'],r['frame_offset']+r['width_bits']//8))for r in rows)
  control_tail.append({'stage':name,'frame_writes_checked':len(rows),'F18_and_F2cc_first_prefix_biases_preserved':True,'F598_preserved':name=='word_extension','computed_word_stores':'Pinned original-source word-grid address certificates;outside these scalar fields.'})
 roots_p={0x740:('TABLE',64),0x750:(frame(0xd10),64),0x758:(frame(0x8b0),64),0x598:(bv(0x5588,32),32)}
 setup=run('setup',roots_p);assert len(setup.sites)==8944 and len(setup.reads)==598 and len(setup.frame_reads)==113 and len(setup.stores)==107
 frame_cert('setup_all107_stores_and113_frame_reads',setup)
 cert('setup_low32_reset_controls_preserved_inputs_and_dispatch',setup,[neq(setup.loadframe(0x738,32),bv(0,32)),neq(setup.loadframe(0x558,32),bv(0x3c0d,32)),neq(setup.loadframe(0x590,32),bv(0x487a61a9,32)),neq(setup.loadframe(0x6c0,32),'IF_48c_32'),neq(setup.loadframe(0x598,32),bv(0x5588,32)),neq(rr(setup,'0x100afeae4')['address'],at(0x5588)),neq(setup.get('x17'),bv(0x8d97))])
 cert('setup_outgoing_64bit_state_views_are_zero_extended',setup,[neq('((_ extract 63 32) '+setup.get('x'+str(j))+')',bv(0,32))for j in[7,13,20,28]])
 rp={**roots_p,0x738:('IX',32),0x580:('CELL0',64),0x588:(bv(0x100fc4130),64),0x568:(bv(0x101031ea0),64)}
 original=run('round',rp);original.decl['CELL0']=64;assert len(original.sites)==3334 and len(original.reads)==262 and len(original.frame_reads)==114 and len(original.stores)==94
 # A separate original-source model supplies containment certificates without
 # assuming image selector/table values. The selected model has one justified
 # low-byte cut and a rebased immutable pointer after its address is proved.
 g=JoinSSA('selected_round',{j:z('J'+str(j))for j in range(31)},presets=rp,loads={'0x100d8c25c':(bv(0x12eb216df),64)});g.decl.update({'J'+str(j):32 for j in range(31)});g.decl['CELL0']=64
 left,right=[bytes.fromhex(b['bytes'])for b in s['data_banks'][:2]];assert{j^right[left[j]^0x4e]for j in range(256)}=={255}
 generic=f'(bvxor B0 {lookup(right,"(bvxor "+lookup(left,"B0")+" #x4e)")})';solve('all256_original_byte_selector_cases_choose_ff','(assert '+neq(generic,'#xff')+')')
 for i in fs['round']['instructions'][:-1]:
  pc=int(i['ea'],16);g.run({'instructions':[i]},pc+4)
  if pc==0x100d8c204:
   a,b=rr(g,'0x100d8c1c4')['input'],rr(g,'0x100d8c1cc')['input'];l,r=rr(g,'0x100d8c1f0')['input'],rr(g,'0x100d8c200')['input'];v=f'((_ extract 7 0) (bvmul (bvxor (bvsub {b} {a}) #x000000a6) #x0a5cd4cf))'
   cert('original_controller_words_byte_bank_addresses_and_selector_projection',g,[neq(rr(g,'0x100d8c1c4')['address'],'CELL0'),neq(rr(g,'0x100d8c1cc')['address'],bv(0x1010c4670)),neq(rr(g,'0x100d8c1f0')['address'],f'(bvadd {bv(0x100fc4130)} {z(v,8)})'),neq(rr(g,'0x100d8c200')['address'],f'(bvadd {bv(0x101031ea0)} {z("(bvxor "+l+" #x4e)",8)})'),neq('((_ extract 7 0) '+g.get('w10')+')',f'(bvxor {v} {r})')])
   old=g.get('w10');replacement=f'(bvor (bvand {old} #xffffff00) #x000000ff)';cuts.append({'site':i['ea'],'register':'w10','original_value':old,'replacement':replacement,'projection':'Only low8 bits replaced;upper24 retained','source_binding_certificate':'original_controller_words_byte_bank_addresses_and_selector_projection','finite_original_bank_lemma':'all256_original_byte_selector_cases_choose_ff','immutable_bank_roots_and_bytes_premise':True});g.put('w10',replacement)
  if pc==0x100d8c25c:cert('original_selected_rebase_pointer_slot_is1010a4568',g,[neq(rr(g,i['ea'])['address'],bv(0x1010a4568))])
 models['selected_round']=g
 frame_cert('round_all94_stores_and114_frame_reads',g)
 grid=lambda base:f'(bvadd {frame(0x8b0)} {z(f"(bvshl (bvurem (bvmul (bvadd IX {bv(base,32)}) #x000000e3) #x00000118) #x00000002)")})'
 rom=lambda mask,base:f'(bvadd {bv(0x100f40e00)} {z(f"(bvshl (bvurem (bvmul (bvadd (bvxor IX {bv(mask,32)}) {bv(base,32)}) #x000000b3) #x000000c0) #x00000002)")})'
 cert('round_two_initialized_grid_and_two_image_word_addresses',g,[neq(rr(g,pc)['address'],grid(base))for pc,base in[('0x100d8c2b0',143),('0x100d8c5c8',211)]]+[neq(rr(g,pc)['address'],rom(mask,base))for pc,mask,base in[('0x100d8c270',0x2f,76),('0x100d8c4e0',8,0)]],True)
 cert('round_counter_epoch_exact64_repetition_and_dispatch',g,[neq(g.loadframe(0x738,32),'(bvadd IX #x00000001)'),neq(g.loadframe(0x730,32),'IF_6d8_32'),neq(rr(g,'0x100d8eeec')['address'],f'(ite (= IX #x0000003f) {at(0xc9e9)} {at(0x5588)})'),neq(g.get('x17'),bv(0x8d97))]+[neq('((_ extract 63 32) '+g.get('x'+str(j))+')',bv(0,32))for j in[7,13,20,28]],True)
 solve('finite64_next_index_and_final_iteration','(assert (bvult IX #x00000040))\n(assert (or (bvule (bvadd IX #x00000001) IX) (bvugt (bvadd IX #x00000001) #x00000040) (distinct (= IX #x0000003f) (= (bvadd IX #x00000001) #x00000040))))')
 # Complete new scratch-byte bounds through original-source shapes/ranges,
 # exact integer quotients and seven direct source certificates.
 byte_ledger=[]
 for label,model in[('setup',setup),('round',original)]:
  rows,special=byte_candidates(model);assert(len(rows),len(special))==((477,7)if label=='setup'else(138,0))
  limited=[r for r in rows if r['coefficient']!=0x8864298f]
  cert(label+'_all_limited_reciprocal_numerators_bounded',model,[f'(bvugt {r["numerator_source_ref"]} {bv(4033828,32)})'for r in limited])
  shapes=[]
  for row in rows:
   n=row['numerator_source_ref'];rem=f'(bvsub {n} (bvmul ((_ extract 31 0) (bvlshr (bvmul ((_ zero_extend 32) {n}) {bv(row["coefficient"])}) {bv(row["shift"])})) #x000003c1))'
   if row['extract_low16']:rem=f'((_ zero_extend 16) ((_ extract 15 0) {rem}))'
   shapes.append(neq(row['original_address'],f'(bvadd {frame(0xd10)} {z(rem)})'));byte_ledger.append({**row,'fragment':label,'numerator_domain':[0,0xffffffff if row['coefficient']==0x8864298f else 4033828],'source_root':'F+0xd10','offset_domain':[0,960]})
  groups=[(start,min(8,len(shapes)-start))for start in range(0,112,8)]+[(start,1)for start in range(112,len(shapes))]if label=='round'else[(start,min(46,len(shapes)-start))for start in range(0,len(shapes),46)]
  for start,count in groups:
   name=label+'_original_scratch_remainder_shapes_'+str(start)
   if label=='round'and start==114:
    row=rows[start];n=row['numerator_source_ref'];remref='round_v2108';lines=model.prefix().splitlines();rem=f'(bvsub {n} (bvmul ((_ extract 31 0) (bvlshr (bvmul ((_ zero_extend 32) {n}) {bv(row["coefficient"])}) {bv(row["shift"])})) #x000003c1))'
    for role,ref,term in [('computed_remainder',n,neq(remref,rem)),('stored_remainder_reload',remref,neq(row['original_address'],f'(bvadd {frame(0xd10)} {z(remref)})'))]:
     hits=[line for line in lines if parse(line)[1]==ref];assert len(hits)==1 and parse(hits[0])[3]==['_','BitVec','32'];replacement='(declare-fun '+ref+' () (_ BitVec 32))';source='\n'.join(replacement if line==hits[0]else line for line in lines)+'\n'
     solve(name+'_'+role,source+'(assert '+term+')',extra=decl(model));shape_overapproximations.append({'site':row['site'],'role':role,'source_ref':ref,'remainder_source_ref':remref,'removed_definition':hits[0],'replacement':replacement,'claim':'Universal source overapproximation;free u32 numerator or remainder,not a chosen value or assumed equality. Actual numerator bounds are certified separately;two exact equalities compose the original address.'})
   else:cert(name,model,shapes[start:start+count])
  for row in special:
   cert('direct_original_scratch_bound_'+row['site'],model,[f'(bvugt (bvsub {row["address"]} {frame(0xd10)}) {bv(960)})']);byte_ledger.append({**row,'fragment':label,'method':'Direct original-source unsigned64 offset bound','offset_domain':[0,960]})
 for coef,shift,limit in[(0x443215,32,4033828),(0x8864298f,41,0xffffffff),(0x8864299,37,4033828)]:
  solve('exact_integer_reciprocal_'+hex(coef),f'(declare-fun X () Int)\n(assert (and (<= 0 X) (<= X {limit})))\n(assert (distinct (div (* X {coef}) {1<<shift}) (div X 961)))',integer=True)
  solve('integer_product_quotient_and_subtraction_widths_'+hex(coef),f'(declare-fun X () Int)\n(assert (and (<= 0 X) (<= X {limit})))\n(define-fun Q () Int (div X 961))\n(assert (or (> (* X {coef}) {2**64-1}) (> Q {2**32-1}) (> (* Q 961) {2**32-1}) (> (* Q 961) X) (< (- X (* Q 961)) 0) (>= (- X (* Q 961)) 961)))',integer=True)
 solve('low16_extract_preserves961_remainders','(assert (bvule VALUE #x000003c0))\n(assert '+neq('((_ zero_extend 16) ((_ extract 15 0) VALUE))','VALUE')+')')
 direct=next(r for r in setup.frame_reads if r['width_bits']==8);assert direct['frame_offset']==0xeed
 cert('setup_literal_scratch_byte_is_Tplus477',setup,[neq(rr(setup,direct['site'])['address'],frame(0xeed))]);byte_ledger.append({'fragment':'setup','site':direct['site'],'frame_offset':0xeed,'offset_domain':[477,477],'method':'Original literal frame load'})
 assert len(byte_ledger)==623
 update=run('update',{**roots_p,0x738:(bv(64,32),32),0x558:(bv(0x3c0d,32),32),0x728:('COUNT',32),0x18:('BIAS',32)});update.decl.update(COUNT=32,BIAS=32)
 assert set(DATA)<={r['frame_offset']for r in update.frame_writes if r['width_bits']==32}
 assert len(update.sites)==4073 and len(update.reads)==51 and len(update.stores)==163 and sum(r['width_bits']==8 for r in update.stores)==128 and not any(r['width_bits']==8 for r in update.reads)
 frame_cert('update_all163_stores_and50_frame_reads',update)
 predicate='(bvugt COUNT (bvadd BIAS #xac6de8b8))'
 cert('update_raw_COUNT_biased_position_predicate_and_two_targets',update,[neq(update.loadframe(0x720,32),f'(ite {predicate} #x00000001 #x00000000)'),neq(rr(update,'0x100ca954c')['address'],f'(ite {predicate} {at(0x3c10)} {at(0x3c0d)})'),neq(update.loadframe(0x6b0,32),bv(0x6317,32)),neq(update.loadframe(0x6f8,32),bv(0x4719,32)),neq(update.loadframe(0x478,32),'(bvadd IF_478_32 IF_610_32)'),neq(update.loadframe(0x48c,32),'(bvadd (bvadd IF_48c_32 IF_6c0_32) #xb966c739)'),neq(update.get('w24'),bv(0x23,32)),neq(update.get('x17'),bv(0xbcfd))])
 solve('selected_first_prefix_predicate_is_COUNT_greater64','(declare-fun COUNT () (_ BitVec 32))\n(assert '+neq('(bvugt COUNT (bvadd #x53921788 #xac6de8b8))','(bvugt COUNT #x00000040)')+')')
 # Re-entry adapter executes only on the predicate-true edge. No frame data
 # changes in this adapter;reusing an entry address does not prove the earlier
 # first-entry data-register premises hold again.
 repeat=run('repeat',{**roots_p,0x6b0:(bv(0x6317,32),32)});assert len(repeat.sites)==96 and len(repeat.reads)==3 and not repeat.stores
 cert('repeat_initializer_target_and_explicit_outgoing_constants',repeat,[neq(rr(repeat,'0x100db5850')['address'],at(0x6317)),neq(repeat.get('x17'),bv(0xbfe1)),neq(repeat.get('w19'),bv(0x4923,32)),neq(repeat.get('w8'),bv(0x7f3081c2,32)),neq(repeat.get('w23'),bv(0xc8,32)),neq(repeat.get('w22'),bv(0x5c,32)),neq(repeat.get('w21'),bv(0x74,32)),neq(repeat.get('w27'),bv(0x16,32)),neq(repeat.get('w24'),'J24')])
 # Literal destinations and their source values are retained even where the
 # compact value equations have not been decoded.
 words=set();image=set();coverage=[];known=set(json.loads(read(ROOT/'daemon_mode_one_record_word_extension_checks.json'))['semantics']['final_known_words'])
 assert math.gcd(227,280)==math.gcd(179,192)==1
 for ix in range(64):
  labels=[143+ix,211+ix];assert set(labels)<=known;slots=[227*v%280 for v in labels];romslots=[179*((ix^0x2f)+76)%192,179*(ix^8)%192];assert not words&set(slots)and not image&set(romslots);words.update(slots);image.update(romslots);coverage.append({'IX':ix,'grid_labels':labels,'grid_slots':slots,'grid_frame_offsets':[0x8b0+4*v for v in slots],'image_slots':romslots,'image_addresses':[hex(0x100f40e00+4*v)for v in romslots],'repeat':ix<63})
 assert len(words)==len(image)==128
 planes=[r for r in update.frame_writes if r['width_bits']==8];cells={r['frame_offset']for r in planes};assert len(cells)==128
 inv=pow(866,-1,961);plane_ledger=[{**r,'coordinate_label':(r['frame_offset']-0xd10)*inv%961}for r in planes];assert{r['coordinate_label']for r in plane_ledger}==set(range(896,960))|set(range(827,891))
 banks={name:{0xd10+(base+866*j)%961 for j in range(n)}for name,base,n in[('C',0x77086,256),('D',0x368c4,256),('E',0,256),('H',0x73704,16),('I',0x6e272,16)]};retained=set.union(*banks.values());assert len(retained)==800 and not cells&retained
 # Topologically propagated declared-leaf census establishes absence of
 # COUNT/BIAS in the128 byte values;presence alone never proves influence.
 dependencies={n:{n}for n in update.decl};dependencies.update({n:{n}for n in re.findall(r'\(declare-fun (\w+)',DECL)})
 def leafset(expr):
  todo=[parse(expr)if isinstance(expr,str)else expr];out=set()
  while todo:
   a=todo.pop()
   if isinstance(a,list):todo.extend(a)
   elif a in dependencies:out.update(dependencies[a])
  return out
 for line in update.prefix().splitlines():
  e=parse(line);dependencies[e[1]]=leafset(e[-1])
 byte_dependencies=[sorted(leafset(r['value']))for r in planes];assert all(not{'COUNT','BIAS'}&set(ds)for ds in byte_dependencies)
 protected={off+j for off,n in[(0x18,4),(0x2cc,4),(0x560,8),(0x568,8),(0x580,8),(0x588,8),(0x598,4),(0x728,4),(0x740,8),(0x748,8),(0x750,8),(0x758,8),(0x768,296),(0x8b0,1120),(0x1210,8)]for j in range(n)};preservation=[]
 for label,model in[('setup',setup),('round',g),('update',update),('repeat',repeat)]:
  written={r['frame_offset']+j for r in model.frame_writes for j in range(r['width_bits']//8)};assert not written&protected,(label,sorted(written&protected));assert not(written-cells)&set(range(0xd10,0x10d1))
  preservation.append({'fragment':label,'source_loads':len(model.reads),'load_bytes':sum(r['width_bits']//8 for r in model.reads),'source_stores':len(model.stores),'store_bytes':sum(r['width_bits']//8 for r in model.stores),'distinct_frame_bytes_written':len(written),'saved_roots_COUNT_biased_positions_workspace_grid_and_budget_preserved':True,'retained800_codebook_cells_preserved':not bool(written&retained)})
 assert all(r['retained800_codebook_cells_preserved']for r in preservation)
 actual={pc for m in models.values()for pc in m.sites};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==16447
 # Feasibility and deliberately wrong-interface controls are abstract SAT
 # facts,not native executions or target-input witnesses.
 solve('round_domain_nonempty','(assert (= IX #x0000003f))',result='sat')
 solve('COUNT65_strict_and_nonstrict_predicates_agree','(declare-fun COUNT () (_ BitVec 32))\n(assert (= COUNT #x00000041))\n(assert (distinct (bvugt COUNT #x00000040) (bvuge COUNT #x00000040)))',result='unsat')
 solve('wrong_greater_equal64_boundary_counterexample','(declare-fun COUNT () (_ BitVec 32))\n(assert (= COUNT #x00000040))\n(assert (distinct (bvugt COUNT #x00000040) (bvuge COUNT #x00000040)))',result='sat')
 sem={'source_models':{n:m.record_full()for n,m in models.items()},'source_cuts':cuts,'source_shape_overapproximations':shape_overapproximations,'source_nonbranch_sites_translated':16447,'selected_traversal_nonbranch_instances_without_repeat':226393,'selected_traversal_nonbranch_instances_with_repeat':226489,'rounds':64,'saved_image_root_lineage':chronology,'first_prefix_control_tail_census':control_tail,'root_F588':'0x100fc4130','root_F568':'0x101031ea0','root_F580':'CELL0;actual owner/identity unknown','controller_global_read':'u32[0x1010c4670]','controller_word_values_arbitrary':True,'image_selector_cases':[j^right[left[j]^0x4e]for j in range(256)],'image_selector_constant':'0xff','selected_image_pointer_slot':'0x1010a4568','image_word_base':'0x100f40e00','image_word_bank_slots':192,'image_word_bank_bytes':768,'image_word_index_rules':['179*((IX XOR0x2f)+76) mod192','179*(IX XOR8) mod192'],'grid_label_bases':[143,211],'grid_permutation':227,'grid_slots':280,'coverage_ledger':coverage,'grid_words_read':128,'grid_read_bytes':512,'grid_populated_words_not_read_by_these_sites':128,'image_words_read':128,'image_read_bytes':512,'image_slots_not_read_by_these_sites':64,'scratch_byte_bound_ledger':byte_ledger,'all623_scratch_byte_read_sites_bounded':True,'scratch_offset_domain':[0,960],'scratch_byte_reads_setup':485,'scratch_byte_reads_per_round':138,'scratch_byte_reads_selected_traversal':485+64*138,'scratch_lookup_values_proved':False,'scratch_initialized_bank_membership_proved':False,'lookup_value_codomain_assumptions_needed_for_bounds':False,'frame_effect_and_preservation_ledger':preservation,'word_grid_bytes_preserved':1120,'populated_word_bytes_preserved':1024,'scratch_bytes_preserved_during_setup_and_rounds':961,'scratch_bytes_rewritten_after_rounds':128,'retained_codebook_cells':800,'update_plane_store_ledger':plane_ledger,'update_plane_byte_declared_dependencies':byte_dependencies,'update_plane_values_independent_of_COUNT_and_BIAS':True,'dependency_membership_does_not_prove_influence':True,'setup_initial_frame_inputs':setup.initial,'update_initial_frame_inputs':update.initial,'setup_F738':'low32=0;upper32 not claimed cleared','round_F738':'IX at entry,IX+1 at exit;64 after final body','update_F738':'repurposed data expression;not retained as round count','update_F720':'state until0x100ca61b8,then boolean suffix predicate','update_raw_predicate':'u32 COUNT > u32(BIAS+0xac6de8b8)','selected_first_prefix_F18':'0x53921788','selected_first_prefix_predicate':'COUNT>64','selected_COUNT64_target':'0x100c74750','selected_COUNT65_or_more_target':'0x100db56f0','repeat_target':'0x100c88438','repeat_frame_stores':0,'repeat_initializer_register_ABI_proved':True,'repeat_initializer_changed_F18_frame_epoch_proved':False,'COUNT_unchanged':True,'biased_progress_F18_and_F2cc_unchanged':True,'record_bytes_read_in_new_fragments':0,'caller_output_publication_proved':False,'decoded_round_recurrence_proved':False,'whole_algorithm_identified':False,'native_ownership_proved':False,'native_traversal_proved':False,'Mach_port_emissions':0,'excluded_solver_attempts':'Aggregate138-address,final46-address and one8-address and one single-address round shape queries returned unknown at15000 ms;excluded. Accepted round groups of at most8 and setup groups of at most46 original-source address shapes supply complete coverage;one reloaded remainder uses separate universally overapproximated computed-remainder and frame-reload identities;unsplit/free-numerator/tactic attempts were excluded. Early exploratory queries with an undeclared CELL0 produced diagnostics and were rejected;corrected queries declare it explicitly.','native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['round'].__setitem__('bytes','00'+q['fragments']['round']['bytes'][2:])),('wrong_round_counter',lambda q:next(i for i in q['fragments']['round']['instructions']if i['ea']=='0x100d8ee7c').__setitem__('operands','w16, #0x40')),('wrong_word_bank',lambda q:q['data_banks'][2].__setitem__('target','0x0')),('wrong_image_byte',lambda q:q['data_banks'][0].__setitem__('bytes','00'*256)),('wrong_suffix_target',lambda q:q['branch_edges'][4].__setitem__('target','0x0')),('wrong_low32_width',lambda q:q['fragments']['setup']['instructions'][0].__setitem__('operands','xzr, [sp, #0x738]')),('wrong_root_lineage',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  altered=copy.deepcopy(s);fn(altered);assert not verify(altered);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':16447,'selected_instances_without_repeat':226393,'selected_instances_with_repeat':226489,'rounds':64,'grid_word_reads':128,'image_word_reads':128,'scratch_byte_source_sites_bounded':623,'scratch_byte_reads_selected_traversal':9317,'byte_selector_cases':256,'source_cuts':len(sem['source_cuts']),'root_lineage_stages':len(sem['saved_image_root_lineage']),'updated_plane_bytes':128,'state_word_destinations':16,'retained_codebook_cells':800,'word_grid_bytes_preserved':1120,'populated_word_bytes_preserved':1024,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','recover_daemon_mode_one_record_word_extension.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_lookup_algebra.py','daemon_word_round_tools.py','validate_daemon_mode_one_word_schedule.py','validate_daemon_existing_scalar_reader.py','validate_daemon_constructor_inputs.py','validate_daemon_constructor_lookup.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'round_consumption_all_byte_bounds_and_COUNT_reentry_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
