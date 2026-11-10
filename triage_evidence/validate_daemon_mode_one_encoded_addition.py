#!/usr/bin/env python3
"""Source contracts for inverse maps,second shuffle and encoded4-bit addition."""
import copy,json,re,subprocess,shutil
from recover_daemon_mode_one_encoded_addition import ROOT,P,SCOPE,FLAGS,DEPS,build,LEFT,RIGHT,ROM,DATA_SLOT,BIAS
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_workspace_passes import ByteSSA,D
from validate_daemon_existing_scalar_reader import DECL,bv,z,frame,at,neq
from validate_daemon_list_output import split
from daemon_mode_one_handoff_tools import parse
SOLVER=shutil.which('z3');assert SOLVER
class NamedByteSSA(ByteSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   super().run({'instructions':[i]},pc+4)
   if i['mnemonic']=='ldrb'and i['ea']in self.supplied_loads:
    v,w=self.supplied_loads[i['ea']];assert w==8;self.reads[-1]['input']=v;self.put(split(i['operands'])[0],'((_ zero_extend 24) '+v+')')
  return self
CUT={0x100dcab0c:(14,'w5','w8'),0x100dcab50:(15,'w7','w9'),0x100dcabc4:(13,'w4','w2'),0x100dcac20:(12,'w3','w10'),0x100dcac48:(11,'w19','w2'),0x100dcac90:(10,'w0','w5'),0x100dcacb0:(9,'w5','w6'),0x100dcada4:(7,'w5','w2'),0x100dcadc4:(6,'w16','w19'),0x100dcae28:(5,'w3','w8'),0x100dcaec4:(3,'w9','w10')};MASK={0x100dcab10:(16,'w14'),0x100dcad6c:(8,'w4'),0x100dcae80:(4,'w16')}
def certificates(s):
 pp=[];models={};cuts=[];replays=[];fs=s['fragments'];data=s['image_data']
 def solve(name,body,result='unsat',extra='',cc=(),logic='QF_BV'):
  q='(set-option :timeout 15000)\n(set-logic '+logic+')\n'+(''if logic=='QF_LIA'else DECL)+extra+body+'\n'+''.join('(assert '+x+')\n'for x in cc)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def dec(g):return''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in g.decl.items())
 def cert(name,g,terms,cc=()):solve(name,g.prefix()+'(assert (or '+' '.join(terms)+'))',extra=dec(g),cc=cc)
 def rd(g,pc):return next(r for r in g.reads if r['site']==hex(pc))
 old=json.loads(read(ROOT/'daemon_mode_one_workspace_passes_checks.json'));assert old['all_checks_pass']and len(old['proofs'])==174
 for p in old['proofs']:
  assert p['result']=='unsat';r=subprocess.run([SOLVER,'-in'],input=p['query'],text=True,capture_output=True,timeout=20);assert not r.returncode and not r.stderr and r.stdout.strip()=='unsat';pp.append({**p,'name':'replayed_workspace_'+p['name'],'replayed_query':True})
 replays.append({'checks':'daemon_mode_one_workspace_passes_checks.json','sha256':sha(ROOT/'daemon_mode_one_workspace_passes_checks.json'),'queries_replayed':174,'all_queries_replayed':True})
 # Current scopes preserve the two fixed image roots and controller pointers.
 protected={o+j for o in[0x438,0x568,0x580,0x588]for j in range(8)};prior_checkpoint=json.loads(read(ROOT/'daemon_mode_one_record_checkpoint_checks.json'))['semantics']['source_models']['checkpoint'];assert all(not protected&set(range(r['frame_offset'],r['frame_offset']+r['width_bits']//8))for r in prior_checkpoint['frame_writes'])
 p0=[0x8b0+799*j%962 for j in range(16)];inv=[0x8b0+799*(593+j)%962 for j in range(16)];dest=[0x8b0+799*(72+j)%962 for j in range(256)];assert len(set(p0+inv+dest))==288 and all(0x8b0<=x<0xc72 for x in p0+inv+dest)
 incoming={0:799,1:962,2:545,3:0x441fef,4:16,5:0x2527,13:0x8721,16:0x73acf,30:0x422b};regs={k:bv(v)for k,v in incoming.items()};regs.update({15:z('IDX'),20:frame(0x8b0),26:frame(0x8b0)})
 g=NamedByteSSA('inverse',regs,presets={0x740:('TABLE',64)},loads={'0x100a4f15c':('PV',8),'0x100a4f18c':('INVERSE_FN',64)});g.decl.update(IDX=32,PV=8,INVERSE_FN=64);f=fs['inverse'];g.run(f,int(f['instructions'][-1]['ea'],16));models['inverse']=g;ic=['(bvult IDX #x00000010)','(bvult PV #x10)']
 assert len(g.stores)==1 and len(g.reads)==3
 cert('inverse_index_byte_store_and_exact16_dispatch',g,[neq(g.stores[0]['value'],'((_ extract 7 0) IDX)'),neq(g.get('w15'),'(bvadd IDX #x00000001)'),neq(rd(g,0x100a4f18c)['address'],f'(ite (= IDX #x0000000f) {at(0xa206)} {at(0x8721)})'),neq(g.get('x20'),frame(0x8b0)),neq(g.get('x30'),bv(0x422b)),neq(g.get('x17'),bv(0xaf8b))],ic)
 for j in range(16):
  cert('inverse_source_cell_'+str(j),g,[neq(rd(g,0x100a4f15c)['address'],frame(p0[j]))],ic+['(= IDX '+bv(j,32)+')'])
  cert('inverse_destination_cell_'+str(j),g,[neq(g.stores[0]['address'],frame(inv[j]))],ic+['(= PV '+bv(j,8)+')'])
 assert not set(s['register_write_sets']['inverse'])&{p+str(k)for p in['x','w']for k in[8,9,10,12,14,20,30]}
 assert not set(json.loads(read(ROOT/'daemon_mode_one_workspace_passes_source.json'))['register_write_sets']['shuffle'])&{p+str(k)for p in['x','w']for k in[8,9,10,12,14]}
 # Symbolic permutation inversion uses4-bit logical coordinates;byte
 # representations are separately bounded by the predecessor source proof.
 ap='(declare-fun PA () (Array (_ BitVec 4) (_ BitVec 4)))\n(declare-fun IA () (Array (_ BitVec 4) (_ BitVec 4)))\n';values=['(select PA '+bv(j,4)+')'for j in range(16)];ap+='(assert (distinct '+' '.join(values)+'))\n';expr='IA'
 for j in range(16):expr='(store '+expr+' '+values[j]+' '+bv(j,4)+')'
 for j in range(16):solve('inverse_coherent_array_cell_'+str(j),ap+'(assert '+neq('(select '+expr+' '+values[j]+')',bv(j,4))+')',logic='QF_ABV')
 # Snapshot the exact ROM law before assigning any group identity.
 left,right=bytes.fromhex(data['selector_left']['bytes']),bytes.fromhex(data['selector_right']['bytes']);selector=[j^right[left[j]^0xa3]for j in range(256)];assert set(selector)=={0x72}
 def lookup(values,arg,width):
  out=bv(values[-1],width)
  for j in reversed(range(len(values)-1)):out='(ite (= '+arg+' '+bv(j,8)+') '+bv(values[j],width)+' '+out+')'
  return out
 selector_expr='(bvxor SEL8 '+lookup(right,'(bvxor '+lookup(left,'SEL8',8)+' #xa3)',8)+')';solve('all256_original_selector_cases_choose72','(assert '+neq(selector_expr,'#x72')+')',extra='(declare-fun SEL8 () (_ BitVec 8))\n')
 table=[r['decoded_u4']for r in data['selected_cells']];assert len(table)==256;op=lambda a,b:table[a+16*b];assert all(sorted(table[16*y:16*y+16])==list(range(16))for y in range(16));assert all(sorted(op(x,y)for y in range(16))==list(range(16))for x in range(16));assert all(op(a,b)==op(b,a)for a in range(16)for b in range(16))
 assoc=[{'a':a,'b':b,'c':c,'value':op(op(a,b),c)}for a in range(16)for b in range(16)for c in range(16)];assert all(r['value']==op(r['a'],op(r['b'],r['c']))for r in assoc);identity=[e for e in range(16)if all(op(e,a)==a==op(a,e)for a in range(16))];assert identity==[12];generators=[]
 for candidate in range(16):
  seq=[];v=12
  while v not in seq:seq.append(v);v=op(v,candidate)
  if len(seq)==16:assert v==12;generators.append({'generator_symbol':candidate,'encoding':seq})
 assert[g['generator_symbol']for g in generators]==[0,4,5,6,11,13,14,15];E=generators[0]['encoding'];EI=[E.index(j)for j in range(16)];assert E==[12,0,10,13,1,14,8,15,2,6,7,5,9,11,3,4]
 addition=[]
 for a in range(16):
  for b in range(16):assert op(a,b)==E[(EI[a]+EI[b])%16];addition.append({'a':a,'b':b,'raw_ROM_result':op(a,b),'decoded_sum_u4':(EI[a]+EI[b])%16})
 # Finite input lookup,with4-bit output;one universal8-bit query binds
 # every original selected ROM entry to the explicit cyclic encoding.
 enc=lambda arr,arg:'(ite (= '+arg+' #x0) '+bv(arr[0],4)+' '+''.join('(ite (= '+arg+' '+bv(j,4)+') '+bv(arr[j],4)+' 'for j in range(1,15))+bv(arr[15],4)+')'*15
 arithmetic=enc(E,'(bvadd '+enc(EI,'A4')+' '+enc(EI,'B4')+')');solve('ROM_operation_is_encoded_addition_mod16','(assert '+neq(lookup(table,'(concat B4 A4)',4),arithmetic)+')',extra='(declare-fun A4 () (_ BitVec 4))\n(declare-fun B4 () (_ BitVec 4))\n')
 # Distinct input/output encodings preserve Latin rows and symmetry but do
 # not generally preserve associativity. This counterexample is abstract.
 swap01=lambda x:f'(ite (= {x} #x0) #x1 (ite (= {x} #x1) #x0 {x}))'
 h=lambda x,y:swap01('(bvadd '+x+' '+y+')')
 solve('different_encoding_roles_do_not_imply_associativity','(assert '+neq(h(h('#x0','#x0'),'#x1'),h('#x0',h('#x0','#x1')))+')',result='sat')

 f=fs['second_shuffle'];g=ByteSSA('second_shuffle',{20:frame(0x8b0),30:bv(0x422b)},presets={0x740:('TABLE',64),0x438:('CELL1',64),0x588:(bv(0x100fc4130),64),0x568:(bv(0x101031ea0),64)},loads={'0x100dcaf28':('SHUFFLE_FN',64)});g.decl.update(SHUFFLE_FN=64,CELL1=64)
 cc=[]
 def query(name,terms):cert(name,g,terms,cc)
 for i in f['instructions'][:-1]:
  pc=int(i['ea'],16)
  if pc in CUT:d,reg,src=CUT[pc];n=g.get(src)
  g.run({'instructions':[i]},pc+4)
  if pc in MASK:
   d,reg=MASK[pc];query('mask'+str(d),['(bvuge '+g.get(reg)+' '+bv(d,32)+')']);cuts.append({'site':i['ea'],'register':reg,'original_expression':g.get(reg),'replacement':'RES'+str(d),'range_u32':[0,d-1],'divisor_or_mask_domain':d,'justification':'Replayed all-u32 integer quotient/mask domain plus fresh current-source BV shape/bound;independent bounded overapproximation.'});g.put(reg,'RES'+str(d));g.decl['RES'+str(d)]=32;cc.append('(bvult RES'+str(d)+' '+bv(d,32)+')')
  if pc in CUT:
   if d==7:
    t='((_ extract 31 0) (bvlshr (bvmul '+z(n)+' '+bv(0x24924925)+') '+bv(32)+'))';q='(bvlshr (bvadd '+t+' (bvlshr (bvsub '+n+' '+t+') #x00000001)) #x00000002)'
   else:
    m,s,h=D[d];q='((_ extract 31 0) (bvlshr (bvmul '+z('(bvlshr '+n+' #x00000001)'if h else n)+' '+bv(m)+') '+bv(s)+'))'
   query('shape'+str(d),[neq(g.get(reg),'(bvsub '+n+' (bvmul '+q+' '+bv(d,32)+'))')]);cuts.append({'site':i['ea'],'register':reg,'original_expression':g.get(reg),'replacement':'RES'+str(d),'range_u32':[0,d-1],'divisor_or_mask_domain':d,'justification':'Replayed all-u32 integer quotient/mask domain plus fresh current-source BV shape/bound;independent bounded overapproximation.'});g.put(reg,'RES'+str(d));g.decl['RES'+str(d)]=32;cc.append('(bvult RES'+str(d)+' '+bv(d,32)+')')
 br=[r for r in g.reads if r['width_bits']==8];bs=[r for r in g.stores if r['width_bits']==8];selected=[br[k]for k in[0,2,3,6,8,10,12,13,16,18,20,22,24,25,27]]
 for j in range(14):
  d=16-j
  for r in range(d):
   logical=(14^r)if j==12 else j+r;cc.append('(= RES'+str(d)+' '+bv(r,32)+')');query('cell'+str(j)+'_case'+str(r),[neq(selected[j]['address'],frame(0x8b0+799*logical%962))]);cc.pop()
 query('last_cell',['(and '+neq(selected[14]['address'],frame(0xb0c))+' '+neq(selected[14]['address'],frame(0xa69))+')']);print('counts',len(g.sites),len(g.reads),len(g.stores),flush=True)
 models['second_shuffle']=g;assert len(cuts)==14 and len(br)==29 and len(bs)==46 and not g.frame_writes
 flow=[];swaps=[]
 for j in range(15):
  a,b=bs[16+2*j:18+2*j];flow.extend([neq(a['address'],frame(p0[j])),neq(b['address'],selected[j]['address']),neq(a['value'],selected[j]['input'])]);rr=[selected[0]]if j==0 else br[2*j-1:2*j+1]
  if j==0:flow.append(neq(b['value'],'#x00'));fixed=None
  else:fixed=next(r for r in rr if r is not selected[j]);flow.extend([neq(fixed['address'],frame(p0[j])),neq(b['value'],fixed['input'])])
  assert all(int(r['site'],16)<int(a['site'],16)and int(r['site'],16)<int(b['site'],16)for r in rr);swaps.append({'fixed_cell':j,'selected_logical_range':[j,15],'selected_read':selected[j],'fixed_read':fixed,'stores':[a,b],'all_reads_before_both_stores':True})
 cert('second_shuffle_all15_swaps_exact_addresses_values_and_order',g,flow,cc);cert('second_shuffle_all16_identity_stores',g,[x for j,r in enumerate(bs[:16])for x in[neq(r['address'],frame(p0[j])),neq(r['value'],bv(j,8))]],cc)
 tail={0:0x883fddf1,4:799,5:928,6:0xa6,7:0xa5cd4cf,11:BIAS,13:0,14:962,15:15,16:0x73acf,19:0xa3,21:64,22:0xe0d19f11,23:439,24:0xc7c0,25:0x112,26:0x20d,27:0xe8c9,30:0x422b}
 cert('second_shuffle_saved_roots_and_complete_builder_ABI',g,[neq(g.get('x'+str(k)),bv(v))for k,v in tail.items()]+[neq(g.get('x20'),frame(0x8b0)),neq(g.get('x1'),bv(LEFT)),neq(g.get('x2'),bv(RIGHT)),neq(g.get('x12'),'CELL1'),neq(g.get('x17'),bv(0xd429)),neq(rd(g,0x100dcaf28)['address'],at(0x422b))],cc)
 # Prove the actual builder from its full source. Byte-level component
 # interfaces compose with the established inverse/permutation and ROM data.
 regs={k:bv(v)for k,v in tail.items()};regs.update({1:bv(LEFT),2:bv(RIGHT),12:'CELL1',13:z('IDX'),20:frame(0x8b0)})
 loads={'0x100cbe044':('ILO',8),'0x100cbe054':('IHI',8),'0x100cbe07c':('C0',32),'0x100cbe080':('C1',32),'0x100cbe0a4':('LBYTE',8),'0x100cbe0b0':('RBYTE',8),'0x100cbe0cc':(bv(0x129c240c7),64),'0x100cbe0d4':('ROMBYTE',8),'0x100cbe140':('QVALUE',8),'0x100cbe160':('BUILD_FN',64)}
 g=NamedByteSSA('builder',regs,presets={0x740:('TABLE',64),0x580:('CELL0',64)},loads=loads);g.decl.update(IDX=32,C0=32,C1=32,CELL0=64,CELL1=64,ILO=8,IHI=8,LBYTE=8,RBYTE=8,ROMBYTE=8,QVALUE=8,BUILD_FN=64);bc=['(bvult IDX #x00000100)','(bvult ILO #x10)','(bvult IHI #x10)','(bvuge ROMBYTE #x40)','(bvult ROMBYTE #x50)','(bvult QVALUE #x10)'];selector_cut=[]
 for i in fs['builder']['instructions'][:-1]:
  g.run({'instructions':[i]},int(i['ea'],16)+4)
  if i['ea']=='0x100cbe09c':mix=g.get('w17')
  if i['ea']=='0x100cbe0b8':
   cert('builder_source_controller_byte_bank_and_selector_interface',g,[neq(rd(g,0x100cbe07c)['address'],'CELL0'),neq(rd(g,0x100cbe080)['address'],'CELL1'),neq(rd(g,0x100cbe0a4)['address'],'(bvadd '+bv(LEFT)+' ((_ zero_extend 56) ((_ extract 7 0) '+mix+')))'),neq(rd(g,0x100cbe0b0)['address'],'(bvadd '+bv(RIGHT)+' ((_ zero_extend 56) (bvxor LBYTE #xa3)))'),neq(g.get('w17'),'((_ zero_extend 24) (bvxor ((_ extract 7 0) '+mix+') RBYTE))')],bc)
   selector_cut.append({'site':i['ea'],'register':'w17','original_expression':g.get('w17'),'replacement':'#x00000072','justification':'Fresh original-source controller/bank projection,all256 pinned image cases and universal8-bit lookup theorem. Immutable roots/bytes and coherent loads required.'});g.put('w17',bv(0x72,32))
 models['builder']=g;assert len(g.reads)==12 and len(g.stores)==1 and not g.frame_writes
 cert('builder_selects_original_rebase_slot_and_byte_input_encoding',g,[neq(rd(g,0x100cbe0cc)['address'],bv(DATA_SLOT)),neq(rd(g,0x100cbe140)['input'],'QVALUE')],bc)
 inverse_cases=[]
 for j in range(16):
  cert('builder_low_inverse_cell_'+str(j),g,[neq(rd(g,0x100cbe044)['address'],frame(inv[j]))],bc+['(= (bvand IDX #x0000000f) '+bv(j,32)+')'])
  cert('builder_high_inverse_cell_'+str(j),g,[neq(rd(g,0x100cbe054)['address'],frame(inv[j]))],bc+['(= (bvlshr IDX #x00000004) '+bv(j,32)+')'])
  cert('builder_Q_source_cell_'+str(j),g,[neq(rd(g,0x100cbe140)['address'],frame(p0[j]))],bc+['(= ROMBYTE '+bv(0x40+j,8)+')'])
 for a in range(16):
  for b in range(16):
   byte=a+16*b;entry=data['selected_cells'][byte];cert('builder_selected_ROM_'+str(byte),g,[neq(rd(g,0x100cbe0d4)['address'],bv(ROM+entry['physical_offset']))],bc+['(= ILO '+bv(a,8)+')','(= IHI '+bv(b,8)+')'])
 cert('builder_exact256_destination_progress_data_and_dispatch',g,[neq(g.stores[0]['address'],'(bvadd '+frame(0x8b0)+' ((_ zero_extend 32) (bvurem (bvmul (bvadd IDX #x00000048) #x0000031f) #x000003c2)))'),neq(g.stores[0]['value'],'QVALUE'),neq(g.get('w13'),'(bvadd IDX #x00000001)'),neq(rd(g,0x100cbe160)['address'],f'(ite (= IDX #x000000ff) {at(0xaae2)} {at(0x422b)})'),neq(g.get('w10'),bv(0,32)),neq(g.get('x20'),frame(0x8b0)),neq(g.get('x30'),bv(0x422b)),neq(g.get('x17'),bv(0xd429))],bc)
 # This width-aware identity is independent of the selected ROM codomain.
 b8='(declare-fun BYTEVAL () (_ BitVec 8))\n';v='((_ zero_extend 24) BYTEVAL)';c=bv(0xe0d19f11,32);decoded=f'(bvadd (bvxor (bvxor (bvxor (bvsub #x00000040 (bvxor {v} #x00000040)) (bvneg {v})) {c}) (bvadd (bvsub {v} (bvand (bvshl {v} #x00000001) #x22222222)) {c})) #x00000040)';solve('byte_decode_identity_is_XOR40', '(assert '+neq(decoded,'((_ zero_extend 24) (bvxor BYTEVAL #x40))')+')',extra=b8)
 # Generic injectivity of a16-value permutation supports Latin-row and
 # column composition without enumerating all dynamic permutations.
 perm='(declare-fun QA () (Array (_ BitVec 4) (_ BitVec 4)))\n(declare-fun X4 () (_ BitVec 4))\n(declare-fun Y4 () (_ BitVec 4))\n(assert (distinct '+' '.join('(select QA '+bv(j,4)+')'for j in range(16))+'))\n(assert (distinct X4 Y4))\n(assert (= (select QA X4) (select QA Y4)))';solve('any16_value_permutation_is_injective',perm,logic='QF_ABV')
 records={n:m.record_full()for n,m in models.items()};actual={pc for m in models.values()for pc in m.sites};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected and len(actual)==435
 assert 799*593==0x73acf and 653*290==0x2e3ba and 799*64==0xc7c0
 sem={'source_models':records,'source_nonbranch_sites_translated':435,'predecessor_replays':replays,'protected_image_root_slots':[hex(x)for x in[0x438,0x568,0x580,0x588]],'checkpoint_image_root_store_intersections':0,'image_root_reaching_contracts':'F588=LEFT,F568=RIGHT,F580=CELL0;F438=CELL1 is an unknown valid reaching pointer. Predecessor image/root preservation and mapping premises apply.','first_permutation_forward_slots':p0,'first_inverse_slots':inv,'output256_slots':dest,'distinct_known_cells_after_builder':288,'inverse_relation':'I[P[j]]=j,0<=j<16;P is the first permutation','inverse_loop_iterations':16,'first_forward_bytes_reinitialized_before_second_read':16,'second_source_retained_registers':[8,9,10,12,14],'statistical_independence_proved':False,'second_shuffle_cuts':cuts,'second_shuffle_bounds':cc,'second_shuffle_source_swaps':swaps,'second_permutation_invariant_proved':True,'inverse_bank_preserved_by_second_shuffle':True,'builder_incoming_constants':{str(k):hex(v)for k,v in tail.items()},'selector_cut':selector_cut,'selector_constant':'0x72','controller_C0_C1_owners':'unknown','controller_values_can_change_selector_byte_access_addresses':True,'selected_ROM_bank_independent_of_controller_words_under_premises':True,'side_channel_noninterference_proved':False,'selected_rebased_pointer_slot':hex(DATA_SLOT),'selected_ROM_base':hex(ROM),'raw_chained_word_used_as_live_pointer':False,'selected_ROM_cells':data['selected_cells'],'ROM_decoded_table':table,'ROM_identity_symbol':12,'ROM_commutative':True,'ROM_associativity_cases':assoc,'ROM_generators':generators,'static_encoding_E':E,'static_decoding_E_inverse':EI,'ROM_mod16_addition_cases':addition,'ROM_equation':'F(a,b)=E((Einverse(a)+Einverse(b))mod16)','builder_equation':'D[x+16*y]=Q(F(I[x],I[y]));I=inverse(P)','input_encoding':'P composed with E','output_encoding':'Q composed with E','builder_decoded_equation':'D[x+16*y]=Eout((Ein_inverse(x)+Ein_inverse(y))mod16)','input_output_encoding_values_must_differ':False,'generated_table_is_Latin':True,'generated_table_is_commutative':True,'generated_table_values_each_occur16_times':True,'generated_table_associativity_or_identity_proved':False,'associativity_negative_control_is_abstract':True,'native_negative_control_reachability_proved':False,'ROM_byte_codomain_only_for_selected256_cells':[0x40,0x4f],'whole928_byte_bank_has_broader_values':True,'builder_iteration_domain':'0<=IDX<256','builder_source_byte_conditions':bc,'builder_source_nibble_bytes':3,'builder_image_byte_reads':3,'builder_byte_writes_per_iteration':1,'builder_table_entries':256,'builder_logical_destination_labels':[72,327],'output_bytes_are_nibbles':True,'output_is_not_a256_value_byte_permutation':True,'bound_source_components_not_native_samples':True,'source_byte_reads_are_named_components':True,'native_ownership_proved':False,'successful_output_proved':False,'daemon_kext_pairing_proved':False,'LOCAL_pointer_dereferences':0,'Mach_port_emissions':0,'next_target':'0x100c1c8a0','next_target_semantics_proved':False,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['inverse'].__setitem__('bytes','00'+q['fragments']['inverse']['bytes'][2:])),('wrong_inverse_stride',lambda q:next(i for i in q['fragments']['inverse']['instructions']if i['ea']=='0x100a4f170').__setitem__('operands','w15, [x20]')),('wrong_ROM_byte',lambda q:q['image_data'].__setitem__('ROM_bytes','00'+q['image_data']['ROM_bytes'][2:])),('wrong_rebase_value',lambda q:q['image_data'].__setitem__('rebased_value','0x0')),('wrong_selector',lambda q:q['image_data'].__setitem__('selector_constant','0x0')),('wrong_next_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('wrong_lineage',lambda q:q['prior_recaptures'][0].__setitem__('sha256','0'*64)),('invent_native',lambda q:q.__setitem__('target_executed',True))];original=build();out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert q!=original;out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(p['result']=='unsat'for p in pp),'queries_sat':sum(p['result']=='sat'for p in pp),'predecessor_queries_replayed':sum(p.get('replayed_query',False)for p in pp),'source_nonbranch_sites_translated':435,'inverse_iterations':16,'inverse_source_address_cases':16,'inverse_destination_address_cases':16,'inverse_array_cells':16,'second_shuffle_overapproximations':14,'second_shuffle_address_cases':133,'second_shuffle_identity_stores':16,'second_shuffle_swaps':15,'second_shuffle_byte_reads':29,'second_shuffle_byte_stores':46,'builder_iterations':256,'builder_inverse_address_cases':32,'builder_Q_address_cases':16,'builder_ROM_address_cases':256,'builder_byte_reads_per_iteration':6,'builder_byte_stores_per_iteration':1,'ROM_associativity_cases':4096,'ROM_encoded_addition_cases':256,'ROM_order16_generators':8,'known_frame_cells':288,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_workspace_passes.py','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','daemon_word_lookup_algebra.py','validate_daemon_mode_one_word_schedule.py','validate_daemon_existing_scalar_reader.py','validate_daemon_constructor_inputs.py','validate_daemon_constructor_lookup.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'inverse_second_permutation_and_encoded_addition_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
