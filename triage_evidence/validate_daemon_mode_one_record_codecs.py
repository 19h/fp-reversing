#!/usr/bin/env python3
"""Source SSA, finite image algebra and disjoint-bank composition; no target run."""
import copy,json,subprocess,shutil
from recover_daemon_mode_one_record_codecs import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_record_adder import Engine,EXTRA,lookup,AA,BB,CC,DD
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,at,frame
SOLVER=shutil.which('z3');assert SOLVER
EE=[866*j%961 for j in range(256)]
HH=[(0x73704+866*j)%961 for j in range(16)]
II=[(0x6e272+866*j)%961 for j in range(16)]
# quotient start,exclusive end,numerator,output,index,base,bank,multiplier,shift
GROUPS={'xor':[(0x100d5e280,0x100d5e28c,'w13','w13','(bvand ARG #x0000000f)',0xaed96,BB,7,32),(0x100d5e290,0x100d5e2a0,'w14','w14','(bvlshr ARG #x00000004)',0xaed96,BB,3,41),(0x100d5e2e0,0x100d5e2ec,'w13','w13','NIB',0xbd700,AA,7,32),(0x100d5e2f0,0x100d5e2fc,'w14','w14','ARG',0,EE,3,41)],'decode':[(0x100d9e074,0x100d9e07c,'w16','w15','ARG',0xaed96,BB,0,0),(0x100d9e0a8,0x100d9e0b4,'w14','w14','ARG',0x73704,HH,3,41)],'encode':[(0x100d03cc4,0x100d03ccc,'w10','w10','NIB',0xbd700,AA,0,0),(0x100d03ce0,0x100d03cec,'w11','w11','ARG',0x6e272,II,3,41)]}
def certificates(s):
 pp=[];models={};addresses=[];cuts=[];invariants={};fs=s['fragments']
 def solve(name,body,result='unsat',cc=(),integer=False,arrays=False,extra=''):
  q='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_ABV'if arrays else'QF_BV')+')\n'+('(declare-fun XI () Int)\n'if integer else DECL+EXTRA)+extra+body+'\n'+''.join('(assert '+c+')\n'for c in cc)+'(check-sat)\n'
  r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  assert r.returncode==0 and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr)
  pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def cert(name,g,terms,cc=()):solve(name,g.declarations+g.prefix()+'(assert (or '+' '.join(terms)+'))',cc=cc)
 def fresh(n,label,r=None,loads=None,a=None,end=None):
  f=fs[n];a=a or int(f['start'],16);end=end or int(f['instructions'][-1]['ea'],16)
  ll=dict(loads or{});dd=[];ii=[i for i in f['instructions']if a<=int(i['ea'],16)<end]
  for i in ii:
   if i['mnemonic']in ['ldr','ldrb']and i['ea']not in ll:
    w=8 if i['mnemonic']=='ldrb'else 32 if i['operands'].startswith('w')else 64;name=label+'_L'+str(len(dd));ll[i['ea']]=(name,w);dd.append(f'(declare-fun {name} () (_ BitVec {w}))')
  g=Engine({**{j:'Z'+str(j)for j in range(31)},'sp':'K',**(r or{})},ll,namespace=label+'_');g.declarations='\n'.join(dd)+'\n';g.run({'instructions':ii},end);models[label]=g;return g
 def rd(g,pc):return next(v for v in g.reads if v['site']==hex(pc))
 def st(g,pc):return next(v for v in g.stores if v['site']==hex(pc))
 from recover_daemon_mode_one_record_adder import build as previous_build
 from validate_daemon_mode_one_record_adder import certificates as previous_certificates
 old=previous_build();assert old==json.loads(read(ROOT/DEPS[0]));prior=json.loads(read(ROOT/DEPS[1]))
 bp,bs=previous_certificates(old);assert bp==prior['proofs']and json.loads(json.dumps(bs))==prior['semantics']
 pp.extend({**p,'name':'replayed_adder_'+p['name'],'replayed_query':True}for p in bp)
 # Newly needed registers were left symbolic by the earlier table-step models.
 # Bind them to original producers,then check every intervening W/X alias.
 first=json.loads(read(ROOT/DEPS[3]))['semantics']['source_models']['permutation']
 solve('first_shuffle_supplies_codec_W25_and_W30',first['declarations']+first['source_SSA']+'(assert (or '+neq('((_ extract 31 0) '+first['final_registers']['25']+')',bv(0x4d,32))+' '+neq('((_ extract 31 0) '+first['final_registers']['30']+')',bv(10,32))+'))')
 prior_source=json.loads(read(ROOT/DEPS[2]))
 for src,names in [(prior_source,['inverse','reset']),(old,['second','sum','carry'])]:
  for n in names:
   for k in [25,30]:assert not{p+str(k)for p in ['w','x']}&set(src['register_write_sets'][n]),(n,k)
 second=bs['source_models']['second'];selcc=[f'(bvult SEL{j} {bv(16-j,32)})'for j in range(15)]
 solve('second_shuffle_supplies_codec_W20',second['declarations']+second['source_SSA']+'(assert '+neq('((_ extract 31 0) '+second['final_registers'][20]+')',bv(0x79,32))+')',cc=selcc)
 for n in ['sum','carry']:assert not{'x20','w20'}&set(old['register_write_sets'][n])
 shared={3:bv(0x8864298f),5:bv(866),6:bv(0xbd700),7:bv(0x443215),8:bv(0xaed96),9:bv(0x100f4a640),10:bv(0x84e8),19:bv(961),20:bv(0x79),21:bv(45),23:bv(0x469f),24:bv(928),25:bv(0x4d),26:frame(0xd10),30:bv(10)}
 # Image algebra is exhaustive over the actual nibble and byte domains.
 image=bytes.fromhex(s['operation_image']['bytes']);label=bs['arithmetic_label_cycle'];inv=[label.index(j)for j in range(16)]
 image_cases={};kernels={}
 for name,count in [('xor',256),('decode',16),('encode',16)]:
  rows=[];values=[]
  for arg in range(count):
   if name=='xor':n=45*(arg^0x1f)+0x68c4
   elif name=='decode':n=45*(arg^10)+0x6135
   else:n=45*(arg^10)
   if name=='encode':q=0;pos=n
   else:q=((n*0x469f)&0xffffffff)>>24;pos=n-q*928;assert q==n//928 and n*0x469f<2**32
   assert 0<=pos<928;y=image[pos]
   if name=='xor':v=(y^arg^0x4d)&255
   elif name=='decode':
    x=0x74^arg;v=(((((x^0x32)-0x74)^((x^5)-0x43)^((x^0x4d)-11))+0x3b)^y^0x77777777)&255
   else:v=y^arg^0xb1
   if name=='decode':assert v==0x74^inv[arg]
   else:assert 0<=v<16
   rows.append({'argument':arg,'numerator':n,'quotient':q,'offset':pos,'image_byte':y,'decoded_value':v});values.append(v)
  image_cases[name]=rows;kernels[name]=values
 assert kernels['encode']==label
 pairs=[]
 for a in range(16):
  for b in range(16):
   q=label[a]+16*label[b];assert kernels['xor'][q]==label[a^b];pairs.append({'a':a,'b':b,'label_argument':q,'result_label':kernels['xor'][q]})
 assert all(kernels['decode'][label[a]]==0x74^a for a in range(16))
 packing=[]
 for low in range(16):
  for high in range(16):
   a=0x74^low;b=(0x74^(high<<4))&255;assert a^b==low|(high<<4)
   packing.append({'low_label':low,'high_label':high,'sum_byte':a,'carry_byte':b,'packed_byte':a^b})
 solve('restricted_image_division928_and_word_product_bound','(assert (and (<= 0 XI) (<= XI 40000)))\n(assert (or (distinct (div (* XI 18079) 16777216) (div XI 928)) (>= (* XI 18079) 4294967296)))',integer=True)
 # Every finite scratch replacement has a source quotient-shape certificate,
 # a live numerator/coefficient certificate,and all actual argument cases.
 for name,groups in GROUPS.items():
  for a,end,num,out,idx,base,bank,mreg,shift in groups:
   rr={int(num[1:]):z('VALUE'),19:bv(961)}
   if mreg:rr[mreg]=bv(0x8864298f if shift==41 else 0x443215)
   else:rr[15 if name=='decode'else 11]=bv(961)
   g=fresh(name,'shape_'+hex(a),rr,a=a,end=end)
   quo=f'((_ extract 31 0) (bvlshr (bvmul {z("VALUE")} {bv(0x8864298f if shift==41 else 0x443215)}) {bv(shift)}))'if mreg else'(bvudiv VALUE #x000003c1)'
   cert('source_scratch_remainder_shape_'+hex(a),g,[neq(g.get(out),f'(bvsub VALUE (bvmul {quo} #x000003c1))')])
 qnat='(bvor ((_ zero_extend 24) (bvxor B0 #x74)) (bvshl ((_ zero_extend 24) (bvxor B1 #x74)) #x00000004))'
 un='((_ zero_extend 24) (bvxor B0 #x74))'
 domains={'xor':['(bvult ARG #x00000100)','(bvult NIB #x00000010)','(bvult (bvxor B0 #x74) #x10)','(bvult (bvxor B1 #x74) #x10)'],'decode':['(bvult ARG #x00000010)','(bvult (bvxor B0 #x74) #x10)'],'encode':['(bvult ARG #x00000010)','(bvult NIB #x00000010)']}
 loads={'xor':{'0x100d5e294':('B0',8),'0x100d5e2a0':('B1',8),'0x100d5e2cc':('YBYTE',8),'0x100d5e2fc':('B2',8),'0x100d5e31c':('TABLE',64),'0x100d5e320':('FN',64)},'decode':{'0x100d9e07c':('B0',8),'0x100d9e0e0':('YBYTE',8),'0x100d9e10c':('TABLE',64),'0x100d9e110':('FN',64)},'encode':{'0x100d03ca4':('YBYTE',8),'0x100d03cdc':('B2',8),'0x100d03d04':('TABLE',64),'0x100d03d08':('FN',64)}}
 ptr=lambda bank,idx:f'(bvadd {frame(0xd10)} ((_ zero_extend 48) {lookup(bank,idx,16)}))'
 for name in ['xor','decode','encode']:
  rr={**shared,**({12:z('ARG')}if name=='xor'else{11:z('ARG')}if name=='decode'else{12:z('ARG'),13:bv(0xa0fd)})}
  g=Engine({**{j:'Z'+str(j)for j in range(31)},'sp':'K',**rr},loads[name],namespace=name+'_step_');g.declarations='';ii=fs[name]['instructions'][:-1];groups=GROUPS[name];starts={row[0]:row for row in groups};ends={row[1]-4:row for row in groups};source_num={};image_num=None;cc=domains[name]
  for i in ii:
   pc=int(i['ea'],16)
   if pc in starts:
    a,end,num,out,idx,base,bank,mreg,shift=starts[pc];terms=[neq(g.get(num),f'(bvadd {bv(base,32)} (bvmul {idx} #x00000362))')]
    terms+=[neq(g.get('w'+str(mreg)),bv(0x8864298f if shift==41 else 0x443215,32)),neq(g.get('w19'),bv(961,32))]if mreg else[neq(g.get('w15'if name=='decode'else'w11'),bv(961,32))]
    cert(name+'_live_scratch_numerator_'+hex(pc),g,terms,cc);source_num[pc]=g.get(num)
   if pc in [0x100d5e2bc,0x100d9e09c]:
    arg=qnat if name=='xor'else un;mask=0x1f if name=='xor'else 10;bias=0x68c4 if name=='xor'else 0x6135;reg='w14'if name=='xor'else'w16';image_num=g.get(reg)
    cert(name+'_live_image_numerator',g,[neq(image_num,f'(bvadd (bvmul (bvxor {arg} {bv(mask,32)}) #x0000002d) {bv(bias,32)})'),neq(g.get('w23'),bv(0x469f,32)),neq(g.get('w24'),bv(928,32))],cc)
   g.run({'instructions':[i]},pc+4)
   if pc in ends:
    a,end,num,out,idx,base,bank,mreg,shift=ends[pc];cases=[]
    for j in range(len(bank)):
     n=base+866*j;quo=(n*(0x8864298f if shift==41 else 0x443215))>>shift if mreg else n//961;rem=n-quo*961
     assert 0<=n<2**32 and quo==n//961 and rem==bank[j];cases.append({'index':j,'numerator':n,'quotient':quo,'remainder':rem})
    value=f'((_ zero_extend 16) {lookup(bank,idx,16)})';addresses.append({'routine':name,'quotient_site':hex(a),'remainder_site':i['ea'],'source_numerator':source_num[a],'source_remainder':g.get(out),'replacement':value,'cases':cases});g.put(out,value)
   if pc in [0x100d5e2c4,0x100d9e0a4]:
    reg='w14'if name=='xor'else'w16';arg=qnat if name=='xor'else un
    want=f'(bvsub {image_num} (bvmul (bvlshr (bvmul {image_num} #x0000469f) #x00000018) #x000003a0))'
    cert(name+'_source_image_remainder',g,[neq(g.get(reg),want)],cc);replacement=f'((_ zero_extend 16) {lookup([v["offset"]for v in image_cases[name]],arg,16)})'
    cuts.append({'routine':name,'site':i['ea'],'original_expression':g.get(reg),'replacement':replacement,'justification':'source live numerator and quotient shape plus restricted integer theorem and exhaustive finite image offsets'});g.put(reg,replacement)
   if pc==0x100d5e2d8:
    want=f'(bvand (bvxor (bvxor ((_ zero_extend 24) YBYTE) {qnat}) #x0000004d) #x000000ff)';cert('xor_source_image_decoder',g,[neq(g.get('w13'),want)],cc)
    cuts.append({'routine':name,'site':i['ea'],'original_expression':g.get('w13'),'replacement':'NIB','actual_value':'Kxor(P_inverse(x),P_inverse(y))','justification':'source decoder,image address and all256 pinned image cases;NIB is bounded to0..15'});g.put('w13','NIB')
   if pc==0x100d03cb4:
    cert('encode_source_image_decoder',g,[neq(g.get('w10'),f'(bvxor (bvxor ARG #x000000b1) ((_ zero_extend 24) YBYTE))'),neq(rd(g,0x100d03ca4)['address'],f'(bvadd {bv(0x100f4a640)} (bvmul {z("(bvxor ARG #x0000000a)")} {bv(45)}))')],cc)
    cuts.append({'routine':name,'site':i['ea'],'original_expression':g.get('w10'),'replacement':'NIB','actual_value':'L(ARG)','justification':'source direct image address/decoder and all16 pinned image cases'});g.put('w10','NIB')
  models[name+'_step']=g
  if name=='xor':
   terms=[neq(rd(g,0x100d5e294)['address'],ptr(BB,'(bvand ARG #x0000000f)')),neq(rd(g,0x100d5e2a0)['address'],ptr(BB,'(bvlshr ARG #x00000004)')),neq(rd(g,0x100d5e2cc)['address'],f'(bvadd {bv(0x100f4a640)} ((_ zero_extend 48) {lookup([v["offset"]for v in image_cases[name]],qnat,16)}))'),neq(rd(g,0x100d5e2fc)['address'],ptr(AA,'NIB')),neq(st(g,0x100d5e308)['address'],ptr(EE,'ARG')),neq(st(g,0x100d5e308)['value'],'B2'),neq(g.get('w12'),'(bvadd ARG #x00000001)'),neq(g.get('w11'),bv(0,32)),neq(rd(g,0x100d5e320)['address'],f'(ite (= ARG #x000000ff) {at(0x84e8)} {at(0x853e)})')]
  elif name=='decode':
   x='((_ zero_extend 24) B0)';word=f'(bvxor (bvxor (bvsub (bvxor {x} #x00000032) #x00000074) (bvsub (bvxor {x} #x00000005) #x00000043)) (bvsub (bvxor {x} #x0000004d) #x0000000b))';expected=f'((_ extract 7 0) (bvxor (bvxor (bvadd {word} #x0000003b) ((_ zero_extend 24) YBYTE)) #x77777777))'
   terms=[neq(rd(g,0x100d9e07c)['address'],ptr(BB,'ARG')),neq(rd(g,0x100d9e0e0)['address'],f'(bvadd {bv(0x100f4a640)} ((_ zero_extend 48) {lookup([v["offset"]for v in image_cases[name]],un,16)}))'),neq(st(g,0x100d9e0f4)['address'],ptr(HH,'ARG')),neq(st(g,0x100d9e0f4)['value'],expected),neq(g.get('w11'),'(bvadd ARG #x00000001)'),neq(g.get('w12'),bv(0,32)),neq(g.get('w13'),bv(0xa0fd,32)),neq(rd(g,0x100d9e110)['address'],f'(ite (= ARG #x0000000f) {at(0xb43f)} {at(0x84e8)})')]
  else:
   terms=[neq(rd(g,0x100d03cdc)['address'],ptr(AA,'NIB')),neq(st(g,0x100d03cf0)['address'],ptr(II,'ARG')),neq(st(g,0x100d03cf0)['value'],'B2'),neq(g.get('w12'),'(bvadd ARG #x00000001)'),neq(g.get('w13'),bv(0xa0fd,32)),neq(rd(g,0x100d03d08)['address'],f'(ite (= ARG #x0000000f) {at(0xa0fd)} {at(0xa102)})')]
  cert(name+'_complete_source_step_IO_control_and_root',g,terms+[neq(g.get('x26'),frame(0xd10)),neq(g.get('x9'),bv(0x100f4a640))],cc)
  assert len(g.stores)==1 and g.stores[0]['width_bits']==8
  assert sum(v['width_bits']==8 for v in g.reads)==(4 if name=='xor'else 2)
  keep=[3,5,6,7,9,19,20,21,23,24,25,26,30]+([8,10]if name in ['xor','decode']else[13])
  for k in keep:assert not{p+str(k)for p in ['w','x']}&set(s['register_write_sets'][name]),(name,k)
  invariants[name]=keep
  solve(name+'_domain_nonempty','',result='sat',cc=cc)
 # Gate reads both values before replacing the saved state word and phase.
 g=fresh('gate','gate_step',{13:bv(0xa0fd)},loads={'0x100d69da0':('SIZE',32),'0x100d69da4':('VALUE',32),'0x100d69dd8':('TABLE',64),'0x100d69ddc':('FN',64)})
 terms=[neq(rd(g,0x100d69da0)['address'],frame(0x728)),neq(rd(g,0x100d69da4)['address'],frame(0x738)),neq(st(g,0x100d69dc0)['address'],frame(0x730)),neq(st(g,0x100d69dc0)['value'],bv(0x4923,32)),neq(st(g,0x100d69de8)['address'],frame(0x738)),neq(st(g,0x100d69de8)['value'],bv(0x34c96b7f,32)),neq(rd(g,0x100d69ddc)['address'],f'(ite (= SIZE VALUE) {at(0x828b)} {at(0x8284)})'),neq(g.get('w8'),bv(0x424f,32))]
 gate_regs={0:0x489e39cd,1:0xd162ee7d,2:0xebe8aefd,10:0xa4725909,11:0xb26f34a3,12:0x1e82fbe4,13:0x117805e7}
 cert('gate_reads_old_words_selects_before_stores_and_sets_outgoing_ABI',g,terms+[neq(g.get('w'+str(k)),bv(v,32))for k,v in gate_regs.items()]);assert len(g.stores)==2 and all(v['width_bits']==32 for v in g.stores)
 solve('gate_equal_domain','(assert (= SIZE VALUE))',result='sat');solve('gate_unequal_domain','(assert (distinct SIZE VALUE))',result='sat')
 banks=AA+BB+CC+DD+EE+HH+II;assert len(banks)==len(set(banks))==832
 protected=set(range(0x2b8,0x2c8))|set(range(0x388,0x390))|set(range(0x568,0x590))|set(range(0x728,0x73c))|set(range(0x740,0x758))|set(range(0x768,0xcf4))|set(range(0x1210,0x1218));assert not{0xd10+v for v in banks}&protected
 for name,bound in [('xor',256),('decode',16),('encode',16)]:
  solve(name+'_strictly_increasing_bounded_loop','(assert (or (bvugt (bvadd ARG #x00000001) '+bv(bound,32)+') (bvule (bvadd ARG #x00000001) ARG)))',cc=['(bvult ARG '+bv(bound,32)+')'])
 records={n:{**m.record(),'source_SSA':m.prefix(),'declarations':m.declarations,'final_registers':m.r}for n,m in models.items()};actual={pc for m in records.values()for pc in m['source_sites']};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected,(expected-actual,actual-expected)
 composition={'input_codebook':'Rin=P composed with L','output_codebook':'Rout=Q composed with L','xor_source':'E(x+16*y)=E0(Q(Kxor(P_inverse(x),P_inverse(y))))','xor_typed':'E(Rin(a)+16*Rin(b))=E0(Rout(a XOR b))','input_decoder':'H(Rin(a))=E0(a)','output_encoder':'I(a)=E0(Rout(a))','E0':'0x74 XOR nibble','E1':'u8(0x74 XOR(nibble<<4))','joint_arithmetic':'Predecessor C/D supply sum/carry for the same Rin/Rout;current E supplies XOR and H/I convert these codebooks to/from ordinary nibble digits','P_equals_Q_proved':False,'native_claim':False,'memory_premises':'valid coherent nonwrapping private frame,initialized A/B,stable original image root/data,no external mutation;all832 bank cells distinct','induction':'each writer starts at0,increments once,branches back before its exact bound and writes each distinct destination once,preserving all input and prior destination banks'}
 sem={'source_models':records,'source_nonbranch_sites_translated':len(actual),'invariant_registers':invariants,'scratch_address_certificates':addresses,'source_cuts':cuts,'image_cases':image_cases,'fixed_kernels':kernels,'arithmetic_label_cycle':label,'label_inverse':inv,'XOR_identities':pairs,'packed_encoding_cases':packing,'codebook_composition':composition,'xor_offsets':EE,'input_decoder_offsets':HH,'output_encoder_offsets':II,'all832_bank_cells_disjoint':True,'current_distinct_written_scratch_cells':288,'current_distinct_touched_scratch_cells':320,'scratch_byte_reads':800,'image_byte_reads':288,'scratch_byte_stores':288,'gate_u32_reads':2,'gate_u32_stores':2,'gate_phase_value':'0x4923','gate_state_value':'0x34c96b7f','gate_outgoing_registers':gate_regs,'gate_equal_target':'0x100c7d5dc','gate_unequal_target':'0x100ca1ef8','gate_original_words_read_before_state_replacement':True,'new_written_cells_beyond_old963_view':sorted(0xd10+x for x in EE+HH+II if 0xd10+x>=0x10c3),'saved_accumulator_word_replaced_by_phase_at_gate':True,'Mach_port_emissions':0,'native_reachability_proved':False,'successful_output_publication_proved':False,'standard_cipher_identity_proved':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['xor'].__setitem__('bytes','00'+q['fragments']['xor']['bytes'][2:])),('image_byte',lambda q:q['operation_image'].__setitem__('bytes','00'+q['operation_image']['bytes'][2:])),('wrong_bias',lambda q:q['operation_image'].__setitem__('bias_u64','0x0')),('wrong_gate_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('wrong_decode_entry',lambda q:q['fragments']['decode'].__setitem__('start','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s)
 counts={**s['verified_source_counts'],'queries_unsat':sum(v['result']=='unsat'for v in pp),'queries_sat':sum(v['result']=='sat'for v in pp),'predecessor_queries_replayed':sum(v.get('replayed_query',False)for v in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'scratch_address_certificates':len(sem['scratch_address_certificates']),'finite_scratch_address_cases':sum(len(v['cases'])for v in sem['scratch_address_certificates']),'image_cases':288,'XOR_identities':256,'decoder_identities':16,'encoder_identities':16,'packed_encoding_identities':256,'scratch_cells_written':288,'scratch_cells_touched':320,'scratch_byte_store_operations':288,'scratch_byte_reads':800,'image_byte_reads':288,'total_byte_reads':1088,'total_disjoint_bank_cells':832,'gate_u32_reads':2,'gate_u32_stores':2,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','recover_daemon_mode_one_record_adder.py','validate_daemon_mode_one_record_adder.py','validate_daemon_mode_one_record_permutation.py','validate_daemon_mode_one_inverse_tables.py','validate_daemon_mode_one_scatter.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py']+DEPS
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'record_XOR_codecs_and_count_gate_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
