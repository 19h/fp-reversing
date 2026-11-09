#!/usr/bin/env python3
"""Source-bound forward swaps,inverse construction and reset; no target run."""
import copy,json,shutil,subprocess
from recover_daemon_mode_one_record_permutation import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_scatter import Engine
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,at,frame
from validate_daemon_mode_one_record_passes import EXTRA as PARENT_DECL
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=PARENT_DECL+''.join(f'(declare-fun SEL{j} () (_ BitVec 32))\n'for j in range(15))
AA=[(0xbd700+866*j)%961 for j in range(16)]
BB=[(0xaed96+866*j)%961 for j in range(16)]
# stage: source range,input,divisor,multiplier,shift,output,carried constants
DIVS={1:(0x100dcfa84,0x100dcfa94,'w28',15,0x88888889,35,'w17',{17:0x88888889}),2:(0x100dcfa20,0x100dcfa3c,'w14',14,0x92492493,34,'w1',{}),3:(0x100dcfb44,0x100dcfb5c,'w13',13,0x4ec4ec4f,34,'w2',{}),4:(0x100dcfbac,0x100dcfbbc,'w17',12,0xaaaaaaab,35,'w1',{23:0xaaaaaaab}),5:(0x100dcfc00,0x100dcfc14,'w2',11,0xba2e8ba3,35,'w1',{8:11}),6:(0x100dcfc78,0x100dcfc8c,'w15',10,0xcccccccd,35,'w0',{8:0xcccccccd}),7:(0x100dcfcbc,0x100dcfcd4,'w13',9,0x38e38e39,33,'w3',{}),9:(0x100dcfd44,0x100dcfd6c,'w17',7,0x24924925,32,'w17',{}),10:(0x100dcfdc8,0x100dcfdd8,'w15',6,0xaaaaaaab,34,'w1',{23:0xaaaaaaab}),11:(0x100dcfe04,0x100dcfe14,'w14',5,0xcccccccd,34,'w1',{8:0xcccccccd}),13:(0x100dcfe84,0x100dcfe94,'w13',3,0xaaaaaaab,33,'w13',{23:0xaaaaaaab})}
SELECTORS={end-4:(j,out)for j,(_,end,_,_,_,_,out,_)in DIVS.items()}
SELECTORS.update({0x100dcfa1c:(0,'w17'),0x100dcfd3c:(8,'w2'),0x100dcfe48:(12,'w17'),0x100dcfec8:(14,'w14')})
# quotient start,remainder,source numerator,stage,result,extra numerator bias
GROUPS=[(0x100dcfa54,0x100dcfa60,'w17',0,'w17',0),(0x100dcfaa4,0x100dcfaac,'w17',1,'w17',0),(0x100dcfad8,0x100dcfae0,'w1',2,'w17',0),(0x100dcfb7c,0x100dcfb84,'w17',3,'w17',0),(0x100dcfbd0,0x100dcfbd8,'w1',4,'w1',0),(0x100dcfc24,0x100dcfc2c,'w3',5,'w3',0),(0x100dcfc64,0x100dcfc6c,'w0',5,'w0',-961),(0x100dcfca0,0x100dcfca8,'w0',6,'w0',0),(0x100dcfce8,0x100dcfcf0,'w15',7,'w0',0),(0x100dcfd78,0x100dcfd80,'w0',8,'w0',0),(0x100dcfda0,0x100dcfda8,'w17',9,'w17',0),(0x100dcfdec,0x100dcfdf4,'w17',10,'w17',0),(0x100dcfe28,0x100dcfe30,'w0',11,'w0',0),(0x100dcfe60,0x100dcfe68,'w17',12,'w17',0),(0x100dcfeb0,0x100dcfeb8,'w13',13,'w13',0),(0x100dcfee0,0x100dcfee8,'w13',14,'w13',0)]
SWAPS=[(0x100dcfa64,0x100dcfa6c,0x100dcfa70,0x100dcfa74),(0x100dcfa94,0x100dcfab4,0x100dcfac4,0x100dcfad4),(0x100dcfb64,0x100dcfb60,0x100dcfb68,0x100dcfb6c),(0x100dcfb90,0x100dcfb8c,0x100dcfbbc,0x100dcfbc0),(0x100dcfbf4,0x100dcfbe0,0x100dcfbf8,0x100dcfbfc),(0x100dcfc34,0x100dcfc38,0x100dcfc40,0x100dcfc80),(0x100dcfc90,0x100dcfcb0,0x100dcfcb8,0x100dcfcd8),(0x100dcfd14,0x100dcfd08,0x100dcfd18,0x100dcfd40),(0x100dcfd5c,0x100dcfd88,0x100dcfd8c,0x100dcfd9c),(0x100dcfdac,0x100dcfdc0,0x100dcfdc4,0x100dcfdd8),(0x100dcfde8,0x100dcfdfc,0x100dcfe00,0x100dcfe14),(0x100dcfe18,0x100dcfe38,0x100dcfe3c,0x100dcfe40),(0x100dcfe6c,0x100dcfe94,0x100dcfe98,0x100dcfe9c),(0x100dcfeac,0x100dcfec0,0x100dcfec4,0x100dcfed4),(0x100dcfedc,0x100dcfef0,0x100dcfef4,0x100dcfef8)]
def lookup(values,expr,w=32):
 out=bv(values[-1],w)
 for j in reversed(range(len(values)-1)):out=f'(ite (= {expr} {bv(j,w)}) {bv(values[j],w)} {out})'
 return out
def selected(j):return f'(bvsub #x0000000f SEL{j})'if j==14 else f'(bvadd {bv(j,32)} SEL{j})'
def certificates(s):
 pp=[];models={};fs=s['fragments'];abstractions=[];addresses=[];finite=[]
 def solve(name,body,result='unsat',conditions=(),integer=False,arrays=False,extra=''):
  q='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_ABV'if arrays else'QF_BV')+')\n'+('(declare-fun XI () Int)\n'if integer else DECL+EXTRA)+extra+body+'\n'+''.join('(assert '+c+')\n'for c in conditions)+'(check-sat)\n';r=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20)
  if r.returncode or r.stderr or r.stdout.strip()!=result:__import__('pathlib').Path('/tmp/fp-record-permutation-failed.smt2').write_text(q)
  assert not r.returncode and not r.stderr and r.stdout.strip()==result,(name,r.stdout,r.stderr);pp.append({'name':name,'query':q,'result':result,'scope':SCOPE});print(name,result,flush=True)
 def pre(g):return g.declarations+g.prefix()
 def cert(name,g,terms,cc=()):solve(name,pre(g)+'(assert (or '+' '.join(terms)+'))',conditions=cc)
 def rd(g,pc):return next(v for v in g.reads if v['site']==hex(pc))
 def st(g,pc):return next(v for v in g.stores if v['site']==hex(pc))
 def make(n,label,r=None,loads=None,a=None,end=None):
  f=fs[n];a=a or int(f['start'],16);end=end or int(f['instructions'][-1]['ea'],16);ii=[i for i in f['instructions']if a<=int(i['ea'],16)<end];ll=dict(loads or{});dd=[]
  for i in ii:
   if i['mnemonic']in ['ldr','ldrb']and i['ea']not in ll:
    w=8 if i['mnemonic']=='ldrb'else 32 if i['operands'].startswith('w')else 64;name=label+'_L'+str(len(dd));ll[i['ea']]=(name,w);dd.append(f'(declare-fun {name} () (_ BitVec {w}))')
  g=Engine({**{j:'Z'+str(j)for j in range(31)},'sp':'K',**(r or{})},ll,namespace=label+'_');g.declarations='\n'.join(dd)+'\n';g.run({'instructions':ii},end);models[label]=g;return g
 from recover_daemon_mode_one_record_passes import build as previous_build
 old=previous_build();assert old==json.loads(read(ROOT/DEPS[0]));prior=json.loads(read(ROOT/DEPS[1]));assert prior['all_checks_pass']and prior['generator_sha256']==sha(ROOT/'validate_daemon_mode_one_record_passes.py')
 rr={**{j:'Z'+str(j)for j in range(31)},'sp':'K',7:bv(0xc6e2f0ee),25:bv(0x4d),28:bv(0xcfa97dc6),30:bv(0x41060280),2:bv(0x4923),8:z('VALUE'),26:frame(0xd10),**{j:z('T'+str(k))for k,j in enumerate([9,10,11,12])},**{j:z('S'+str(k))for k,j in enumerate([13,14,15])}}
 parent_ll={'0x100bf2ac4':('TABLE',64),'0x100bf2ac8':('FN',64),'0x100c919dc':('TABLE',64),'0x100c919e0':('FN',64)};seed=Engine(rr,parent_ll,namespace='parent_seed_');seed.declarations='';seed.run(old['fragments']['scatter_seed'],0x100bf2b2c)
 cert('reconstructed_parent_scratch_seed',seed,[neq(seed.get('w16'),bv(0x18be,32)),neq(seed.get('w1'),bv(0x2f1e,32)),neq(seed.get('w5'),bv(961,32)),neq(seed.get('x26'),frame(0xd10))])
 parent_models={'seed':seed};parent_sites=set(seed.sites)
 for label,f,regs,loads in [('length_gate',json.loads(read(ROOT/DEPS[2]))['fragments']['length_gate'],{0:'NODE',12:'PBUF',10:bv(0x4cc6),11:bv(0x4f)},{'0x100bf2d2c':('COUNT',32),'0x100bf2d70':('TABLE',64),'0x100bf2d74':('FN',64)}),('restore',old['fragments']['restore'],{}, {'0x100b088f4':(bv(0x4923,32),32),'0x100b08900':('TABLE',64),'0x100b08904':('FN',64),'0x100b08908':(frame(0xd10),64)})]:
  c=Engine({**{j:'Z'+str(j)for j in range(31)},'sp':'K',**regs},loads,namespace='parent_'+label+'_');c.declarations='';c.run(f,int(f['instructions'][-1]['ea'],16));cert('reconstructed_parent_'+label+'_seed_constants',c,[neq(c.get('w'+str(k)),bv(v,32))for k,v in {2:0x4923,7:0xc6e2f0ee,25:0x4d,28:0xcfa97dc6,30:0x41060280}.items()]);parent_models[label]=c;parent_sites.update(c.sites)
 for j in range(16):
  q=Engine({**seed.r,2:bv(0x7e4ab0b3+j),3:bv(15-j),4:bv(0xbd700+866*j)},parent_ll,namespace='parent_scatter'+str(j)+'_');q.defs=list(seed.defs);q.declarations='';q.run(old['fragments']['scatter'],0x100c919f0);row=st(q,0x100c919c4)
  cert('reconstructed_parent_initialization_'+str(j),q,[neq(row['address'],frame(0xd10+AA[j])),neq(row['value'],bv(0x74^j,8)),neq(q.get('w16'),bv(0x18be,32)),neq(q.get('x26'),frame(0xd10)),neq(rd(q,0x100c919e0)['address'],at(0x2f3b if j==15 else 0x2f1e))]+[neq(q.get('w'+str(n)),'T'+str(k))for k,n in enumerate([9,10,11,12])]+[neq(q.get('w'+str(n)),'S'+str(k))for k,n in enumerate([13,14,15])]);parent_models['scatter'+str(j)]=q;parent_sites.update(q.sites)
 assert len(parent_sites)==138
 excluded_query=next(v['query']for v in prior['proofs']if v['name']=='first_pass_byte_counter_and_unsigned_control')
 excluded={'name':'predecessor_full_first_pass_counter_replay','query_sha256':__import__('hashlib').sha256(excluded_query.encode()).hexdigest(),'observed_result':'unknown','timeout_ms':15000,'accepted_as_proof':False,'needed_scratch_preconditions_independently_reconstructed':True}
 for j,(a,end,src,d,m,shift,out,constants)in DIVS.items():
  g=make('permutation','division'+str(j),{int(src[1:]):z('VALUE'),**{k:bv(v)for k,v in constants.items()}},a=a,end=end);v='(bvlshr VALUE #x00000001)'if j==2 else'VALUE';q=f'((_ extract 31 0) (bvlshr (bvmul {z(v)} {bv(m)}) {bv(shift)}))'
  if j==9:q=f'(bvlshr (bvadd {q} (bvlshr (bvsub VALUE {q}) #x00000001)) #x00000002)'
  cert('source_remainder_shape_'+str(j),g,[neq(g.get(out),f'(bvsub VALUE (bvmul {q} {bv(d,32)}))')])
  if j not in [2,9]:solve('exact_unsigned_division_'+str(d),f'(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (distinct (div (* XI {m}) {1<<shift}) (div XI {d})))',integer=True)
 solve('exact_halved_division14','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (distinct (div (* (div XI 2) 2454267027) 17179869184) (div XI 14)))',integer=True)
 q='(div (* XI 613566757) 4294967296)';solve('exact_corrected_division7',f'(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or (> {q} XI) (>= (+ {q} (div (- XI {q}) 2)) 4294967296) (distinct (div (+ {q} (div (- XI {q}) 2)) 4) (div XI 7))))',integer=True)
 solve('all_selector_remainder_ranges','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or '+' '.join(f'(or (< (- XI (* {d} (div XI {d}))) 0) (>= (- XI (* {d} (div XI {d}))) {d}) (>= (* {d} (div XI {d})) 4294967296))'for d in [3,5,6,7,9,10,11,12,13,14,15])+'))',integer=True)
 # Named loads are independent byte inputs here. A separate coherent-memory
 # theorem composes the source read/write pairs,including aliasing self swaps.
 f=fs['permutation'];ll={};dd=[]
 for i in f['instructions'][:-1]:
  if i['mnemonic']in ['ldr','ldrb']:
   w=8 if i['mnemonic']=='ldrb'else 32 if i['operands'].startswith('w')else 64;n='perm_L'+str(len(dd));ll[i['ea']]=(n,w);dd.append(f'(declare-fun {n} () (_ BitVec {w}))')
 ll['0x100dcfa80']=('VALUE',32);ll['0x100dcfefc']=('TABLE',64)
 g=Engine({**{j:'Z'+str(j)for j in range(31)},'sp':'K',26:frame(0xd10),16:bv(0x18be),**{j:z('T'+str(k))for k,j in enumerate([9,10,11,12])},**{j:z('S'+str(k))for k,j in enumerate([13,14,15])}},ll,namespace='perm_');g.declarations='\n'.join(dd)+'\n';cc=[];starts={a:(end,num,j,out,bias)for a,end,num,j,out,bias in GROUPS};ends={end:(a,num,j,out,bias)for a,end,num,j,out,bias in GROUPS};snap={}
 for i in f['instructions'][:-1]:
  pc=int(i['ea'],16);snap[pc]=dict(g.r)
  if pc in starts:
   end,num,j,out,bias=starts[pc];want=f'(bvadd {bv(0xbd700+bias,32)} (bvmul {selected(j)} #x00000362))';cert('source_address_numerator_'+hex(pc),g,[neq(g.get(num),want),neq(g.get('w7'),bv(0x443215,32))],cc)
  g.run({'instructions':[i]},pc+4)
  if pc in SELECTORS:
   j,out=SELECTORS[pc];raw=g.get(out)
   if j in [0,8,12,14]:cert('source_mask_selector_range_'+str(j),g,[f'(bvuge {raw} {bv(16-j,32)})'],cc)
   else:
    a,end,src,d,m,shift,output,constants=DIVS[j];assert output==out and d==16-j
    if constants:
     probe=Engine(snap[a],namespace='probe_');probe.defs=list(g.defs);probe.declarations=g.declarations;cert('source_carried_division_constants_'+str(j),probe,[neq(probe.get('w'+str(k)),bv(v,32))for k,v in constants.items()],cc)
   abstractions.append({'stage':j,'site':i['ea'],'source_value':raw,'replacement':'SEL'+str(j),'upper_exclusive':16-j,'source_justification':'source mask-range certificate'if j in [0,8,12,14]else'source remainder shape plus exact quotient/range certificates','independent_native_reachability_claim':False});g.put(out,'SEL'+str(j));cc.append(f'(bvult SEL{j} {bv(16-j,32)})')
  if pc in ends:
   a,num,j,out,bias=ends[pc];expect=lookup(AA,selected(j));cert('source_address_remainder_'+hex(pc),g,[neq(g.get(out),expect),neq(g.get('w19'),bv(961,32))],cc);cases=[]
   for k in range(16-j):
    pos=15-k if j==14 else j+k;n=0xbd700+bias+866*pos;q=(n*0x443215)>>32;assert n-q*961==AA[pos]and q==n//961;cases.append({'selector':k,'position':pos,'numerator':n,'quotient':q,'remainder':AA[pos]})
   addresses.append({'quotient_site':hex(a),'remainder_site':i['ea'],'stage':j,'numerator_bias':bias,'source_remainder':g.get(out),'replacement':expect,'cases':cases});g.put(out,expect)
 models['permutation']=g;terms=[];swaps=[]
 for j,(fr,sr,fw,sw)in enumerate(SWAPS):
  a,b,c,d=rd(g,fr),rd(g,sr),st(g,fw),st(g,sw);fixed=frame(0xd10+AA[j]);terms.extend([neq(a['address'],fixed),neq(c['address'],fixed),neq(c['value'],b['input']),neq(d['address'],b['address']),neq(d['value'],a['input']),'(and '+' '.join(neq(b['address'],frame(0xd10+x))for x in AA[j:])+')']);assert max(fr,sr)<min(fw,sw)
  swaps.append({'stage':j,'fixed_frame_offset':0xd10+AA[j],'read_fixed':hex(fr),'read_selected':hex(sr),'write_fixed':hex(fw),'write_selected':hex(sw),'possible_selected_positions':list(range(j,16)),'both_reads_precede_both_writes':True})
  for k in range(j,16):
   labels=list(range(16));labels[j],labels[k]=labels[k],labels[j];assert sorted(labels)==list(range(16));finite.append({'stage':j,'selected_position':k,'labels':labels})
 tail={13:0x6c46a5eb,16:0x18be,6:0xbd700,5:866,3:0xb90e920a,4:0x8864298f,19:961,8:0x84c}
 terms.extend(neq(g.get('w'+str(k)),bv(v,32))for k,v in tail.items());terms.extend([neq(rd(g,0x100dcff00)['address'],at(0x18be)),neq(g.get('x26'),frame(0xd10))]);terms.extend(neq(g.get('w'+str(j)),'T'+str(k))for k,j in enumerate([9,10,11,12]));cert('all15_source_swaps_and_inverse_entry_ABI',g,terms,cc);assert len(g.stores)==30 and sum(v['width_bits']==8 for v in g.reads)==30
 ir={**{j:bv(v)for j,v in tail.items()},26:frame(0xd10),**{j:z('T'+str(k))for k,j in enumerate([9,10,11,12])}}
 decoder=make('inverse','inverse_byte_decode',ir,{'0x100c87d08':('B0',8)},end=0x100c87d6c);k32='((_ zero_extend 24) (bvxor B0 #x74))'
 cert('inverse_source_byte_decode',decoder,[neq(decoder.get('w15'),f'(bvadd {k32} #x7fffff8c)')])
 inverse=[];reset=[];byte_domain='(bvult (bvxor B0 #x74) #x10)'
 for j in range(16):
  q=make('inverse','inverse'+str(j),{**ir,13:bv(0x6c46a5eb+j)},{'0x100c87d08':('B0',8),'0x100c87ddc':('TABLE',64),'0x100c87de0':('FN',64)});row=st(q,0x100c87dc8);assert len(q.stores)==1 and row['width_bits']==8 and sum(v['width_bits']==8 for v in q.reads)==1
  cert('inverse_source_iteration_'+str(j),q,[neq(rd(q,0x100c87d08)['address'],frame(0xd10+AA[j])),neq(row['address'],f'(bvadd {frame(0xd10)} {z(lookup(BB,k32))})'),neq(row['value'],bv(0x74^j,8)),neq(q.get('w13'),bv(0x6c46a5ec+j,32)),neq(q.get('w14'),bv(0x18cc,32)),neq(q.get('w15'),bv(0x82d657e,32)),neq(rd(q,0x100c87de0)['address'],at(0x18cc if j==15 else 0x18be))]+[neq(q.get('w'+str(n)),'T'+str(k))for k,n in enumerate([9,10,11,12])],[byte_domain])
  inverse.append({'iteration':j,'read_frame_offset':0xd10+AA[j],'write_bank_offsets':BB,'decoded_position':'u8(input_byte XOR0x74)','value_u8':0x74^j,'read_site':'0x100c87d08','write_site':row['site'],'all_sixteen_input_byte_codes_checked_by_domain':True})
  r=make('reset','reset'+str(j),{**ir,14:bv(0x18cc),15:bv(0x82d657e+j)},{'0x100d86a48':('TABLE',64),'0x100d86a4c':('FN',64)});row=st(r,0x100d86a24);assert len(r.stores)==1 and row['width_bits']==8 and not any(v['width_bits']==8 for v in r.reads)
  cert('reset_source_iteration_'+str(j),r,[neq(row['address'],frame(0xd10+AA[j])),neq(row['value'],bv(0x74^j,8)),neq(r.get('w15'),bv(0x82d657f+j,32)),neq(rd(r,0x100d86a4c)['address'],at(0x768d if j==15 else 0x18cc))]+[neq(r.get('w'+str(n)),'T'+str(k))for k,n in enumerate([9,10,11,12])])
  reset.append({'iteration':j,'frame_offset':0xd10+AA[j],'value_u8':0x74^j,'write_site':row['site']})
 # Source swap writes are composed with coherent memory,not independent reads.
 swap_mem='(declare-fun MEM () (Array (_ BitVec 64) (_ BitVec 8)))\n(define-fun SWAPPED () (Array (_ BitVec 64) (_ BitVec 8)) (store (store MEM A (select MEM U)) U (select MEM A)))\n'
 solve('coherent_swap_including_self_alias','(assert (or (distinct (select SWAPPED A) (select MEM U)) (distinct (select SWAPPED U) (select MEM A)) (and (distinct O A) (distinct O U) (distinct (select SWAPPED O) (select MEM O)))))',arrays=True,extra=swap_mem)
 assert len(AA)==len(set(AA))==len(BB)==len(set(BB))==16 and not set(AA)&set(BB)
 mem='(declare-fun MEM () (Array (_ BitVec 64) (_ BitVec 8)))\n(declare-fun PERM () (Array (_ BitVec 4) (_ BitVec 4)))\n'
 for name,bank in [('A_CELL',AA),('B_CELL',BB)]:
  addr=frame(0xd10+bank[-1])
  for j in range(14,-1,-1):addr=f'(ite (= J {bv(j,4)}) {frame(0xd10+bank[j])} {addr})'
  mem+=f'(define-fun {name} ((J (_ BitVec 4))) (_ BitVec 64) {addr})\n'
 ps=[f'(select PERM {bv(j,4)})'for j in range(16)];mem+='(assert (distinct '+' '.join(ps)+'))\n';last='MEM';claims=[]
 for j,pj in enumerate(ps):
  enc=f'(bvxor #x74 ((_ zero_extend 4) {pj}))';mem+=f'(assert (= (select MEM (A_CELL {bv(j,4)})) {enc}))\n';claims.append(neq(f'(select {last} (A_CELL {bv(j,4)}))',enc));n='INV'+str(j);mem+=f'(define-fun {n} () (Array (_ BitVec 64) (_ BitVec 8)) (store {last} (B_CELL {pj}) {bv(0x74^j,8)}))\n';last=n
 inverse_final=last
 for j,pj in enumerate(ps):claims.append(neq(f'(select {last} (B_CELL {pj}))',bv(0x74^j,8)))
 for j in range(16):
  n='RESET'+str(j);mem+=f'(define-fun {n} () (Array (_ BitVec 64) (_ BitVec 8)) (store {last} (A_CELL {bv(j,4)}) {bv(0x74^j,8)}))\n';last=n
 for j,pj in enumerate(ps):claims.extend([neq(f'(select {last} (A_CELL {bv(j,4)}))',bv(0x74^j,8)),neq(f'(select {last} (B_CELL {pj}))',bv(0x74^j,8))])
 outside='(and '+' '.join(neq('O',frame(0xd10+x))for x in AA+BB)+')';claims.append(f'(and {outside} {neq(f"(select {last} O)","(select MEM O)")})')
 excluded_mem_query='(set-option :timeout 15000)\n(set-logic QF_ABV)\n'+DECL+EXTRA+mem+'(assert (or '+' '.join(claims)+'))\n(check-sat)\n'
 excluded_mem={'name':'monolithic_coherent_inverse_then_forward_reset','query_sha256':__import__('hashlib').sha256(excluded_mem_query.encode()).hexdigest(),'query':excluded_mem_query,'observed_result':'unknown','timeout_ms':15000,'accepted_as_proof':False,'replaced_by':'universal single-cell and commuting-store lemmas,finite bank layouts,source iteration contracts and explicit bijection induction'}
 cell='(declare-fun MEM () (Array (_ BitVec 64) (_ BitVec 8)))\n(define-fun WRITTEN () (Array (_ BitVec 64) (_ BitVec 8)) (store MEM U B0))\n'
 solve('coherent_inverse_or_reset_single_cell_store','(assert (or (distinct (select WRITTEN U) B0) (and (distinct A U) (distinct (select WRITTEN A) (select MEM A)))))',arrays=True,extra=cell)
 commute='(declare-fun MEM () (Array (_ BitVec 64) (_ BitVec 8)))\n'
 solve('disjoint_inverse_and_reset_stores_commute','(assert (distinct (store (store MEM A B0) U B1) (store (store MEM U B1) A B0)))',conditions=['(distinct A U)'],arrays=True,extra=commute)
 solve('index_byte_encoding_is_bijective_on16','(assert (or (distinct ((_ zero_extend 24) ((_ extract 7 0) (bvxor IX #x00000074))) (bvxor IX #x00000074)) (distinct (bvxor (bvxor IX #x00000074) #x00000074) IX) (bvult (bvxor IX #x00000074) #x00000070) (bvugt (bvxor IX #x00000074) #x0000007f)))',conditions=['(bvult IX #x00000010)'])
 for row in finite:
  inverse_labels=[None]*16
  for i,k in enumerate(row['labels']):inverse_labels[k]=i
  assert sorted(inverse_labels)==list(range(16))and all(inverse_labels[row['labels'][i]]==i for i in range(16));row['inverse_labels']=inverse_labels
 induction={'base':'nineteen reconstructed predecessor-source obligations establish sixteen distinct A cells with byte74 XOR index;all other scratch cells need no invented initialization','permutation_step':'each of fifteen source-certified forward swaps is a coherent transposition,including self alias;135 finite transpositions preserve a bijection P on sixteen positions','inverse_step':'at iteration i,the source reads A(i)=encode(P(i)) and writes encode(i) to B(P(i));disjoint banks preserve all future A reads and bijective P prevents overwriting earlier inverse entries','inverse_completion':'sixteen distinct P(i) in a sixteen-element set cover the whole set;the bank contains the complete inverse of P','reset_step':'sixteen source-certified A(i)=encode(i) stores preserve every B cell by bank disjointness and the universal store lemma','conclusion':'A is the identity encoding and B is the encoded inverse of the first permutation;second accumulator bank and all cells outside A/B are preserved','native_distribution_or_reachability_claim':False}

 protected=[*range(0x2b8,0x2c8),*range(0x388,0x390),*range(0x728,0x73c),*range(0x748,0x758),*range(0x768,0xcf4)];assert not {0xd10+x for x in AA+BB}&set(protected);assert all(0xd00<=0xd10+x<0x10c3 for x in AA+BB)
 for n,f in fs.items():
  for reg in [9,10,11,12,26]:assert not {prefix+str(reg)for prefix in ['x','w']}&set(s['register_write_sets'][n]),(n,reg)
 solve('abstract_selector_domain_nonempty','',result='sat',conditions=cc)
 solve('valid_inverse_byte_domain_nonempty','',result='sat',conditions=[byte_domain])
 solve('wrong_full_byte_inverse_domain_counterexample','(assert (bvuge (bvxor B0 #x74) #x10))',result='sat')
 records={n:{**q.record(),'source_SSA':q.prefix(),'declarations':q.declarations,'final_registers':q.r}for n,q in models.items()};actual={pc for m in records.values()for pc in m['source_sites']};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected
 sem={'source_models':records,'predecessor_scratch_source_models':{n:{**q.record(),'source_SSA':q.prefix(),'final_registers':q.r}for n,q in parent_models.items()},'predecessor_scratch_nonbranch_sites_translated':len(parent_sites),'reconstructed_predecessor_queries':19,'excluded_solver_attempts':[excluded,excluded_mem],'coherent_memory_induction':induction,'source_nonbranch_sites_translated':len(actual),'source_selector_abstractions':abstractions,'source_address_certificates':addresses,'swap_ledger':swaps,'finite_transpositions':finite,'forward_offsets_in_961_view':AA,'inverse_offsets_in_961_view':BB,'forward_initial_bytes':[0x74^j for j in range(16)],'byte_encoder':'0x74 XOR index','inverse_byte_source_decoder':'u32(zero_extend(input_byte XOR0x74)+0x7fffff8c)','inverse_numerator_base':'0xaed96','inverse_ledger':inverse,'reset_ledger':reset,'banks_disjoint':True,'distinct_cells_touched':32,'source_store_operations':62,'source_byte_reads':46,'source_stage5_read_write_numerator_difference':961,'source_last_swap_selected_position':'15-(live W14 AND1)','second_bank_W9_W12_preserved':True,'F730_preserved':True,'frame_roots_and_prior_workspace_preserved':True,'first_shuffle_structure':'forward Fisher-Yates transpositions;distribution/reachability of all permutations unproved','inverse_contract':'B(P(i))=0x74 XOR i for forward A(i)=0x74 XOR P(i)','after_reset_contract':'A(i)=0x74 XOR i;inverse B retained','permutation_composition_premises':'prior16-cell initialization,source-bound bounded selectors,coherent stable writable nonwrapping private frame,bijective forward index map and disjoint A/B layouts','Mach_port_emissions':0,'next_frontier':'0x100d09004','next_frontier_second_bank_preserved':True,'bank_equality_proved':False,'algorithm_identity_proved':False,'native_reachability_proved':False,'successful_output_publication_proved':False,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['permutation'].__setitem__('bytes','00'+q['fragments']['permutation']['bytes'][2:])),('inverse_read_offset',lambda q:q['fragments']['inverse']['instructions'][5].__setitem__('operands','w17, [x26, #1]')),('inverse_target',lambda q:q['branch_edges'][1].__setitem__('target','0x0')),('reset_target',lambda q:q['branch_edges'][-1].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(v['result']=='unsat'for v in pp),'queries_sat':sum(v['result']=='sat'for v in pp),'predecessor_queries_replayed':sum(v.get('replayed_query',False)for v in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'reconstructed_predecessor_queries':19,'predecessor_scratch_nonbranch_sites_translated':138,'selector_abstractions':len(sem['source_selector_abstractions']),'address_certificates':len(sem['source_address_certificates']),'finite_address_cases':sum(len(v['cases'])for v in sem['source_address_certificates']),'source_swaps':len(sem['swap_ledger']),'finite_transpositions':len(sem['finite_transpositions']),'inverse_iterations':16,'reset_iterations':16,'distinct_cells_touched':32,'source_store_operations':62,'source_byte_reads':46,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_scatter.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','validate_daemon_mode_one_record_passes.py','recover_daemon_mode_one_record_passes.py']+DEPS;c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'record_permutation_inverse_and_reset_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
