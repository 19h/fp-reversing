#!/usr/bin/env python3
"""Source-bound forward swaps,inverse construction and reset; no target run."""
import copy,json,shutil,subprocess
from recover_daemon_mode_one_record_adder import ROOT,P,SCOPE,FLAGS,DEPS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_mode_one_inverse_tables import Engine as Parent
from validate_daemon_list_output import split
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,at,frame
from validate_daemon_mode_one_record_permutation import EXTRA as PARENT_DECL
SOLVER=shutil.which('z3');assert SOLVER
EXTRA=PARENT_DECL+''.join(f'(declare-fun {n} () (_ BitVec 32))\n'for n in ['ARG','NIB','CWORD0','CWORD1'])+''.join(f'(declare-fun {n} () (_ BitVec 8))\n'for n in ['LBYTE','RBYTE','YBYTE'])
AA=[(0xbd700+866*j)%961 for j in range(16)]
BB=[(0xaed96+866*j)%961 for j in range(16)]
CC=[(0x77086+866*j)%961 for j in range(256)]
DD=[(0x368c4+866*j)%961 for j in range(256)]
class Engine(Parent):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='ubfx':
    q=split(i['operands']);w=32 if q[0].startswith('w')else 64;lsb,n=int(q[2][1:],0),int(q[3][1:],0);self.put(q[0],f'(bvand (bvlshr {self.get(q[1],w)} {bv(lsb,w)}) {bv((1<<n)-1,w)})');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
DIVS={1:(0x100d09018,0x100d09028,'w9',15,0x88888889,35,'w16',{8:0x88888889}),2:(0x100d09044,0x100d0905c,'w11',14,0x92492493,34,'w1',{24:14}),3:(0x100d090b4,0x100d090c0,'w12',13,0x4ec4ec4f,34,'w0',{8:0x4ec4ec4f,21:13}),4:(0x100d091c4,0x100d091d4,'w16',12,0xaaaaaaab,35,'w1',{8:0xaaaaaaab}),5:(0x100d09180,0x100d09190,'w16',11,0xba2e8ba3,35,'w2',{8:0xba2e8ba3}),6:(0x100d091b0,0x100d091bc,'w1',10,0xcccccccd,35,'w17',{4:0xcccccccd,30:10}),7:(0x100d0923c,0x100d0924c,'w10',9,0x38e38e39,33,'w10',{15:0x38e38e39}),9:(0x100d092f8,0x100d0931c,'w12',7,0x24924925,32,'w12',{}),10:(0x100d09380,0x100d09390,'w11',6,0xaaaaaaab,34,'w12',{8:0xaaaaaaab}),11:(0x100d093b8,0x100d093d0,'w10',5,0xcccccccd,34,'w17',{4:0xcccccccd}),13:(0x100d09440,0x100d09450,'w9',3,0xaaaaaaab,33,'w9',{8:0xaaaaaaab})}
SELECTORS={end-4:(j,out)for j,(_,end,_,_,_,_,out,_)in DIVS.items()}
SELECTORS.update({0x100d0900c:(0,'w15'),0x100d092f4:(8,'w15'),0x100d09408:(12,'w15'),0x100d0947c:(14,'w10')})
GROUPS=[(0x100d09030,0x100d09038,'w15',0,'w15',0),(0x100d09074,0x100d0907c,'w15',1,'w15',0),(0x100d09098,0x100d090a0,'w16',2,'w16',0),(0x100d090e8,0x100d090f0,'w17',3,'w12',0),(0x100d091e8,0x100d091f0,'w15',4,'w15',0),(0x100d09210,0x100d09218,'w15',5,'w15',0),(0x100d0924c,0x100d09254,'w12',6,'w12',0),(0x100d09270,0x100d09278,'w15',6,'w15',0),(0x100d092a4,0x100d092ac,'w10',7,'w10',0),(0x100d09328,0x100d09330,'w15',8,'w15',0),(0x100d09354,0x100d0935c,'w12',9,'w12',0),(0x100d093a0,0x100d093a8,'w12',10,'w12',0),(0x100d093e0,0x100d093e8,'w12',11,'w12',0),(0x100d09430,0x100d09438,'w15',12,'w11',0),(0x100d09464,0x100d0946c,'w9',13,'w9',0),(0x100d09490,0x100d09498,'w9',14,'w9',0)]
SWAPS=[(0x100d0902c,0x100d09040,0x100d0905c,0x100d09060),(0x100d09070,0x100d09084,0x100d09088,0x100d0908c),(0x100d09090,0x100d090a8,0x100d090cc,0x100d090d0),(0x100d090dc,0x100d091a0,0x100d091a4,0x100d091d4),(0x100d091d8,0x100d091f8,0x100d091fc,0x100d09200),(0x100d09208,0x100d09220,0x100d09228,0x100d0922c),(0x100d09280,0x100d09284,0x100d0928c,0x100d09290),(0x100d092a0,0x100d092b4,0x100d092d0,0x100d092d4),(0x100d0933c,0x100d09338,0x100d09340,0x100d09344),(0x100d09368,0x100d09364,0x100d0936c,0x100d0937c),(0x100d09390,0x100d093b0,0x100d093b4,0x100d093d0),(0x100d093ec,0x100d093f4,0x100d093f8,0x100d093fc),(0x100d09400,0x100d09450,0x100d09454,0x100d09458),(0x100d0945c,0x100d09474,0x100d09478,0x100d09488),(0x100d094a4,0x100d094a0,0x100d094a8,0x100d094ac)]
def lookup(values,expr,w=32,index_width=32):
 out=bv(values[-1],w)
 for j in reversed(range(len(values)-1)):out=f'(ite (= {expr} {bv(j,index_width)}) {bv(values[j],w)} {out})'
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
 from recover_daemon_mode_one_record_permutation import build as previous_build
 from validate_daemon_mode_one_record_permutation import certificates as previous_certificates
 old=previous_build();assert old==json.loads(read(ROOT/DEPS[0]));prior=json.loads(read(ROOT/DEPS[1]));bp,bs=previous_certificates(old);assert bp==prior['proofs']and json.loads(json.dumps(bs))==prior['semantics']
 for p in bp:pp.append({**p,'name':'replayed_first_permutation_'+p['name'],'replayed_query':True})
 carried={7:0x443215,20:0xbddc4,21:13,22:0xbe126,23:0xc02fa,24:14,27:0xbe7ea,28:0xbeb4c,30:10}
 pm=bs['source_models']['permutation'];terms=[neq('((_ extract 31 0) '+pm['final_registers'][k]+')',bv(v,32))for k,v in carried.items()];solve('first_permutation_carries_second_shuffle_coefficients',pm['declarations']+pm['source_SSA']+'(assert (or '+' '.join(terms)+'))')
 for n in ['inverse','reset']:
  for k in carried:assert not{prefix+str(k)for prefix in ['x','w']}&set(old['register_write_sets'][n]),(n,k)
 pm=bs['source_models']['reset15'];terms=[neq('((_ extract 31 0) '+pm['final_registers'][13]+')',bv(0x45a6,32)),neq(pm['final_registers'][26],frame(0xd10))]+[neq('((_ extract 31 0) '+pm['final_registers'][j]+')','T'+str(k))for k,j in enumerate([9,10,11,12])];solve('actual_reset_supplies_phase_pointer_and_second_bank',pm['declarations']+pm['source_SSA']+'(assert (or '+' '.join(terms)+'))')
 initial={**{k:bv(v)for k,v in carried.items()},5:bv(866),6:bv(0xbd700),19:bv(961),13:bv(0x45a6),26:frame(0xd10),**{j:z('T'+str(k))for k,j in enumerate([9,10,11,12])}}
 for j,(a,end,src,d,m,shift,out,constants)in DIVS.items():
  g=make('second','division'+str(j),{int(src[1:]):z('VALUE'),**{k:bv(v)for k,v in constants.items()}},a=a,end=end);v='(bvlshr VALUE #x00000001)'if j==2 else'VALUE';q=f'((_ extract 31 0) (bvlshr (bvmul {z(v)} {bv(m)}) {bv(shift)}))'
  if j==9:q=f'(bvlshr (bvadd {q} (bvlshr (bvsub VALUE {q}) #x00000001)) #x00000002)'
  cert('source_remainder_shape_'+str(j),g,[neq(g.get(out),f'(bvsub VALUE (bvmul {q} {bv(d,32)}))')])
  if j not in [2,9]:solve('exact_unsigned_division_'+str(d),f'(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (distinct (div (* XI {m}) {1<<shift}) (div XI {d})))',integer=True)
 solve('exact_halved_division14','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (distinct (div (* (div XI 2) 2454267027) 17179869184) (div XI 14)))',integer=True)
 q='(div (* XI 613566757) 4294967296)';solve('exact_corrected_division7',f'(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or (> {q} XI) (>= (+ {q} (div (- XI {q}) 2)) 4294967296) (distinct (div (+ {q} (div (- XI {q}) 2)) 4) (div XI 7))))',integer=True)
 solve('all_selector_remainder_ranges','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or '+' '.join(f'(or (< (- XI (* {d} (div XI {d}))) 0) (>= (- XI (* {d} (div XI {d}))) {d}) (>= (* {d} (div XI {d})) 4294967296))'for d in [3,5,6,7,9,10,11,12,13,14,15])+'))',integer=True)
 # Named loads are independent byte inputs here. A separate coherent-memory
 # theorem composes the source read/write pairs,including aliasing self swaps.
 f=fs['second'];ll={};dd=[]
 for i in f['instructions'][:-1]:
  if i['mnemonic']in ['ldr','ldrb']:
   w=8 if i['mnemonic']=='ldrb'else 32 if i['operands'].startswith('w')else 64;n='perm_L'+str(len(dd));ll[i['ea']]=(n,w);dd.append(f'(declare-fun {n} () (_ BitVec {w}))')
 ll['0x100d094b0']=('TABLE',64);ll['0x100d094d8']=('CELL',64)
 g=Engine({**{j:'Z'+str(j)for j in range(31)},'sp':'K',**initial},ll,namespace='second_');g.declarations='\n'.join(dd)+'\n';cc=[];starts={a:(end,num,j,out,bias)for a,end,num,j,out,bias in GROUPS};ends={end:(a,num,j,out,bias)for a,end,num,j,out,bias in GROUPS};snap={}
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
 models['second']=g;terms=[];swaps=[]
 for j,(fr,sr,fw,sw)in enumerate(SWAPS):
  a,b,c,d=rd(g,fr),rd(g,sr),st(g,fw),st(g,sw);fixed=frame(0xd10+AA[j]);terms.extend([neq(a['address'],fixed),neq(c['address'],fixed),neq(c['value'],b['input']),neq(d['address'],b['address']),neq(d['value'],a['input']),'(and '+' '.join(neq(b['address'],frame(0xd10+x))for x in AA[j:])+')']);assert max(fr,sr)<min(fw,sw)
  swaps.append({'stage':j,'fixed_frame_offset':0xd10+AA[j],'read_fixed':hex(fr),'read_selected':hex(sr),'write_fixed':hex(fw),'write_selected':hex(sw),'possible_selected_positions':list(range(j,16)),'both_reads_precede_both_writes':True})
  for k in range(j,16):
   labels=list(range(16));labels[j],labels[k]=labels[k],labels[j];assert sorted(labels)==list(range(16));finite.append({'stage':j,'selected_position':k,'labels':labels})
 tail={13:0x45a6,11:0x6031,10:0xaed96,8:0xaed96,4:47,21:45,22:1080,23:0x469f,24:928,27:166,14:0}
 terms.extend(neq(g.get('w'+str(k)),bv(v,32))for k,v in tail.items());terms.extend([neq(rd(g,0x100d094b4)['address'],at(0x45a6)),neq(g.get('x26'),frame(0xd10)),neq(g.get('x0'),bv(0x1010c4000)),neq(g.get('x1'),bv(0x1010a1960)),neq(g.get('x2'),'CELL'),neq(rd(g,0x100d094d8)['address'],frame(0x580))]);cert('all15_second_swaps_and_adder_entry_ABI',g,terms,cc);assert len(g.stores)==30 and sum(v['width_bits']==8 for v in g.reads)==30
 # Exact source quotient shapes and finite immutable-data kernels.
 data={v['role']:v for v in s['data_roots']};left=bytes.fromhex(data['left']['bytes']);right=bytes.fromhex(data['right']['bytes']);op=bytes.fromhex(data['operation']['bytes'])
 assert [j^right[left[j]^0x61]for j in range(256)]==[0x19]*256
 kernels={};image_cases={}
 for name,mask,bias in [('sum',0x1b,1080),('carry',0xfe,0x32a0)]:
  rows=[];values=[]
  for q in range(256):
   n=45*(q^mask)+bias;product=n*0x469f;quotient=product>>24;pos=n-quotient*928;assert product<2**32 and quotient==n//928 and 0<=pos<928;y=op[pos];v=(y^0x8e^(((y<<4)^0x10)-0x50))&255 if name=='sum'else(((y+10)>>4)&15)^6;assert 0<=v<16;values.append(v);rows.append({'argument':q,'encoded_argument':q^mask,'numerator':n,'quotient':quotient,'offset':pos,'image_byte':y,'decoded_nibble':v})
  kernels[name]=values;image_cases[name]=rows
 label=[0]
 for j in range(1,16):label.append(kernels['sum'][label[-1]+16*14])
 assert len(set(label))==16 and kernels['sum'][label[-1]+16*14]==0
 algebra=[]
 for a in range(16):
  for b in range(16):
   q=label[a]+16*label[b];assert kernels['sum'][q]==label[(a+b)%16]and kernels['carry'][q]==label[(a+b)//16];algebra.append({'a':a,'b':b,'source_argument':q,'sum_label':kernels['sum'][q],'carry_label':kernels['carry'][q]})
 assert all(kernels['sum'][kernels['sum'][a+16*b]+16*c]==kernels['sum'][a+16*kernels['sum'][b+16*c]]for a in range(16)for b in range(16)for c in range(16))
 # start,end,numerator,out,index,base,bank,multiplier-register,shift
 TG={'sum':[(0x100b111a4,0x100b111b0,'w12','w12','(bvand ARG #x0000000f)',0xaed96,BB,3,41),(0x100b111b8,0x100b111c4,'w9','w9','(bvlshr ARG #x00000004)',0xaed96,BB,3,41),(0x100b1127c,0x100b11288,'w12','w12','NIB',0xbd700,AA,7,32),(0x100b11294,0x100b112a0,'w16','w16','ARG',0x77086,CC,3,41)],'carry':[(0x100d8b718,0x100d8b724,'w13','w13','(bvand ARG #x0000000f)',0xaed96,BB,3,41),(0x100d8b728,0x100d8b738,'w14','w14','(bvlshr ARG #x00000004)',0xaed96,BB,3,41),(0x100d8b778,0x100d8b784,'w13','w13','NIB',0xbd700,AA,7,32),(0x100d8b794,0x100d8b7a8,'w14','w14','ARG',0x368c4,DD,3,41)]}
 for name,groups in TG.items():
  for a,end,num,out,idx,base,bank,mreg,shift in groups:
   m=0x8864298f if shift==41 else 0x443215;q=make(name,'shape_'+hex(a),{int(num[1:]):z('VALUE'),mreg:bv(m),19:bv(961)},a=a,end=end);qq=f'((_ extract 31 0) (bvlshr (bvmul {z("VALUE")} {bv(m)}) {bv(shift)}))';cert('source_scratch_remainder_shape_'+hex(a),q,[neq(q.get(out),f'(bvsub VALUE (bvmul {qq} #x000003c1))')])
 for name,a,end,num,out in [('sum',0x100b1122c,0x100b11248,9,'w16'),('carry',0x100d8b754,0x100d8b760,13,'w13')]:
  q=make(name,name+'_image_remainder_shape',{num:z('VALUE'),23:bv(0x469f),24:bv(928)},a=a,end=end);cert(name+'_source_image_remainder_shape',q,[neq(q.get(out),'(bvsub VALUE (bvmul (bvlshr (bvmul VALUE #x0000469f) #x00000018) #x000003a0))')])
 solve('unsigned_division961_shift41','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or (distinct (div (* XI 2288265615) 2199023255552) (div XI 961)) (>= (* XI 2288265615) 18446744073709551616)))',integer=True)
 solve('restricted_image_division928_and_product_bound','(assert (and (<= 0 XI) (<= XI 30000)))\n(assert (or (distinct (div (* XI 18079) 16777216) (div XI 928)) (>= (* XI 18079) 4294967296)))',integer=True)
 y32='((_ zero_extend 24) YBYTE)';d0=f'(bvand (bvxor (bvxor {y32} #x0000008e) (bvsub (bvxor (bvshl {y32} #x00000004) #x00000010) #x00000050)) #x000000ff)';d1=f'(bvxor (bvand (bvlshr (bvadd {y32} #x0000000a) #x00000004) #x0000000f) #x00000006)'
 q=make('sum','sum_source_decoder',{12:z(y32)},a=0x100b1125c,end=0x100b11278);cert('sum_source_byte_decoder',q,[neq(q.get('w12'),d0)])
 q=make('carry','carry_source_decoder',{13:z(y32)},a=0x100d8b768,end=0x100d8b774);cert('carry_source_byte_decoder',q,[neq(q.get('w13'),d1)])
 qnat='(bvor ((_ zero_extend 24) (bvxor B0 #x74)) (bvshl ((_ zero_extend 24) (bvxor B1 #x74)) #x00000004))'
 domains=['(bvult ARG #x00000100)','(bvult NIB #x00000010)','(bvult (bvxor B0 #x74) #x10)','(bvult (bvxor B1 #x74) #x10)']
 table_models={};table_cuts=[];table_addresses=[]
 shared={3:bv(0x8864298f),4:bv(47),5:bv(866),6:bv(0xbd700),7:bv(0x443215),8:bv(0xaed96),10:bv(0xaed96),11:bv(0x6031),13:bv(0x45a6),19:bv(961),21:bv(45),22:bv(1080),23:bv(0x469f),24:bv(928),27:bv(166),26:frame(0xd10),0:bv(0x1010c4000),1:bv(0x1010a1960),2:'CELL'}
 loads_sum={'0x100b111b4':('B0',8),'0x100b111c4':('B1',8),'0x100b111d0':('CWORD0',32),'0x100b111d4':('CWORD1',32),'0x100b111f0':(bv(data['left']['fixup']['target']),64),'0x100b11204':('LBYTE',8),'0x100b11214':(bv(data['right']['fixup']['target']),64),'0x100b11228':('RBYTE',8),'0x100b1123c':(bv(data['operation']['fixup']['target']),64),'0x100b11258':('YBYTE',8),'0x100b112a0':('B2',8),'0x100b112c0':('TABLE',64),'0x100b112c4':('FN',64)}
 loads_carry={'0x100d8b730':('B0',8),'0x100d8b738':('B1',8),'0x100d8b764':('YBYTE',8),'0x100d8b784':('B2',8),'0x100d8b7d0':('TABLE',64),'0x100d8b7d4':('FN',64)}
 for name,initial_regs,loads in [('sum',{**shared,14:z('ARG')},loads_sum),('carry',{**shared,9:bv(0x100f4a640),15:z('ARG'),16:z('(bvadd ARG #x3bfaedb2)')},loads_carry)]:
  q=Engine({**{j:'Z'+str(j)for j in range(31)},'sp':'K',**initial_regs},loads,namespace=name+'_step_');q.declarations='';ii=fs[name]['instructions'][:-1];groups=TG[name];starts={v[0]:v for v in groups};ends={v[1]-4:v for v in groups};source_before={};image_nn=None
  image_start=0x100b1122c if name=='sum'else 0x100d8b754;image_end=0x100b11244 if name=='sum'else 0x100d8b75c;image_out='w16'if name=='sum'else'w13';mask=0x1b if name=='sum'else 0xfe;bias=1080 if name=='sum'else 0x32a0
  image_pos16=lookup([r['offset']for r in image_cases[name]],qnat,16);decoder_pc=0x100b11274 if name=='sum'else 0x100d8b770;decoder_out='w12'if name=='sum'else'w13'
  for i in ii:
   pc=int(i['ea'],16)
   if pc in starts:
    a,end,num,out,idx,base,bank,mreg,shift=starts[pc];m=0x8864298f if shift==41 else 0x443215;want=f'(bvadd {bv(base,32)} (bvmul {idx} #x00000362))';cert(name+'_live_scratch_numerator_'+hex(pc),q,[neq(q.get(num),want),neq(q.get('w'+str(mreg)),bv(m,32)),neq(q.get('w19'),bv(961,32))],domains);source_before[pc]=q.get(num)
   if pc==image_start:
    num='w9'if name=='sum'else'w13';image_nn=q.get(num);want=f'(bvadd (bvmul (bvxor {qnat} {bv(mask,32)}) #x0000002d) {bv(bias,32)})';cert(name+'_source_encoded_kernel_argument',q,[neq(image_nn,want),neq(q.get('w23'),bv(0x469f,32)),neq(q.get('w24'),bv(928,32))],domains)
   q.run({'instructions':[i]},pc+4)
   if name=='sum'and pc==0x100b11234:
    mix='(bvmul (bvxor (bvsub CWORD1 CWORD0) #x000000a6) #x0a5cd4cf)';env=f'((_ extract 7 0) {mix})';cert('source_state_word_codec_addresses_and_family_expression',q,[neq(rd(q,0x100b111d0)['address'],'CELL'),neq(rd(q,0x100b111d4)['address'],bv(0x1010c4670)),neq(rd(q,0x100b111f0)['address'],bv(int(data['left']['slot'],16))),neq(rd(q,0x100b11214)['address'],bv(int(data['right']['slot'],16))),neq(rd(q,0x100b11204)['address'],f'(bvadd {bv(int(data["left"]["target"],16))} ((_ zero_extend 56) {env}))'),neq(rd(q,0x100b11228)['address'],f'(bvadd {bv(int(data["right"]["target"],16))} ((_ zero_extend 56) (bvxor LBYTE #x61)))'),neq(q.get('w12'),f'((_ zero_extend 24) (bvxor {env} RBYTE))')])
    table_cuts.append({'site':i['ea'],'source_value':q.get('w12'),'replacement':'0x19','justification':'source state-word/root/address expression and all256 original left/right byte cases','word_values_remain_arbitrary':True});q.put('w12',bv(0x19,32))
   if pc in ends:
    a,end,num,out,idx,base,bank,mreg,shift=ends[pc];m=0x8864298f if shift==41 else 0x443215;cases=[]
    for j in range(len(bank)):
     n=base+866*j;quo=(n*m)>>shift;rem=n-quo*961;assert 0<=n<2**32 and n*m<2**64 and quo==n//961 and rem==bank[j];cases.append({'index':j,'numerator':n,'quotient':quo,'remainder':rem})
    value=f'((_ zero_extend 16) {lookup(bank,idx,16)})';table_addresses.append({'routine':name,'quotient_site':hex(a),'remainder_site':i['ea'],'source_numerator':source_before[a],'source_remainder':q.get(out),'replacement':value,'source_shape_certificate':'source_scratch_remainder_shape_'+hex(a),'live_binding_certificate':name+'_live_scratch_numerator_'+hex(a),'cases':cases});q.put(out,value)
   if pc==image_end:
    want=f'(bvsub {image_nn} (bvmul (bvlshr (bvmul {image_nn} #x0000469f) #x00000018) #x000003a0))';cert(name+'_live_image_remainder_shape',q,[neq(q.get(image_out),want)],domains);value=f'((_ zero_extend 16) {image_pos16})';table_cuts.append({'site':i['ea'],'source_remainder':q.get(image_out),'replacement':value,'justification':'source image quotient shape,live encoded argument,and all256 finite image-position cases','source_argument_SMT':qnat});q.put(image_out,value)
   if pc==(0x100b11258 if name=='sum'else 0x100d8b764):
    cert(name+'_source_operation_image_address',q,[neq(rd(q,pc)['address'],f'(bvadd {bv(0x100f4a640)} ((_ zero_extend 48) {image_pos16}))')]+([neq(rd(q,0x100b1123c)['address'],bv(int(data['operation']['slot'],16)))]if name=='sum'else[]),domains)
   if pc==decoder_pc:
    table_cuts.append({'site':i['ea'],'source_value':q.get(decoder_out),'replacement':'NIB','upper_exclusive':16,'justification':name+'_source_byte_decoder and all256 original selected image bytes','actual_relationship':name+'_kernel(source_argument)','source_argument_SMT':qnat});q.put(decoder_out,'NIB')
  models[name+'_step']=q;table_models[name]=q
  ptr=lambda bank,index:f'(bvadd {frame(0xd10)} ((_ zero_extend 48) {lookup(bank,index,16)}))'
  if name=='sum':
   terms=[neq(rd(q,0x100b111b4)['address'],ptr(BB,'(bvand ARG #x0000000f)')),neq(rd(q,0x100b111c4)['address'],ptr(BB,'(bvlshr ARG #x00000004)')),neq(rd(q,0x100b112a0)['address'],ptr(AA,'NIB')),neq(st(q,0x100b112ac)['address'],ptr(CC,'ARG')),neq(st(q,0x100b112ac)['value'],'B2'),neq(q.get('w14'),'(bvadd ARG #x00000001)'),neq(q.get('w16'),bv(0x3bfaedb2,32)),neq(q.get('w15'),bv(0,32)),neq(q.get('x9'),bv(0x100f4a640)),neq(q.get('x2'),'CELL'),neq(rd(q,0x100b112c4)['address'],f'(ite (= ARG #x000000ff) {at(0xc9be)} {at(0x45a6)})')];assert sum(v['width_bits']==8 for v in q.reads)==6
  else:
   terms=[neq(rd(q,0x100d8b730)['address'],ptr(BB,'(bvand ARG #x0000000f)')),neq(rd(q,0x100d8b738)['address'],ptr(BB,'(bvlshr ARG #x00000004)')),neq(rd(q,0x100d8b784)['address'],ptr(AA,'NIB')),neq(st(q,0x100d8b7b8)['address'],ptr(DD,'ARG')),neq(st(q,0x100d8b7b8)['value'],'(bvxor #x34 (bvshl B2 #x04))'),neq(q.get('w15'),'(bvadd ARG #x00000001)'),neq(q.get('w16'),'(bvadd ARG #x3bfaedb3)'),neq(q.get('w12'),bv(0,32)),neq(q.get('w10'),bv(0x84e8,32)),neq(q.get('x9'),bv(0x100f4a640)),neq(rd(q,0x100d8b7d4)['address'],f'(ite (= ARG #x000000ff) {at(0x6031)} {at(0x6035)})')];assert sum(v['width_bits']==8 for v in q.reads)==4
  cert(name+'_complete_source_step_IO_and_loop_control',q,terms+[neq(q.get('x26'),frame(0xd10))],domains);assert len(q.stores)==1 and q.stores[0]['width_bits']==8
 sum_keep=[0,1,2,3,4,5,6,7,8,10,11,13,19,21,22,23,24,26,27];carry_keep=[0,1,2,3,4,5,6,7,8,9,11,19,21,22,23,24,26,27]
 for name,regs in [('sum',sum_keep),('carry',carry_keep)]:
  for reg in regs:assert not{prefix+str(reg)for prefix in ['x','w']}&set(s['register_write_sets'][name]),(name,reg)
 assert all(((0x34^((0x74^v)<<4))&255)==(0x74^(v<<4))for v in range(16))
 all_cells=AA+BB+CC+DD;assert len(all_cells)==len(set(all_cells))==544
 protected=set(range(0x2b8,0x2c8))|set(range(0x388,0x390))|set(range(0x568,0x590))|set(range(0x728,0x73c))|set(range(0x740,0x758))|set(range(0x768,0xcf4))|set(range(0x1210,0x1218));assert not {0xd10+x for x in all_cells}&protected
 assert len(set(CC))==len(set(DD))==256
 # A valid abstract P/Q pair that does not yield an associative one-alphabet
 # operation;this is not a native bank-state or target-input witness.
 qq=list(range(16));qq[0],qq[1]=qq[1],qq[0];mixed=[qq[v]for v in kernels['sum']];counterexample=None
 for a in range(16):
  for b in range(16):
   for c in range(16):
    l=mixed[mixed[a+16*b]+16*c];r=mixed[a+16*mixed[b+16*c]]
    if l!=r and counterexample is None:counterexample={'P':'identity','Q':qq,'a':a,'b':b,'c':c,'left':l,'right':r,'native_reachability_claim':False}
 assert counterexample is not None
 solve('table_loop_next_offset_bound','(assert (or (bvugt (bvadd ARG #x00000001) #x00000100) (bvule (bvadd ARG #x00000001) ARG)))',conditions=['(bvult ARG #x00000100)'])
 solve('second_selector_domain_nonempty','',result='sat',conditions=cc)
 solve('adder_input_domains_nonempty','',result='sat',conditions=domains)
 solve('last_table_iteration_domain','(assert (= ARG #x000000ff))',result='sat',conditions=domains)
 # Source iteration contracts,finite pinned-data kernels and bijection
 # composition establish the complete typed arithmetic relationship.
 composition={'second_shuffle':'A(i)=E0(Q(i)),with inverse B(P(i))=E0(i) retained from the first shuffle','source_sum':'C(x+16*y)=E0(Q(Ksum(P_inverse(x),P_inverse(y))))','source_carry':'D(x+16*y)=E1(Q(Kcarry(P_inverse(x),P_inverse(y))))','input_codebook':'Rin=P composed with L','output_codebook':'Rout=Q composed with L','typed_sum':'C(Rin(a)+16*Rin(b))=E0(Rout((a+b)mod16))','typed_carry':'D(Rin(a)+16*Rin(b))=E1(Rout(floor((a+b)/16)))','E0':'0x74 XOR index','E1':'u8(0x74 XOR(index<<4))','permutation_equality_required_for_typed_adder':False,'P_equals_Q_proved':False,'same_alphabet_group_claim':'conditional on P=Q;without that condition only the two-codebook arithmetic and commutative Latin-square sum relation are established','memory_premises':'coherent initialized A/B,stable original image banks/root values,valid nonwrapping private frame and readable state-word pointers;all A/B/C/D cells are distinct','loop_induction':'each table starts at argument zero,increments by one,branches back exactly before256,and writes each distinct destination once;neither writer changes A/B or earlier C cells','source_step_binding':'scratch and image quotient shapes plus checked live numerators/coefficient bindings and exhaustive finite address cases justify every replacement;decoded NIB stands for the actual finite image kernel output'}
 records={n:{**q.record(),'source_SSA':q.prefix(),'declarations':q.declarations,'final_registers':q.r}for n,q in models.items()};actual={pc for m in records.values()for pc in m['source_sites']};expected={i['ea']for f in fs.values()for i in f['instructions']if i['mnemonic']!='braa'};assert actual==expected,(expected-actual,actual-expected)
 sem={'source_models':records,'source_nonbranch_sites_translated':len(actual),'source_selector_abstractions':abstractions,'second_shuffle_address_certificates':addresses,'second_shuffle_swap_ledger':swaps,'finite_second_transpositions':finite,'predecessor_carried_coefficients':carried,'sum_invariant_registers':sum_keep,'carry_invariant_registers':carry_keep,'table_address_certificates':table_addresses,'table_source_cuts':table_cuts,'image_kernel_cases':image_cases,'decoded_sum_kernel':kernels['sum'],'decoded_carry_kernel':kernels['carry'],'arithmetic_label_cycle':label,'paired_arithmetic_identities':algebra,'fixed_kernel_associativity_triples_checked':4096,'unequal_codebook_counterexample':counterexample,'arithmetic_composition':composition,'forward_offsets':AA,'inverse_offsets':BB,'sum_offsets':CC,'carry_offsets':DD,'all544_cells_disjoint':True,'scratch_cells_written':528,'scratch_cells_touched':544,'scratch_byte_store_operations':542,'scratch_byte_reads':1566,'image_byte_reads':1024,'total_byte_reads':2590,'state_u32_reads':512,'sum_source_store':'0x100b112ac','carry_source_store':'0x100d8b7b8','global_state_word_address':'0x1010c4670','saved_word_pointer_cell':'F+0x580','family_selector_constant':'0x19','family_independent_of_two_word_values':True,'image_kernel_base':'0x100f4a640','newly_written_cells_beyond_old963_view':sorted(0xd10+x for x in set(CC+DD)if 0xd10+x>=0x10c3),'private_word_view_workspace_roots_and_budget_cells_unwritten':True,'next_frontier':'0x100d5e270','Mach_port_emissions':0,'same_alphabet_group_proved':False,'standard_cipher_identity_proved':False,'native_reachability_proved':False,'successful_output_publication_proved':False,'native_claim':False}
 return pp,sem
def verify(s):return s==build()
def alterations(s):
 cases=[('source_byte',lambda q:q['fragments']['second'].__setitem__('bytes','00'+q['fragments']['second']['bytes'][2:])),('wrong_left_bias',lambda q:q['data_roots'][0].__setitem__('bias_u64','0x0')),('wrong_operation_byte',lambda q:q['data_roots'][2].__setitem__('bytes','00'+q['data_roots'][2]['bytes'][2:])),('wrong_family',lambda q:q['family_results256'].__setitem__(0,0)),('wrong_sum_exit',lambda q:q['branch_edges'][2].__setitem__('target','0x0')),('invent_native',lambda q:q.__setitem__('target_executed',True))];out=[]
 for name,fn in cases:
  q=copy.deepcopy(s);fn(q);assert not verify(q);out.append({'name':name,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,sem=certificates(s);aa=alterations(s);counts={**s['verified_source_counts'],'queries_unsat':sum(v['result']=='unsat'for v in pp),'queries_sat':sum(v['result']=='sat'for v in pp),'predecessor_queries_replayed':sum(v.get('replayed_query',False)for v in pp),'source_nonbranch_sites_translated':sem['source_nonbranch_sites_translated'],'second_selector_abstractions':15,'second_address_certificates':len(sem['second_shuffle_address_certificates']),'second_finite_address_cases':sum(len(v['cases'])for v in sem['second_shuffle_address_certificates']),'second_source_swaps':15,'finite_second_transpositions':135,'table_address_certificates':len(sem['table_address_certificates']),'table_finite_address_cases':sum(len(v['cases'])for v in sem['table_address_certificates']),'image_kernel_cases':512,'paired_arithmetic_identities':512,'fixed_kernel_associativity_triples':4096,'scratch_cells_written':528,'scratch_cells_touched':544,'scratch_byte_store_operations':542,'total_byte_reads':2590,'state_u32_reads':512,'rejected_alterations':len(aa)}
 deps=[P+'_source.json','validate_daemon_mode_one_record_permutation.py','recover_daemon_mode_one_record_permutation.py','validate_daemon_mode_one_inverse_tables.py','validate_daemon_mode_one_scatter.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py']+DEPS;c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':pp,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'record_second_permutation_and_typed_adder_proved':True,'complete_operation_proved':False,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
