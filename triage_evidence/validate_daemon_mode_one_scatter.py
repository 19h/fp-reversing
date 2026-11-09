#!/usr/bin/env python3
"""Compositional original-source SSA, division and finite permutation certificates.

No target CPU, emulator, API or IPC operation is run. Fresh bounded selectors
overapproximate source remainders; they do not assert independent reachability.
"""
import copy,json,subprocess,shutil
from recover_daemon_mode_one_scatter import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_list_output import StaticSSA,bv,split
from validate_daemon_existing_scalar_reader import DECL,z,neq,prefix
SOLVER=shutil.which('z3');assert SOLVER
ADDR=[(84784+757*j)%963 for j in range(16)]
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec 32))\n'for n in ['IDX']+['SEL'+str(j)for j in range(14)])
def frame(o):return f'(bvadd K {bv(o)})'
def at(i):return f'(bvadd TABLE {bv(i*8)})'
def lookup(i):
 e=bv(ADDR[15],32)
 for j in range(14,i-1,-1):e=f'(ite (= SEL{i} {bv(j-i,32)}) {bv(ADDR[j],32)} {e})'
 return e
class Engine(StaticSSA):
 def run(self,f,end):
  for i in f['instructions']:
   if int(i['ea'],16)>=end:break
   p=split(i['operands']);m=i['mnemonic'];w=32 if p[0].startswith('w')else 64
   if m=='umull':self.put(p[0],f'(bvmul {z(self.get(p[1],32))} {z(self.get(p[2],32))})')
   elif m=='msub':self.put(p[0],f'(bvsub {self.get(p[3],w)} (bvmul {self.get(p[1],w)} {self.get(p[2],w)}))')
   elif m=='udiv':self.put(p[0],f'(bvudiv {self.get(p[1],w)} {self.get(p[2],w)})')
   elif m=='tst':self.flags={'eq':f'(= (bvand {self.get(p[0],w)} {self.get(p[1],w)}) {bv(0,w)})','ne':f'(distinct (bvand {self.get(p[0],w)} {self.get(p[1],w)}) {bv(0,w)})'}
   else:super().run({'instructions':[i]},int(i['ea'],16)+4);continue
   self.sites.append(i['ea'])
  return self
def fresh(n,r=None,loads=None):
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=Engine(rr,loads,namespace=n+'_');g.declarations='';return g

# Exact source remainder sites. The 14-way case first halves VALUE.
# id:(start,end,input,divisor,multiplier,shift,output,external constants)
DIVS={
 1:(0x100ca04ac,0x100ca04c4,'w0',15,0x88888889,35,'w12',{}),
 2:(0x100ca050c,0x100ca0528,'w2',14,0x92492493,34,'w12',{}),
 3:(0x100ca0534,0x100ca054c,'w3',13,0x4ec4ec4f,34,'w16',{}),
 4:(0x100ca0630,0x100ca0648,'w14',12,0xaaaaaaab,35,'w10',{}),
 5:(0x100ca060c,0x100ca0624,'w19',11,0xba2e8ba3,35,'w9',{}),
 6:(0x100ca06e4,0x100ca06fc,'w21',10,0xcccccccd,35,'w14',{}),
 7:(0x100ca0710,0x100ca0728,'w7',9,0x38e38e39,33,'w9',{}),
 9:(0x100ca07ac,0x100ca07d0,'w2',7,0x24924925,32,'w24',{}),
 10:(0x100ca07f8,0x100ca0808,'w10',6,0xaaaaaaab,34,'w9',{1:0xaaaaaaab}),
 11:(0x100ca089c,0x100ca08ac,'w15',5,0xcccccccd,34,'w15',{3:0xcccccccd}),
 13:(0x100ca0940,0x100ca0978,'w16',3,0xaaaaaaab,33,'w14',{1:0xaaaaaaab}),
}
SELECTORS={end-4:(j,out)for j,(_,end,_,_,_,_,out,_)in DIVS.items()}
SELECTORS.update({0x100ca0480:(0,'w10'),0x100ca07a4:(8,'w22'),0x100ca08e8:(12,'w12')})
# quotient start, remainder site, source numerator, quotient-output divisor,
# selected stage, result register; all address quotients are contiguous.
ADDRESS_GROUPS=[
 (0x100ca049c,0x100ca04a8,'w10','w25',0,'w10'),
 (0x100ca04e0,0x100ca04e8,'w9','w25',1,'w9'),
 (0x100ca05a0,0x100ca05a8,'w9','w25',2,'w9'),
 (0x100ca05c8,0x100ca05d0,'w9','w25',3,'w9'),
 (0x100ca06a4,0x100ca06a8,'w14','w10',4,'w10'),
 (0x100ca06b0,0x100ca06b8,'w14','w25',4,'w14'),
 (0x100ca06d0,0x100ca06d8,'w9','w25',5,'w9'),
 (0x100ca0738,0x100ca0740,'w14','w25',6,'w14'),
 (0x100ca077c,0x100ca0784,'w9','w25',7,'w9'),
 (0x100ca0828,0x100ca0830,'w14','w25',8,'w14'),
 (0x100ca0844,0x100ca084c,'w15','w25',9,'w14'),
 (0x100ca0870,0x100ca0878,'w9','w25',10,'w9'),
 (0x100ca08ec,0x100ca08f4,'w14','w25',11,'w14'),
 (0x100ca0914,0x100ca091c,'w9','w25',12,'w9'),
 (0x100ca0984,0x100ca098c,'w12','w25',13,'w9'),
]
SWAPS=[
 (0x100ca047c,0x100ca04c8,0x100ca04cc,0x100ca04d0),
 (0x100ca04f0,0x100ca04f8,0x100ca0500,0x100ca0504),
 (0x100ca0528,0x100ca05b0,0x100ca05b4,0x100ca05b8),
 (0x100ca05dc,0x100ca05d8,0x100ca05e0,0x100ca05f8),
 (0x100ca0654,0x100ca06ac,0x100ca06bc,0x100ca06c0),
 (0x100ca0700,0x100ca06e0,0x100ca0708,0x100ca070c),
 (0x100ca0728,0x100ca0748,0x100ca074c,0x100ca0750),
 (0x100ca07a8,0x100ca078c,0x100ca07e4,0x100ca0808),
 (0x100ca0824,0x100ca0838,0x100ca083c,0x100ca0840),
 (0x100ca0850,0x100ca0858,0x100ca085c,0x100ca0860),
 (0x100ca08b0,0x100ca0880,0x100ca08b8,0x100ca08d8),
 (0x100ca08dc,0x100ca08fc,0x100ca0900,0x100ca0904),
 (0x100ca092c,0x100ca0924,0x100ca094c,0x100ca0980),
 (0x100ca0998,0x100ca0994,0x100ca099c,0x100ca09a0),
 (0x100ca09a4,0x100ca09b8,0x100ca09bc,0x100ca09c0),
]
def certificates(s):
 pp=[];tr={};abstractions=[];address_certs=[];finite=[];fs=s['fragments']
 def solve(n,body,result='unsat',integer=False,extra='',note='',arrays=False):
  q='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_ABV'if arrays else'QF_BV')+')\n'+('(declare-fun XI () Int)\n'if integer else DECL+EXTRA)+extra+body+'\n(check-sat)\n'
  v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr)
  pp.append({'name':n,'query':q,'result':result,'scope':note or SCOPE});print(n,result,flush=True)
 def cert(n,g,terms,cc=()):solve(n,prefix(g)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(terms)+'))')
 def subset(n,a,b):return {'instructions':[i for i in fs[n]['instructions']if a<=int(i['ea'],16)<b]}
 def run(n,label,r=None,loads=None,a=None,end=None):
  f=fs[n];a=a or int(f['start'],16);end=end or int(f['instructions'][-1]['ea'],16);ii=subset(n,a,end)['instructions'];ll=dict(loads or{});dd=[]
  for i in ii:
   if i['mnemonic']in('ldr','ldrb')and i['ea']not in ll:
    bits=8 if i['mnemonic']=='ldrb'else 32 if i['operands'].startswith('w')else 64;v=label+'_L'+str(len(dd));ll[i['ea']]=(v,bits);dd.append(f'(declare-fun {v} () (_ BitVec {bits}))')
  g=fresh(label,r,ll);g.declarations='\n'.join(dd)+'\n';g.run({'instructions':ii},end);tr[label]=g.record();return g
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def st(g,pc):return next(q for q in g.stores if q['site']==hex(pc))
 hand=run('handoff','handoff',{15:bv(0x3d26),9:'TABLE'},loads={'0x100d5e3f0':(frame(0xd00),64),'0x100d5e3f4':('TABLE',64)})
 vals={4:15,5:84784,6:0x440dd2cf,7:963,12:0x44eca315,13:0x8a66,14:0x2a813e61,15:0x3d26,16:0xbb135d00,19:0x557ec19e,20:0xaa813e61,21:0x557ec19e,22:0x76,23:0xfaca}
 cert('handoff_initializes_scatter_and_preserves_first_bank',hand,[neq(hand.get('w'+str(j)),bv(v,32))for j,v in vals.items()]+[neq(hand.get('x11'),frame(0xd00)),neq(hand.get('x8'),'TABLE'),neq(rd(hand,0x100d5e390)['address'],at(0x3d26))]+[neq(hand.get('x'+str(j)),'Z'+str(j))for j in range(4)])
 # Every multiplication is unsigned32*32, so its64-bit product is exact.
 divisors=[(15,0x88888889,35),(13,0x4ec4ec4f,34),(12,0xaaaaaaab,35),(11,0xba2e8ba3,35),(10,0xcccccccd,35),(9,0x38e38e39,33),(6,0xaaaaaaab,34),(5,0xcccccccd,34),(3,0xaaaaaaab,33),(963,0x440dd2cf,40)]
 for d,m,shift in divisors:
  solve(f'exact_unsigned_division_{d}',f'(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (distinct (div (* XI {m}) {1<<shift}) (div XI {d})))',integer=True)
 solve('restricted_highword_division963',f'(assert (and (<= 0 XI) (<= XI 100000)))\n(assert (distinct (div (* XI {0x440dd3}) 4294967296) (div XI 963)))',integer=True,note='The32-bit-highword reciprocal is certified only for0..100000,not all u32. All selected address numerators are84784..96139.')
 solve('exact_halved_division14',f'(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (distinct (div (* (div XI 2) {0x92492493}) {1<<34}) (div XI 14)))',integer=True)
 q=f'(div (* XI {0x24924925}) 4294967296)';correct=f'(div (+ {q} (div (- XI {q}) 2)) 4)'
 solve('exact_corrected_division7',f'(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or (< {q} 0) (> {q} XI) (>= (+ {q} (div (- XI {q}) 2)) 4294967296) (distinct {correct} (div XI 7))))',integer=True)
 solve('exact_unsigned_remainder_ranges','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or '+' '.join(f'(or (< (- XI (* {d} (div XI {d}))) 0) (>= (- XI (* {d} (div XI {d}))) {d}) (>= (* {d} (div XI {d})) 4294967296))'for d in range(3,17))+'))',integer=True)
 # Source32-bit recurrence for W3 is an identity, including wraparound.
 rr={j:bv(v)for j,v in vals.items()};rr[3]=z('VALUE')
 ident=run('scatter','scatter_word3_identity',rr,a=0x100d4fdec,end=0x100d4fe00);cert('scatter_does_not_change_word3',ident,[neq(ident.get('w3'),'VALUE')])
 rr.update({4:z('(bvsub #x0000000f IDX)'),5:z('(bvadd #x00014b30 (bvmul IDX #x000002f5))'),12:z('(bvadd #x44eca315 IDX)'),16:z('(bvsub #xbb135d00 IDX)'),11:frame(0xd00),8:'TABLE',3:z('VALUE')})
 scatter=run('scatter','scatter_round',rr,loads={'0x100d4fe44':('FN',64)})
 row=st(scatter,0x100d4fe2c);expected=lookup(0).replace('SEL0','IDX')
 cert('scatter_round_exact_address_byte_and_control',scatter,[neq(row['address'],f'(bvadd {frame(0xd00)} {z(expected)})'),neq(row['value'],'((_ extract 7 0) (bvxor IDX #x000000d4))'),neq(scatter.get('w3'),'VALUE'),neq(scatter.get('w4'),'(bvsub #x0000000e IDX)'),neq(scatter.get('w12'),'(bvadd #x44eca316 IDX)'),neq(scatter.get('w16'),'(bvsub #xbb135cff IDX)'),neq(scatter.get('w5'),'(bvadd #x00014e25 (bvmul IDX #x000002f5))'),neq(rd(scatter,0x100d4fe44)['address'],f'(ite (= IDX #x0000000f) {at(0xc7ec)} {at(0x3d26)})')],['(bvult IDX #x00000010)'])
 # Independently translate each source reciprocal/remainder implementation.
 # These prove the BV expression shape; integer certificates above establish
 # its division meaning. Full-stream constant preconditions below bind them.
 for j,(a,end,src,d,m,shift,out,constants)in DIVS.items():
  r={int(src[1:]):z('VALUE'),**{k:bv(v)for k,v in constants.items()}}
  g=run('permutation','division_shape'+str(j),r,a=a,end=end)
  product=f'(bvlshr (bvmul {z("(bvlshr VALUE #x00000001)"if j==2 else"VALUE")} {bv(m)}) {bv(shift)})'
  qq=f'((_ extract 31 0) {product})'
  if j==9:qq=f'(bvlshr (bvadd {qq} (bvlshr (bvsub VALUE {qq}) #x00000001)) #x00000002)'
  want=f'(bvsub VALUE (bvmul {qq} {bv(d,32)}))'
  cert('source_remainder_shape'+str(j),g,[neq(g.get(out),want)])
 # Full consumer stream, with explicit sound bounded-selector abstractions.
 # Loads remain arbitrary bytes until a separate memory-coherence induction.
 ii=fs['permutation']['instructions'][:-1];ll={};dd=[]
 for i in ii:
  if i['mnemonic']in('ldr','ldrb'):
   bits=8 if i['mnemonic']=='ldrb'else 64;v='perm_L'+str(len(dd));ll[i['ea']]=(v,bits);dd.append(f'(declare-fun {v} () (_ BitVec {bits}))')
 ll['0x100ca09c4']=('TABLE',64)
 g=fresh('perm',{11:frame(0xd00),13:bv(0x8a66)},ll);g.declarations='\n'.join(dd)+'\n';cc=[];starts={a:(b,num,div,j,out)for a,b,num,div,j,out in ADDRESS_GROUPS};ends={b:(a,num,div,j,out)for a,b,num,div,j,out in ADDRESS_GROUPS};saved={};snapshots={}
 for i in ii:
  pc=int(i['ea'],16);snapshots[pc]=dict(g.r)
  if pc in starts:
   b,num,div,j,out=starts[pc];ps=split(i['operands']);want=f'(bvadd #x00014b30 (bvmul (bvadd SEL{j} {bv(j,32)}) #x000002f5))'
   terms=[neq(g.get(num),want)]
   if i['mnemonic']=='udiv':terms+=[neq(g.get(ps[2]),bv(963,32))]
   else:
    assert i['mnemonic']=='umull'and ps[1]==num;shiftpc=next(q for q in ii if int(q['ea'],16)==pc+4);shift=int(shiftpc['operands'].split('#')[1],0);assert shift in(32,40)and shiftpc['mnemonic']=='lsr'and split(shiftpc['operands'])[:2]==[ps[0],ps[0]];mult=0x440dd3 if shift==32 else 0x440dd2cf;terms+=[neq(g.get(ps[2]),bv(mult,32))]
   if div!='w25'or pc!=0x100ca049c:terms+=[neq(g.get(div),bv(963,32))]
   # At the first quotient W25 is established between quotient and MSUB.
   cert('address_numerator_and_divisor_'+hex(pc),g,terms,cc)
   saved[b]={'site':hex(pc),'stage':j,'selector_domain':list(range(16-j)),'numerator_expression':g.get(num),'required_numerator':want,'division':'UDIV963'if i['mnemonic']=='udiv'else f'unsigned_product_shift{shift}'}
  g.run({'instructions':[i]},pc+4)
  if pc in SELECTORS:
   j,out=SELECTORS[pc];raw=g.get(out)
   if j in(0,8,12):cert('bitmask_selector_range'+str(j),g,[f'(bvuge {raw} {bv(16-j,32)})'],cc)
   else:
    a,end,src,d,m,shift,output,constants=DIVS[j];assert output==out and d==16-j
    before=snapshots[a]
    if constants:
     probe=fresh('probe',before);probe.defs=list(g.defs);probe.declarations=g.declarations
     cert('full_stream_division_constants'+str(j),probe,[neq(probe.get('w'+str(k)),bv(v,32))for k,v in constants.items()],cc)
    # Mechanical source dependency closure: between the isolated first site
    # and last site, full stream has exactly the same instruction sequence.
    assert subset('permutation',a,end)['instructions']==[q for q in ii if a<=int(q['ea'],16)<end]
   abstractions.append({'stage':j,'site':hex(pc),'source_output':raw,'abstract_value':'SEL'+str(j),'upper_exclusive':16-j,'justification':'source bitmask bound'if j in(0,8,12)else f'source_remainder_shape{j} plus exact unsigned division/range certificate; arbitraryu32 source operand','relationship_to_live_state':'computed source output; fresh selector overapproximates this value and does not establish independence/reachability'})
   g.put(out,'SEL'+str(j));cc.append(f'(bvult SEL{j} {bv(16-j,32)})')
  if pc in ends:
   a,num,div,j,out=ends[pc];assert i['mnemonic']=='msub';ps=split(i['operands']);assert ps[0]==out and ps[2]==div and ps[3]==num
   cert('address_remainder_divisor_'+hex(pc),g,[neq(g.get(div),bv(963,32))]if out!=div else[],cc)if out!=div else None
   qsite=next(q for q in ii if int(q['ea'],16)==a);qparts=split(qsite['operands']);assert ps[1]==qparts[0].replace('x','w',1)
   intermediate=[q for q in ii if a<int(q['ea'],16)<pc]
   assert [q['mnemonic']for q in intermediate]==([]if qsite['mnemonic']=='udiv'else['lsr','mov']if a==0x100ca049c else['lsr'])
   rows=[]
   for k in range(16-j):
    n=84784+757*(j+k);qq=n//963;rr=n-qq*963
    assert n<=100000 and rr==ADDR[j+k]
    if qsite['mnemonic']=='udiv':actual=n//963
    # Use the actual encoded shift rather than a layout heuristic.
    if qsite['mnemonic']!='udiv':
     sh=next(q for q in ii if int(q['ea'],16)==a+4);ss=int(sh['operands'].split('#')[1],0);mm=0x440dd3 if ss==32 else 0x440dd2cf;actual=(n*mm)>>ss
    assert actual==qq;rows.append({'selector':k,'position':j+k,'numerator':n,'quotient':qq,'remainder':rr})
   address_certs.append({**saved[pc],'remainder_site':hex(pc),'source_remainder':g.get(out),'replacement':lookup(j),'cases':rows,'all_cases_match':True})
   g.put(out,lookup(j))
 tr['permutation_abstract_stream']=g.record()
 terms=[];swaps=[]
 for j,(fp,sp,fw,sw)in enumerate(SWAPS):
  fr,sr,ft,st0=rd(g,fp),rd(g,sp),st(g,fw),st(g,sw);fixed=frame(0xd00+ADDR[j]);selected=sr['address']
  terms +=[neq(fr['address'],fixed),neq(ft['address'],fixed),neq(ft['value'],sr['input']),neq(st0['address'],selected),neq(st0['value'],fr['input'])]
  choices=[frame(0xd00+v)for v in ADDR[j:]];terms.append('(and '+' '.join(neq(selected,v)for v in choices)+')')
  assert max(fp,sp)<min(fw,sw)
  swaps.append({'stage':j,'fixed_position':j,'fixed_frame_offset':hex(0xd00+ADDR[j]),'read_fixed':hex(fp),'read_selected':hex(sp),'write_fixed':hex(fw),'write_selected':hex(sw),'possible_selected_positions':list(range(j,16)),'both_reads_before_both_writes':True,'self_swap_requires_coherent_reads':True})
 cert('all15_source_swaps_and_selected_cell_membership',g,terms+[neq(rd(g,0x100ca09c8)['address'],at(0x8a66))],cc)
 # All source stores in these two new bodies are accounted for; the four
 # second-bank cells and8 B budget cell are outside every possible swap.
 assert len(g.stores)==30 and len(scatter.stores)==1
 assert len(set(ADDR))==16 and all(0<=v<963 for v in ADDR)
 for j in range(15):
  for k in range(j,16):
   labels=list(range(16));labels[j],labels[k]=labels[k],labels[j]
   assert sorted(labels)==list(range(16));finite.append({'stage':j,'selected_position':k,'label_permutation':labels})
 assert len(finite)==135
 memory='(declare-fun MEM () (Array (_ BitVec 64) (_ BitVec 8)))\n(define-fun SWAPPED () (Array (_ BitVec 64) (_ BitVec 8)) (store (store MEM A (select MEM U)) U (select MEM A)))\n'
 solve('coherent_two_read_two_write_swap_including_alias', '(assert (or (distinct (select SWAPPED A) (select MEM U)) (distinct (select SWAPPED U) (select MEM A)) (and (distinct O A) (distinct O U) (distinct (select SWAPPED O) (select MEM O)))))',extra=memory,arrays=True,note='Universal array-store theorem,including A=U. Both source reads precede both writes; this establishes the coherent-memory step used by finite transposition induction.')
 collisions=[]
 for off in [0xd00+v for v in ADDR]:
  for protected in [*range(0x720,0x724),*range(0x728,0x72c),*range(0x730,0x734),*range(0x748,0x74c),*range(0x1210,0x1218)]:collisions.append('(= '+frame(off)+' '+frame(protected)+')')
 solve('scratch_cells_disjoint_from_second_bank_and_budget','(assert (or '+' '.join(collisions)+'))')
 solve('selector_domain_nonempty',''.join('(assert '+c+')\n'for c in cc),'sat',note='Abstract nonempty selector domain only; no native state or independent-selector reachability claim.')
 return pp,tr,{'selector_abstractions':abstractions,'address_reduction_certificates':address_certs,'swap_ledger':swaps,'finite_transpositions':finite,'scatter_addresses':ADDR,'initial_bytes':[0xd4^j for j in range(16)],'induction':{'base':'source scatter certificate initializes16 distinct cells with all bytesd0..df','step':'source15-swap contract:two coherent reads before two writes,selected cell is one of the16 initialized cells; includes self swaps','conclusion':'final16 cells permute the initial bytes; all other scratch bytes,second-bank spills and budget are preserved','premises':'same writable nonwrapping private frame,no external concurrent modification,ordinary coherent memory and selected admitted source path; no all-permutations reachability or standard algorithm claim'}}
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_scatter_stride',lambda t:t['fragments']['scatter']['instructions'][-3].__setitem__('operands','w5, w5, #0x2f4')),('wrong_scratch_store',lambda t:t['fragments']['scatter']['instructions'][19].__setitem__('operands','w10, [sp]')),('missing_permutation',lambda t:t['fragments'].pop('permutation')),('wrong_next_index',lambda t:t['branch_edges'][-1].__setitem__('index','0x8a67')),('invent_native',lambda t:t.__setitem__('target_executed',True)),('invent_full_completion',lambda t:t.__setitem__('full_goal_complete',True))];out=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,sem=certificates(s);aa=alterations(s);sites={pc for q in tr.values()for pc in q['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert sites==expected,(expected-sites,sites-expected)
 counts={**s['verified_source_counts'],'queries_unsat':sum(q['result']=='unsat'for q in pp),'domain_checks_sat':sum(q['result']=='sat'for q in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'selector_abstractions':len(sem['selector_abstractions']),'address_reduction_certificates':len(sem['address_reduction_certificates']),'finite_address_cases':sum(len(q['cases'])for q in sem['address_reduction_certificates']),'source_swaps':len(sem['swap_ledger']),'transposition_cases':len(sem['finite_transpositions']),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_list_output.py':sha(ROOT/'validate_daemon_list_output.py'),'validate_daemon_existing_scalar_reader.py':sha(ROOT/'validate_daemon_existing_scalar_reader.py')},'proofs':pp,'translations':tr,'semantics':sem,'alterations':aa,'verified_counts':counts,'solver':{'executable':'z3','sha256':sha(SOLVER)},'all_checks_pass':True,'complete_operation_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
