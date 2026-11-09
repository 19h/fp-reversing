#!/usr/bin/env python3
"""Source SSA,exact integer quotient and compositional twin-pass certificates."""
import copy,json,subprocess
from recover_daemon_mode_one_source_passes import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_reader_outer_lifecycle import Engine as Parent
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix,split
SOLVER='/opt/homebrew/bin/z3'
EXTRA=''.join(f'(declare-fun A{j} () (_ BitVec 32))\n'for j in range(4))+''.join(f'(declare-fun {n} () (_ BitVec 32))\n'for n in ['IDX','REM','V0','V1','V2','V3','V4'])+'(declare-fun FLAG_LO () Bool)\n'
def add(*xs):return '(bvadd '+' '.join(xs)+')'
def sub(x,y):return f'(bvsub {x} {y})'
def xo(*xs):
 e=xs[0]
 for x in xs[1:]:e=f'(bvxor {e} {x})'
 return e
class Engine(Parent):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   ps=split(i['operands']);mn=i['mnemonic']
   if pc in getattr(self,'captures',{}):
    target,fn=self.captures[pc];self.cut_values[target]=fn(self)
   if pc in getattr(self,'cut_values',{})or pc in getattr(self,'cuts',{}):
    v=self.cut_values[pc]if pc in self.cut_values else self.cuts[pc];v=v(self)if callable(v)else v;self.put(ps[0],v);self.sites.append(i['ea'])
   elif mn=='neg':self.put(ps[0],f'(bvneg {self.get(ps[1],32)})');self.sites.append(i['ea'])
   elif mn=='umull':self.put(ps[0],f'(bvmul ((_ zero_extend 32) {self.get(ps[1],32)}) ((_ zero_extend 32) {self.get(ps[2],32)}))');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
def canonical():
 dd=[]
 def val(n,e):dd.append(f'(define-fun {n} () (_ BitVec 32) {e})\n');return n
 zz=val('C_Z',add(sub('(bvmul (bvadd ((_ zero_extend 24) B0) IDX) #x5b9896c1)','A1'),'#x761e1051'))
 tt=val('C_t',xo(sub(sub('VALUE','A0'),'A2'),'#x9abad348'));uu=val('C_u',xo(tt,'A3'));aa=val('C_a',add('A0',uu));cc=val('C_c',sub('A2',uu));vv=val('C_v',xo(add(sub(f'((_ rotate_left 3) {uu})',aa),cc),tt));bb=val('C_b',add(vv,'#x1b392e51'));hh=val('C_h',xo(f'((_ rotate_left 1) {bb})',aa,bb));ss=val('C_s',add(sub(add(vv,tt),add(cc,bb)),hh));ww=val('C_w',add(ss,'#x0b1139f2'));rr=val('C_r',add(vv,tt,'#x1b392e51',ww));nn=val('C_n',xo(ww,aa,bb));bn=val('C_B',add(xo(add(nn,f'((_ rotate_left 2) {ww})'),rr,ww,add(cc,bb)),'#x17debfe5'));an=val('C_A',add(bn,nn));cn=val('C_C',xo(bn,ww,add(cc,bb)));dn=val('C_D',add(bn,rr));return ''.join(dd)
class WordNormalForm:
 """Exact u32 ring/XOR/rotation DAG normal forms after source-proved cuts.
 O(N^2 log N) time/O(N^2) space worst case;no target code execution.
 """
 def __init__(self,text):
  import re
  tt=re.findall(r'\(|\)|[^\s()]+',text);k=0
  def parse():
   nonlocal k
   t=tt[k];k+=1
   if t!='(':return t
   out=[]
   while tt[k]!=')':out.append(parse())
   k+=1;return out
  roots=[]
  while k<len(tt):roots.append(parse())
  self.defs={q[1]:(int(q[3][2]),q[4])for q in roots if q and q[0]=='define-fun'};self.widths={q[1]:int(q[3][2])for q in roots if q and q[0]=='declare-fun'and isinstance(q[3],list)and q[3][:2]==['_','BitVec']};self.nodes=[];self.ids={};self.memo={}
 def intern(self,key):
  if key not in self.ids:self.ids[key]=len(self.nodes);self.nodes.append(key)
  return self.ids[key]
 def constant(self,n):return self.intern(('const',n&0xffffffff))
 def plus(self,pairs):
  values={};c=0
  def append(v,scale):
   nonlocal c
   n=self.nodes[v]
   if n[0]=='const':c=(c+n[1]*scale)&0xffffffff
   elif n[0]=='add':
    c=(c+n[1]*scale)&0xffffffff
    for a,b in n[2]:append(a,b*scale)
   else:values[v]=(values.get(v,0)+scale)&0xffffffff
  for a,b in pairs:append(a,b)
  terms=tuple(sorted((a,b)for a,b in values.items()if b))
  if not terms:return self.constant(c)
  if c==0 and len(terms)==1 and terms[0][1]==1:return terms[0][0]
  return self.intern(('add',c,terms))
 def xors(self,args):
  c=0;terms=set()
  def append(v):
   nonlocal c
   n=self.nodes[v]
   if n[0]=='const':c^=n[1]
   elif n[0]=='xor':
    c^=n[1]
    for a in n[2]:append(a)
   elif v in terms:terms.remove(v)
   else:terms.add(v)
  for a in args:append(a)
  if not terms:return self.constant(c)
  if not c and len(terms)==1:return next(iter(terms))
  return self.intern(('xor',c,tuple(sorted(terms))))
 def expression(self,text):
  import re
  tt=re.findall(r'\(|\)|[^\s()]+',text);k=0
  def p():
   nonlocal k
   t=tt[k];k+=1
   if t!='(':return t
   o=[]
   while tt[k]!=')':o.append(p())
   k+=1;return o
  x=p();assert k==len(tt);return self.norm(x)
 def width(self,x):
  if isinstance(x,str):
   if x.startswith('#x'):return 4*(len(x)-2)
   return self.defs[x][0]if x in self.defs else self.widths[x]
  op=x[0]
  if isinstance(op,list):
   if op[1]=='extract':return int(op[2])-int(op[3])+1
   if op[1]=='zero_extend':return self.width(x[1])+int(op[2])
   assert op[1]in('rotate_left','rotate_right');return self.width(x[1])
  return self.width(x[1])
 def norm(self,x):
  if isinstance(x,str):
   if x.startswith('#x'):return self.constant(int(x[2:],16))
   if x in self.memo:return self.memo[x]
   if x in self.defs:
    width,expr=self.defs[x];assert width in(32,64);v=self.norm(expr)
   else:v=self.intern(('var',x,self.widths.get(x,32)))
   self.memo[x]=v;return v
  op=x[0]
  if isinstance(op,list):
   assert op[0]=='_';kind=op[1]
   if kind in('extract','zero_extend'):
    if kind=='extract':assert op[2:] in(['31','0'],['15','0'],['7','0'])
    # Every reachable cast is a low32 projection of a zero-extended word.
    if kind=='extract'and op[2:]!=['31','0']:return self.intern(('extract',op[2],op[3],self.norm(x[1])))
    return self.norm(x[1])
   assert kind in('rotate_left','rotate_right')and self.width(x[1])==32,op;n=int(op[2])%32
   if kind=='rotate_right':n=(-n)%32
   v=self.norm(x[1]);return v if not n else self.intern(('rol',n,v))
  args=[self.norm(q)for q in x[1:]]
  if op=='bvadd':return self.plus([(v,1)for v in args])
  if op=='bvsub':assert len(args)==2;return self.plus([(args[0],1),(args[1],-1)])
  if op=='bvneg':return self.plus([(args[0],-1)])
  if op=='bvxor':return self.xors(args)
  if op=='bvmul':
   assert len(args)==2
   for j,v in enumerate(args):
    if self.nodes[v][0]=='const':return self.plus([(args[1-j],self.nodes[v][1])])
   return self.intern(('mul',tuple(sorted(args))))
  if op in('bvand','bvor','bvnot'):
   if all(self.nodes[v][0]=='const'for v in args):
    values=[self.nodes[v][1]for v in args];result=~values[0]if op=='bvnot'else values[0]&values[1]if op=='bvand'else values[0]|values[1];return self.constant(result)
   return self.intern((op,tuple(args)))
  if op=='bvshl':
   assert self.width(x[1])==32 and self.nodes[args[1]][0]=='const';n=self.nodes[args[1]][1];return self.constant(0)if n>=32 else self.plus([(args[0],1<<n)])
  raise AssertionError(('unsupported reachable state operation',op))
def certificates(s):
 pp=[];tr={};normal=[];fs=s['fragments'];can=canonical();frame=lambda off:f'(bvadd K {bv(off)})';at=lambda ix:f'(bvadd TABLE {bv(ix*8)})'
 def solve(n,body,result='unsat',note='',integer=False):
  decl='(declare-fun XI () Int)\n'if integer else DECL+EXTRA+can;q='(set-option :timeout 15000)\n(set-logic '+('QF_LIA'if integer else'QF_BV')+')\n'+decl+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr);pp.append({'name':n,'query':q,'result':result,'scope':SCOPE+' '+note,'reused_lemma':False});print(n,result,flush=True)
 def part(n,label=None,r=None,loads=None,chain=None,a=None,end=None,cuts=None,captures=None):
  label=label or n;f=fs[n];a=a or int(f['start'],16);end=end or int(f['instructions'][-1]['ea'],16);ii=[i for i in f['instructions']if a<=int(i['ea'],16)<end];ll={};dd=[]
  for i in ii:
   if i['mnemonic']in('ldr','ldrb','ldrh','ldrsh','ldur'):
    w=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']in('ldrh','ldrsh')else 32 if i['operands'].startswith('w')else 64;n0=label+'_L'+str(len(dd));dd.append(f'(declare-fun {n0} () (_ BitVec {w}))');ll[i['ea']]=(n0,w)
  ll.update(loads or{});rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K'
  if chain:rr.update({j:chain[-1].get('x'+str(j))for j in range(31)})
  rr.update(r or{});g=Engine(rr,ll,namespace=label+'_');g.cuts=cuts or{};g.captures=captures or{};g.cut_values={};g.flags={'lo':'false'if label=='first_round'else'FLAG_LO'};g.run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';tr[label]=g.record();return(chain or[])+[g]
 def cert(n,gs,tt,cc=(),note=''):solve(n,prefix(*gs)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(tt)+'))',note=note)
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def store(g,pc,a,v):q=next(q for q in g.stores if q['site']==hex(pc));return[neq(q['address'],a),neq(q['value'],v)]
 ent=part('entry',r={19:bv(0x4923),13:bv(0x16f293e0),25:'BUF'},loads={'0x100d5e02c':('TABLE',64)});g=ent[-1]
 cert('LEN32_entry_selects_source_seed_and_two_local_views',ent,[neq(rd(g,0x100d5e030)['address'],at(0xbce2)),neq(g.get('w12'),'#x00002e5e'),neq(g.get('x30'),'BUF')]+store(g,0x100d5dfdc,frame(0x758),frame(0x8b0))+store(g,0x100d5dfe4,frame(0x738),frame(0xd00)))
 seed=part('seed',chain=ent,loads={'0x100d77754':('#x16f293e0',32)});g=seed[-1];initial=[0x49fe8fbf,0x6bae77d6,0xc2864be0,0x14267dee]
 cert('first_pass_initial_state_counters_and_loop_target',seed,[neq(g.get('w'+str(j)),bv(v,32))for j,v in enumerate(initial)]+[neq(g.get('w8'),'#x0000bd2a'),neq(g.get('w4'),'#x8bc9588b'),neq(g.get('w11'),'#xf9bdc98a'),neq(g.get('w13'),'#x7436a775'),neq(g.get('w14'),'#x1edb6ce2'),neq(g.get('w15'),'#xf9bdc96b'),neq(g.get('w16'),'#xf9bdc96a'),neq(rd(g,0x100d777b0)['address'],at(0x2e5e))]+store(g,0x100d777e8,frame(0x748),'#x5cffd950'))
 base={j:g.get('x'+str(j))for j in range(31)};base.update({j:z('A'+str(j))for j in range(4)});base.update({13:z('(bvadd IDX #x7436a775)'),14:z('(bvadd IDX #x1edb6ce2)'),15:z('(bvadd IDX #xf9bdc96b)')});domain='(bvult IDX #x00000020)';ld={'0x100b035b4':('B0',8)}
 inject=part('first','first_inject',r=base,loads=ld,chain=seed,end=0x100b035f0);g=inject[-1]
 cert('first_pass_byte_address_and_compact_injection',inject,[neq(rd(g,0x100b035b4)['address'],'(bvadd BUF ((_ zero_extend 32) IDX))'),neq(g.get('w17'),'C_Z'),neq(g.flags['lo'],'false')],[domain])
 quotient=part('first','quotient',r={17:z('VALUE')},a=0x100b035f0,end=0x100b03600);g=quotient[-1];qq='(bvlshr (bvmul ((_ zero_extend 32) VALUE) #x00000000ff00ff01) #x0000000000000028)'
 cert('original_UMULL_shift_expression',quotient,[neq(g.get('x1'),qq)])
 rem='(bvsub VALUE (bvadd V0 (bvshl V0 #x00000008)))'
 qr=part('first','remainder',r={17:z('VALUE'),1:z('V0')},a=0x100b03600,end=0x100b0360c);g=qr[-1]
 cert('original_word_remainder_and_XOR',qr,[neq(g.get('w1'),rem),neq(g.get('w17'),xo('VALUE',rem))],note='V0 is low32 of the preceding proved unsigned quotient;the integer theorem proves its exact value and range.')
 solve('reciprocal257_exact_for_every_u32','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or (distinct (div (* XI 4278255361) 1099511627776) (div XI 257)) (>= (* XI 4278255361) 18446744073709551616)))',integer=True,note='UMULL product has no u64 wrap;LSR40 is exact floor division by2^40. 257*ff00ff01=2^40+1 and XI<2^32 justify the integer/BV correspondence.')
 solve('quotient_shift_add257_has_no_u32_wrap','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or (> (div XI 257) 16711935) (>= (* 256 (div XI 257)) 4294967296) (>= (+ (div XI 257) (* 256 (div XI 257))) 4294967296)))',integer=True,note='The source32-bit quotient shift/add equals257*q without intermediate overflow;links the exact word remainder to the integer division theorem.')
 solve('remainder257_range_and_identity','(assert (and (<= 0 XI) (< XI 4294967296)))\n(assert (or (< (- XI (* 257 (div XI 257))) 0) (>= (- XI (* 257 (div XI 257))) 257)))',integer=True,note='This is the source remainder consumed by the XOR,not a numerical sample or target execution.')
 # Small universal source slices justify each MBA cut used by the full round certificate.
 cases=[('rotate3_source_identity',0x100b0364c,0x100b03654,{3:z('(bvshl V0 #x00000003)'),1:z('V0'),0:z('V1')},'w1',sub('((_ rotate_left 3) V0)','V1')),('c_update',0x100b0362c,0x100b03648,{2:z('V0'),1:z('V1')},'w2',sub('V0','V1')),
 ('h_update',0x100b03668,0x100b03680,{3:z('V0'),0:z(xo('V1','#x1d40b1e0','V0'))},'w19',xo('((_ rotate_left 1) V0)','V1','V0')),
 ('n_update',0x100b03694,0x100b036ac,{17:z('V0'),0:z(xo('V1','#x1d40b1e0','V2'))},'w17',xo(add('V0','#x0b1139f2'),'V1','V2')),
 ('r_update',0x100b036d0,0x100b036e0,{19:z('V0'),0:z('V1')},'w2',xo('V0','#x0e019e96','V1')),
 ('last_c_update',0x100b036f4,0x100b03708,{1:z('V0'),2:z(sub('V0','#x17debfe5')),0:z('V1')},'w2',xo('V0','V1'))]
 for n,a,end,regs,out,want in cases:
  rr={j:seed[-1].get('x'+str(j))for j in range(31)};rr.update(regs);gs=part('first',n,r=rr,a=a,end=end,chain=seed);cert(n,gs,[neq(gs[-1].get(out),want)])
 captures={0x100b0362c:(0x100b03644,lambda g:sub(g.get('w2'),g.get('w1'))),0x100b0364c:(0x100b03650,lambda g:sub('((_ rotate_left 3) '+g.get('w1')+')',g.get('w0'))),0x100b03668:(0x100b0367c,lambda g:xo('((_ rotate_left 1) '+g.get('w3')+')','#x1d40b1e0',g.get('w0'))),0x100b03694:(0x100b036a8,lambda g:xo(add(g.get('w17'),'#x0b1139f2'),'#x1d40b1e0',g.get('w0'))),0x100b036d0:(0x100b036dc,lambda g:xo(g.get('w19'),'#x0e019e96',g.get('w0'))),0x100b036f4:(0x100b03704,lambda g:xo(g.get('w1'),g.get('w0')))}
 full=part('first','first_round',r={**base,17:z('VALUE')},loads={'0x100b03720':('FN',64)},chain=seed,a=0x100b0360c,captures=captures);g=full[-1]
 nf=WordNormalForm(DECL+EXTRA+can+prefix(*full));pairs=[(nf.expression(g.get('w'+str(j))),nf.expression(v))for j,v in enumerate(['C_A','C_B','C_C','C_D'])];assert all(x==y for x,y in pairs),('first',pairs,nf.nodes)
 normal.append({'name':'first_round_compact_four_word_recurrence','method':'u32 ring/XOR/rotation DAG canonicalization after source-proved live-register cuts','paired_output_node_ids':pairs,'nodes':nf.nodes,'all_equal':True,'remainder_binding':'VALUE = C_Z XOR(C_Z mod257),from source quotient and integer lemmas','monolithic_SMT_query_excluded':'unknown after15000 ms'})
 cert('first_pass_control_reads32_bytes_in_order',full,[neq(rd(g,0x100b03720)['address'],f'(ite (bvult IDX #x0000001f) {at(0xbd2a)} {at(0xbd5a)})'),neq(g.get('w13'),'(bvadd IDX #x7436a776)'),neq(g.get('w14'),'(bvadd IDX #x1edb6ce3)'),neq(g.get('w15'),'(bvadd IDX #xf9bdc96c)')],[domain])
 between=part('between',r={0:z('A0'),1:z('A1'),2:z('A2'),3:z('A3')},chain=seed,loads={'0x100d64e34':('#x5cffd950',32),'0x100d64e44':('#x16f293e0',32)});g=between[-1]
 cert('second_pass_reseeds_same_words_and_preserves_first_bank',between,[neq(g.get('w'+str(j)),v)for j,v in zip([8,13,11,23],map(lambda x:bv(x,32),initial))]+[neq(g.get('w'+str(j)),'A'+str(j))for j in range(4)]+[neq(g.get('x30'),'BUF'),neq(g.get('w12'),'#x00001520'),neq(g.get('w14'),'#x0000303e'),neq(g.get('w16'),'#xb275bb7a'),neq(g.get('w4'),'#xb275bb5a'),neq(g.get('w26'),'#x3bb4f453'),neq(rd(g,0x100d64ec8)['address'],at(0x303e))])
 sb={j:g.get('x'+str(j))for j in range(31)};sb.update({8:z('A0'),13:z('A1'),11:z('A2'),23:z('A3'),26:z('(bvadd IDX #x3bb4f453)')})
 si=part('second','second_inject',r=sb,chain=between,loads={'0x100d9f110':('B0',8)},end=0x100d9f158);g=si[-1]
 cert('second_pass_same_source_byte_and_compact_injection',si,[neq(rd(g,0x100d9f110)['address'],'(bvadd BUF ((_ zero_extend 32) IDX))'),neq(g.get('w10'),'C_Z'),neq(g.get('w17'),'#x00000000'),neq(g.get('w15'),'#x00003d26')],[domain])
 scases=[('second_v_association',0x100d9f19c,0x100d9f1a0,{22:z('(bvadd V0 V1)'),8:z('V2')},'w13',add(sub('V0','V2'),'V1')),('second_h_update',0x100d9f1b4,0x100d9f1c8,{22:z('V0'),8:z(xo('V1','#x3f515c36','V0'))},'w22',xo('((_ rotate_left 1) V0)','V1','V0')),
 ('second_n_update',0x100d9f1d4,0x100d9f1f0,{13:z('V0'),8:z(xo('V1','#x3f515c36','V2'))},'w8',xo(add('V0','#x0b1139f2'),'V1','V2')),
 ('second_r_update',0x100d9f220,0x100d9f230,{10:z('V0'),11:z('V1')},'w13',xo('V0','#x9d94625f','V1'))]
 for n,a,end,regs,out,want in scases:
  rr={j:between[-1].get('x'+str(j))for j in range(31)};rr.update(regs);gs=part('second',n,r=rr,a=a,end=end,chain=between);cert(n,gs,[neq(gs[-1].get(out),want)])
 scaptures={0x100d9f194:(0x100d9f19c,lambda g:add(sub(g.get('w22'),add(g.get('w8'),g.get('w13'))),g.get('w11'))),0x100d9f1b4:(0x100d9f1c4,lambda g:xo('((_ rotate_left 1) '+g.get('w22')+')','#x3f515c36',g.get('w8'))),0x100d9f1d4:(0x100d9f1ec,lambda g:xo(add(g.get('w13'),'#x0b1139f2'),'#x3f515c36',g.get('w8'))),0x100d9f220:(0x100d9f22c,lambda g:xo(g.get('w10'),'#x9d94625f',g.get('w11')))}
 sf=part('second','second_round',r={**sb,10:z('VALUE'),17:bv(0),15:bv(0x3d26)},chain=between,loads={'0x100d9f25c':('FN',64)},a=0x100d9f174,captures=scaptures);g=sf[-1]
 nf=WordNormalForm(DECL+EXTRA+can+prefix(*sf));pairs=[(nf.expression(g.get('w'+str(j))),nf.expression(v))for j,v in zip([8,13,11,23],['C_A','C_B','C_C','C_D'])];assert all(x==y for x,y in pairs),('second',pairs,nf.nodes)
 normal.append({'name':'second_round_same_compact_four_word_recurrence','method':'same exact normal form,with independently proved second-body source cuts','paired_output_node_ids':pairs,'nodes':nf.nodes,'all_equal':True,'remainder_binding':'same source byte/index,C_Z and exact reduction257'})
 cert('second_pass_control_reads32_bytes_in_order',sf,[neq(rd(g,0x100d9f25c)['address'],f'(ite (bvult IDX #x0000001f) {at(0x303e)} {at(0x306c)})'),neq(g.get('w26'),'(bvadd IDX #x3bb4f454)'),neq(g.get('x30'),'BUF')],[domain])
 # Second quotient implementation uses the identical exact unsigned product/shift idiom.
 sr=part('second','second_quotient',r={10:z('VALUE')},a=0x100d9f158,end=0x100d9f168);g=sr[-1]
 cert('second_UMULL_shift_is_same_quotient',sr,[neq(g.get('x13'),qq)])
 sr=part('second','second_remainder',r={10:z('VALUE'),13:z('V0')},a=0x100d9f168,end=0x100d9f174);g=sr[-1]
 cert('second_word_remainder_is_same_expression',sr,[neq(g.get('w13'),rem),neq(g.get('w10'),xo('VALUE',rem))])
 hand=part('handoff',r={0:'Z0',1:'Z1',2:'Z2',3:'Z3',8:z('A0'),13:z('A1'),11:z('A2'),23:z('A3'),30:'BUF',15:bv(0x3d26),9:'TABLE'},loads={'0x100d5e3f0':(frame(0xd00),64),'0x100d5e3f4':('TABLE',64)});g=hand[-1]
 tt=[neq(g.get('x'+str(j)),'Z'+str(j))for j in range(4)]+[neq(rd(g,0x100d5e390)['address'],at(0x3d26)),neq(g.get('x11'),frame(0xd00)),neq(g.get('x8'),'TABLE')]
 for pc,off,v in [(0x100d5e37c,0x720,'A1'),(0x100d5e380,0x728,'A2'),(0x100d5e384,0x730,'A3'),(0x100d5e388,0x748,'A0'),(0x100d5e38c,0x458,'BUF')]:tt+=store(g,pc,frame(off),v)
 cert('handoff_spills_second_bank_and_retains_first_bank',hand,tt,note='Second-bank values land in four4 B frame cells;first-bank registers0..3 remain untouched. Deeper consumers/serialization and native output ownership remain unproved.')
 semantic=[]
 for name,changed,outputs in [('wrong_final_additive',can.replace('#x17debfe5','#x17debfe4'),['C_A','C_B','C_C','C_D']),('wrong_rotation',can.replace('((_ rotate_left 2) C_w)','((_ rotate_left 1) C_w)'),['C_A','C_B','C_C','C_D']),('swapped_C_D',can,['C_A','C_B','C_D','C_C']),('wrong_t_constant',can.replace('#x9abad348','#x9abad349'),['C_A','C_B','C_C','C_D'])]:
  test=WordNormalForm(DECL+EXTRA+changed+prefix(*full));equal=[test.expression(full[-1].get('w'+str(j)))==test.expression(v)for j,v in enumerate(outputs)];assert not all(equal),name;semantic.append({'name':name,'rejected_by_source_normal_form':True})
 normal.append({'name':'semantic_negative_controls','cases':semantic,'all_rejected':True})
 collisions=[]
 for st in s['frame_store_ledger']:
  for j in range(st['width_bytes']):
   for k in range(8):collisions.append('(= '+frame(st['frame_offset']+j)+' '+frame(0x1210+k)+')')
 cert('retained72_frame_bytes_do_not_overlap_budget',[],collisions,note='Fixed core frame F=K;budget BP=F+1210 from the parent frame contract. No SP writes,calls or other memory-write instructions occur in the six retained ranges. Later handoff targets are outside this preservation theorem.')
 solve('whole_source_byte_domain_is_nonempty','(assert (bvult IDX #x00000020))\n(assert (bvule REM #x00000100))','sat',note='Abstract nonempty domain check,not a native state or target input.')
 return pp,tr,normal
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_round_multiplier',lambda t:t['fragments']['first']['instructions'][11].__setitem__('operands','w19, #0')),('wrong_divisor_reciprocal',lambda t:t['fragments']['first']['instructions'][17].__setitem__('operands','w1, #1')),('missing_second_pass',lambda t:t['fragments'].pop('second')),('wrong_handoff_word',lambda t:t['fragments']['handoff']['instructions'][0].__setitem__('operands','w11, [sp, #0x720]')),('invent_output_publication',lambda t:t.__setitem__('public_output_published',True)),('invent_native',lambda t:t.__setitem__('native_target_executed',True))];out=[]
 for n,op in ops:t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,normal=certificates(s);aa=alterations(s);sites={pc for q in tr.values()for pc in q['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'};assert sites==expected,(expected-sites,sites-expected)
 counts={**s['verified_source_counts'],'new_queries_unsat':sum(q['result']=='unsat'for q in pp),'reused_queries_unsat':0,'counterexamples_sat':sum(q['result']=='sat'for q in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'algebraic_round_certificates':sum('paired_output_node_ids'in q for q in normal),'algebraic_output_equalities':sum(len(q.get('paired_output_node_ids',[]))for q in normal),'semantic_negative_controls':4,'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_outer_lifecycle.py':sha(ROOT/'validate_daemon_reader_outer_lifecycle.py')},'canonical_recurrence_SMT':canonical(),'proofs':pp,'algebraic_normal_forms':normal,'translations':tr,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'induction_argument':{'base':'first_pass_initial_state_counters_and_loop_target and second_pass_reseeds_same_words_and_preserves_first_bank','step':'first_round_compact_four_word_recurrence and second_round_same_compact_four_word_recurrence;live source-register snapshots justify each MBA cut','length':'both control certificates:indices0..31,exactly32 rounds','memory_premise':'same stable SRC bytes;no loop stores/calls,between-frame stores disjoint from SRC','conclusion':'equal four-word final banks,not native output publication'},'source_recapture_match':True,'all_checks_pass':True,'two_pass_equal_recurrences_proved':True,'complete_parser_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
