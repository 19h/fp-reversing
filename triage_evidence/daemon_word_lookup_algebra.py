#!/usr/bin/env python3
"""Typed source-SMT DAG,explicit rewrite ledger and bounded arithmetic facts."""
import re,functools
T=re.compile(r'\(|\)|[^\s()]+')
def parse(text):
 if not text.lstrip().startswith("("):return text.strip()
 stack=[];root=None
 for t in T.findall(text):
  if t=='(':v=[];stack.append(v)
  elif t==')':
   v=stack.pop()
   if stack:stack[-1].append(v)
   else:root=v
  else:stack[-1].append(t)
 return root
class DAG:
 def __init__(self):self.nodes=[];self.keys={};self.alias={};self.rewrites=[]
 def record(self,rule,lhs,rhs,decl='',bindings=None,result=None):
  self.rewrites.append({'rule':rule,'lhs':lhs,'rhs':rhs,'declarations':decl,'bindings':bindings or{},'result_node':result})
 def lit(self,v,w):return f'(_ bv{v%2**w} {w})'
 def intern(self,key,w):
  k=(key,w)
  if k not in self.keys:self.keys[k]=len(self.nodes);self.nodes.append((key,w))
  return self.keys[k]
 def cn(self,v,w):return self.intern(('const',v%2**w),w)
 def const(self,x):k,w=self.nodes[x];return k[1]if k[0]=='const'else None
 def get(self,e):
  if isinstance(e,str):
   if e.startswith('#x'):return self.cn(int(e[2:],16),4*(len(e)-2))
   if e.startswith('#b'):return self.cn(int(e[2:],2),len(e)-2)
   if e in self.alias:return self.alias[e]
   w=8 if re.fullmatch('B[0-9]+',e)else 32 if e in['IX','VALUE','SIZE','TAG','PL']or e.startswith('WORD')else 64
   return self.intern(('sym',e),w)
  op=e[0]
  if isinstance(op,list):
   c=self.get(e[1]);k,w=self.nodes[c];value=self.const(c)
   if op[1]=='zero_extend':
    n=int(op[2]);nw=w+n
    if value is not None:
     out=self.cn(value,nw);self.record('constant_fold',f'((_ zero_extend {n}) {self.lit(value,w)})',self.lit(value,nw),result=out);return out
    if not n:
     self.record('zero_extend_identity','((_ zero_extend 0) A)','A',f'(declare-fun A () (_ BitVec {w}))',{'A':c},c);return c
    if k[0]=='zext':
     base=k[1];bw=self.nodes[base][1];out=self.intern(('zext',base),nw);self.record('zero_extend_composition',f'((_ zero_extend {n}) ((_ zero_extend {w-bw}) A))',f'((_ zero_extend {nw-bw}) A)',f'(declare-fun A () (_ BitVec {bw}))',{'A':base},out);return out
    return self.intern(('zext',c),nw)
   if op[1]in ['rotate_right','rotate_left']:
    n=int(op[2]);return self.intern((op[1],c,n),w)
   assert op[1]=='extract',e;hi,lo=map(int,op[2:]);nw=hi-lo+1
   assert 0<=lo<=hi<w
   if value is not None:
    out=self.cn(value>>lo,nw);self.record('constant_fold',f'((_ extract {hi} {lo}) {self.lit(value,w)})',self.lit(value>>lo,nw),result=out);return out
   if nw==w:
    self.record('extract_identity',f'((_ extract {hi} {lo}) A)','A',f'(declare-fun A () (_ BitVec {w}))',{'A':c},c);return c
   if k[0]=='zext':
    base=k[1];bw=self.nodes[base][1]
    if hi<bw:
     out=self.extract(base,hi,lo);rhs='A'if nw==bw else f'((_ extract {hi} {lo}) A)';self.record('extract_zero_extended_low',f'((_ extract {hi} {lo}) ((_ zero_extend {w-bw}) A))',rhs,f'(declare-fun A () (_ BitVec {bw}))',{'A':base},out);return out
    if lo==0 and nw>=bw:
     out=self.intern(('zext',base),nw)if nw>bw else base;rhs=f'((_ zero_extend {nw-bw}) A)'if nw>bw else'A';self.record('extract_zero_extended_resize',f'((_ extract {hi} {lo}) ((_ zero_extend {w-bw}) A))',rhs,f'(declare-fun A () (_ BitVec {bw}))',{'A':base},out);return out
   if k[0]=='extract':
    base=k[1];bw=self.nodes[base][1];out=self.extract(base,hi+k[3],lo+k[3]);rhs='A'if nw==bw else f'((_ extract {hi+k[3]} {lo+k[3]}) A)';self.record('extract_composition',f'((_ extract {hi} {lo}) ((_ extract {k[2]} {k[3]}) A))',rhs,f'(declare-fun A () (_ BitVec {bw}))',{'A':base},out);return out
   return self.intern(('extract',c,hi,lo),nw)
  if op=='ite':
   a,b,c=[self.get(x)for x in e[1:]];return self.intern(('ite',a,b,c),self.nodes[b][1])
  cs=[self.get(x)for x in e[1:]];w=self.nodes[cs[0]][1]
  vals=[self.const(x)for x in cs]
  if all(v is not None for v in vals):
   a=vals[0];b=vals[1]if len(vals)>1 else None
   funcs={'bvadd':lambda:a+b,'bvsub':lambda:a-b,'bvmul':lambda:a*b,'bvand':lambda:a&b,'bvor':lambda:a|b,'bvxor':lambda:a^b,'bvnot':lambda:~a,'bvshl':lambda:a<<b,'bvlshr':lambda:a>>b,'bvneg':lambda:-a}
   if op in funcs:
    out=self.cn(funcs[op](),w);self.record('constant_fold','('+op+' '+' '.join(self.lit(v,self.nodes[c][1])for v,c in zip(vals,cs))+')',self.lit(funcs[op](),w),result=out);return out
  before=list(cs)
  if op in['bvadd','bvmul','bvand','bvor','bvxor']:cs.sort()
  out=self.intern(tuple([op]+cs),1 if op in['=','distinct','bvult','bvugt','bvslt','bvsge','and','not']else w)
  if before!=cs:self.record('commutativity','('+op+' A B)','('+op+' B A)',f'(declare-fun A () (_ BitVec {w}))\n(declare-fun B () (_ BitVec {w}))',{'A':before[0],'B':before[1]},out)
  return out
 def extract(self,c,hi,lo):
  w=self.nodes[c][1]
  assert 0<=lo<=hi<w
  if hi-lo+1==w:
   self.record('extract_identity',f'((_ extract {hi} {lo}) A)','A',f'(declare-fun A () (_ BitVec {w}))',{'A':c},c);return c
  return self.intern(('extract',c,hi,lo),hi-lo+1)
 def show(self,x,depth=3):
  k,w=self.nodes[x]
  if k[0]=='const':return hex(k[1])+':'+str(w)
  if k[0]=='sym':return k[1]+':'+str(w)
  if depth<=0:return '@'+str(x)+':'+str(w)
  if k[0]=='extract':return f'extract({self.show(k[1],depth-1)},{k[2]},{k[3]})'
  return k[0]+'('+','.join(self.show(a,depth-1)for a in k[1:])+')'
 def defs(self,text):
  for line in text.splitlines():
   e=parse(line);assert e[0]=='define-fun'and e[1]not in self.alias;self.alias[e[1]]=self.get(e[4]);assert self.nodes[self.alias[e[1]]][1]==int(e[3][2])
 def index(self,address):
  a=self.get(parse(address));k,w=self.nodes[a];assert k[0]=='bvadd',self.show(a);root=[x for x in k[1:]if self.nodes[x][0][0]=='zext']
  if root:
   v=self.nodes[root[0]][0][1];return v
  # Named pointer aliases reduce to the same root+zero-extended index.
  raise AssertionError(self.show(a))

def range_engine(d):
 @functools.lru_cache(None)
 def abstract(x):
  k,w=d.nodes[x];mask=2**w-1;op=k[0];v=d.const(x)
  if v is not None:return(v,v,mask^v,v)
  if op=='sym':
   lo,hi=0,mask
   dif=lo^hi;vary=(1<<dif.bit_length())-1;one=lo&~vary;zero=mask^(one|vary);return lo,hi,zero,one
  if op in['zext','extract','rotate_right','rotate_left']:
   a=abstract(k[1]);aw=d.nodes[k[1]][1]
   if op=='zext':lo,hi,zr,on=a;return lo,hi,zr|(mask^(2**aw-1)),on
   if op=='extract':
    sh=k[3];zr=(a[2]>>sh)&mask;on=(a[3]>>sh)&mask
    if a[0]>>(sh+w)==a[1]>>(sh+w):lo,hi=(a[0]>>sh)&mask,(a[1]>>sh)&mask
    else:lo,hi=on,mask^zr
    return max(lo,on),min(hi,mask^zr),zr,on
   n=k[2]%w
   def rot(v):return((v>>n)|(v<<(w-n)))&mask if op=='rotate_right'else((v<<n)|(v>>(w-n)))&mask
   zr,on=rot(a[2]),rot(a[3]);return on,mask^zr,zr,on
  args=[abstract(v)for v in k[1:]];a=args[0];b=args[1]if len(args)>1 else None;lo,hi,zr,on=0,mask,0,0
  if op=='ite':
   aa,bb=args[1:];lo,hi,zr,on=min(aa[0],bb[0]),max(aa[1],bb[1]),aa[2]&bb[2],aa[3]&bb[3]
  elif op=='bvand':zr,on=a[2]|b[2],a[3]&b[3]
  elif op=='bvor':zr,on=a[2]&b[2],a[3]|b[3]
  elif op=='bvxor':zr,on=(a[2]&b[2])|(a[3]&b[3]),(a[3]&b[2])|(a[2]&b[3])
  elif op in['bvnot','bvneg']:
   if op=='bvnot':zr,on=a[3],a[2]
  elif op in['bvadd','bvsub','bvmul']:
   if op=='bvadd':ll,hh=a[0]+b[0],a[1]+b[1]
   elif op=='bvsub':ll,hh=a[0]-b[1],a[1]-b[0]
   else:ll,hh=a[0]*b[0],a[1]*b[1]
   if ll//(mask+1)==hh//(mask+1):
    lo,hi=ll&mask,hh&mask;vary=(1<<(lo^hi).bit_length())-1;on=lo&~vary;zr=mask^(on|vary)
  elif op in['bvshl','bvlshr']:
   if b[0]==b[1]:
    n=b[0]
    if n>=w:zr=mask;lo=hi=0
    elif op=='bvlshr':zr=(a[2]>>n)|(((1<<n)-1)<<(w-n));on=a[3]>>n;lo,hi=a[0]>>n,a[1]>>n
    else:
     zr=((a[2]<<n)|((1<<n)-1))&mask;on=(a[3]<<n)&mask
     if a[1]<<n<=mask:lo,hi=a[0]<<n,a[1]<<n
   elif op=='bvlshr':lo,hi=(a[0]>>b[1]if b[1]<w else 0),(a[1]>>b[0]if b[0]<w else 0)
  elif op=='bvudiv':
   if b[0]>0:lo,hi=a[0]//b[1],a[1]//b[0]
  elif w==1:lo,hi=0,1
  else:raise AssertionError(op)
  lo,hi=max(lo,on),min(hi,mask^zr);assert 0<=lo<=hi<=mask,(x,k,lo,hi,zr,on)
  vary=(1<<(lo^hi).bit_length())-1;on|=lo&~vary;zr|=mask^((lo&~vary)|vary)
  return lo,hi,zr,on
 return abstract

BOOL={'=','distinct','bvult','bvugt','bvslt','bvsge','and','not'}
def literal(v,w):return f'(_ bv{v} {w})'
def typ(d,x):return'Bool'if d.nodes[x][0][0]in BOOL else f'(_ BitVec {d.nodes[x][1]})'
def ref(d,x):
 k,w=d.nodes[x]
 if k[0]=='const':return literal(k[1],w)
 if k[0]=='sym':return k[1]
 return'CB'+str(x)
def expression(d,x,refs=None):
 k,w=d.nodes[x];op=k[0];rr=refs if refs is not None else [ref(d,a)for a in children(d,x)]
 if op=='zext':return f'((_ zero_extend {w-d.nodes[k[1]][1]}) {rr[0]})'
 if op=='extract':return f'((_ extract {k[2]} {k[3]}) {rr[0]})'
 if op in['rotate_right','rotate_left']:return f'((_ {op} {k[2]}) {rr[0]})'
 return'('+op+' '+' '.join(rr)+')'
def children(d,x):
 k,w=d.nodes[x]
 return list(k[1:2])if k[0]in['zext','extract','rotate_right','rotate_left']else list(k[1:])
