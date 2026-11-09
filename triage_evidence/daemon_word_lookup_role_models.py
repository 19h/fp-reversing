#!/usr/bin/env python3
"""Source-linked lookup roles with explicit algebra and premise ledgers."""
import functools,collections,re
from daemon_word_lookup_algebra import DAG,parse,children,expression,literal,typ
REGIONS={'U':(0,15),'B':(17,32),'D':(182,437),'Q':(440,695),'C':(706,961)}
INV757=0x91c1195d
E_FACT=(208,223,0x20,0xd0)
H_FACT=(4,244,0xb,4)
SIZE_FACT=(0xd00,0xdf0,0xffffffff^(0xd00|0xf0),0xd00)
def range_typed(d,domains,nodefacts):
 @functools.lru_cache(None)
 def abstract(x):
  k,w=d.nodes[x];mask=2**w-1;op=k[0];v=d.const(x)
  if x in nodefacts:return nodefacts[x]
  if v is not None:return(v,v,mask^v,v)
  if op=='sym':
   lo,hi=0,mask
   if k[1]in domains:return domains[k[1]]
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

def node(d,op,args,w=None,params=()):
 names=[]
 for x in args:
  name='_role_value_'+str(x);d.alias[name]=x;names.append(name)
 if op=='zext':return d.get([['_','zero_extend',str(w-d.nodes[args[0]][1])],names[0]])
 if op=='extract':return d.get([['_','extract',*map(str,params)],names[0]])
 if op in['rotate_right','rotate_left']:return d.get([['_',op,str(params[0])],names[0]])
 return d.get([op,*names])
def flattened(d,x,op):
 k,w=d.nodes[x]
 return flattened(d,k[1],op)+flattened(d,k[2],op)if k[0]==op else[x]
def combine(d,op,terms,w):
 constant=0;rest=[]
 for t in terms:
  v=d.const(t)
  if v is None:rest.append(t)
  elif op=='bvadd':constant=(constant+v)%2**w
  else:constant^=v
 if constant or not rest:rest.append(d.cn(constant,w))
 if op=='bvxor':
  counts=collections.Counter(rest);rest=[x for x in sorted(counts)if counts[x]%2]
  if not rest:return d.cn(0,w)
 out=rest[0]
 for t in rest[1:]:out=node(d,op,[out,t])
 return out
def unary(d,expr):
 terms=flattened(d,expr,'bvadd');constant=sum(d.const(t)or 0 for t in terms)%2**32;rest=[t for t in terms if d.const(t)is None]
 if len(rest)!=1:return None
 terms=flattened(d,rest[0],'bvxor')
 if len(terms)!=3:return None
 inputs=[];parameters=[]
 for term in terms:
  tt=flattened(d,term,'bvadd');constants=[v for v in tt if d.const(v)is not None];var=[v for v in tt if d.const(v)is None]
  if len(var)!=1:return None
  added=sum(d.const(v)for v in constants)%2**32;xx=flattened(d,var[0],'bvxor');xor_constant=0;variables=[]
  for v in xx:
   if d.const(v)is None:variables.append(v)
   else:xor_constant^=d.const(v)
  if not variables:return None
  inputs.append(combine(d,'bvxor',variables,32));parameters.append((xor_constant,added))
 if len(set(inputs))!=1:return None
 return inputs[0],parameters,constant
def emit_cut(d,x,cuts):
 if x in cuts:return cuts[x]
 k,w=d.nodes[x]
 if k[0]=='const':return literal(k[1],w)
 if k[0]=='sym':return k[1]
 return expression(d,x,[emit_cut(d,a,cuts)for a in children(d,x)])
def leaves(d,x):
 seen=set();out=set()
 def visit(v):
  if v in seen:return
  seen.add(v);k,w=d.nodes[v]
  if k[0]=='sym':out.add(k[1])
  elif k[0]!='const':
   for a in children(d,v):visit(a)
 visit(x);return out

class Optimizer:
 def __init__(self,d,domains,bounds,solve,range_proof):
  self.d=d;self.domains=domains;self.bounds=bounds;self.solve=solve;self.range_proof=range_proof;self.nodefacts={};self.origins={};self.abstract=range_typed(d,domains,self.nodefacts);self.events=[];self.memo={};self.transformations=[];self.special_numerator=None
 def prove(self,name,body):return self.solve(name,body)
 def simplify(self,x):
  if x in self.memo:return self.memo[x]
  d=self.d;k,w=d.nodes[x];op=k[0]
  if op in['const','sym']:self.memo[x]=x;return x
  if op in['extract','zext','rotate_right','rotate_left']:cs=[self.simplify(k[1])];params=k[2:]if op!='zext'else()
  else:cs=[self.simplify(a)for a in k[1:]];params=()
  y=node(d,op,cs,w,params);rebuilt=y;first_event=len(self.events);kk,_=d.nodes[y]
  if kk[0]=='bvand':
   constants=[v for v in kk[1:]if d.const(v)is not None]
   if len(constants)==1:
    mask=d.const(constants[0]);other=next(v for v in kk[1:]if v!=constants[0]);ko,_=d.nodes[other]
    if ko[0]=='bvor':
     for added,subtracted in[(ko[1],ko[2]),(ko[2],ko[1])]:
      ka,_=d.nodes[added];ks,_=d.nodes[subtracted]
      if ka[0]=='bvadd'and ks[0]=='bvsub'and d.const(ks[1])is not None:
       aa=[v for v in ka[1:]if d.const(v)is not None]
       if len(aa)==1:
        v=next(v for v in ka[1:]if v!=aa[0]);c=d.const(aa[0]);b=d.const(ks[1]);limit=(1<<mask.bit_length())-1
        if v==ks[2]and(c+b)&limit==limit:
         body=f'(declare-fun V () (_ BitVec {w}))\n(assert (distinct (bvand (bvor (bvadd V {literal(c,w)}) (bvsub {literal(b,w)} V)) {literal(mask,w)}) {literal(mask,w)}))'
         cert=self.prove('opaque_or_stride_'+hex(mask),body);out=d.cn(mask,w);self.events.append({'kind':'opaque_or_stride','input_node':y,'output_node':out,'V_node':v,'certificate':cert});y=out;break
  kk,_=d.nodes[y]
  if kk[0]in['bvadd','bvxor']:
   op=kk[0];terms=flattened(d,y,op)
   if op=='bvadd':
    again=True
    while again:
     again=False
     for left in list(terms):
      kl,_=d.nodes[left]
      if kl[0]!='bvxor':continue
      cc=[v for v in kl[1:]if d.const(v)is not None]
      if len(cc)!=1:continue
      c0=d.const(cc[0]);arg=next(v for v in kl[1:]if v!=cc[0]);argk,_=d.nodes[arg]
      if argk[0]!='bvand':continue
      ac=[v for v in argk[1:]if d.const(v)is not None]
      if len(ac)!=1:continue
      input_mask=d.const(ac[0]);input_node=next(v for v in argk[1:]if v!=ac[0])
      for right in list(terms):
       if right==left:continue
       kr,_=d.nodes[right];c1=0;arg1=right
       if kr[0]=='bvxor':
        rc=[v for v in kr[1:]if d.const(v)is not None]
        if len(rc)!=1:continue
        c1=d.const(rc[0]);arg1=next(v for v in kr[1:]if v!=rc[0])
       if arg1!=arg or input_mask&~(c0^c1):continue
       value=(c0+c1)%2**w;body=f'(declare-fun V () (_ BitVec {w}))\n(define-fun Y () (_ BitVec {w}) (bvand V {literal(input_mask,w)}))\n(assert (distinct (bvadd (bvxor Y {literal(c0,w)}) (bvxor Y {literal(c1,w)})) {literal(value,w)}))'
       cert=self.prove('masked_xor_pair_'+str(w),body);terms.remove(left);terms.remove(right);terms.append(d.cn(value,w));self.events.append({'kind':'masked_xor_pair','input_node':y,'V_node':input_node,'mask':input_mask,'constants':[c0,c1],'certificate':cert});again=True;break
      if again:break
    # Parent scratch-bound facts justify the physical-offset cancellation.
    changed=True
    while changed:
     changed=False
     for left in list(terms):
      kl,_=d.nodes[left]
      if kl[0]!='bvor':continue
      lc=[v for v in kl[1:]if d.const(v)is not None]
      if len(lc)!=1:continue
      c=d.const(lc[0]);r=next(v for v in kl[1:]if v!=lc[0])
      if r not in self.nodefacts:continue
      for right in list(terms):
       kr,_=d.nodes[right]
       if kr[0]!='bvsub':continue
       km,_=d.nodes[kr[2]]
       if km[0]!='bvand'or r not in km[1:]:continue
       mc=[v for v in km[1:]if d.const(v)is not None]
       if len(mc)!=1:continue
       m=d.const(mc[0]);union=c|m
       if c&m or union&(union+1)or self.nodefacts[r][1]>union:continue
       body=f'(declare-fun R () (_ BitVec {w}))\n(declare-fun G () (_ BitVec {w}))\n(assert (bvule R {literal(self.nodefacts[r][1],w)}))\n(assert (distinct (bvadd (bvor R {literal(c,w)}) (bvsub G (bvand R {literal(m,w)}))) (bvadd G {literal(c,w)})))'
       cert=self.prove('physical_offset_cancellation',body);terms.remove(left);terms.remove(right);terms.extend([kr[1],d.cn(c,w)]);self.events.append({'kind':'physical_offset_cancellation','R_node':r,'origin':self.origins[r],'G_node':kr[1],'certificate':cert});changed=True;break
      if changed:break
   y=combine(d,op,terms,w)
  # The exceptional stride's complete remaining expression has one byte input.
  if x==self.special_numerator:
   ky,_=d.nodes[y];assert ky[0]=='bvmul';matches=[]
   for arg,coefficient in[(ky[1],ky[2]),(ky[2],ky[1])]:
    ka,_=d.nodes[arg]
    if ka[0]!='bvadd':continue
    aa=[v for v in ka[1:]if d.const(v)==0xb6]
    if len(aa)!=1:continue
    v=next(v for v in ka[1:]if v!=aa[0]);lo,hi,_,_=self.abstract(v)
    if not(0<=lo<=hi<=255):continue
    expr=emit_cut(d,coefficient,{v:'V'});assert not re.findall(r'\b(?:B\d+|WORD\d+|SIZE|Z\d+)\b',expr)
    range_record=self.range_proof(v,self)
    body=f'(declare-fun V () (_ BitVec 32))\n(assert (bvule V #x000000ff))\n(assert (distinct {expr} #x000002f5))';cert=self.prove('conditional_byte_stride757',body);matches.append((arg,coefficient,v,cert,range_record))
   assert len(matches)==1;arg,coefficient,v,cert,range_record=matches[0];out=node(d,'bvmul',[arg,d.cn(757,32)]);self.events.append({'kind':'conditional_byte_stride757','input_node':y,'output_node':out,'coefficient_node':coefficient,'V_node':v,'range_record':range_record,'certificate':cert});y=out
  self.transformations.append({'input_node':x,'mapped_children':cs,'rebuilt_node':rebuilt,'output_node':y,'first_event':first_event,'event_count':len(self.events)-first_event});self.memo[x]=y
  if x in self.bounds:
   self.nodefacts[y]=(0,962,(2**d.nodes[y][1]-1)^1023,0);self.origins[y]=self.bounds[x];self.abstract.cache_clear()
  return y
 def coordinate(self,n):
  d=self.d;n=self.simplify(n);terms=flattened(d,n,'bvadd');constant=sum(d.const(v)or 0 for v in terms)%2**32;variables=[v for v in terms if d.const(v)is None]
  if not variables:return d.cn(constant*INV757%2**32,32)
  if len(variables)!=1:return None
  k,w=d.nodes[variables[0]]
  if k[0]!='bvmul'or not any(d.const(v)==757 for v in k[1:]):return None
  arg=next(v for v in k[1:]if d.const(v)!=757)
  return combine(d,'bvadd',[arg,d.cn(constant*INV757%2**32,32)],32)
