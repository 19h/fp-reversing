#!/usr/bin/env python3
"""Source SSA for unscaled accesses and candidate-only typed word expressions."""
from daemon_word_round_tools import FrameSSA as Parent
from daemon_word_lookup_algebra import DAG,parse,children,expression,literal
from validate_daemon_list_output import split
class FrameSSA(Parent):
 def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.normalizations=[]
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   row=i
   if i['mnemonic']=='ldur':
    row={**i,'mnemonic':'ldr'};self.normalizations.append({'site':i['ea'],'kind':'LDUR_as_unscaled_load','original_operands':i['operands']})
   elif i['mnemonic']=='stur':
    assert pc==0x100d9db74 and i['operands']=='x14, [x19, #0xff]';address=self.address(split(i['operands'])[1]);row={**i,'mnemonic':'str','operands':'x14, [sp, #0x834]'};self.normalizations.append({'site':i['ea'],'kind':'STUR_private_alias','original_address':address,'frame_offset':0x834,'width_bits':64})
   super().run({'instructions':[row]},pc+4)
  return self
 def record_full(self):return{**super().record_full(),'unscaled_access_normalizations':self.normalizations}
class CandidateDAG(DAG):
 """Propose compact expressions;accepted claims require original-source SMT proofs."""
 def get(self,e):
  if isinstance(e,list)and e[0]=='_'and e[1].startswith('bv'):return self.cn(int(e[1][2:]),int(e[2]))
  if isinstance(e,list)and e[0]=='concat':
   a,b=[self.get(v)for v in e[1:]];ka,wa=self.nodes[a];kb,wb=self.nodes[b]
   if ka[0]==kb[0]=='const':return self.cn((ka[1]<<wb)|kb[1],wa+wb)
   if ka[0]==kb[0]=='extract'and ka[1]==kb[1]and ka[3]==kb[2]+1:return self.extract(ka[1],ka[2],kb[3])
   return self.intern(('concat',a,b),wa+wb)
  return super().get(e)
def graph(g):
 d=CandidateDAG()
 for n,w in g.decl.items():d.alias[n]=d.intern(('sym',n),w)
 d.defs(g.prefix());return d
def leaves(d,x):
 seen=set();out=set()
 def visit(v):
  if v in seen:return
  seen.add(v);k,w=d.nodes[v]
  if k[0]=='sym':out.add(k[1])
  elif k[0]!='const':
   for c in children(d,v):visit(c)
 visit(x);return out
def emit(d,x):
 k,w=d.nodes[x]
 if k[0]=='const':return literal(k[1],w)
 if k[0]=='sym':return k[1]
 return expression(d,x,[emit(d,v)for v in children(d,x)])
def flatten(d,x,op):
 k,w=d.nodes[x]
 return flatten(d,k[1],op)+flatten(d,k[2],op)if k[0]==op else[x]
def affine_candidate(d,x):
 terms=flatten(d,x,'bvadd');constant=sum(d.const(v)or 0 for v in terms)%2**32;variables=[v for v in terms if d.const(v)is None]
 if len(variables)!=1:return None
 k,w=d.nodes[variables[0]]
 if k[0]!='bvmul':return None
 cs=[v for v in k[1:]if d.const(v)is not None]
 if len(cs)!=1:return None
 coefficient=d.const(cs[0]);arg=next(v for v in k[1:]if v!=cs[0]);kk,_=d.nodes[arg];mask=0
 if kk[0]=='bvsub'and d.const(kk[1])is not None:
  constant=(constant+coefficient*d.const(kk[1]))%2**32;coefficient=(-coefficient)%2**32;arg=kk[2];kk,_=d.nodes[arg]
 if kk[0]=='bvxor':
  cc=[v for v in kk[1:]if d.const(v)is not None]
  if len(cc)!=1:return None
  mask=d.const(cc[0]);arg=next(v for v in kk[1:]if v!=cc[0]);kk,_=d.nodes[arg]
 if kk[0]!='sym':return None
 return{'input':kk[1],'xor_mask':mask,'multiplier':coefficient,'bias':constant}
