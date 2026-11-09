"""Compact source-level model of the address/table-derived 64-bit mixer.
Seven fixed rounds, O(1) time/space per word. Native cryptographic identity and
security properties are unknown; this is only the inspected A64 transform.
"""
MASK=(1<<64)-1
def rotate(v,n):
 if isinstance(v,int):return ((v>>n)|(v<<(64-n)))&MASK
 import z3
 return z3.RotateRight(v,n)
def u64(v):return v&MASK if isinstance(v,int)else v
def word(address,cached,c,compact=True):
 v=u64(rotate(address,8)+cached);w=cached;a=0x1bae835e9c76d854
 v=(v^a)if compact else u64((v|a)-(v|c['x16'])+c['x16']);v^=c['x0']
 def round_pair(v,w):
  w=v^rotate(w,61);v=u64(rotate(v,8)+w);return v,w
 for name in ['x1','x2','x3']:v,w=round_pair(v,w);v^=c[name]
 v,w=round_pair(v,w)
 v=u64((c['x4']//2+c['x5'])-(v^(c['x4']//2)))if compact else u64(((v<<1)&c['x4'])-v+c['x5']);v^=c['x6']
 v,w=round_pair(v,w)
 v=u64((v^(c['x7']//2))+(c['x7']//2)+c['x15'])if compact else u64(((v<<1)|c['x7'])-v+c['x15']);v^=c['x20']
 v,w=round_pair(v,w);v^=c['x22']
 v=u64((v^(c['x23']//2))+(c['x23']//2)+c['x24'])if compact else u64(((v<<1)|c['x23'])-v+c['x24']);v^=c['x26']
 v,w=round_pair(v,w);return u64(v^c['x27'])
