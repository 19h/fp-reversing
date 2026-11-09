#!/usr/bin/env python3
"""Compact source equations for the consumer byte codec and prefix handover.
Eight fixed rounds, O(1) time/space per byte; no standard cipher identity or
native ownership/lifetime is asserted. All word arithmetic is modulo 2^64.
"""
from daemon_object_initialization_model import rotate,u64
KEYS={'x3':0x612907e886213192,'x4':0x262778af91ffd516,
 'x5':0x5a3ca9b544497e0c,'x10':0xd2e1ab255ddb40fa,
 'x7':0xb7737651507adcd9,'x19':0xda716d2c7b2f1a54,
 'x20':0x0d9c6139b237b9a6,'x21':0x06ce309cd91bdcd3,
 'x22':0x573fdc5aef7bf82e,'x23':0x22fb017a6f4e1a1d,
 'x24':0x0d707e32c15ab9b6,'x25':0x9f904fa63158b131}
DECODER_CONSTANTS={**KEYS,'w14':0x4d362b75,'w15':0x8621f936,
 'w1':0x79de0359,'w2':0x1698323a,'x0':0x1010c67d4,
 'x6':0x1010c8268,'w26':0x3d,'w12':0x655f,'x30':0x101039ef0}
COPY_CONSTANTS={'w8':0x7e65,'w11':0xffffc8b7,'w13':0x471d,
 'w14':0xe98c785d,'w15':0xc3,'x30':0x101039ef0}
EXTRA_SPECS=[('format_result_capture',0x100ad6fd0,0x100ad6fd8),
 ('consumer_byte_codec',0x100be097c,0x100be0a88),
 ('context_initialization',0x100aee670,0x100aee70c),
 ('prefix_copy',0x100d59b88,0x100d59bd0)]
def word(address,cached,compact=False):
 v=address&~7;y=cached
 for j in range(8):
  v=u64(rotate(v,8)+y)
  if j==2:
   v=u64((v^(KEYS['x5']//2))+(KEYS['x5']//2)+KEYS['x10'])if compact else u64(((v<<1)|KEYS['x5'])-v+KEYS['x10']);v^=KEYS['x7']
  elif j==4:
   v=u64((v^(KEYS['x20']//2))-(KEYS['x20']//2)+KEYS['x21'])if compact else u64(v-((v<<1)&KEYS['x20'])+KEYS['x21']);v^=KEYS['x22']
  else:v^=KEYS[['x3','x4',None,'x19',None,'x23','x24','x25'][j]]
  if j<7:y=v^rotate(y,61)
 return u64(v)
def byte_value(address,cached,value):
 v=word(address,cached);shift=(address&7)*8
 if isinstance(v,int):return ((v>>shift)^value)&255
 import z3
 return (z3.LShR(v,shift)^value)&255
def word_index(address,mask=255):
 if isinstance(address,int):
  a=address&0xfffffff8;q=((a|(((0x4d362b75&0xb2c9d7fb)+0x8621f936)&0xffffffff))+((a|0x79de0359)+0x1698323a))&0xffffffff;q&=mask;q=q if q<0x80000000 else q-(1<<32);return q&((1<<64)-8)
 import z3
 a=z3.Extract(31,0,address)&0xfffffff8;q=((a|(((0x4d362b75&0xb2c9d7fb)+0x8621f936)&0xffffffff))+((a|0x79de0359)+0x1698323a))&mask
 return z3.SignExt(32,q)&~7
