#!/usr/bin/env python3
"""Independent SHA-1 compression reference, FIPS180-4 sections4.1.1/4.2.1/6.1.2.
One block: 80 rounds, O(80) time/space with retained schedule/round history.
"""
import struct
IV=[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0]
STATE_XOR=0xf4f92df7;WORD_XOR=0x8b3dc651;MASK=0xffffffff
ROUND_STARTS=[0x100a0dd8c,0x100d30e74,0x100acc478,0x100d30c74]
ROUND_ENDS=[0x100a0e070,0x100d31024,0x100acc6bc,0x100d30e18]
ROUND_MAPS=[[11,19,0,30,15],[11,13,0,20,5],[11,13,0,26,19],[11,13,0,5,4]]
def rol(x,n):return ((x<<n)|(x>>(32-n)))&MASK
def pad(message):
 n=len(message);return message+b'\x80'+bytes((55-n)%64)+(n*8).to_bytes(8,'big')
def reference(block,initial):
 assert len(block)==64 and len(initial)==5
 w=list(struct.unpack('>16I',block));states=[];s=list(initial)
 for t in range(16,80):w.append(rol(w[t-3]^w[t-8]^w[t-14]^w[t-16],1))
 for t in range(80):
  states.append(list(s));a,b,c,d,e=s
  f=(b&c)|((~b)&d)if t<20 else b^c^d if t<40 or t>=60 else (b&c)|(b&d)|(c&d)
  k=[0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6][t//20]
  s=[(rol(a,5)+f+e+k+w[t])&MASK,a,rol(b,30),c,d]
 states.append(s);return {'schedule80':w,'working_states81':states,'final_state5':[(a+b)&MASK for a,b in zip(initial,s)]}
