"""Partial source-record readers and local instruction lifts;not target types.

All offsets are bytes;u32 limbs little endian with XOR ada56e3c. Time/space
O(active limbs);integer oracles live separately in the independent verifier.
"""
import struct
K=0xada56e3c;BIAS=0x693be708;M=0xffffffff

def signed32(v):return v-(1<<32)if v>>31 else v

def memory(record,address,n):
 for q in record['pointed_views'].values():
  for v in [q['prefix'],*q['nested_views'].values()]:
   p=int(v['address'],16);raw=bytes.fromhex(v['bytes_hex'])
   if p<=address and address+n<=p+len(raw):return raw[address-p:address-p+n]
 raise ValueError(('uncaptured view',hex(address),n))

def integer_at(record,address):
 h=memory(record,address,16);cap,used,p=struct.unpack('<IIQ',h);count=signed32((used-BIAS)&M);n=abs(count);assert n<=cap and n<=132
 raw=memory(record,p,4*n)if n else b'';words=[x^K for x in struct.unpack('<'+'I'*n,raw)];value=sum(w<<(32*j)for j,w in enumerate(words));return {'address':hex(address),'capacity':cap,'signed_count':count,'limb_pointer':hex(p),'value':-value if count<0 else value,'active_bytes_hex':raw.hex()}

def integer_arg(record,offset):
 raw=bytes.fromhex(record['prefix96_hex']);return integer_at(record,struct.unpack_from('<Q',raw,offset)[0])

def square_key_lift(P):return (((((P&0x7cbed57f)<<1)-P+0x03412a80)^0x79d36d76)*0x31b6b333)&M

def product_key_lift(P):return (((((P|0x9fd4f935)-P+(P&0x602b06ca))&M)^0x09baa127)*0x592e2f77)&M

def count_magnitude_lift(stored):
 used=(stored+0x96c418f8)&M;return used if not used>>31 else(BIAS-stored)&M
