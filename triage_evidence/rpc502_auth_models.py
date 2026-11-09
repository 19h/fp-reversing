"""Source-pinned scalar lifts and independent bounded byte/DER oracles.

No target execution. Scalar source lifts O(I);byte matching O(N);DER O(B).
All register widths and shifted operands are explicit. Native trust unknown.
"""
import struct
from rpc502_startup_tools import certificate_view
MASK=(1<<32)-1;K=0x8b3dc651;E=0x74c29d8a;D=0x502230ca

def status_oracle(saved,prior):return K if saved&255==0 and prior&255==0x51 else E

def status_lift(A,B):
 import z3
 from rpc502_parser_lift import Lift
 r=Lift({'w24':0,'w14':B},{'[sp, #0x2e4]':A}).run(0x100896930,0x10089695c)
 r.regs['w10']=r.regs['w8']>>4 # Original ASR at89695c.
 r.run(0x100896960,0x10089698c)
 r.regs['w8']=r.regs['w10']&z3.LShR(r.regs['w8'],2) # Original shifted AND at89698c.
 r.run(0x100896990,0x1008969a8);return r.regs['w1']

def length_lift(i,L):
 import z3
 # Exact64b420..484 comparisons;encoded limit D+L,previous index i-1.
 b64=lambda x:z3.BitVecVal(x&((1<<64)-1),64)
 limit=L+b64(D);prev=i-b64(1);wrapped_limit=z3.ULT(limit,b64(D));next_i=prev+b64(1);wrapped_i=z3.UGT(next_i,b64(-D-1));biased=prev+b64(D+1)
 return z3.If(wrapped_i!=wrapped_limit,wrapped_limit,z3.ULT(biased,limit))

def name_text(view,which):
 keys={'550406':'C','55040a':'O','55040b':'OU','550403':'CN'}
 return ''.join('/'+keys[e['OID_bytes_hex']]+'='+e['value']for e in view[which]).encode('ascii')

def input_view(body):return certificate_view(body)

def tail_view(point):
 v=point['certificate_tail_view'];assert v is not None
 b=bytes.fromhex(v['bytes_hex']);n=struct.unpack_from('<I',b,256)[0]^K;d=struct.unpack_from('<I',b,260)[0]
 assert n<=256 and d<=20
 return {'child_record':point['registers'][9],'issuer_record':point['registers'][11],'signature_size_bytes':n,'digest_size_bytes':d,'signature_raw_hex':b[:n].hex(),'digest_decoded_hex':bytes(x^0x98 for x in b[264:264+d]).hex(),'raw_view':v}

def first_status_lift(A):
 import z3
 from rpc502_parser_lift import Lift,b32
 r=Lift({'w8':A,'w9':1,'w10':1}).run(0x100950fd8,0x100951014)
 r.regs['w8']=r.regs['w8']|z3.LShR(r.regs['w8'],2) # Original shifted ORR951014.
 r.run(0x100951018,0x100951024);r.cmp=(r.regs['w8']+r.regs['w10'],b32(0));r.run(0x100951028,0x10095103c);return r.regs['w14']
