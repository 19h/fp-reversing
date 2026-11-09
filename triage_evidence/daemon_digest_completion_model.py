#!/usr/bin/env python3
"""Reference byte/entry contracts for an isolated digest-completion phase.
O(N) time and output space; arithmetic wraps at the stated width.
"""
MASK=(1<<64)-1
CONSTANTS={'w20':0x8aefa97d,'w21':0xd17a2e6e,'w22':0x887bad6d,
 'w23':0xb72b493a,'w24':0x5b958712,'w25':0x48948111,
 'w26':0x6e561c40,'w27':0xd4,'w28':0xe011,'w30':0x813a,
 'w4':0x471c,'w2':0x7e8c,'x19':0x101039ef0}
SAVED={0x2a88:0x1010c4e18,0x2a90:0x1010c4670,
 0x2978:0x100fc4230,0x2988:0x101031ea0,0x2edc:0x8b3dc651}
SPECS=[('seed',0x100bb1574,0x100bb15d0),
 ('opaque_aliases',0x100bb15d0,0x100bb1620),
 ('entry',0x100bb1620,0x100bb16c4),
 ('overwrite_start',0x100a048d4,0x100a04904),
 ('overwrite_loop',0x100a1bf1c,0x100a1bfa4),
 ('overwrite_exit',0x100abd000,0x100abd010),
 ('gate1',0x100a21560,0x100a21590),
 ('gate2',0x100bdb0f0,0x100bdb130),
 ('gate3',0x100b3ffb0,0x100b3fff8),
 ('gate4',0x100babce8,0x100babd2c),
 ('gate5',0x100bf7b18,0x100bf7b60),
 ('size_gate',0x100b132f8,0x100b13358),
 ('copy_start',0x1009a33bc,0x1009a33e4),
 ('copy_loop',0x1009a2e90,0x1009a2eb8),
 ('restore',0x100b56660,0x100b5668c),
 ('complete',0x100a53630,0x100a53684),
 ('next_frontier',0x100b687e0,0x100b687f4),
 ('identity_save',0x100baff8c,0x100baffb8),
 ('scratch_aliases',0x100bd8f80,0x100bd9000),
 ('destination_save',0x100abdf8c,0x100abdf94),
 ('stack_destination',0x10082f448,0x10082f464)]
def seed(F):
 a=F+0x2ba0
 return (((0x7e8c+0x3fffb7ff7fd77d2b)^a)
         +((a<<1)&0x7fff6ffeffaff760)+0xef40fb3daeadd5db)&MASK
def overwrite_byte(s):
 # Each intermediate is an 8-bit cell. The proof checks equivalence to the
 # original 32-bit MBA for every input, including all discarded upper bits.
 s&=255;a=s^0x7d;b=s&0x6e;c=((s^0x6d)&(b<<1))^b
 d=(((a<<1)^0x471c^0x3a)&a)^((a<<1)&0x12)
 e=d^0x11;c^=d&(c<<2)
 c^=(0x40^(e<<2))&(e&(c<<4))
 return ((s^(c<<1)^0xd4)*(s+0x7f))&255
def pattern(F,n=92):
 out=bytearray(n);s=seed(F)
 for j in range(n):out[n-1-j]=overwrite_byte(s+j)
 return bytes(out)
