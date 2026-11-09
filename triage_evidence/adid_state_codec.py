#!/usr/bin/env python3
"""Compact local64-byte state codec for the inspected original prefix.

Scope: fixed source constants,8-byte aligned address,and original local
permutation/byte loop. No complete native type,valid context or DRM algorithm.
O(64) time/space; no target/API call.
"""
import struct

MULTIPLIER=0xb15198a9
XOR_WORD=0x2a379458
SWAP_MULTIPLIER=0x01000193


def state_word(address):return (((address&0xffffffff)*MULTIPLIER)&0xffffffff)^XOR_WORD


def checked(data,address):
    if len(data)!=64:raise ValueError('state span must be 64 bytes')
    if address&7:raise ValueError('state address must be 8-byte aligned')


def term(i,key):return ((i*i-key*key)^key)&255


def open64(data,address):
    checked(data,address);words=list(struct.unpack('<8Q',data));words=words[-1:]+words[:-1];rotated=struct.pack('<8Q',*words);key=state_word(address)
    return bytes(((155*x)&255)^term(i,key) for i,x in enumerate(rotated))


def close64(data,address):
    checked(data,address);key=state_word(address);raw=bytes((147*(x^term(i,key)))&255 for i,x in enumerate(data));words=list(struct.unpack('<8Q',raw));return struct.pack('<8Q',*(words[1:]+words[:1]))
