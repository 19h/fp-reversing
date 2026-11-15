#!/usr/bin/env python3
"""Standalone fixed-width AES-128 component model; no source DAG or solver.
O(10*16) byte work and O(176+256) bytes of key/table/state storage per block.
Masks and key are explicit contract parameters, not native object claims.
"""
SBOX = bytes.fromhex('637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16')


def multiply(a, b):
    result = 0
    for bit in range(8):
        if b & 1: result ^= a
        a = ((a << 1) ^ (0x11b if a & 128 else 0)) & 255
        b >>= 1
    return result


def expand(key):
    assert len(key) == 16
    words = [list(key[j:j+4]) for j in range(0, 16, 4)]; rc = 1
    for j in range(4, 44):
        value = words[j-1][:]
        if j % 4 == 0:
            value = [SBOX[x] for x in value[1:]+value[:1]]; value[0] ^= rc
            rc = multiply(rc, 2)
        words.append([x ^ y for x, y in zip(words[j-4], value)])
    return [bytes(sum(words[j:j+4], [])) for j in range(0, 44, 4)]


def encrypt(data, key):
    assert len(data) == len(key) == 16
    keys = expand(key); state = [x ^ y for x, y in zip(data, keys[0])]
    matrix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    for layer in range(1, 11):
        state = [SBOX[x] for x in state]
        state = [state[4*((col+row) % 4)+row] for col in range(4) for row in range(4)]
        if layer < 10:
            mixed = []
            for col in range(4):
                for row in range(4):
                    value = 0
                    for k in range(4): value ^= multiply(matrix[row][k], state[4*col+k])
                    mixed.append(value)
            state = mixed
        state = [x ^ y for x, y in zip(state, keys[layer])]
    return bytes(state)


def transform(contract, data, external=False):
    name = 'external' if external else 'core'
    before = bytes.fromhex(contract[name+'_input_xor16_hex'])
    after = bytes.fromhex(contract[name+'_output_xor16_hex'])
    assert len(data) == len(before) == len(after) == 16
    value = encrypt(bytes(x ^ y for x, y in zip(data, before)), bytes.fromhex(contract['key16_hex']))
    return bytes(x ^ y for x, y in zip(value, after))
