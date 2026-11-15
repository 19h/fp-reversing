#!/usr/bin/env python3
"""Five encoded u32 words to the conditional twenty-byte record-input format.
O(20 + AES block) work; O(20 + AES workspace) logical byte storage.
"""
from daemon_core_cipher_kernel import encrypt


def encode(words, key):
    assert len(words) == 5 and all(0 <= x < (1 << 32) for x in words)
    decoded = b''.join((x ^ 0xf4f92df7).to_bytes(4, 'big') for x in words)
    result = decoded[:2]+encrypt(decoded[2:18], key)+decoded[18:]
    return bytes(x ^ 0x98 for x in result)
