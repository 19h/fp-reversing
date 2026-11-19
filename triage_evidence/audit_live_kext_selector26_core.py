#!/usr/bin/env python3
"""Compare compiler-bounded selector 26 core code and selected parser edges."""

import argparse
import bisect
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from audit_live_kext_selector26 import Collection, DRIVER, IDENTITIES
from audit_live_kext_selector26_transfer import address_pair, words
from bootpolicy_cache_reader import uleb
from resolve_kernel_collection_interfaces import CACHE, commands

CORE_SIZE = 202536
CORE_DELTA = 0x41190
EXPECTED_DIFFERENCES = {'adrp': 45, 'add': 41, 'ldr': 6}
TABLE_INDICES = (0x1c2, 0x386, 0x5a1, 0x63d, 0x7c6, 0x82d, 0xce0)
PARSER_RANGES = (
    (0xfffffe000a660dcc, 0xfffffe000a660f30),
    (0xfffffe000a660fc0, 0xfffffe000a661138),
    (0xfffffe000a661908, 0xfffffe000a661940),
    (0xfffffe000a661948, 0xfffffe000a661960),
    (0xfffffe000a661b40, 0xfffffe000a661b64),
)


def compiler_extent(image, entry):
    obj = image.entries[DRIVER]
    command, = (at for at, kind, _ in commands(image.data, obj['header_offset']) if kind == 0x26)
    offset, length = struct.unpack_from('<II', image.data, command + 8)
    raw = image.data[offset:offset + length]
    address = next(s['address'] for s in obj['segments'] if s['name'] == '__TEXT')
    starts = []
    cursor = 0
    while cursor < len(raw):
        delta, cursor = uleb(raw, cursor)
        if not delta:
            break
        address += delta
        starts.append(address)
    index = bisect.bisect_left(starts, entry)
    assert len(starts) == 450 and starts[index:index + 2] == [entry, entry + CORE_SIZE]
    return {'start': hex(entry), 'end': hex(starts[index + 1]),
            'start_index': index, 'starts_count': len(starts), 'starts_sha256': hashlib.sha256(raw).hexdigest()}


def capture(path, index):
    image = Collection(path, IDENTITIES[index])
    root = image.named('_PRnut72j9')
    slide = CORE_DELTA * index
    assert root == 0xfffffe000a635208 + slide
    extent = compiler_extent(image, root)
    base = address_pair(image, root + 0xc0, 'x28')
    table = base + 0x1020
    assert image.read(table - 8, 8) == bytes(8)
    edges = {hex(idx): image.pointer(table + 8 * idx) for idx in TABLE_INDICES}
    parser = [words(image, start + slide, end - start) for start, end in PARSER_RANGES]
    return image.read(root, CORE_SIZE), words(image, root, CORE_SIZE), {
        'identity': IDENTITIES[index], 'compiler_extent': extent,
        'core_sha256': hashlib.sha256(image.read(root, CORE_SIZE)).hexdigest(),
        'table': hex(table), 'edges': edges, 'parser': parser,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('current', type=Path)
    parser.add_argument('--pinned', type=Path, default=CACHE)
    args = parser.parse_args()
    pinned_bytes, pinned_words, pinned = capture(args.pinned, 0)
    current_bytes, current_words, current = capture(args.current, 1)
    assert hashlib.sha256(pinned_bytes).hexdigest() == 'd54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297'
    count = Counter()
    changed = []
    for index, (a, b) in enumerate(zip(pinned_words, current_words, strict=True)):
        mnemonic = a['mnemonic']
        assert mnemonic == b['mnemonic']
        xor = int(a['word'], 16) ^ int(b['word'], 16)
        if xor:
            assert a['operands'].split('#')[0] == b['operands'].split('#')[0]
            cpu_xor = int.from_bytes(xor.to_bytes(4, 'big'), 'little')
            mask = {'adrp': 0x60ffffe0, 'add': 0x003ffc00, 'ldr': 0x003ffc00}[mnemonic]
            assert not cpu_xor & ~mask, (a, b, hex(cpu_xor))
            count[mnemonic] += 1
            changed.append({'offset': hex(index * 4), 'pinned': a, 'current': b})
    assert count == EXPECTED_DIFFERENCES
    for a, b in zip(pinned['parser'], current['parser'], strict=True):
        assert [row['word'] for row in a] == [row['word'] for row in b]
    for index in pinned['edges']:
        a, b = pinned['edges'][index], current['edges'][index]
        assert int(b['target'], 16) - int(a['target'], 16) == CORE_DELTA
        for key in ('format', 'auth', 'diversity', 'key', 'address_diversity'):
            assert a[key] == b[key] and a['auth'] == 1
    print(json.dumps({'core_bytes': len(current_bytes), 'decoded_words': len(current_words),
                      'changed_counts': count, 'changes': changed,
                      'pinned': pinned, 'current': current}, indent=2))


if __name__ == '__main__':
    main()
