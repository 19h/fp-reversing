#!/usr/bin/env python3
"""Verify current FairPlay provider callers and constructor mode routing."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from audit_live_fairplay_kernel_rpc import RPC_BANKS, TABLE
from audit_live_kext_selector26 import Collection, DRIVER, IDENTITIES
from audit_live_kext_selector26_transfer import address_pair, words
from bootpolicy_cache_reader import uleb
from resolve_kernel_collection_interfaces import CACHE, commands, macho, string

DELTA = 0x41190
PINNED_TABLE = 0xfffffe0008472f20
CONSTRUCTOR = 0xfffffe000a6ab970
DISPATCH = 0xfffffe000a6478b8
PAGER = 0xfffffe000b174298
METHODS = (
    ('DCkic', 0x880, 0xfffffe000a545f4c, 0xfffffe000a545f68, 'b'),
    ('xhU6d1', 0x8d0, 0xfffffe000a546074, 0xfffffe000a5460a8, 'bl'),
    ('ycJai39mD8', 0x8d8, 0xfffffe000a5460b8, 0xfffffe000a5460e8, 'bl'),
)


def compiler_bounds(image):
    obj = image.entries[DRIVER]
    at, = (at for at, kind, _ in commands(image.data, obj['header_offset']) if kind == 0x26)
    offset, size = struct.unpack_from('<II', image.data, at + 8)
    encoded = image.data[offset:offset + size]
    address = next(item['address'] for item in obj['segments'] if item['name'] == '__TEXT')
    starts = []
    cursor = 0
    while cursor < size:
        delta, cursor = uleb(encoded, cursor)
        if not delta:
            break
        address += delta
        starts.append(address)
    assert len(starts) == 450
    return starts


def compare_code(pinned, current):
    pinned_starts, current_starts = compiler_bounds(pinned), compiler_bounds(current)
    assert (pinned.named('_fcHfFIGhsx'), current.named('_fcHfFIGhsx')) == (CONSTRUCTOR - DELTA, CONSTRUCTOR)
    results = {}
    for role, ordinal, start, size, expected in (
        ('constructor', 427, CONSTRUCTOR, 1232, {'adrp': 8, 'add': 6, 'ldr': 4}),
        ('dispatcher', 394, DISPATCH, 65848, {'adrp': 40, 'add': 38, 'ldr': 4}),
    ):
        assert current_starts[ordinal:ordinal + 2] == [start, start + size]
        assert pinned_starts[ordinal:ordinal + 2] == [start - DELTA, start + size - DELTA]
        before = pinned.read(start - DELTA, size)
        after = current.read(start, size)
        changes = []
        kinds = Counter()
        for offset in range(0, size, 4):
            a = before[offset:offset + 4]
            b = after[offset:offset + 4]
            if a == b:
                continue
            old, = pinned.instructions(start - DELTA + offset, 4)
            new, = current.instructions(start + offset, 4)
            assert old.mnemonic == new.mnemonic
            mask = {'adrp': 0x60ffffe0, 'add': 0x003ffc00, 'ldr': 0x003ffc00}[new.mnemonic]
            assert ((int.from_bytes(a, 'little') ^ int.from_bytes(b, 'little')) & ~mask) == 0
            kinds[new.mnemonic] += 1
            changes.append({'pc': hex(start + offset), 'pinned': a.hex(), 'current': b.hex()})
        assert kinds == expected
        results[role] = {'compiler_ordinal': ordinal, 'bytes': size, 'pinned_start': hex(start - DELTA),
                         'current_start': hex(start), 'pinned_sha256': hashlib.sha256(before).hexdigest(),
                         'current_sha256': hashlib.sha256(after).hexdigest(), 'changes': changes,
                         'change_counts': dict(kinds)}
    return results


def ingress(image):
    entries = {CONSTRUCTOR, DISPATCH, PAGER, *(row[2] for row in METHODS)}
    calls = {target: [] for target in sorted(entries)}
    ranges = {}
    for segment in image.root['segments']:
        if segment['name'] not in ('__TEXT_EXEC', '__TEXT_BOOT_EXEC'):
            continue
        base, size = segment['address'], segment['file_size']
        ranges[segment['name']] = {'base': hex(base), 'words': size // 4}
        offset = segment['file_offset']
        data = memoryview(image.data)[offset:offset + size]
        for index, (word,) in enumerate(struct.iter_unpack('<I', data)):
            if word & 0x7c000000 != 0x14000000:
                continue
            pc = base + 4 * index
            target = pc + ((word & 0x1ffffff) - (word & 0x2000000)) * 4
            if target in entries:
                op = 'bl' if word >> 31 else 'b'
                assert image.branch(pc, op) == target
                calls[target].append(hex(pc))
    assert calls[CONSTRUCTOR] == [hex(row[3]) for row in METHODS]
    assert calls[DISPATCH] == []
    assert calls[PAGER] == ['0xfffffe000b173d10']
    refs = {target: [] for target in sorted(entries)}
    for offset, pointer in image.fixups.items():
        target = int(pointer['target'], 16)
        if target not in entries:
            continue
        owner = next(s for s in image.root['segments']
                     if s['file_offset'] <= offset < s['file_offset'] + s['file_size'])
        slot = owner['address'] + offset - owner['file_offset']
        refs[target].append(hex(slot))
    assert refs[CONSTRUCTOR] == []
    assert refs[DISPATCH] == ['0xfffffe00084912f8']
    return {'ranges': ranges, 'direct': {hex(k): v for k, v in calls.items()},
            'chained': {hex(k): v for k, v in refs.items()}, 'fixups_examined': len(image.fixups)}


def pager_symbol(image):
    target = '__ZN31AppleFairplayTextCrypterSession12fairplayOpenEPb'
    for at, kind, _ in commands(image.data, 0):
        if kind != 0x80000035:
            continue
        _, head, name_offset, _ = struct.unpack_from('<QQII', image.data, at + 8)
        name = string(image.data, at + name_offset)
        if name == 'com.apple.IOTextEncryptionFamily':
            break
    assert name == 'com.apple.IOTextEncryptionFamily'
    obj = macho(image.data, head, name)
    offset, count, pool, size = obj['symtab']
    matches = []
    for index in range(count):
        field, flags, _, _, entry = struct.unpack_from('<IBBHQ', image.data, offset + index * 16)
        if field and flags & 0xee == 0x0e:
            assert field < size
            if string(image.data, pool + field) == target:
                matches.append(entry)
    assert matches == [PAGER]
    return {'image': name, 'uuid': obj['uuid'], 'entry': hex(PAGER), 'symbol': target}


def route(image):
    vptr = image.named('__ZTV30com_apple_driver_FairPlayIOKit') + 16
    methods = {}
    for name, offset, entry, site, opcode in METHODS:
        pointer = image.pointer(vptr + offset)
        assert int(pointer['target'], 16) == entry
        symbols = image.names(entry)
        assert any(name in symbol for symbol in symbols)
        image.instruction(site - 4, 'mov', 'w4, #1')
        assert image.branch(site, opcode) == CONSTRUCTOR
        methods[name] = {'vptr_offset': hex(offset), 'binding': pointer, 'call': hex(site),
                         'symbols': symbols, 'words': words(image, entry, site + 4 - entry)}
    assert methods['ycJai39mD8']['binding']['diversity'] == '0x89c4'
    base = address_pair(image, 0xfffffe000a6aba04, 'x19')
    assert TABLE == base + 0x1020
    left, left_bias, right, right_bias = RPC_BANKS
    assert (left, right) == (base + 0xc08, base + 0x158)
    banks = [image.pointer(left), image.pointer(right)]
    left_bytes = image.read(int(banks[0]['target'], 16) - left_bias, 256)
    right_bytes = image.read(int(banks[1]['target'], 16) - right_bias, 256)
    assert {value ^ right_bytes[left_bytes[value] ^ 5] for value in range(256)} == {45}
    dispatcher_slot = image.pointer(TABLE + 8 * (0xefa + 45))
    assert int(dispatcher_slot['target'], 16) == DISPATCH
    assert (dispatcher_slot['auth'], dispatcher_slot['diversity'], dispatcher_slot['key']) == (1, '0xd0c8', 0)
    for pc, mnemonic, operand in (
        (0xfffffe000b17431c, 'ldpsw', 'x2, x3, [x20, #0x28]'),
        (0xfffffe000b174320, 'ldr', 'w4, [x20, #0x30]'),
        (0xfffffe000b174348, 'ldr', 'x9, [x16, #0x8d8]'),
        (0xfffffe000b174358, 'movk', 'x17, #0x89c4, lsl #48'),
        (0xfffffe000b17435c, 'blraa', 'x9, x17'),
        (0xfffffe000a5460e0, 'mov', 'x3, x4'),
        (0xfffffe000a6ab998, 'stp', 'w3, w4, [sp, #0x2c]'),
        (0xfffffe000a6aba28, 'sub', 'x12, x12, #8'),
        (0xfffffe000a6aba44, 'sub', 'x13, x13, #4'),
        (0xfffffe000a6abbcc, 'ldr', 'x26, [sp]'),
        (0xfffffe000a6abc24, 'ldp', 'w10, w9, [sp, #0x2c]'),
        (0xfffffe000a6abc28, 'stp', 'w10, w9, [sp, #0x60]'),
        (0xfffffe000a6abc88, 'add', 'x8, sp, #0x40'),
        (0xfffffe000a6abc90, 'stp', 'x8, x19, [x20, #0x28]'),
        (0xfffffe000a6abcb4, 'mov', 'w10, #5'),
        (0xfffffe000a6abcd0, 'add', 'w8, w8, #0xefa'),
        (0xfffffe000a6abcd8, 'mov', 'x0, x20'),
        (0xfffffe000a6abcdc, 'mov', 'x17, #0xd0c8'),
        (0xfffffe000a6abce0, 'blraa', 'x8, x17'),
        (0xfffffe000a6478dc, 'mov', 'x16, x0'),
        (0xfffffe000a6479f0, 'ldp', 'x1, x10, [x16, #0x20]'),
        (0xfffffe000a6479f4, 'stp', 'x10, x16, [x29, #-0xe0]'),
        (0xfffffe000a64bd48, 'ldur', 'x8, [x29, #-0xe0]'),
        (0xfffffe000a64bd4c, 'ldr', 'w23, [x8, #0x24]'),
        (0xfffffe000a64bd7c, 'sub', 'w26, w20, #0x43e'),
        (0xfffffe000a64bd98, 'mov', 'w8, #0x22'),
        (0xfffffe000a64bd9c, 'mov', 'w9, #0x11'),
        (0xfffffe000a64bda0, 'cmp', 'w23, w26'),
        (0xfffffe000a64bda4, 'csel', 'w2, w9, w8, eq'),
        (0xfffffe000a64c96c, 'ldr', 'w11, [sp, #0x100]'),
        (0xfffffe000a64c978, 'ldur', 'x25, [x29, #-0xe0]'),
        (0xfffffe000a64c97c, 'ldp', 'w5, w8, [x25, #0x20]'),
        (0xfffffe000a64c980, 'cmp', 'w8, #1'),
        (0xfffffe000a64c984, 'cset', 'w8, eq'),
        (0xfffffe000a64c998, 'sub', 'w9, w11, #0x6fe'),
        (0xfffffe000a64c99c, 'mul', 'w8, w8, w9'),
        (0xfffffe000a64c9a0, 'eor', 'w8, w8, w11'),
        (0xfffffe000a64c9ac, 'braa', 'x8, x17'),
    ):
        image.instruction(pc, mnemonic, operand)
    assert ((0x448 + 0x8fb0c137) & 0x704f3ebf) - 0x43e == 1
    outcomes = []
    for equal, slot, rpc, expected in ((1, 17, 502, 0xfffffe000a64c9b0), (0, 34, 700, 0xfffffe000a64e4c4)):
        index = ((0x8ea - 0x6fe) * equal) ^ 0x8ea
        edge = image.pointer(TABLE + index * 8)
        assert int(edge['target'], 16) == expected and edge['diversity'] == '0xde28'
        outcomes.append({'mode_equals_one': bool(equal), 'host_slot': slot, 'rpc': rpc,
                         'rpc_dispatch_index': hex(index), 'edge': edge})
    return {'methods': methods, 'dispatcher_slot': dispatcher_slot, 'banks': banks,
            'bank_bytes': [left_bytes.hex(), right_bytes.hex()], 'outcomes': outcomes,
            'windows': {name: words(image, start, size) for name, start, size in (
                ('pager', PAGER, 0xc8),
                ('record_pack', 0xfffffe000a6abc10, 0xd4),
                ('frame_record', 0xfffffe000a6479f0, 8),
                ('host_mode', 0xfffffe000a64bd24, 0x84),
                ('rpc_mode', 0xfffffe000a64c96c, 0x44),
            )}}


def trace_correspondence(pinned, current, path):
    raw = subprocess.check_output(['zstd', '-dc', str(path)])
    traces = json.loads(raw)
    assert traces['kernel_sha256'] == pinned.digest and len(traces['cases']) == 25
    ranges = ((DISPATCH - DELTA, DISPATCH - DELTA + 65848),
              (CONSTRUCTOR - DELTA, CONSTRUCTOR - DELTA + 1232))
    slots = {}
    for index in range(0x1000):
        address = PINNED_TABLE + index * 8
        if pinned.offset(address, 8) in pinned.fixups:
            binding = pinned.pointer(address)
            slots.setdefault((binding['target'], binding['diversity']), []).append(index)
    matches = {}
    eligible_visits = 0
    for case in traces['cases']:
        assert case['entry_PC'] == hex(CONSTRUCTOR - DELTA)
        for visit in case['source_visits']:
            pc = int(visit['pc'], 16)
            if any(start <= pc < end for start, end in ranges):
                assert pinned.read(pc, 4).hex() == visit['bytes_hex']
                eligible_visits += 1
        for edge in case['logical_edges']:
            site, target = (int(edge[key], 16) for key in ('pc', 'target'))
            if not all(any(start <= address < end for start, end in ranges) for address in (site, target)):
                continue
            identity = (edge['pc'], edge['target'], edge['modifier'])
            if identity not in matches:
                original = slots[(edge['target'], edge['modifier'])]
                candidates = []
                for index in original:
                    old = pinned.pointer(PINNED_TABLE + index * 8)
                    new = current.pointer(TABLE + index * 8)
                    if int(new['target'], 16) == target + DELTA:
                        assert all(old[k] == new[k] for k in ('format', 'auth', 'diversity', 'address_diversity', 'key'))
                        candidates.append(index)
                assert candidates
                assert current.instructions(site + DELTA, 4)[0].mnemonic == edge['kind']
                matches[identity] = {'current_site': hex(site + DELTA), 'current_target': hex(target + DELTA),
                                     'modifier': edge['modifier'], 'matching_indices': candidates, 'visits': 0}
            matches[identity]['visits'] += 1
    return {'pinned_trace_sha256': hashlib.sha256(raw).hexdigest(), 'case_count': len(traces['cases']),
            'eligible_visits': eligible_visits, 'internal_edges': list(matches.values())}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('current', type=Path)
    parser.add_argument('--pinned', type=Path, default=CACHE)
    parser.add_argument('--traces', type=Path, default=Path(__file__).with_name('kext_constructor_request_profiles.json.zst'))
    args = parser.parse_args()
    pinned = Collection(args.pinned, IDENTITIES[0])
    current = Collection(args.current, IDENTITIES[1])
    receipt = {'identities': IDENTITIES, 'comparison': compare_code(pinned, current),
               'ingress': ingress(current), 'pager': pager_symbol(current), 'route': route(current),
               'trace_correspondence': trace_correspondence(pinned, current, args.traces),
               'current_native_exchange_observed': False}
    print(json.dumps(receipt, indent=2))
