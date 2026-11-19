#!/usr/bin/env python3
"""Verify installed FairPlay shared-table bootstrap, initialization and rollback."""

import argparse
import hashlib
import json
import struct
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import (
    CODE_DELTA, POOL, POOL_ROOTS, TABLE, function_starts, read_descriptor, read_receipt,
    replay_proof, verify_bodies,
)
from audit_live_kext_selector26 import Collection, IDENTITIES

HERE = Path(__file__).resolve().parent
RECEIPT_HASHES = {
    'bootstrap_checks': '440ddc3b13a08d0db1dd5b8cdedd101a53a53301f805c3686053361a94870b96',
    'bootstrap_audit': '11190d134c384308880db8f909ad86bae04ed88f0be7f1d473ca6c904ca78621',
    'initializer_checks': '8daa704b136cfeb42d21efad5360e4eb7d15fceb2c4a44f4490c9706017c37f7',
    'initializer_audit': '74cda9ca05f63296fa580560ee0ca6ae1f836e9934dbca2a694258124a3fdb57',
}
HOLDER = 0xfffffe000cd4e8a0
HEADER_ALLOC = 0xfffffe0008492400
HEADER_ROLLBACK = 0xfffffe0008492440
ENTRY_TYPE = 0xfffffe000cd43500
RELOCATIONS = {
    'initializer': (
        (0x24, 'adrp', 'x8, #0xfffffe0008493000'),
        (0x28, 'ldr', 'x8, [x8, #0x98]'),
        (0x34, 'adrp', 'x8, #0xfffffe000cd43000'),
        (0x38, 'ldr', 'w10, [x8, #0x120]'),
        (0x3c, 'adrp', 'x9, #0xfffffe000cd43000'),
        (0x40, 'ldr', 'w12, [x9, #0xd8]'),
        (0x68, 'adrp', 'x10, #0xfffffe0007954000'),
        (0x6c, 'add', 'x10, x10, #0x90'),
        (0x80, 'adrp', 'x11, #0xfffffe0007939000'),
        (0x84, 'add', 'x11, x11, #0xe80'),
        (0x94, 'adrp', 'x21, #0xfffffe0008488000'),
        (0x98, 'add', 'x21, x21, #0x9a0'),
        (0x22c, 'ldr', 'w8, [x8, #0x120]'),
        (0x230, 'ldr', 'w9, [x9, #0xd8]'),
        (0x414, 'adrp', 'x9, #0xfffffe0008493000'),
        (0x418, 'ldr', 'x9, [x9, #0x98]'),
    ),
    'size_helper': (
        (0x18, 'adrp', 'x9, #0xfffffe000cd43000'),
        (0x1c, 'ldr', 'x10, [x9, #0x178]'),
        (0x20, 'adrp', 'x11, #0xfffffe000cd43000'),
        (0x24, 'ldr', 'x12, [x11, #0xd8]'),
        (0x5c, 'str', 'x14, [x9, #0x178]'),
        (0x60, 'str', 'x15, [x11, #0xd8]'),
        (0x114, 'adrp', 'x12, #0xfffffe0007954000'),
        (0x118, 'add', 'x12, x12, #0x290'),
        (0x12c, 'adrp', 'x13, #0xfffffe000793a000'),
        (0x130, 'add', 'x13, x13, #0x280'),
        (0x140, 'adrp', 'x12, #0xfffffe0008488000'),
        (0x144, 'add', 'x12, x12, #0x9a0'),
    ),
}
EXTRA_BANKS = {
    0x4f0: (0xfffffe0007954294, 'UL', -4),
    0x578: (0xfffffe000793a284, 'UR', -4),
    0xc08: (0xfffffe000794c228, 'VL', -8),
    0x158: (0xfffffe0007954394, 'VR', -4),
}


def historical(name):
    source = command('zstd', '-dcq', str(HERE / f'userclient_hash_table_{name}.json.zst'))
    assert hashlib.sha256(source).hexdigest() == RECEIPT_HASHES[name]
    evidence = json.loads(source)
    if name.endswith('_checks'):
        assert evidence['kernel_collection_sha256'] == IDENTITIES[0][0]
    return evidence


def verify_initializer_code(image, source):
    starts = function_starts(image)
    results = {}
    for label, expected_start, expected_size in (
        ('initializer', 0xfffffe000a668590, 1100),
        ('size_helper', 0xfffffe000a5f4f58, 504),
    ):
        old = source['functions'][label]
        start = int(old['start'], 16) + CODE_DELTA
        end = starts[starts.index(start) + 1]
        old_bytes = bytes.fromhex(old['bytes_hex'])
        assert start == expected_start and len(old_bytes) == end - start == expected_size
        assert hashlib.sha256(old_bytes).hexdigest() == old['sha256']
        current = image.read(start, end - start)
        changes = RELOCATIONS[label]
        assert [offset for offset in range(0, len(current), 4)
                if old_bytes[offset:offset + 4] != current[offset:offset + 4]
                ] == [row[0] for row in changes]
        changed_words = assert_instructions(image.read, [
            (start + offset, mnemonic, operands) for offset, mnemonic, operands in changes
        ])
        results[label] = dict(start=hex(start), end_exclusive=hex(end), words=expected_size // 4,
                              old_sha256=old['sha256'], current_sha256=hashlib.sha256(current).hexdigest(),
                              changed_words=changed_words)
    assert image.branch(0xfffffe000a6689d8, 'bl') == 0xfffffe000a6e0424
    return results


def verify_selection(image, bootstrap, initializer):
    roots = {}
    banks = {}
    for offset, (address, label, bias) in (POOL_ROOTS | EXTRA_BANKS).items():
        if label.startswith('B'):
            continue
        roots[label] = verify_fixup(image, POOL + offset, address)
        banks[label] = image.read(address + bias, 256)
    for source in (bootstrap, initializer):
        for label, record in source['banks'].items():
            name = label.replace('descriptor', 'A').replace('free', 'F')
            assert banks[name].hex() == record['bytes_hex']
    targets = {
        'free': image.named('_IOFreeTypeImpl'),
        'descriptor': 0xfffffe0008491d40,
        'holder': HOLDER,
        'allocate': image.named('_IOMallocTypeImpl'),
        'allocate_descriptor': HEADER_ALLOC,
        'initialize': 0xfffffe000a668590,
        'rollback_free': image.named('_IOFreeTypeImpl'),
        'rollback_descriptor': HEADER_ROLLBACK,
        'init_controller_A': 0xfffffe000cd43120,
        'init_controller_B': 0xfffffe000cd430d8,
        'init_table': TABLE,
        'size_table': TABLE,
        'size_helper': 0xfffffe000a5f4f58,
        'variable_allocate': image.named('_IOMallocTypeVarImpl'),
        'variable_descriptor': ENTRY_TYPE,
    }
    rules = {}
    for item in bootstrap['bank_rules'] + initializer['bank_rules']:
        name = item['name']
        pair = item.get('pair', 'A' if name == 'descriptor' else 'F')
        left, right = (banks[('F' if pair == 'free' else pair) + side] for side in 'LR')
        key = int(item['key'], 16)
        constant = int(item['constant'], 16)
        assert {x ^ right[left[x] ^ key] for x in range(256)} == {constant}
        index = int(item['additive'], 16) + constant
        assert index == int(item['index'], 16)
        bias = int(item['bias'], 16)
        if bias >= 1 << 63:
            bias -= 1 << 64
        modifier = item['original_pointer']['diversity']
        base = TABLE if item['original_pointer']['authenticated'] else POOL
        fixup = verify_fixup(image, base + index * 8, targets[name] - bias, modifier)
        rules[name] = dict(index=hex(index), constant=hex(constant), bias=bias,
                           target=hex(targets[name]), fixup=fixup)
    branches = {}
    for row in bootstrap['branch_pointers'] + initializer['branch_pointers']:
        index = row['index']
        target = int(row['target'], 16) + CODE_DELTA
        branches[hex(index)] = verify_fixup(image, TABLE + 8 * index, target, row['diversity'])
        image.instruction(target, 'bti', 'j')
    assert len(branches) == 18 and len(rules) == 15 and len(roots) == 10
    return dict(pool_roots=roots, bank_rules=rules, branch_fixups=branches)


def audit(collection):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(collection, IDENTITIES[1])
    bootstrap = historical('bootstrap_checks')
    initializer = historical('initializer_checks')
    context = read_receipt('userclient_context_lifecycle_source')
    bodies = verify_initializer_code(image, initializer)
    prior_bodies = verify_bodies(image, context)
    selection = verify_selection(image, bootstrap, initializer)
    assert image.read(HOLDER, 8) == bytes(8)
    allocated = read_descriptor(image, HEADER_ALLOC, 'site.FPHashTable', '21', 16)
    rollback = read_descriptor(image, HEADER_ROLLBACK, 'site.FPHashTable', '21', 16)
    assert allocated['bytes'] == rollback['bytes']
    entry = image.read(ENTRY_TYPE, 64)
    assert struct.unpack_from('<II', entry) == (1, 24)
    entry_name = image.pointer(ENTRY_TYPE + 16)
    assert (entry_name['format'], entry_name['auth']) == (8, 0)
    assert image.read(int(entry_name['target'], 16), 22) == b'site.FPHashTableEntry\0'
    guard = verify_fixup(image, 0xfffffe0008493098, image.named('___stack_chk_guard'))
    fail = image.pointer(0xfffffe0008492f18)
    assert fail['target'] == hex(image.named('___stack_chk_fail'))
    assert (fail['format'], fail['auth'], fail['key'], fail['diversity'],
            fail['address_diversity']) == (8, 1, 0, '0x0', 1)
    adapters = assert_instructions(image.read, (
        (0xfffffe000a6e0424, 'adrp', 'x17, #0xfffffe0008492000'),
        (0xfffffe000a6e0428, 'add', 'x17, x17, #0xf18'),
        (0xfffffe000a6e042c, 'ldr', 'x16, [x17]'),
        (0xfffffe000a6e0430, 'braa', 'x16, x17'),
        (0xfffffe000c509778, 'ldr', 'w8, [x0, #0x28]'),
        (0xfffffe000c50977c, 'tst', 'w8, #0x10'),
        (0xfffffe000c509788, 'csel', 'w1, w9, w8, eq'),
        (0xfffffe000c50978c, 'b', '#0xfffffe000bd46a80'),
        (0xfffffe000c50998c, 'b', '#0xfffffe000bd46f04'),
        (0xfffffe000c509f7c, 'bti', 'c'),
        (0xfffffe000c509f80, 'orr', 'x0, x0, #1'),
        (0xfffffe000c509f84, 'mov', 'w2, #0x1004'),
        (0xfffffe000c509f88, 'movk', 'w2, #0x1f, lsl #16'),
        (0xfffffe000c509f8c, 'mov', 'x3, #0'),
        (0xfffffe000c509f90, 'b', '#0xfffffe000bd464ac'),
    ))
    proofs = []
    for name, count in (('bootstrap_audit', 12), ('initializer_audit', 21)):
        group = historical(name)['source_proofs']
        assert len(group) == count
        proofs.extend(group)
    with ThreadPoolExecutor(max_workers=4) as workers:
        replays = list(workers.map(replay_proof, proofs))
    return dict(build=build, identity=IDENTITIES[1], historical_receipts=RECEIPT_HASHES,
                functions=dict(bootstrap=prior_bodies['destroy'], **bodies), **selection,
                holder=hex(HOLDER), holder_file_bytes_zero=True, native_holder_known=False,
                header_allocate_descriptor=allocated, header_rollback_descriptor=rollback,
                entry_descriptor=dict(address=hex(ENTRY_TYPE), bytes=entry.hex(),
                                      name_pointer=entry_name, stride_bytes=24),
                canary_fixups=[guard, fail], adapter_checks=adapters, historical_proof_replays=replays,
                native_allocation_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.collection), indent=2))
