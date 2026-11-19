#!/usr/bin/env python3
"""Check installed FairPlay tunnel allocation and table insertion bindings."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import struct

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import CODE_DELTA, POOL, POOL_ROOTS, TABLE, function_starts, replay_proof
from audit_live_fairplay_shared_table import EXTRA_BANKS
from audit_live_fairplay_table_cleanup import LOOKUP, PAYLOAD_TYPE, WRITER
from audit_live_kext_selector26 import Collection, IDENTITIES

HERE = Path(__file__).resolve().parent
HASHES = {
    'allocation_checks': '447c0147f900d5da40c67b314f3e41c82a34ded9045699e4e7b761b96e0e81fe',
    'allocation_audit': '58bbb935c0cbb2fb4121f69a43b3887ac5a3d04982922874dcf5728da1111d8c',
    'table_insertion_checks': '2a02b7cad33072f3790125634f6d8d0deacd690f978df65a76b3939688b7e9df',
    'table_insertion_audit': '51a55c97d7989c6bc57b48b0c77301aeb11bf52eb5b3bc4871c0c4e88a9e9f02',
}
ALLOC_TYPE = 0xfffffe0008492bc0
HEADER_TYPE = 0xfffffe0008492240
RELOCATIONS = (
    (0xfffffe000a69b6d8, 'adrp', 'x10, #0xfffffe0008488000'),
    (0xfffffe000a69b6dc, 'add', 'x10, x10, #0x9a0'),
)


def load_receipt(key):
    raw = command('zstd', '-dcq', str(HERE / f'secure_tunnel_{key}.json.zst'))
    assert hashlib.sha256(raw).hexdigest() == HASHES[key]
    return json.loads(raw)


def verify_code(image, allocation, insertion):
    container = allocation['function_container']
    assert container == insertion['function_container']
    start = image.named('_PRnut72j9')
    starts = function_starts(image)
    end = starts[starts.index(start) + 1]
    assert start == int(container['start'], 16) + CODE_DELTA
    assert end == int(container['end_exclusive'], 16) + CODE_DELTA
    raw = image.read(start, end - start)
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == 'f6e14d3993bdc8ff46e4dfe9ac6b00f71d04ca2a8902d40d6ca06e23a1fd9220'

    spans = {}
    changes = set()
    for label, source in (('allocation', allocation), ('insertion', insertion)):
        ranges = [(r['label'], r['start'], r['bytes_hex']) for r in source['spans']]
        ranges.extend((f'transfer_{r["ea"]}', r['ea'], r['bytes_hex']) for r in source['transfers'])
        if label == 'insertion':
            gap = source['record_root_def_use_gap']
            ranges.append(('def_use_gap', gap['start'], gap['bytes_hex']))
        spans[label] = {}
        for name, address, contents in ranges:
            old = bytes.fromhex(contents)
            pc = int(address, 16) + CODE_DELTA
            new = image.read(pc, len(old))
            differing = [pc + i for i in range(0, len(old), 4) if old[i:i+4] != new[i:i+4]]
            changes.update(differing)
            spans[label][name] = dict(address=hex(pc), words=len(old) // 4,
                                      sha256=hashlib.sha256(new).hexdigest(),
                                      changed_addresses=[hex(a) for a in differing])
    assert changes == {row[0] for row in RELOCATIONS}
    relocated = assert_instructions(image.read, RELOCATIONS)
    return dict(container=dict(start=hex(start), end_exclusive=hex(end), words=len(raw) // 4,
                               sha256=digest), compared_ranges=spans, relocated=relocated)


def verify_descriptor(image, address, size, name):
    raw = image.read(address, 64)
    assert struct.unpack_from('<II', raw, 40) == (0x6c, size)
    pointers = {}
    for key, offset, value in (('name', 16, name), ('signature', 32, '')):
        ptr = image.pointer(address + offset)
        fixup = verify_fixup(image, address + offset, int(ptr['target'], 16))
        expected = value.encode() + bytes(1)
        assert image.read(int(fixup['target'], 16), len(expected)) == expected
        pointers[key] = fixup
    return dict(address=hex(address), name=name, size_bytes=size, flags=0x6c, bytes=raw.hex(),
                pointers=pointers)


def verify_bindings(image, allocation, insertion):
    banks = {}
    roots = {}
    for offset, (address, label, bias) in (POOL_ROOTS | EXTRA_BANKS).items():
        if label[0] in 'BTFV':
            roots[label] = verify_fixup(image, POOL + offset, address)
            banks[label] = image.read(address + bias, 256)

    alloc = image.named('_IOMallocTypeImpl')
    expected = {
        'allocate_adapter': ('B', 0x93, 0xe27, TABLE, alloc, '0xd0c8'),
        'allocate_descriptor': ('B', 0x93, -0x58, POOL, ALLOC_TYPE + 4, '0x0'),
        'lookup': ('T', 0xd8, 0xef9, TABLE, LOOKUP, '0x6a0f'),
        'writer': ('T', 0x5c, 0xe8b, TABLE, WRITER, '0x3936'),
        'header_allocate_adapter': ('F', 0x87, 0xe34, TABLE, alloc, '0xd0c8'),
        'header_allocate_descriptor': ('V', 0x98, -0x72, POOL, HEADER_TYPE + 4, '0x0'),
    }
    rules = {}
    prior_rules = {row['name']: row for source in (allocation, insertion) for row in source['bank_rules']}
    for label, (pair, key, additive, base, target, modifier) in expected.items():
        left, right = (banks[pair + side] for side in 'LR')
        constant, = {x ^ right[left[x] ^ key] for x in range(256)}
        index = additive + constant
        if label in prior_rules:
            assert index == int(prior_rules[label]['index'], 16)
            assert modifier == prior_rules[label]['original_pointer']['diversity']
        rules[label] = dict(index=hex(index), constant=hex(constant),
                            fixup=verify_fixup(image, base + index * 8, target, modifier))
    for source, pairs in ((allocation, ('BL', 'BR')), (insertion, ('TL', 'TR'))):
        for old, name in zip(source['banks'].values(), pairs, strict=True):
            assert banks[name].hex() == old['bytes_hex']
    branches = {}
    for row in allocation['branch_pointers'] + insertion['branch_pointers']:
        target = int(row['target'], 16) + CODE_DELTA
        branches[hex(row['index'])] = verify_fixup(image, TABLE + row['index'] * 8, target,
                                                  row['diversity'])
        image.instruction(target, 'bti', 'j')
    return dict(bank_roots=roots, bank_rules=rules, branch_fixups=branches)


def verify_header_fallback(image):
    checks = assert_instructions(image.read, (
        (0xfffffe000a6776e8, 'ldr', 'x3, [sp, #0xa50]'),
        (0xfffffe000a677718, 'add', 'x16, x3, x11'),
        (0xfffffe000a677728, 'ldrb', 'w16, [x25, w16, uxtw]'),
        (0xfffffe000a677734, 'sub', 'w17, w16, #0x72'),
        (0xfffffe000a67773c, 'sub', 'x17, x17, #4'),
        (0xfffffe000a677740, 'str', 'x17, [sp, #0x848]'),
        (0xfffffe000a6777ec, 'ldr', 'x9, [x28, #0x458]'),
        (0xfffffe000a6777f4, 'ldr', 'x9, [x28, #0x638]'),
        (0xfffffe000a677828, 'str', 'x10, [sp, #0xa20]'),
        (0xfffffe000a69b84c, 'ldr', 'x8, [x7, w8, uxtw #3]'),
        (0xfffffe000a69b850, 'ldr', 'x0, [sp, #0x848]'),
        (0xfffffe000a69b858, 'blraa', 'x8, x17'),
        (0xfffffe000a69b8c0, 'braa', 'x8, x17'),
        (0xfffffe000a69b8d0, 'str', 'w9, [x0]'),
        (0xfffffe000a69b8d4, 'strh', 'wzr, [x0, #4]'),
        (0xfffffe000a69b8dc, 'str', 'x0, [x10]'),
        (0xfffffe000a69b8e0, 'str', 'w9, [x1]'),
        (0xfffffe000a69b8f0, 'strb', 'w9, [x1, #5]'),
    ))
    phase = 0x9f3 ^ 0xe64
    phase_input = (phase - 0x7795e642 - 0x4b2) & 0xffffffff
    followup = phase_input ^ (0x886a1ca3 - 0x73)
    assert (phase, followup) == (0x797, 0x93)
    null_index = phase ^ (followup - 0x84)
    assert null_index == 0x798
    null_pc = 0xfffffe000a69c06c
    image.instruction(null_pc, 'bti', 'j')
    null_fixup = verify_fixup(image, TABLE + 8 * null_index, null_pc, '0xe9eb')
    return dict(instructions=checks, nonnull_index=hex(phase), null_index=hex(null_index),
                null_branch=null_fixup)


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    allocation = load_receipt('allocation_checks')
    insertion = load_receipt('table_insertion_checks')
    assert allocation['kernel_collection_sha256'] == insertion['kernel_collection_sha256'] == IDENTITIES[0][0]
    code = verify_code(image, allocation, insertion)
    bindings = verify_bindings(image, allocation, insertion)
    descriptors = {
        'allocate': verify_descriptor(image, ALLOC_TYPE, 120, 'site.FPSecureTunnel'),
        'free': verify_descriptor(image, PAYLOAD_TYPE, 120, 'site.FPSecureTunnel'),
        'header_fallback_allocate': verify_descriptor(image, HEADER_TYPE, 8, 'site.FPSecureTunnelAttr'),
    }
    assert descriptors['allocate']['bytes'] == descriptors['free']['bytes']
    fallback = verify_header_fallback(image)
    proofs = []
    for key, count in (('allocation', 10), ('table_insertion', 15)):
        prior = load_receipt(key + '_audit')
        assert prior['checks_sha256'] == HASHES[key + '_checks']
        assert len(prior['source_proofs']) == count
        proofs.extend(prior['source_proofs'])
    with ThreadPoolExecutor(max_workers=4) as workers:
        replays = list(workers.map(replay_proof, proofs))
    return dict(build=build, identity=IDENTITIES[1], historical_hashes=HASHES, **code,
                **bindings, descriptors=descriptors, fallback=fallback, history=replays,
                native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
