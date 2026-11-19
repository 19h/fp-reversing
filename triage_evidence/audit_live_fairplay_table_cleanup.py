#!/usr/bin/env python3
"""Verify installed FairPlay table lookup, reclamation and typed payload release."""

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
    CODE_DELTA, POOL, POOL_ROOTS, TABLE, function_starts, read_receipt, replay_proof, verify_bodies,
)
from audit_live_fairplay_shared_table import EXTRA_BANKS
from audit_live_kext_selector26 import Collection, IDENTITIES

HERE = Path(__file__).resolve().parent
HISTORICAL_HASHES = {
    'lookup_checks': '16fba57feb5ae001eb4309a331352acc8ec6a512045171d45d878e5a3b970f22',
    'lookup_audit': '7f9b62cf8034038c7443678fd0f13e8eb257ec7c453e8f6d0596be3a6fe46e68',
    'reclamation_checks': '831f3e6b1a7283f2b1b6a87df5a99a1bb627f3552e0c72da0c65d7e88b6757c0',
    'reclamation_audit': 'c3bea10d4cdbc608f9f03d208249ea2cb94e30f91a16c2b146f40d59e968aab4',
}
LOOKUP = 0xfffffe000a5ef4e4
WRITER = 0xfffffe000a5efdb4
RECLAIMER = 0xfffffe000a6579f0
PAYLOAD_TYPE = 0xfffffe0008492a00
HELPER_LAYOUTS = {
    'lookup': (LOOKUP, 1336),
    'writer': (WRITER, 496),
    'reclaimer': (RECLAIMER, 1272),
}
RELOCATIONS = {
    'lookup': (
        (0x28, 'adrp', 'x9, #0xfffffe000cd42000'),
        (0x2c, 'ldr', 'x10, [x9, #0xf38]'),
        (0x30, 'adrp', 'x11, #0xfffffe000cd43000'),
        (0x34, 'ldr', 'x12, [x11, #0xd8]'),
        (0x6c, 'str', 'x15, [x9, #0xf38]'),
        (0x70, 'str', 'x16, [x11, #0xd8]'),
        (0xf4, 'adrp', 'x14, #0xfffffe000793a000'),
        (0xf8, 'add', 'x14, x14, #0x80'),
        (0x10c, 'adrp', 'x15, #0xfffffe0007943000'),
        (0x110, 'add', 'x15, x15, #0x5b0'),
        (0x128, 'adrp', 'x12, #0xfffffe0008488000'),
        (0x12c, 'add', 'x12, x12, #0x9a0'),
    ),
    'writer': (
        (0x8, 'adrp', 'x8, #0xfffffe000cd43000'),
        (0xc, 'ldr', 'x9, [x8, #0x180]'),
        (0x10, 'adrp', 'x10, #0xfffffe000cd43000'),
        (0x14, 'ldr', 'x11, [x10, #0xd8]'),
        (0x4c, 'str', 'x14, [x8, #0x180]'),
        (0x50, 'str', 'x15, [x10, #0xd8]'),
        (0xac, 'adrp', 'x12, #0xfffffe000794c000'),
        (0xb0, 'add', 'x12, x12, #0x220'),
        (0xc4, 'adrp', 'x13, #0xfffffe0007954000'),
        (0xc8, 'add', 'x13, x13, #0x390'),
        (0xd8, 'adrp', 'x12, #0xfffffe0008488000'),
        (0xdc, 'add', 'x12, x12, #0x9a0'),
    ),
    'reclaimer': (
        (0x28, 'adrp', 'x8, #0xfffffe0008493000'),
        (0x2c, 'ldr', 'x8, [x8, #0x98]'),
        (0x50, 'adrp', 'x8, #0xfffffe000cd43000'),
        (0x54, 'ldr', 'w10, [x8, #0x108]'),
        (0x58, 'adrp', 'x9, #0xfffffe000cd43000'),
        (0x5c, 'ldr', 'w13, [x9, #0xd8]'),
        (0x6c, 'adrp', 'x10, #0xfffffe0007954000'),
        (0x70, 'add', 'x10, x10, #0x90'),
        (0x84, 'adrp', 'x11, #0xfffffe0007939000'),
        (0x88, 'add', 'x11, x11, #0xe80'),
        (0x9c, 'adrp', 'x12, #0xfffffe0008488000'),
        (0xa0, 'add', 'x12, x12, #0x9a0'),
        (0x168, 'ldr', 'w8, [x8, #0x108]'),
        (0x16c, 'ldr', 'w9, [x9, #0xd8]'),
        (0x4c0, 'adrp', 'x9, #0xfffffe0008493000'),
        (0x4c4, 'ldr', 'x9, [x9, #0x98]'),
    ),
}


def historical(name):
    raw = command('zstd', '-dcq', str(HERE / f'userclient_hash_table_{name}.json.zst'))
    assert hashlib.sha256(raw).hexdigest() == HISTORICAL_HASHES[name]
    receipt = json.loads(raw)
    if name.endswith('_checks'):
        assert receipt['kernel_collection_sha256'] == IDENTITIES[0][0]
    return receipt


def verify_code(image, lookup, reclamation):
    context = read_receipt('userclient_context_lifecycle_source')
    destroy = verify_bodies(image, context)['destroy']
    starts = function_starts(image)
    functions = {}
    for name, saved in {'lookup': lookup['lookup_function'], **reclamation['functions']}.items():
        start, size = HELPER_LAYOUTS[name]
        end = starts[starts.index(start) + 1]
        assert int(saved['start'], 16) + CODE_DELTA == start
        assert int(saved['end'], 16) + CODE_DELTA == end
        old = bytes.fromhex(saved['bytes_hex'])
        assert end - start == len(old) == size
        assert hashlib.sha256(old).hexdigest() == saved['sha256']
        current = image.read(start, size)
        changes = RELOCATIONS[name]
        assert [offset for offset in range(0, size, 4)
                if old[offset:offset + 4] != current[offset:offset + 4]
                ] == [row[0] for row in changes]
        changed_words = assert_instructions(image.read, [
            (start + offset, mnemonic, operands) for offset, mnemonic, operands in changes
        ])
        functions[name] = dict(start=hex(start), end_exclusive=hex(end), words=size // 4,
                               old_sha256=saved['sha256'], sha256=hashlib.sha256(current).hexdigest(),
                               changed_words=changed_words)
    regions = {}
    for name, source in (('lookup', lookup), ('reclamation', reclamation)):
        assert source['parent_caller_sha256'] == destroy['old_sha256']
        old = source['caller_region']
        start = int(old['start'], 16) + CODE_DELTA
        end = int(old['end_exclusive'], 16) + CODE_DELTA
        raw = image.read(start, end - start)
        assert raw.hex() == old['bytes_hex']
        regions[name] = dict(start=hex(start), end_exclusive=hex(end), words=len(raw) // 4,
                             sha256=hashlib.sha256(raw).hexdigest())
    assert regions['lookup']['start'] == '0xfffffe000a667f58'
    assert regions['lookup']['end_exclusive'] == regions['reclamation']['start']
    assert regions['reclamation']['end_exclusive'] == destroy['end_exclusive']
    return destroy, functions, regions


def verify_tables(image, lookup, reclamation):
    banks = {
        'BL': image.read(0xfffffe000793a080, 256),
        'BR': image.read(0xfffffe00079435b0, 256),
    }
    roots = {}
    for offset, (address, name, bias) in (POOL_ROOTS | EXTRA_BANKS).items():
        if name[0] in 'FVTU':
            roots[name] = verify_fixup(image, POOL + offset, address)
            banks[name] = image.read(address + bias, 256)
    targets = {
        'first_lookup': LOOKUP,
        'second_lookup': LOOKUP,
        'helper_table': TABLE,
        'caller_writer': WRITER,
        'caller_reclaimer': RECLAIMER,
        'caller_free': image.named('_IOFreeTypeImpl'),
        'free_descriptor': PAYLOAD_TYPE,
        'writer_table': TABLE,
        'table_controller_A': 0xfffffe000cd43108,
        'table_controller_B': 0xfffffe000cd430d8,
        'table_table': TABLE,
        'nested_writer': WRITER,
    }
    rules = {}
    branches = {}
    for source in (lookup, reclamation):
        for name, bank in source['banks'].items():
            assert banks[name].hex() == bank['bytes_hex']
        for rule in source['bank_rules']:
            name, pair = rule['name'], rule['pair']
            key, constant, bias = (int(rule[field], 16) for field in ('key', 'constant', 'bias'))
            left, right = banks[pair + 'L'], banks[pair + 'R']
            assert {x ^ right[left[x] ^ key] for x in range(256)} == {constant}
            index = int(rule['additive'], 16) + constant
            assert index == int(rule['index'], 16)
            bias = struct.unpack('<q', struct.pack('<Q', bias))[0]
            original = rule['original_pointer']
            base = TABLE if original['authenticated'] else POOL
            fixup = verify_fixup(image, base + 8 * index, targets[name] - bias,
                                 original['diversity'])
            rules[name] = dict(index=hex(index), constant=hex(constant), bias=bias,
                               target=hex(targets[name]), fixup=fixup)
        for branch in source['branch_pointers']:
            index = branch['index']
            target = int(branch['target'], 16) + CODE_DELTA
            fixup = verify_fixup(image, TABLE + 8 * index, target, branch['diversity'])
            image.instruction(target, 'bti', 'j')
            branches[hex(index)] = fixup
    assert len(banks) == 10 and len(roots) == 8 and len(rules) == 12 and len(branches) == 37
    return dict(pool_roots=roots, bank_rules=rules, branch_fixups=branches,
                bank_sha256={name: hashlib.sha256(data).hexdigest() for name, data in banks.items()})


def verify_release_interface(image, previous):
    raw = image.read(PAYLOAD_TYPE, 64)
    old = bytes.fromhex(previous['original64_bytes_hex'])
    assert raw[:16] == old[:16] and raw[24:32] == old[24:32] and raw[40:] == old[40:]
    assert struct.unpack_from('<II', raw, 40) == (0x6c, 120)
    name = verify_fixup(image, PAYLOAD_TYPE + 16, 0xfffffe000794d980)
    signature = verify_fixup(image, PAYLOAD_TYPE + 32, 0xfffffe00079460a0)
    assert image.read(int(name['target'], 16), 20) == b'site.FPSecureTunnel\0'
    assert image.read(int(signature['target'], 16), 1) == b'\0'
    assert image.named('_IOFreeTypeImpl') == 0xfffffe000c509988
    assert image.branch(0xfffffe000a657ee4, 'bl') == 0xfffffe000a6e0424
    guard = verify_fixup(image, 0xfffffe0008493098, image.named('___stack_chk_guard'))
    failure = image.pointer(0xfffffe0008492f18)
    assert failure['target'] == hex(image.named('___stack_chk_fail'))
    assert (failure['format'], failure['auth'], failure['key'], failure['diversity'],
            failure['address_diversity']) == (8, 1, 0, '0x0', 1)
    instructions = assert_instructions(image.read, (
        (0xfffffe000c509988, 'bti', 'c'),
        (0xfffffe000c50998c, 'b', '#0xfffffe000bd46f04'),
        (0xfffffe000a6e0424, 'adrp', 'x17, #0xfffffe0008492000'),
        (0xfffffe000a6e0428, 'add', 'x17, x17, #0xf18'),
        (0xfffffe000a6e042c, 'ldr', 'x16, [x17]'),
        (0xfffffe000a6e0430, 'braa', 'x16, x17'),
    ))
    descriptor = dict(address=hex(PAYLOAD_TYPE), bytes=raw.hex(), name='site.FPSecureTunnel',
                      signature='', flags_u32=0x6c, size_bytes=120, name_pointer=name,
                      signature_pointer=signature)
    return dict(payload_release_descriptor=descriptor, canary_fixups=[guard, failure],
                adapter_instructions=instructions)


def audit(collection):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(collection, IDENTITIES[1])
    lookup = historical('lookup_checks')
    reclamation = historical('reclamation_checks')
    destroy, functions, regions = verify_code(image, lookup, reclamation)
    tables = verify_tables(image, lookup, reclamation)
    release = verify_release_interface(image, reclamation['typed_free_descriptor'])

    proofs = []
    for name, expected_count in (('lookup_audit', 37), ('reclamation_audit', 36)):
        prior = historical(name)
        assert prior['checks_sha256'] == HISTORICAL_HASHES[name.replace('_audit', '_checks')]
        assert len(prior['source_proofs']) == expected_count
        proofs.extend(prior['source_proofs'])
    with ThreadPoolExecutor(max_workers=4) as workers:
        replays = list(workers.map(replay_proof, proofs))
    return dict(build=build, identity=IDENTITIES[1], historical_receipts=HISTORICAL_HASHES,
                destroy=destroy, functions=functions, caller_regions=regions, **tables, **release,
                historical_proof_replays=replays, native_deallocation_observed=False,
                native_daemon_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.collection), indent=2))
