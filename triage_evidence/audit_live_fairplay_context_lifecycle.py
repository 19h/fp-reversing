#!/usr/bin/env python3
"""Verify which typed FairPlay context lifecycle paths carry over to the installed build."""

import argparse
import hashlib
import json
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_kext_selector26 import DRIVER, Collection, IDENTITIES
from resolve_kernel_collection_interfaces import commands

HERE = Path(__file__).resolve().parent
POOL = 0xfffffe00084889a0
TABLE = 0xfffffe00084899c0
CODE_DELTA = 0x41190
RECEIPTS = {
    'userclient_context_lifecycle_source':
        '290ed4483ba0a9e4b4350f3b70a55537f4c4adeef963942bfbc452f3d99a4fa1',
    'userclient_context_lifecycle_checks':
        '91ae174d57898ee7b21b164635c06fbd6f56c5d54ea01edd2c1adc24f8d59f52',
    'userclient_uidlist_cleanup_checks':
        'd43b29782714595f1d80e59a2169b2c87ec9ffe55366aaa93ee5f6af597407bd',
    'userclient_uidlist_cleanup_audit':
        '801e96725f8b9bf58dd6c50c705c6978242c84abc372792e2654b34223025c01',
}
RELOCATIONS = {
    'create': (
        (0x3c, 'adrp', 'x13, #0xfffffe000cd43000'),
        (0x40, 'ldr', 'w10, [x13, #0x168]'),
        (0x44, 'adrp', 'x14, #0xfffffe000cd43000'),
        (0x48, 'ldr', 'w15, [x14, #0xd8]'),
        (0x58, 'adrp', 'x10, #0xfffffe0007954000'),
        (0x5c, 'add', 'x10, x10, #0x190'),
        (0x70, 'adrp', 'x16, #0xfffffe000793a000'),
        (0x74, 'add', 'x16, x16, #0x180'),
        (0x88, 'adrp', 'x11, #0xfffffe0008488000'),
        (0x8c, 'add', 'x11, x11, #0x9a0'),
        (0x114, 'ldr', 'w13, [x13, #0x168]'),
        (0x118, 'ldr', 'w14, [x14, #0xd8]'),
        (0x124, 'adrp', 'x14, #0xfffffe0007954000'),
        (0x128, 'add', 'x14, x14, #0x90'),
        (0x13c, 'adrp', 'x0, #0xfffffe0007939000'),
        (0x140, 'add', 'x0, x0, #0xe80'),
    ),
    'destroy': (
        (0x24, 'adrp', 'x8, #0xfffffe0008493000'),
        (0x28, 'ldr', 'x8, [x8, #0x98]'),
        (0x4c, 'adrp', 'x8, #0xfffffe000cd43000'),
        (0x50, 'ldr', 'w9, [x8, #0x110]'),
        (0x54, 'adrp', 'x10, #0xfffffe000cd43000'),
        (0x58, 'ldr', 'w11, [x10, #0xd8]'),
        (0x68, 'adrp', 'x12, #0xfffffe0007954000'),
        (0x6c, 'add', 'x12, x12, #0x90'),
        (0x80, 'adrp', 'x14, #0xfffffe0007939000'),
        (0x84, 'add', 'x14, x14, #0xe80'),
        (0x98, 'adrp', 'x25, #0xfffffe0008488000'),
        (0x9c, 'add', 'x25, x25, #0x9a0'),
        (0x118, 'ldr', 'w8, [x8, #0x110]'),
        (0x11c, 'ldr', 'w10, [x10, #0xd8]'),
        (0x1c8, 'adrp', 'x9, #0xfffffe0008488000'),
        (0x1cc, 'add', 'x9, x9, #0xdf8'),
        (0x2a0, 'adrp', 'x10, #0xfffffe0008493000'),
        (0x2a4, 'ldr', 'x10, [x10, #0x98]'),
    ),
}
POOL_ROOTS = {
    0x840: (0xfffffe0007954090, 'TL', 0),
    0xbb8: (0xfffffe0007939e80, 'TR', 0),
    0xb70: (0xfffffe0007954190, 'AL', 0),
    0xa10: (0xfffffe000793a180, 'AR', 0),
    0xf50: (0xfffffe000793a084, 'BL', -4),
    0xf20: (0xfffffe00079435b4, 'BR', -4),
    0x458: (0xfffffe0007939f88, 'FL', -8),
    0x638: (0xfffffe00079434bc, 'FR', -12),
}
SELECTED_TARGETS = {
    'CA': 0xfffffe000cd43168,
    'CB': 0xfffffe000cd430dc,
    'CT': TABLE,
    'ADESC': 0xfffffe0008492300,
    'DA': 0xfffffe000cd43110,
    'DB': 0xfffffe000cd430d8,
    'DT': TABLE,
    'FDESC': 0xfffffe0008492d00,
    'descriptor': 0xfffffe0008491d40,
}
CONTEXT_PROOFS = (
    'context_create_entry_exact_controller_stores_table_and_null_cell_gate',
    'context_create_exact_typed_allocator_descriptor_and_saved_mode_task',
    'context_create_null_allocation_gate_and_raw_error',
    'context_success_exact24_byte_head_mode_task_and_cell_publication',
    'context_destroy_exact_roots_and_null_cell_gate',
    'context_destroy_reads_cell_and_returns_zero_for_empty_cell',
    'context_destroy_empty_head_selects_typed_free_and_saves_cell',
    'context_destroy_empty_head_exact_typed_free_ABI',
    'context_destroy_after_free_clears_original_cell_and_returns_zero',
    'context_destroy_normal_epilogue_uses_raw_status_in_w8',
)


def read_receipt(name):
    raw = command('zstd', '-dcq', str(HERE / (name + '.json.zst')))
    assert hashlib.sha256(raw).hexdigest() == RECEIPTS[name]
    return json.loads(raw)


def function_starts(image):
    entry = image.entries[DRIVER]
    location, = (at for at, cmd, _ in commands(image.data, entry['header_offset'])
                 if cmd == 0x26)
    offset, size = struct.unpack_from('<II', image.data, location + 8)
    value = next(segment['address'] for segment in entry['segments'] if segment['name'] == '__TEXT')
    starts = []
    delta = shift = 0
    for byte in image.data[offset:offset + size]:
        delta |= (byte & 127) << shift
        if byte >= 128:
            shift += 7
            assert shift < 70
        elif delta:
            value += delta
            starts.append(value)
            delta = shift = 0
        else:
            break
    assert len(starts) == 450
    return starts


def verify_bodies(image, historical):
    starts = function_starts(image)
    results = {}
    for role, symbol, size in (('create', '_lapsl183ah', 640), ('destroy', '_kratpzs81h', 3512)):
        previous = historical['functions'][role]
        old = bytes.fromhex(previous['bytes'])
        start = image.named(symbol)
        end = starts[starts.index(start) + 1]
        assert end - start == len(old) == size
        assert start - int(previous['start'], 16) == CODE_DELTA
        assert hashlib.sha256(old).hexdigest() == previous['sha256']
        new = image.read(start, size)
        changes = RELOCATIONS[role]
        assert [offset for offset in range(0, size, 4)
                if old[offset:offset + 4] != new[offset:offset + 4]] == [row[0] for row in changes]
        checked = assert_instructions(image.read, [(start + offset, mnemonic, operands)
                                                for offset, mnemonic, operands in changes])
        results[role] = dict(symbol=symbol, start=hex(start), end_exclusive=hex(end),
                             sha256=hashlib.sha256(new).hexdigest(), old_sha256=previous['sha256'],
                             words=size // 4, changed_words=checked)
    return results


def verify_banks(image, context, nodes):
    roots = {}
    raw_banks = {}
    for offset, (address, label, bias) in POOL_ROOTS.items():
        roots[label] = verify_fixup(image, POOL + offset, address)
        blob = image.read(address + bias, 256)
        assert blob.hex() == context['banks'][label]['bytes']
        raw_banks[label] = blob
    assert image.pointer(POOL + 0x33 * 8)['target'] == hex(TABLE + 12)
    targets = dict(SELECTED_TARGETS, ALLOC=image.named('_IOMallocTypeImpl'),
                   FREE=image.named('_IOFreeTypeImpl'), free=image.named('_IOFreeTypeImpl'))
    rules = []
    for row in context['bank_rules'] + nodes['bank_rules']:
        name = row['name']
        pair = row.get('pair', 'F' if name == 'free' else 'A')
        left, right = (raw_banks[pair + side] for side in 'LR')
        key, bias = (int(row[field], 16) for field in ('key', 'bias'))
        if bias >= 1 << 63:
            bias -= 1 << 64
        constant = int(row['constant'], 16)
        assert {x ^ right[left[x] ^ key] for x in range(256)} == {constant}
        index = int(row['additive'], 16) + constant
        assert index == int(row['index'], 16)
        base = TABLE if name in ('ALLOC', 'FREE', 'free') else POOL
        modifier = row['original_pointer']['diversity']
        fixup = verify_fixup(image, base + index * 8, targets[name] - bias, modifier)
        rules.append(dict(name=name, pair=pair, key=hex(key), constant=hex(constant), index=hex(index),
                          bias=bias, target=hex(targets[name]), fixup=fixup))
    return roots, rules


def verify_branches(image, context, nodes):
    branches = {}
    for row in context['branch_pointers'] + nodes['branch_pointers']:
        index = row['index']
        target = int(row['target'], 16) + CODE_DELTA
        fixup = verify_fixup(image, TABLE + index * 8, target, row['diversity'])
        image.instruction(target, 'bti', 'j')
        assert branches.setdefault(hex(index), fixup) == fixup
    assert len(branches) == 13
    return branches


def read_descriptor(image, address, name, signature, size):
    data = image.read(address, 64)
    assert struct.unpack_from('<II', data, 40) == (0x64, size)
    pointers = {}
    for offset, label, value in ((16, 'name', name), (32, 'signature', signature)):
        fixup = image.pointer(address + offset)
        assert (fixup['format'], fixup['auth']) == (8, 0)
        assert image.read(int(fixup['target'], 16), len(value) + 1) == value.encode() + b'\0'
        pointers[label] = fixup
    return dict(address=hex(address), bytes=data.hex(), name=name, signature=signature,
                flags_u32=0x64, size_bytes=size, pointers=pointers)


def replay_proof(proof):
    query = proof['query'].encode()
    result = subprocess.run(['z3', '-in', '-T:45'], input=query, capture_output=True,
                            timeout=50, check=True).stdout.strip()
    assert result == b'unsat' and proof['result'] == 'unsat'
    return dict(name=proof.get('name') or proof['label'],
                query_sha256=hashlib.sha256(query).hexdigest(), result='unsat')


def audit(collection):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(collection, IDENTITIES[1])
    context = read_receipt('userclient_context_lifecycle_source')
    nodes = read_receipt('userclient_uidlist_cleanup_checks')
    assert context['kernel_collection_sha256'] == nodes['kernel_collection_sha256'] == IDENTITIES[0][0]
    assert context['kext_UUID'] == IDENTITIES[0][2]
    bodies = verify_bodies(image, context)
    roots, rules = verify_banks(image, context, nodes)
    branches = verify_branches(image, context, nodes)
    descriptors = {
        'allocate': read_descriptor(image, SELECTED_TARGETS['ADESC'], 'site.IOUCCtx', '121', 24),
        'free': read_descriptor(image, SELECTED_TARGETS['FDESC'], 'site.IOUCCtx', '121', 24),
        'node': read_descriptor(image, SELECTED_TARGETS['descriptor'], 'site.UIDList', '21', 16),
    }
    assert descriptors['allocate']['bytes'] == descriptors['free']['bytes']
    canary = verify_fixup(image, 0xfffffe0008493098, image.named('___stack_chk_guard'))
    fail = image.pointer(0xfffffe0008492f18)
    assert fail['target'] == hex(image.named('___stack_chk_fail'))
    assert (fail['format'], fail['auth'], fail['diversity'], fail['address_diversity'],
            fail['key']) == (8, 1, '0x0', 1, 0)
    adapters = assert_instructions(image.read, (
        (0xfffffe000a66858c, 'bl', '#0xfffffe000a6e0424'),
        (0xfffffe000a6e0424, 'adrp', 'x17, #0xfffffe0008492000'),
        (0xfffffe000a6e0428, 'add', 'x17, x17, #0xf18'),
        (0xfffffe000a6e042c, 'ldr', 'x16, [x17]'),
        (0xfffffe000a6e0430, 'braa', 'x16, x17'),
        (0xfffffe000c509778, 'ldr', 'w8, [x0, #0x28]'),
        (0xfffffe000c50977c, 'tst', 'w8, #0x10'),
        (0xfffffe000c509780, 'mov', 'w8, #4'),
        (0xfffffe000c509784, 'mov', 'w9, #0x8004'),
        (0xfffffe000c509788, 'csel', 'w1, w9, w8, eq'),
        (0xfffffe000c50978c, 'b', '#0xfffffe000bd46a80'),
        (0xfffffe000c50998c, 'b', '#0xfffffe000bd46f04'),
    ))
    context_proofs = read_receipt('userclient_context_lifecycle_checks')['proofs']
    by_name = {proof['name']: proof for proof in context_proofs}
    node_proofs = read_receipt('userclient_uidlist_cleanup_audit')['source_proofs']
    assert len(node_proofs) == 5
    with ThreadPoolExecutor(max_workers=4) as workers:
        replayed = list(workers.map(replay_proof, [by_name[n] for n in CONTEXT_PROOFS] + node_proofs))
    return dict(build=build, identity=IDENTITIES[1], historical_receipts=RECEIPTS,
                pool=hex(POOL), table=hex(TABLE), bodies=bodies, pool_roots=roots, bank_rules=rules,
                branch_fixups=branches, descriptors=descriptors, allocator_and_canary_checks=adapters,
                canary_fixups=[canary, fail], historical_proof_replays=replayed,
                native_context_retirement_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.collection), indent=2))
