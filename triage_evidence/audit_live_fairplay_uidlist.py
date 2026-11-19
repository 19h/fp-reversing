#!/usr/bin/env python3
"""Verify installed UIDList publication and context-cell uses."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import (
    CODE_DELTA, POOL, POOL_ROOTS, SELECTED_TARGETS, TABLE, function_starts,
    read_descriptor, replay_proof,
)
from audit_live_fairplay_shared_table import EXTRA_BANKS
from audit_live_kext_selector26 import Collection, IDENTITIES

HERE = Path(__file__).resolve().parent
CHECKS_HASH = 'd9e9a2ce995fa6b3703f3eecbc63f6e22328dfd2f1e9601679b9df760dfb5b53'
AUDIT_HASH = 'b66d2254114e0a7d984faa024007b8193845489d9b83fa9cdcbb78661682db04'
BODY_HASH = 'f6e14d3993bdc8ff46e4dfe9ac6b00f71d04ca2a8902d40d6ca06e23a1fd9220'
PRIOR_AUDITS = {
    '51a55c97d7989c6bc57b48b0c77301aeb11bf52eb5b3bc4871c0c4e88a9e9f02':
        'secure_tunnel_table_insertion_audit',
    '801e96725f8b9bf58dd6c50c705c6978242c84abc372792e2654b34223025c01':
        'userclient_uidlist_cleanup_audit',
    '7f9b62cf8034038c7443678fd0f13e8eb257ec7c453e8f6d0596be3a6fe46e68':
        'userclient_hash_table_lookup_audit',
}
RELOCATIONS = (
    (0xfffffe000a69f97c, 'adrp', 'x9, #0xfffffe0008488000'),
    (0xfffffe000a69f980, 'add', 'x9, x9, #0x9a0'),
)
ROOT_PINS = (
    (0xfffffe000a676458, 'adrp', 'x28, #0xfffffe0008488000'),
    (0xfffffe000a67645c, 'add', 'x28, x28, #0x9a0'),
    (0xfffffe000a676478, 'ldr', 'x12, [x28, #0xc08]'),
    (0xfffffe000a67647c, 'sub', 'x27, x12, #8'),
    (0xfffffe000a676490, 'ldr', 'x13, [x28, #0x158]'),
    (0xfffffe000a676494, 'sub', 'x13, x13, #4'),
    (0xfffffe000a676498, 'str', 'x13, [sp, #0xa58]'),
    (0xfffffe000a6764e8, 'ldr', 'x22, [x28, #0x840]'),
    (0xfffffe000a6764fc, 'ldr', 'x23, [x28, #0xbb8]'),
    (0xfffffe000a6765e0, 'str', 'x23, [sp, #0xa40]'),
    (0xfffffe000a676688, 'str', 'x27, [sp, #0xa50]'),
    (0xfffffe000a6766e8, 'mov', 'x28, x22'),
    (0xfffffe000a67748c, 'str', 'x7, [sp, #0xa60]'),
    (0xfffffe000a677490, 'str', 'x4, [sp, #0xa08]'),
    (0xfffffe000a677494, 'str', 'x2, [sp, #0xa28]'),
)
CONTEXT_USES = (
    (0xfffffe000a67d954, 'cmp', 'x11, #0'),
    (0xfffffe000a67d9c0, 'ldr', 'w10, [x10, #8]'),
    (0xfffffe000a67eea8, 'cmp', 'x8, #0'),
    (0xfffffe000a683df8, 'str', 'x9, [x0]'),
    (0xfffffe000a683f5c, 'cmp', 'x8, #0'),
    (0xfffffe000a683fe0, 'ldr', 'w8, [x8, #8]'),
    (0xfffffe000a6843d0, 'cmp', 'x9, #0'),
    (0xfffffe000a688f28, 'ldr', 'x8, [x8, #0x10]'),
    (0xfffffe000a68c4dc, 'ldr', 'x8, [x8, #0x10]'),
    (0xfffffe000a6926fc, 'ldr', 'x11, [x11, #0x10]'),
    (0xfffffe000a69fee8, 'str', 'x8, [x2, #0x118]'),
)


def receipt(name, expected_hash):
    raw = command('zstd', '-dcq', str(HERE / f'{name}.json.zst'))
    assert hashlib.sha256(raw).hexdigest() == expected_hash
    return json.loads(raw)


def verify_body(image, source):
    start = image.named('_PRnut72j9')
    starts = function_starts(image)
    end = starts[starts.index(start) + 1]
    old = source['function_container']
    assert start == int(old['start'], 16) + CODE_DELTA
    assert end == int(old['end_exclusive'], 16) + CODE_DELTA
    body = image.read(start, end - start)
    assert hashlib.sha256(body).hexdigest() == BODY_HASH

    compared = []
    changes = set()
    for section, rows in (('spans', source['spans']), ('transfers', source['transfers'])):
        for row in rows:
            pc = int(row.get('start', row.get('ea')), 16) + CODE_DELTA
            old = bytes.fromhex(row['bytes_hex'])
            current = image.read(pc, len(old))
            different = [pc + n for n in range(0, len(old), 4) if old[n:n+4] != current[n:n+4]]
            changes.update(different)
            compared.append(dict(section=section, address=hex(pc), words=len(old) // 4,
                                 sha256=hashlib.sha256(current).hexdigest(),
                                 changed=[hex(item) for item in different]))
    assert changes == {row[0] for row in RELOCATIONS}
    assert sum(row['words'] for row in compared) == 244
    relocated = assert_instructions(image.read, RELOCATIONS)
    roots = assert_instructions(image.read, ROOT_PINS)
    return dict(start=hex(start), end_exclusive=hex(end), sha256=BODY_HASH, compared=compared,
                relocated=relocated, root_pins=roots)


def context_accesses(image, body):
    start = int(body['start'], 16)
    end = int(body['end_exclusive'], 16)
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    cs.skipdata = True
    direct = [ins for ins in cs.disasm(image.read(start, end - start), start)
              if ins.op_str.endswith('[sp, #0x738]')]
    save, *loads = direct
    assert (save.address, save.mnemonic, save.op_str) == (
        0xfffffe000a6763dc, 'str', 'x2, [sp, #0x738]',
    )
    assert [ins.address for ins in loads] == [row[0] - 4 for row in CONTEXT_USES]
    assert all(ins.mnemonic == 'ldr' and ins.op_str.startswith('x') for ins in loads)
    uses = assert_instructions(image.read, CONTEXT_USES)
    return dict(direct_cell_accesses=[dict(address=hex(x.address), mnemonic=x.mnemonic,
                                           operands=x.op_str) for x in direct],
                next_instructions=uses)


def verify_dispatch(image, source):
    banks = {}
    roots = {}
    for offset, (target, name, bias) in (POOL_ROOTS | EXTRA_BANKS).items():
        if name in source['banks']:
            roots[name] = verify_fixup(image, POOL + offset, target)
            banks[name] = image.read(target + bias, 256)
            assert banks[name].hex() == source['banks'][name]['bytes_hex']
    assert set(banks) == set(source['banks'])

    descriptors = {}
    selectors = {}
    for row in source['bank_rules']:
        left, right = (banks[row[k]] for k in ('left_name', 'right_name'))
        key = int(row['key'], 16)
        constant, = {x ^ right[left[x] ^ key] for x in range(256)}
        assert constant == int(row['constant'], 16)
        index = constant + int(row['additive'], 16)
        assert index == int(row['index'], 16)
        if row['name'] == 'allocate_adapter':
            fixup = verify_fixup(image, TABLE + 8 * index, image.named('_IOMallocTypeImpl'), '0xd0c8')
        else:
            fixup = verify_fixup(image, POOL + 8 * index, 0xfffffe000849234c)
            descriptors['allocate'] = read_descriptor(image, int(fixup['target'], 16) - 12,
                                                      'site.UIDList', '21', 16)
        selectors[row['name']] = dict(index=hex(index), constant=hex(constant), fixup=fixup)
    descriptors['free'] = read_descriptor(image, SELECTED_TARGETS['descriptor'],
                                          'site.UIDList', '21', 16)
    assert descriptors['allocate']['bytes'] == descriptors['free']['bytes']
    branches = {}
    for row in source['branch_pointers']:
        index = row['index']
        target = int(row['target'], 16) + CODE_DELTA
        image.instruction(target, 'bti', 'j')
        branches[hex(index)] = verify_fixup(image, TABLE + 8 * index, target, row['diversity'])
    return dict(roots=roots, selectors=selectors, descriptors=descriptors, branches=branches)


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    source = receipt('userclient_uidlist_publication_checks', CHECKS_HASH)
    proof_receipt = receipt('userclient_uidlist_publication_audit', AUDIT_HASH)
    assert source['kernel_collection_sha256'] == IDENTITIES[0][0]
    assert proof_receipt['checks_sha256'] == CHECKS_HASH
    body = verify_body(image, source)
    dispatch = verify_dispatch(image, source)
    context = context_accesses(image, body)
    proofs = proof_receipt['source_proofs']
    prior = {digest: {row['label']: row for row in receipt(name, digest)['source_proofs']}
             for digest, name in PRIOR_AUDITS.items()}
    predecessors = [prior[row['source_audit_sha256']][row['label']]
                    for row in proof_receipt['rechecked_prior_source_proofs']]
    assert len(proofs) == 17 and len(predecessors) == 6
    with ThreadPoolExecutor(max_workers=4) as workers:
        replays = list(workers.map(replay_proof, proofs + predecessors))
    return dict(build=build, identity=IDENTITIES[1], historical_checks=CHECKS_HASH,
                historical_audit=AUDIT_HASH, body=body, dispatch=dispatch, context=context,
                source_replays=replays[:len(proofs)], predecessor_replays=replays[len(proofs):],
                native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
