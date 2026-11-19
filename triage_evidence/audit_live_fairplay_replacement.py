#!/usr/bin/env python3
"""Check installed UIDList replacement and missing-holder construction."""

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
    CODE_DELTA, POOL, POOL_ROOTS, TABLE, function_starts, read_descriptor, replay_proof,
)
from audit_live_fairplay_shared_table import (
    EXTRA_BANKS, HEADER_ALLOC, HEADER_ROLLBACK, HOLDER, RECEIPT_HASHES,
    historical, verify_initializer_code,
)
from audit_live_fairplay_table_cleanup import LOOKUP, PAYLOAD_TYPE, RECLAIMER, WRITER
from audit_live_fairplay_tunnel import verify_descriptor
from audit_live_fairplay_uidlist import AUDIT_HASH as PUBLICATION_AUDIT_HASH, BODY_HASH, receipt
from audit_live_kext_selector26 import Collection, IDENTITIES

CHECKS = {
    'uidlist_replacement': '02169372dbf37cf1a8807ed2dcf3ce74a93ed4f20e7f2d77d96c4d145d88e174',
    'replacement_bootstrap': '2e1d5733decedc4660bf373bd17e7fafc1a2469ab4be1de9db7ac052c6d1e5b3',
}
AUDITS = {
    'uidlist_replacement': '8b94deb2ddf686f660bce197f87aeaf32cb143b6647ac42dc9c14e4d3fd20b51',
    'replacement_bootstrap': 'c25989647b89033df33cb52c2797697c6434fb3db5252cd8f3a680700253e44c',
}
DEPENDENCIES = {
    PUBLICATION_AUDIT_HASH: 'userclient_uidlist_publication_audit',
    '7f9b62cf8034038c7443678fd0f13e8eb257ec7c453e8f6d0596be3a6fe46e68':
        'userclient_hash_table_lookup_audit',
    'c3bea10d4cdbc608f9f03d208249ea2cb94e30f91a16c2b146f40d59e968aab4':
        'userclient_hash_table_reclamation_audit',
    RECEIPT_HASHES['initializer_audit']: 'userclient_hash_table_initializer_audit',
}
CALLER_RELOCATIONS = (
    (0xfffffe000a677558, 'adrp', 'x28, #0xfffffe0008488000'),
    (0xfffffe000a67755c, 'add', 'x28, x28, #0x9a0'),
    (0xfffffe000a69bddc, 'adrp', 'x10, #0xfffffe0008488000'),
    (0xfffffe000a69bde0, 'add', 'x10, x10, #0x9a0'),
    (0xfffffe000a69bec0, 'adrp', 'x9, #0xfffffe0008488000'),
    (0xfffffe000a69bec4, 'add', 'x9, x9, #0x9a0'),
    (0xfffffe000a69f7e4, 'adrp', 'x9, #0xfffffe0008488000'),
    (0xfffffe000a69f7e8, 'add', 'x9, x9, #0x9a0'),
)


def compare_sources(image, sources):
    start = image.named('_PRnut72j9')
    starts = function_starts(image)
    end = starts[starts.index(start) + 1]
    body = image.read(start, end - start)
    assert hashlib.sha256(body).hexdigest() == BODY_HASH
    changes = set()
    ranges = {}
    for name, source in sources.items():
        original = source['function_container']
        assert start == int(original['start'], 16) + CODE_DELTA
        assert end == int(original['end_exclusive'], 16) + CODE_DELTA
        gap = ('codec_basis_def_use_gap' if name == 'uidlist_replacement'
               else 'bank_root_def_use_envelope')
        rows = [(row['label'], row) for row in source['spans']]
        rows.extend(('terminal_transfer', row) for row in source['transfers'])
        rows.append((gap, source[gap]))
        ranges[name] = []
        for label, row in rows:
            pc = int(row.get('start', row.get('ea')), 16) + CODE_DELTA
            old = bytes.fromhex(row['bytes_hex'])
            current = image.read(pc, len(old))
            edited = [pc + n for n in range(0, len(old), 4) if old[n:n+4] != current[n:n+4]]
            changes.update(edited)
            ranges[name].append(dict(label=label, address=hex(pc), words=len(old) // 4,
                                     sha256=hashlib.sha256(current).hexdigest(),
                                     changed=[hex(x) for x in edited]))
    assert changes == {row[0] for row in CALLER_RELOCATIONS}
    relocated = assert_instructions(image.read, CALLER_RELOCATIONS)
    return dict(start=hex(start), end_exclusive=hex(end), sha256=BODY_HASH,
                ranges=ranges, relocated=relocated)


def check_status_cell(image, body):
    start = int(body['start'], 16)
    end = int(body['end_exclusive'], 16)
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    cs.skipdata = True
    direct = [x for x in cs.disasm(image.read(start, end - start), start)
              if x.op_str.endswith('[sp, #0x9ec]')]
    stores = [x for x in direct if x.mnemonic != 'ldr']
    assert len(direct) == 48 and len(stores) == 1
    assert all(x.op_str.startswith('w') for x in direct)
    store, = stores
    assert (store.address, store.mnemonic, store.op_str) == (
        0xfffffe000a677820, 'str', 'w9, [sp, #0x9ec]',
    )
    assert any(x.address == 0xfffffe000a69c2b0 and x.op_str == 'w23, [sp, #0x9ec]'
               for x in direct)
    return [dict(address=hex(x.address), mnemonic=x.mnemonic, operands=x.op_str) for x in direct]


def verify_selection(image, sources):
    bank_specs = POOL_ROOTS | EXTRA_BANKS
    names = {name for source in sources.values() for name in source['banks']}
    roots = {}
    banks = {}
    for offset, (target, name, bias) in bank_specs.items():
        name = {'AL': 'EL', 'AR': 'ER'}.get(name, name)
        if name in names:
            roots[name] = verify_fixup(image, POOL + offset, target)
            banks[name] = image.read(target + bias, 256)
    assert len(roots) == 8

    allocate = image.named('_IOMallocTypeImpl')
    free = image.named('_IOFreeTypeImpl')
    targets = dict(holder=HOLDER, first_lookup=LOOKUP, second_lookup=LOOKUP, writer=WRITER,
                   reclaimer=RECLAIMER, free=free, free_descriptor=PAYLOAD_TYPE,
                   allocate=allocate, allocate_descriptor=HEADER_ALLOC,
                   initialize=0xfffffe000a668590, rollback=free, rollback_descriptor=HEADER_ROLLBACK,
                   root_call_allocate=allocate, root_call_descriptor=0xfffffe0008492600)
    branches = {}
    rules = {}
    for group, source in sources.items():
        for name, row in source['banks'].items():
            assert banks[name].hex() == row['bytes_hex']
        rules[group] = {}
        for row in source['bank_rules']:
            name = row['name']
            left, right = (banks[row[k]] for k in ('left_name', 'right_name'))
            key = int(row['key'], 16)
            constant, = {x ^ right[left[x] ^ key] for x in range(256)}
            assert constant == int(row['constant'], 16)
            index = constant + int(row['additive'], 16)
            assert index == int(row['index'], 16)
            bias = int(row['bias'], 16)
            target = (targets[name] - bias) % (1 << 64)
            original = row['original_pointer']
            base = TABLE if original['authenticated'] else POOL
            fixup = verify_fixup(image, base + 8 * index, target, original['diversity'])
            rules[group][name] = dict(index=hex(index), constant=hex(constant),
                                      target=hex(targets[name]), fixup=fixup)
        for row in source['branch_pointers']:
            index = hex(row['index'])
            target = int(row['target'], 16) + CODE_DELTA
            image.instruction(target, 'bti', 'j')
            fixup = verify_fixup(image, TABLE + 8 * row['index'], target, row['diversity'])
            assert branches.setdefault(index, fixup) == fixup
    return dict(roots=roots, rules=rules, branches=branches)


def run_proofs():
    audits = {name: receipt(f'userclient_{name}_audit', digest) for name, digest in AUDITS.items()}
    for name, source in audits.items():
        assert source['checks_sha256'] == CHECKS[name]
    dependencies = {digest: receipt(path, digest) for digest, path in DEPENDENCIES.items()}
    dependencies.update({AUDITS[name]: source for name, source in audits.items()})
    known = {digest: {proof['label']: proof for proof in source['source_proofs']}
             for digest, source in dependencies.items()}
    source_proofs = [proof for source in audits.values() for proof in source['source_proofs']]
    predecessor_refs = [row for source in audits.values() for row in source['rechecked_prior_source_proofs']]
    prior_proofs = [known[row['source_audit_sha256']][row['label']] for row in predecessor_refs]
    assert len(source_proofs) == 56 and len(prior_proofs) == 44
    unique = {proof['query']: proof for proof in source_proofs + prior_proofs}
    with ThreadPoolExecutor(max_workers=4) as workers:
        replays = list(workers.map(replay_proof, unique.values()))
    return dict(source_proofs=len(source_proofs), predecessor_references=len(prior_proofs),
                distinct_queries=replays)


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    sources = {name: receipt(f'userclient_{name}_checks', digest) for name, digest in CHECKS.items()}
    assert all(source['kernel_collection_sha256'] == IDENTITIES[0][0] for source in sources.values())
    initializer = historical('initializer_checks')
    old_initializer = sources['replacement_bootstrap']['initializer_function']
    assert old_initializer['bytes_hex'] == initializer['functions']['initializer']['bytes_hex']
    helpers = verify_initializer_code(image, initializer)
    body = compare_sources(image, sources)
    selection = verify_selection(image, sources)
    cell = check_status_cell(image, body)
    assert image.read(HOLDER, 8) == bytes(8)
    alloc = read_descriptor(image, HEADER_ALLOC, 'site.FPHashTable', '21', 16)
    rollback = read_descriptor(image, HEADER_ROLLBACK, 'site.FPHashTable', '21', 16)
    assert alloc['bytes'] == rollback['bytes']
    descriptors = dict(header_allocate=alloc, header_rollback=rollback,
                       tunnel_release=verify_descriptor(image, PAYLOAD_TYPE, 120, 'site.FPSecureTunnel'))
    return dict(build=build, identity=IDENTITIES[1], historical_checks=CHECKS,
                historical_audits=AUDITS, body=body, helpers=helpers, selection=selection,
                status_cell_accesses=cell, descriptors=descriptors, proofs=run_proofs(),
                native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
