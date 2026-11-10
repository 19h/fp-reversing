#!/usr/bin/env python3
"""Recover original reference methods and the descriptor-to-owner release sites."""
import json

from kernel_native_reader import Kernel
from kext_port_tools import IMAGE, ROOT
from recover_kext_cold_init import pointer
from recover_versioned_request_abi import FLAGS
from verify_daemon_reader_record_payloads_publication import read, sha

P = 'mixed_data_release'
SCOPE = (
    'Original-source correspondence from descriptor and creator release sites through '
    'inherited OSObject reference methods to nominal MixedData free and deletion. '
    'Successful CAS, stable receiver/slot identity and field epochs are explicit premises.'
)
OWNER = 0xfffffe0007f43440
BASE = 0xfffffe0007f8a030
BUFFER = 0xfffffe0007f85d80
COLLECTION_TAG = 0xfffffe000cb51ce8
PANIC = 0xfffffe000c62a2b0
FUNCTIONS = {
    'release': 0xfffffe000c4451d0,
    'release_threshold': 0xfffffe000c44523c,
    'tagged_release': 0xfffffe000c444f78,
    'tagged_release_threshold': 0xfffffe000c444e18,
    'retain': 0xfffffe000c445200,
    'tagged_retain': 0xfffffe000c444fa8,
    'getter': 0xfffffe000c445230,
    'creator': 0xfffffe000c537394,
    'helper': 0xfffffe000c536f94,
    'free': 0xfffffe000c5397f0,
    'delete': 0xfffffe000c539894,
    'general_free': 0xfffffe000c538044,
    'general_delete': 0xfffffe000c538bd0,
    'buffer_free': 0xfffffe000c525288,
    'buffer_delete': 0xfffffe000c5254c0,
    'raw_backing_retirement': 0xfffffe000bcfec48,
}
DEPS = [
    'mixed_data_lifecycle_source.json', 'mixed_data_lifecycle_checks.json',
    'mixed_data_backing_checks.json', 'dma_map_constraints_checks.json',
    'kernel_native_reader.py', 'kext_port_tools.py', 'recover_kext_cold_init.py',
    'resolve_kernel_collection_interfaces.py',
    'verify_daemon_reader_record_payloads_publication.py',
    'recover_versioned_request_abi.py',
]
CALLERS = [
    ('creator', 0xfffffe000c537440, 0xfffffe000c537470),
    ('helper', 0xfffffe000c537058, 0xfffffe000c537074),
    ('general_free', 0xfffffe000c5381e4, 0xfffffe000c538200),
    ('general_delete', 0xfffffe000c538c10, 0xfffffe000c538c2c),
    ('buffer_delete', 0xfffffe000c525500, 0xfffffe000c52551c),
]
WRAPPERS = {
    'release': (0x50, 0xbe60),
    'release_threshold': (0x58, 0x32e5),
    'tagged_release': (0x58, 0x32e5),
    'retain': (0x48, 0x5635),
}


def literal(kernel, address, expected):
    raw = kernel.read(address, len(expected) + 1)
    assert raw == expected.encode('ascii') + b'\0'
    return {'address': hex(address), 'bytes': raw.hex(), 'text': expected}


def build():
    kernel = Kernel()
    captured = {name: kernel.function(address) for name, address in FUNCTIONS.items()}
    parent = json.loads(read(ROOT / 'mixed_data_lifecycle_source.json'))
    for name in ('creator', 'helper', 'free', 'delete', 'retain_count'):
        assert captured['getter' if name == 'retain_count' else name] == parent['functions'][name]

    slots = []
    for table, offsets in [
        (OWNER, (8, 0x10, 0x18, 0x20, 0x28, 0x38, 0x48, 0x50, 0x58, 0xb0)),
        (BASE, (8, 0x10, 0x18, 0x20, 0x28, 0x38, 0x48, 0x50, 0x58, 0xb0)),
        (BUFFER, (8, 0x28, 0x50, 0x58, 0xb0)),
    ]:
        for off in offsets:
            row = pointer(kernel, table + off)
            assert row['authenticated'] and row['chain_membership_verified']
            row.update(vptr=hex(table), offset=off)
            slots.append(row)
    symbols = kernel.symbols([int(row['target'], 16) for row in slots]
                             + [COLLECTION_TAG, PANIC, *FUNCTIONS.values()])
    assert [row['name'] for row in symbols[hex(COLLECTION_TAG)]] == [
        '__ZN12OSCollection10gMetaClassE']
    assert [row['name'] for row in symbols[hex(PANIC)]] == ['_panic']
    for row in slots:
        row['exact_symbols'] = symbols[row['target']]

    start, end = 0xfffffe000a5085f4, 0xfffffe000a50865c
    raw = kernel.read(start, end - start)
    assert raw == IMAGE.read(start, end - start)
    instructions = [{'ea': hex(i.address), 'mnemonic': i.mnemonic, 'operands': i.op_str}
                    for i in kernel.cs.disasm(raw, start)]
    assert len(instructions) * 4 == len(raw)
    counts = {
        'kernel_functions': len(captured),
        'kernel_instructions': sum(len(f['instructions']) for f in captured.values()),
        'kext_instructions': len(instructions),
        'original_slots': len(slots),
        'owner_release_sites': len(CALLERS),
    }
    return {
        'generator_sha256': sha(__file__),
        'static_scope': SCOPE,
        'kernel_collection_sha256': kernel.sha256,
        'dependencies': {name: sha(ROOT / name) for name in DEPS},
        'functions': captured,
        'kext_cleanup': {'start': hex(start), 'end': hex(end),
                         'bytes': raw.hex(), 'instructions': instructions},
        'slots': slots,
        'symbols': symbols,
        'strings': {
            'source_file': literal(kernel, 0xfffffe00070d268f, 'OSObject.cpp'),
            'release_diagnostic': literal(kernel, 0xfffffe00070d269c,
                'A kext releasing a(n) %s %p has corrupted the registry. @%s:%d'),
        },
        'verified_source_counts': counts,
        'new_IDA_access': False,
        **{flag: False for flag in FLAGS},
    }


if __name__ == '__main__':
    source = build()
    (ROOT / (P + '_source.json')).write_text(json.dumps(source, indent=2) + '\n')
    print(json.dumps(source['verified_source_counts']), flush=True)
