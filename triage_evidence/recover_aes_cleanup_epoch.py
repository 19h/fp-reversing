#!/usr/bin/env python3
"""Extract original AES initialization and selected cleanup resource handoffs."""
import json

from kernel_native_reader import Kernel
from kext_port_tools import IMAGE, POOL, ROOT, TABLE, selected
from recover_kext_aes_handoff import function, starts
from recover_kext_cold_init import pointer
from recover_versioned_request_abi import FLAGS
from verify_daemon_reader_record_payloads_publication import read, sha

P = 'aes_cleanup_epoch'
SCOPE = (
    'Original-source initializer publication and cleanup contracts, selected protected '
    'cleanup continuation, and matched 512-byte auxiliary allocation and retirement. '
    'Original caller state and native resources remain explicit premises.'
)
DEPS = [
    'kext_buffer_contracts.json', 'kext_aes_dispatch_contracts.json',
    'sample_caller_contracts.json', 'descriptor_prepare_lifecycle_source.json',
    'recover_kext_aes_handoff.py', 'recover_kext_cold_init.py', 'kernel_native_reader.py',
    'resolve_kernel_collection_interfaces.py', 'kext_port_tools.py',
    'verify_daemon_reader_record_payloads_publication.py', 'recover_versioned_request_abi.py',
]
KEXT = {
    'init': 0xfffffe000a508030, 'cleanup': 0xfffffe000a5085e0,
    'status': 0xfffffe000a508c78, 'adapter': 0xfffffe000a62259c,
    'adapter_tail_helper': 0xfffffe000a6229c8, 'lock_free': 0xfffffe000a508dcc,
}
KERNEL = {
    'waiter': 0xfffffe000c4eb5d8, 'factory': 0xfffffe000c526070,
    'allocate_data': 0xfffffe000c4ba60c, 'free_data': 0xfffffe000c4ba84c,
}
SPANS = {
    'producer': (0xfffffe000a66af38, 0xfffffe000a66b280),
    'core_cleanup': (0xfffffe000a60802c, 0xfffffe000a6080c4),
    'core_return': (0xfffffe000a60ec64, 0xfffffe000a60ec90),
    'lock_free_stub': (0xfffffe000a69f084, 0xfffffe000a69f094),
}
A = (0xfffffe0007949dd0, 0xfffffe000792fbc0)
B = (0xfffffe0007949fd0, 0xfffffe000792ffc0)
C = (0xfffffe0007949ed0, 0xfffffe000792fec0)
D = (0xfffffe000792fcc0, 0xfffffe00079391f0)
E = (0xfffffe0007941f60, 0xfffffe000794a0d0)
RULES = {
    'producer_table': (A, 0x3e, -0x21, POOL, -12, TABLE),
    'producer_allocate': (B, 0x37, 0xed6, TABLE, 0, KERNEL['allocate_data']),
    'producer_publication': (B, 0xac, 0x165, POOL, -4, 0xfffffe000cccba48),
    'core_adapter': (D, 0x87, 0xeb8, TABLE, 0, KEXT['adapter']),
    'adapter_cleanup': (C, 0x32, 0xe88, TABLE, 0, KEXT['cleanup']),
    'adapter_free_data': (B, 0x37, 0xee0, TABLE, 0, KERNEL['free_data']),
    'adapter_lock_cell': (A, 0xb4, 0x6c, POOL, -4, 0xfffffe000ccceab8),
    'adapter_helper': (A, 0x73, 0xeb9, TABLE, 0, KEXT['adapter_tail_helper']),
    'helper_table': (E, 0x98, -0x62, POOL, -12, TABLE),
    'helper_free_lock': (B, 0xef, 0xf17, TABLE, 0, KEXT['lock_free']),
}
CONTINUATIONS = {
    0x335: (0xfffffe000a60ec64, 0x58fd),
    0x786: (0xfffffe000a6228a0, 0x283c),
    0x78d: (0xfffffe000a622838, 0x283c),
    0xd7b: (0xfffffe000a62290c, 0x4bb5),
    0xd9f: (0xfffffe000a6229a4, 0x4bb5),
    0xbc3: (0xfffffe000a6229a4, 0xdad6),
    0x756: (0xfffffe000a622b4c, 0x1ac4),
    0x7a5: (0xfffffe000a622bb8, 0x1ac4),
}


def span(kernel, start, end):
    raw = kernel.read(start, end - start)
    assert raw == IMAGE.read(start, end - start)
    rows = [{'ea': hex(i.address), 'mnemonic': i.mnemonic, 'operands': i.op_str}
            for i in kernel.cs.disasm(raw, start)]
    assert len(rows) * 4 == len(raw)
    return {'start': hex(start), 'end': hex(end), 'bytes': raw.hex(), 'instructions': rows}


def build():
    kernel = Kernel()
    kext = next(x for x in kernel.entries if x['name'] == 'com.apple.driver.FairPlayIOKit')
    functions = {n: function(kernel, kext, a) for n, a in KEXT.items()}
    assert all(IMAGE.read(int(f['start'], 16), len(bytes.fromhex(f['bytes_hex']))).hex()
               == f['bytes_hex'] for f in functions.values())
    functions.update({n: kernel.function(a) for n, a in KERNEL.items()})
    spans = {n: span(kernel, *bounds) for n, bounds in SPANS.items()}
    catalog = starts(kernel, kext)
    producer_index = catalog.index(SPANS['producer'][0])
    assert catalog[producer_index + 1] == 0xfffffe000a676d7c

    prior = json.loads(read(ROOT / 'kext_buffer_contracts.json'))
    for name in ('init', 'status', 'cleanup'):
        old = next(r for r in prior['kext_ranges'] if r['start'] == functions[name]['start'])
        assert functions[name]['bytes_hex'] == old['bytes_hex']
    rules = {}
    for name, (banks, key, additive, base, bias, target) in RULES.items():
        record = selected(*banks, key, additive, base=base, bias=bias)
        assert int(record['target'], 16) == target
        fixup = pointer(kernel, int(record['slot'], 16))
        assert (int(fixup['target'], 16) + bias) % (1 << 64) == target
        rules[name] = {**record, 'original_fixup': fixup,
                       'banks_hex': [IMAGE.read(address, 256).hex() for address in banks]}
    continuations = {}
    for index, (address, diversity) in CONTINUATIONS.items():
        row = pointer(kernel, TABLE + index * 8)
        assert row['authenticated'] and int(row['target'], 16) == address
        assert int(row['diversity'], 16) == diversity
        continuations[hex(index)] = row
    lock_import = pointer(kernel, 0xfffffe000847c370)
    symbols = kernel.symbols([*KEXT.values(), *KERNEL.values(), int(lock_import['target'], 16)])
    counts = {
        'complete_bodies': len(functions),
        'selected_source_spans': len(spans),
        'captured_instructions': sum(len(f['instructions']) for f in [*functions.values(), *spans.values()]),
        'constant_bank_rules': len(rules),
        'constant_bank_inputs_checked': 256 * len(rules),
        'original_continuation_slots': len(continuations),
    }
    counts['captured_code_bytes'] = 4 * counts['captured_instructions']
    return {
        'generator_sha256': sha(__file__),
        'static_scope': SCOPE,
        'kernel_collection_sha256': kernel.sha256,
        'dependencies': {n: sha(ROOT / n) for n in DEPS},
        'functions': functions,
        'spans': spans,
        'bank_rules': rules,
        'continuations': continuations,
        'lock_import': lock_import,
        'exact_symbols': symbols,
        'verified_source_counts': counts,
        'new_IDA_access': False,
        **{flag: False for flag in FLAGS},
    }


if __name__ == '__main__':
    source = build()
    (ROOT / (P + '_source.json')).write_text(json.dumps(source, indent=2) + '\n')
    print(json.dumps(source['verified_source_counts']), flush=True)
