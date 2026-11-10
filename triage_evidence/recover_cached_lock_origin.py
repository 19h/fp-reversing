#!/usr/bin/env python3
"""Verify the selected cached-lock producer, nominal consumers and kernel types."""
import json
import struct

import z3

from kernel_native_reader import Kernel
from kext_port_tools import POOL, ROOT, TABLE, selected
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read, sha

CELL = 0xfffffe000ccceab8
GROUP = 0xfffffe000cb52628
A = (0xfffffe0007949dd0, 0xfffffe000792fbc0)
B = (0xfffffe0007949ed0, 0xfffffe000792fec0)
C = (0xfffffe000792fcc0, 0xfffffe00079391f0)
D = (0xfffffe000792fdc0, 0xfffffe00079392f0)
E = (0xfffffe0007941f60, 0xfffffe000794a0d0)
BANKS = {
    'caller_destination': (A, 0xb4, 0x6c, POOL, -4, CELL),
    'helper_call': (B, 0x92, 0xe52, TABLE, 0, 0xfffffe000a616d58),
    'helper_table': (E, 0x98, -0x62, POOL, -12, TABLE),
    'mutex_alloc_call': (A, 0x5c, 0xeba, TABLE, 0, 0xfffffe000a508dc4),
    'rw_write_cell': (D, 0x93, -0x12, POOL, -4, CELL),
    'rw_done_cell': (C, 0x87, -5, POOL, -4, CELL),
    'rw_write_call': (A, 0x16, 0xf12, TABLE, 0, 0xfffffe000a508d94),
    'rw_done_call': (C, 0x47, 0xeaf, TABLE, 0, 0xfffffe000a508d9c),
    'cleanup_cell': (A, 0xb4, 0x6c, POOL, -4, CELL),
    'mutex_free_call': ((0xfffffe0007949fd0, 0xfffffe000792ffc0), 0xef, 0xf17,
                        TABLE, 0, 0xfffffe000a508dcc),
}
SPANS = {
    'startup_caller': (0xfffffe000a62784c, 0xfffffe000a627b84),
    'publication_helper': (0xfffffe000a616d58, 0xfffffe000a616fc8),
    'mutex_alloc_and_free_wrappers': (0xfffffe000a508dc4, 0xfffffe000a508dd4),
    'mutex_import_stubs': (0xfffffe000a69f074, 0xfffffe000a69f094),
    'rw_wrappers': (0xfffffe000a508d7c, 0xfffffe000a508da4),
    'rw_import_stubs': (0xfffffe000a69f104, 0xfffffe000a69f154),
    'rw_write_adapter': (0xfffffe000a5b403c, 0xfffffe000a5b4314),
    'rw_done_adapter': (0xfffffe000a5bfc6c, 0xfffffe000a5bff88),
    'cleanup': (0xfffffe000a6228a0, 0xfffffe000a622bc4),
}
IMPORTS = {
    'IOLockAlloc': (0xfffffe000847c368, 0xfffffe000c4bb23c),
    'IOLockFree': (0xfffffe000847c370, 0xfffffe000c4bb2c4),
    'IORWLockAlloc': (0xfffffe000847c3b0, 0xfffffe000c4bb6e4),
    'IORWLockFree': (0xfffffe000847c3b8, 0xfffffe000c4bb780),
    'IORWLockWrite': (0xfffffe000847c3d0, 0xfffffe000bd0655c),
    'IORWLockUnlock': (0xfffffe000847c3c8, 0xfffffe000bd08174),
}
CORES = {
    'lck_mtx_alloc_init': 0xfffffe000bd03ec4, 'lck_mtx_destroy': 0xfffffe000bd04004,
    'lck_rw_alloc_init': 0xfffffe000bd06180, 'lck_rw_free': 0xfffffe000bd062b8,
    'lck_rw_lock_exclusive': 0xfffffe000bd0655c, 'lck_rw_done': 0xfffffe000bd08174,
}
ANCHORS = {
    0xfffffe000a627acc: ('mul', 'w10, w10, w11'),
    0xfffffe000a627ad4: ('str', 'w9, [x20, #8]'),
    0xfffffe000a627b30: ('str', 'x9, [x20]'),
    0xfffffe000a627b78: ('mov', 'x0, x20'),
    0xfffffe000a627b80: ('blraa', 'x8, x17'),
    0xfffffe000a616e8c: ('ldr', 'x20, [x0]'),
    0xfffffe000a616e80: ('mul', 'w15, w15, w16'),
    0xfffffe000a616f60: ('blraa', 'x8, x17'),
    0xfffffe000a616f98: ('str', 'x0, [x20]'),
    0xfffffe000a616fac: ('str', 'w11, [x19, #0xc]'),
    0xfffffe000a5b4274: ('ldur', 'x0, [x11, #-4]'),
    0xfffffe000a5bfef8: ('ldur', 'x0, [x12, #-4]'),
    0xfffffe000a6228e8: ('ldur', 'x9, [x9, #-4]'),
    0xfffffe000a622994: ('blraa', 'x8, x17'),
    0xfffffe000a622ba4: ('blraa', 'x8, x17'),
    0xfffffe000c4bb244: ('ldr', 'x0, [x8, #0x628]'),
    0xfffffe000c4bb24c: ('b', '#0xfffffe000bd03ec4'),
    0xfffffe000c4bb2dc: ('ldr', 'x1, [x8, #0x628]'),
    0xfffffe000c4bb2e0: ('bl', '#0xfffffe000bd04004'),
    0xfffffe000c4bb2e8: ('add', 'x0, x0, #0xb98'),
    0xfffffe000c4bb2fc: ('b', '#0xfffffe000bd7a4b8'),
    0xfffffe000c4bb6ec: ('ldr', 'x0, [x8, #0x628]'),
    0xfffffe000c4bb6f4: ('b', '#0xfffffe000bd06180'),
    0xfffffe000c4bb788: ('ldr', 'x1, [x8, #0x628]'),
    0xfffffe000c4bb78c: ('b', '#0xfffffe000bd062b8'),
    0xfffffe000bd03f08: ('stp', 'w10, wzr, [x0]'),
    0xfffffe000bd03f0c: ('str', 'xzr, [x0, #8]'),
    0xfffffe000bd03f1c: ('str', 'w9, [x0, #8]'),
    0xfffffe000bd04034: ('cmp', 'w9, w10'),
    0xfffffe000bd061e0: ('str', 'd0, [x0]'),
    0xfffffe000bd061e8: ('strh', 'w8, [x0, #0xa]'),
    0xfffffe000bd062d8: ('cmp', 'w10, #0x33'),
    0xfffffe000bd0657c: ('ldrh', 'w9, [x0, #0xa]'),
    0xfffffe000bd081ac: ('ldxr', 'w21, [x9]'),
}


def prove():
    p, s, key, group, debug = z3.BitVecs('p s key group debug', 32)
    v = lambda n: z3.BitVecVal(n, 32)
    caller = (2 * (p & v(0x18872ddd)) - p + v(0x6778d222)) ^ v(0x1dc32ba7)
    helper = ((p & v(0x2124b8bd)) | ~(p | v(0x2124b8bd))) ^ v(0xa460bec7)
    compact = p ^ v(0x7abbf985)
    mutex = (group & v(0xffffff)) | v(0x22000000)
    word8 = z3.If((debug & 1) == 1, v(0x80000000), v(0))
    checks = {
        'caller_operand_before_common_multiply': caller != compact,
        'helper_operand_before_common_multiply': helper != compact,
        'record_decode_with_common_key': ((s ^ key) ^ key) != s,
        'mutex_tag': z3.LShR(mutex, 24) != v(0x22),
        'mutex_header_distinct_from_rw_tag': z3.LShR(mutex, 24) == v(0x33),
        'fresh_mutex_rw_attribute_halfword': z3.Extract(31, 16, word8) & 0x40 != 0,
    }
    result = {}
    for name, mismatch in checks.items():
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(mismatch)
        assert solver.check() == z3.unsat, name
        result[name] = {'query': solver.to_smt2(), 'result': 'unsat'}
    return result


def retained_cases(kernel):
    profiles = json.loads(read(ROOT / 'kext_provider_initialize_profiles.json'))
    checks = json.loads(read(ROOT / 'kext_provider_initialize_checks.json'))
    result = []
    for index, case in enumerate(profiles['cases']):
        model = next(m for m in case['API_models'] if m['symbol'] == 'lock_allocation_model')
        assert model['pc'] == hex(IMPORTS['IOLockAlloc'][1])
        assert model['return_pc'] == '0xfffffe000a616f64'
        assert model['after_registers31'][20:25] == [
            hex(CELL), '0xadc', hex(TABLE), '0x231', '0x229']
        assert model['native_effects_executed'] is False
        coverage = {int(row['pc'], 16): row for row in case['original_PC_coverage']}
        for site in [0xfffffe000a627ad4, 0xfffffe000a627b30, 0xfffffe000a627b80,
                     0xfffffe000a616e8c, 0xfffffe000a616f60]:
            assert coverage[site]['bytes_hex'] == kernel.read(site, 4).hex()
        writes = [e for e in case['critical_effects'] if e['address'] == hex(CELL)]
        returned = int(model['return_value'], 16)
        assert len(writes) == int(index in (0, 2, 3)) == int(returned != 0)
        for write in writes:
            assert write['pc'] == '0xfffffe000a616f98' and write['phase'] == 0
            assert write['source_visit_index'] > model['before_source_visit_index']
            assert bytes.fromhex(write['after_hex']) == struct.pack('<Q', returned)
            assert {'case': index, 'phase': 0, 'pc': write['pc'], 'cell': hex(CELL),
                    'lock': hex(returned)} in checks['lock_publication_sites']
        final = case['final_cells_hex'][hex(CELL)]
        assert final == struct.pack('<Q', returned).hex()
        outer_returns = [r['registers31'][0] for r in case['returns']]
        assert outer_returns == (['0x0', '0x0'] if index == 0 else
                                 ['0xffff5bd4'] if index in (1, 2) else ['0x0'])
        result.append({'case': index, 'model_boundary': model['pc'],
                       'model_return': model['return_value'], 'publications': writes,
                       'final_cell_hex': final, 'outer_returns': outer_returns})
    assert len(result) == 4
    return result


def build():
    kernel = Kernel()
    spans = {name: span(kernel, *bounds) for name, bounds in SPANS.items()}
    targets = set(CORES.values()) | {target for _, target in IMPORTS.values()}
    bodies = {hex(target): kernel.function(target) for target in sorted(targets)}
    instructions = {int(i['ea'], 16): (i['mnemonic'], i['operands'])
                    for body in [*spans.values(), *bodies.values()] for i in body['instructions']}
    assert all(instructions[address] == expected for address, expected in ANCHORS.items())
    banks = {}
    for name, (bank, key, additive, base, bias, target) in BANKS.items():
        row = selected(*bank, key, additive, base=base, bias=bias)
        fixup = pointer(kernel, int(row['slot'], 16))
        assert int(fixup['target'], 16) + bias == target == int(row['target'], 16)
        banks[name] = {**row, 'fixup': fixup,
                       'original_banks': [kernel.read(address, 256).hex() for address in bank]}
    assert banks['helper_call']['fixup']['diversity'] == '0xca0c'
    assert banks['mutex_alloc_call']['fixup']['diversity'] == '0xa860'
    assert banks['mutex_free_call']['fixup']['diversity'] == '0x9ae8'
    assert {banks[name]['slot'] for name in ('caller_destination', 'rw_write_cell',
            'rw_done_cell', 'cleanup_cell')} == {'0xfffffe00084725d0'}

    decoded_selector = 0x229
    saved = (decoded_selector + 0x8ab) | 8
    post_success = saved - 0x8ab
    post_null = saved ^ ((saved - 0x8b3) ^ post_success ^ 0x37)
    assert (saved, post_success, post_null) == (0xadc, 0x231, 0xaf3)
    slots = {}
    for index, (target, modifier) in {
        0x229: (0xfffffe000a616f08, 0x266f), 0x231: (0xfffffe000a616fa8, 0x266f),
        0xadc: (0xfffffe000a616f90, 0x33e), 0xaf3: (0xfffffe000a616fa8, 0x33e),
    }.items():
        slot = pointer(kernel, TABLE + index * 8)
        assert slot['authenticated'] and (int(slot['target'], 16),
                                          int(slot['diversity'], 16)) == (target, modifier)
        slots[hex(index)] = slot
    imports = {name: pointer(kernel, slot) for name, (slot, _) in IMPORTS.items()}
    symbols = kernel.symbols(targets)
    for name, (_, target) in IMPORTS.items():
        assert int(imports[name]['target'], 16) == target
        assert '_' + name in {s['name'] for s in symbols[hex(target)]}
    for name, target in CORES.items():
        assert '_' + name in {s['name'] for s in symbols[hex(target)]}

    views = {}
    for address, name in [(0xfffffe0007e42b98, 'site.lck_mtx_t'),
                          (0xfffffe0007e42bd8, 'site.lck_rw_old_t')]:
        raw = kernel.read(address, 0x30)
        label = pointer(kernel, address + 0x10)
        assert kernel.read(int(label['target'], 16), len(name) + 1) == name.encode() + b'\0'
        assert struct.unpack_from('<I', raw, 0x2c) == (16,)
        views[name] = {'address': hex(address), 'source_hex': raw.hex(), 'label': label}
    rw_header = kernel.read(0xfffffe000700dd08, 8)
    assert rw_header == bytes.fromhex('0000003300000000')
    proofs = prove()
    cases = retained_cases(kernel)
    return {
        'scope': __doc__, 'kernel_collection_sha256': kernel.sha256,
        'generator_sha256': sha(__file__), 'spans': spans, 'kernel_bodies': bodies,
        'banks': banks, 'continuation_slots': slots, 'imports': imports, 'symbols': symbols,
        'views': views, 'group_cell': hex(GROUP), 'rw_header_hex': rw_header.hex(),
        'helper_dispatch': {'decoded_selector': decoded_selector, 'nonnull_index': saved,
                            'null_index': post_null, 'post_store_index': post_success},
        'retained_cases': cases, 'proofs': proofs, 'solver_version': z3.get_version_string(),
        'dependencies': {name: sha(ROOT / name) for name in [
            'kext_provider_initialize_profiles.json', 'kext_provider_initialize_checks.json',
            'recover_aes_cleanup_epoch.py', 'kernel_native_reader.py', 'recover_kext_cold_init.py',
            'kext_port_tools.py', 'verify_daemon_reader_record_payloads_publication.py',
        ]},
        'verified_counts': {
            'kext_spans': len(spans), 'kernel_bodies': len(bodies), 'operand_anchors': len(ANCHORS),
            'instructions': len(instructions), 'code_bytes': 4 * len(instructions),
            'bank_rules': len(banks), 'byte_bank_inputs': 256 * len(banks), 'imports': len(imports),
            'continuation_slots': len(slots), 'typed_views': len(views), 'queries_unsat': len(proofs),
            'retained_cases': len(cases), 'publications': sum(len(c['publications']) for c in cases),
        },
        'new_target_execution': False, 'new_IDA_access': False, 'native_epoch_matched': False,
        'all_checks_pass': True, 'full_goal_complete': False,
    }


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    capture = build()
    path = ROOT / 'cached_lock_origin_checks.json'
    if args.verify:
        assert json.loads(read(path)) == capture
    else:
        path.write_text(json.dumps(capture, indent=2) + '\n')
    print(json.dumps(capture['verified_counts']))
