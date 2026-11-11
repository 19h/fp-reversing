#!/usr/bin/env python3
"""Original-source RW construction records and conditional LSKD publication.

No target execution, native synchronization, heap operation, IPC or IDB change.
Source capture is O(B+I+256R+pointer-chain work), with O(B+I) storage.
Instruction lifting is O(I). Each solver query has a 10 s limit.
"""
import argparse
import json

import z3

from kernel_native_reader import Kernel
from kext_port_tools import IMAGE, ROOT, SOURCE, qword, selected
from lskd_values_symbolic import Lift, cell, mem, part, resize
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read, sha

TABLE = 0xfffffe000846c420
POOL = 0xfffffe00084716e0
LSKD = 0xfffffe000ccc78a8
SAMPLE = 0xfffffe000ccceab8
SPANS = {
    'generic_wrapper': (0xfffffe000a50b36c, 0xfffffe000a50b564),
    'global_preparer': (0xfffffe000a52ea1c, 0xfffffe000a52ed28),
    'allocation_adapter': (0xfffffe000a552490, 0xfffffe000a552638),
    'allocation_and_return_gate': (0xfffffe000a530fc4, 0xfffffe000a531058),
    'publication': (0xfffffe000a56d3c0, 0xfffffe000a56d3fc),
    'status_and_return': (0xfffffe000a57dcb0, 0xfffffe000a57dcd0),
    'free_adapter': (0xfffffe000a5529a8, 0xfffffe000a552b58),
    'free_and_clear': (0xfffffe000a579364, 0xfffffe000a5793cc),
    'allocation_wrapper_and_free': (0xfffffe000a508d7c, 0xfffffe000a508d8c),
    'allocation_and_free_import_stubs': (0xfffffe000a69f104, 0xfffffe000a69f124),
}
A = (0xfffffe00079171c0, 0xfffffe0007919bb0)
B = (0xfffffe000791d3b0, 0xfffffe0007920e10)
C = (0xfffffe00079174c0, 0xfffffe0007919db0)
D = (0xfffffe0007920c10, 0xfffffe00079170c0)
RULES = {
    'generic_wrapper_call': (B, 0x65, 0x948, TABLE, 0, 0xfffffe000a552490),
    'generic_wrapper_table': ((0xfffffe0007920d10, 0xfffffe00079173c0),
                              0xbb, -0x58, POOL, -8, TABLE),
    'preparer_destination': (A, 0xca, -0x92, POOL, 0, LSKD),
    'preparer_call': (B, 0xe3, 0x944, TABLE, 0, 0xfffffe000a552490),
    'preparer_table': ((0xfffffe00079172c0, 0xfffffe0007919cb0),
                        0xff, -0x43, POOL, -8, TABLE),
    'adapter_table': (A, 0xea, 0x69, POOL, -8, TABLE),
    'allocator': (A, 0xca, 0x996, TABLE, 0, 0xfffffe000a508d7c),
    'free_destination': (C, 0x18, -0xb8, POOL, 0, LSKD),
    'free_table': ((0xfffffe00079172c0, 0xfffffe0007919cb0),
                    0x8d, 0x3f, POOL, -8, TABLE),
    'free_call': (D, 0xaa, 0x97b, TABLE, 0, 0xfffffe000a508d84),
}
ANCHORS = {
    0xfffffe000a50b49c: ('str', 'x0, [sp, #0x18]'),
    0xfffffe000a50b534: ('blraa', 'x8, x17'),
    0xfffffe000a50b538: ('ldr', 'w0, [sp, #0x20]'),
    0xfffffe000a52eb60: ('ldr', 'x20, [x0, #8]'),
    0xfffffe000a52ebf0: ('add', 'x0, x20, #0x40'),
    0xfffffe000a52ebf8: ('blraa', 'x8, x17'),
    0xfffffe000a52ec78: ('str', 'x9, [x20, #8]'),
    0xfffffe000a52ec88: ('str', 'w8, [x20]'),
    0xfffffe000a52ecd4: ('blraa', 'x8, x17'),
    0xfffffe000a5525c0: ('ldr', 'x20, [x0, #8]'),
    0xfffffe000a5525cc: ('sub', 'w21, w15, #0xa5'),
    0xfffffe000a552634: ('braa', 'x12, x17'),
    0xfffffe000a531028: ('blraa', 'x8, x17'),
    0xfffffe000a53104c: ('mov', 'w11, #-0xa69c'),
    0xfffffe000a55262c: ('mov', 'w11, #-0xa69a'),
    0xfffffe000a56d3c8: ('str', 'x0, [x20]'),
    0xfffffe000a57dcb4: ('str', 'w11, [x19, #0x10]'),
    0xfffffe000a552ae0: ('ldr', 'x20, [x13, w15, sxtw #3]'),
    0xfffffe000a552ae8: ('ldr', 'x0, [x20]'),
    0xfffffe000a5793b8: ('blraa', 'x8, x17'),
    0xfffffe000a5793bc: ('str', 'xzr, [x20]'),
}


def proofs(capture):
    r, b, p, a = z3.BitVecs('outer_record64 child_record64 destination64 allocation64', 64)
    e, d, q, status = z3.BitVecs('encoded32 decoded32 parent_phase32 status32', 32)
    counts = {}
    queries = {}

    def run(name, start, end, seeds, memory=()):
        obj = Lift(part(capture, name, start, end))
        for reg, value in seeds.items():
            obj.seed(reg, value)
        for address, width, value in memory:
            mem(obj, address, width, value)
        obj.run(name)
        counts[name] = obj.count
        return obj

    key = lambda address: resize((address ^ 0xae0701e7) * 0x952f3cb7, 32)
    v = run('wrapper_key_basis', 0xfffffe000a50b45c, 0xfffffe000a50b488,
            {'sp': r - 0x10})
    queries['wrapper_key_basis'] = v.read('w15') != resize(r ^ 0xae0701e7, 32)
    v = run('wrapper_record', 0xfffffe000a50b488, 0xfffffe000a50b4a0,
            {'sp': r - 0x10, 'w15': resize(r ^ 0xae0701e7, 32), 'x0': p})
    queries['wrapper_record'] = z3.Or(cell(v, r, 4) != key(r) + 0x90d,
                                      cell(v, r + 8, 8) != p)
    v = run('receiver_key_basis', 0xfffffe000a55257c, 0xfffffe000a5525b0, {'x19': r})
    queries['receiver_key_basis'] = v.read('w15') != resize(r ^ 0xae0701e7, 32)
    v = run('receiver_decode', 0xfffffe000a5525b0, 0xfffffe000a5525c0,
            {'x0': r, 'w15': resize(r ^ 0xae0701e7, 32)}, [(r, 4, e)])
    queries['receiver_decode'] = v.read('w15') != e - key(r)
    v = run('destination_gate', 0xfffffe000a5525c0, 0xfffffe000a5525dc,
            {'x0': r, 'w15': d}, [(r + 8, 8, p)])
    nullbit = z3.If(p == 0, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    compact = d | (((d - 0xa5) ^ ~nullbit) & 1) << 1
    queries['destination_gate'] = z3.Or(v.read('x20') != p, v.read('w21') != d - 0xa5,
                                       v.read('w15') != compact)
    queries['selected_90d_destination_gate'] = z3.And(d == 0x90d, z3.Or(
        v.read('w21') != 0x868,
        v.read('w15') != z3.If(p == 0, z3.BitVecVal(0x90d, 32), z3.BitVecVal(0x90f, 32))))
    v = run('allocation_saved_state', 0xfffffe000a530fc8, 0xfffffe000a530fd8,
            {'w21': 0x868})
    queries['allocation_saved_state'] = z3.Or(v.read('w24') != 0xb025eddd,
                                             v.read('w23') != 0xb025e4d5)
    v = run('allocation_outcome', 0xfffffe000a53102c, 0xfffffe000a531048,
            {'x0': a, 'w24': 0xb025eddd, 'w21': 0x868})
    queries['allocation_outcome'] = v.read('w8') != z3.If(
        a == 0, z3.BitVecVal(0x868, 32), z3.BitVecVal(0x8b4, 32))
    v = run('publication_and_return', 0xfffffe000a56d3c4, 0xfffffe000a56d3f0,
            {'x0': a, 'x20': p, 'w24': 0xb025eddd, 'w23': 0xb025e4d5})
    queries['publication_and_return'] = z3.Or(cell(v, p, 8) != a, v.read('w11') != 0,
                                             v.read('w8') != 0x441)
    v = run('status_store', 0xfffffe000a57dcb4, 0xfffffe000a57dcb8,
            {'x19': r, 'w11': status})
    queries['status_store'] = cell(v, r + 0x10, 4) != status
    v = run('parent_key_basis', 0xfffffe000a52eb1c, 0xfffffe000a52eb54, {'x19': r})
    queries['parent_key_basis'] = v.read('w10') != resize(r ^ 0xc410a4c0, 32)
    parent_key = resize((r ^ 0xc410a4c0) * 0xaed3b63b, 32)
    v = run('parent_record_decode', 0xfffffe000a52eb54, 0xfffffe000a52eb68,
            {'x0': r, 'w10': resize(r ^ 0xc410a4c0, 32), 'w12': 0xaed3b63b},
            [(r + 0x20, 4, e), (r + 8, 8, b), (r + 0x28, 8, p)])
    queries['parent_record_decode'] = z3.Or(v.read('w26') != e ^ parent_key,
                                           v.read('x20') != b, v.read('x1') != p)
    v = run('child_key_basis', 0xfffffe000a52ebfc, 0xfffffe000a52ec28, {'x20': b})
    queries['child_key_basis'] = v.read('w8') != resize(b ^ 0xae0701e7, 32)
    v = run('global_destination_record', 0xfffffe000a52ec60, 0xfffffe000a52ec8c,
            {'x20': b, 'w8': resize(b ^ 0xae0701e7, 32), 'w26': q,
             'w9': 0xb9, 'x23': POOL}, [(POOL + 0x27 * 8, 8, LSKD)])
    queries['global_destination_record'] = z3.Or(cell(v, b + 8, 8) != LSKD,
                                               cell(v, b, 4) != key(b) + q + 0x3d4e2d1b)
    common_key = z3.BitVec('proved_common_address_key32', 32)
    queries['common_key_composition'] = ((common_key + d) - common_key) != d
    queries['parent_phase_90d_equivalence'] = ((q + 0x3d4e2d1b) == 0x90d) != (q == 0xc2b1dbf2)
    v = run('parent_status_normalization', 0xfffffe000a52ecd8, 0xfffffe000a52ed08,
            {'x20': b, 'x19': r}, [(b + 0x10, 4, status)])
    queries['parent_status_normalization'] = cell(v, r + 0x10, 4) != status + 0x5e561849
    v = run('retirement_clear', 0xfffffe000a5793bc, 0xfffffe000a5793c0, {'x20': LSKD})
    queries['retirement_clear'] = cell(v, LSKD, 8) != 0
    results = {}
    for name, mismatch in queries.items():
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(mismatch)
        result = str(solver.check())
        assert result == 'unsat', (name, result)
        results[name] = {'query': solver.to_smt2(), 'result': result}
    return results, counts


def build():
    kernel = Kernel()
    spans = []
    for label, bounds in SPANS.items():
        row = span(kernel, *bounds)
        row['bytes_hex'] = row.pop('bytes')
        row['label'] = label
        spans.append(row)
    instructions = {int(row['ea'], 16): (row['mnemonic'], row['operands'])
                    for source in spans for row in source['instructions']}
    assert all(instructions[address] == expected for address, expected in ANCHORS.items())
    roots = {}
    for offset, bias, target in [(0x150, -4, 0xfffffe00079172c0),
                                 (0x2c0, 0, 0xfffffe0007919cb0),
                                 (0x210, 0, B[0]), (0x530, 0, B[1]),
                                 (0x4f0, -12, A[0]), (0x600, -8, A[1]),
                                 (0x308, 0, C[0]), (0x420, 0, C[1])]:
        original = pointer(kernel, POOL + offset)
        assert int(original['target'], 16) == qword(POOL + offset)
        assert int(original['target'], 16) + bias == target
        roots[hex(offset)] = {'original_pointer': original, 'bias_B': bias,
                              'effective_bank_address': hex(target)}
    rules = {}
    for label, (banks, key, additive, base, bias, target) in RULES.items():
        row = selected(*banks, key, additive, base=base, bias=bias)
        original = pointer(kernel, int(row['slot'], 16))
        assert int(row['target'], 16) == int(original['target'], 16) + bias == target
        assert all(IMAGE.read(address, 256) == kernel.read(address, 256) for address in banks)
        rules[label] = {**row, 'original_pointer': original,
                       'original_banks_hex': [kernel.read(address, 256).hex() for address in banks]}
    assert rules['preparer_destination']['slot'] == rules['free_destination']['slot'] == '0xfffffe0008471818'
    slots = {}
    for index, (target, diversity) in {
        0x90d: (0xfffffe000a57dcb0, 0xcc5), 0x90f: (0xfffffe000a530fc4, 0xcc5),
        0x868: (0xfffffe000a57dcb0, 0x7e6f), 0x8b4: (0xfffffe000a56d3c0, 0x7e6f),
        0x441: (0xfffffe000a57dcb0, 0xac26), 0x595: (0xfffffe000a579364, 0x3eba),
    }.items():
        row = pointer(kernel, TABLE + 8 * index)
        assert row['authenticated'] and (int(row['target'], 16), int(row['diversity'], 16)) == (target, diversity)
        slots[hex(index)] = row
    bindings = {}
    for name, address, target in [('IORWLockAlloc', 0xfffffe000847c3b0, 0xfffffe000c4bb6e4),
                                  ('IORWLockFree', 0xfffffe000847c3b8, 0xfffffe000c4bb780)]:
        row = pointer(kernel, address)
        symbols = kernel.symbols([target])[hex(target)]
        assert int(row['target'], 16) == target and '_' + name in {s['name'] for s in symbols}
        bindings[name] = {'original_pointer': row, 'exact_symbols': symbols}
    retained = json.loads(read(ROOT / 'lskd_continuations_contracts.json'))
    for label in ['free_api', 'cached_global_release']:
        old = next(r for r in retained['bank_rules'] if r['label'] == label)
        current = rules['free_call' if label == 'free_api' else 'preparer_destination']
        assert (old['slot'], old['target']) == (current['slot'], current['target'])
    prior = json.loads(read(ROOT / 'cached_lock_origin_checks.json'))
    sample = prior['banks']['caller_destination']
    original_sample = pointer(kernel, int(sample['slot'], 16))
    assert int(original_sample['target'], 16) - 4 == SAMPLE and SAMPLE != LSKD
    source = {'spans': spans}
    solved, counts = proofs(source)
    excerpts = []
    for name, ranges in [('com.apple.driver.FairPlayIOKit.c', [(17052, 17092), (47158, 47212),
                                                             (74274, 74299), (94340, 94354)]),
                          ('com.apple.driver.FairPlayIOKit_calls.txt', [(105, 109)])]:
        path = ROOT.parent / name
        lines = path.read_text().splitlines(keepends=True)
        for start, end in ranges:
            excerpts.append({'path': name, 'sha256': sha(path), 'first_line': start,
                             'last_line': end, 'text': ''.join(lines[start - 1:end])})
    return {
        'scope': __doc__, 'kernel_collection_sha256': kernel.sha256,
        'normalized_image_sha256': sha(SOURCE), 'generator_sha256': sha(__file__),
        'spans': spans, 'bank_pointer_roots': roots, 'banks': rules,
        'control_slots': slots, 'bindings': bindings,
        'supplied_reference_excerpts': excerpts, 'proofs': solved,
        'source_lift_counts': counts, 'solver_version': z3.get_version_string(),
        'lock_domains': {'LSKD_cell': hex(LSKD), 'LSKD_original8_hex': kernel.read(LSKD, 8).hex(),
                         'sample_cell': hex(SAMPLE), 'sample_pointer': original_sample,
                         'same_live_epoch_proved': False},
        'selected_contract': {'decoded_child_phase32': '0x90d', 'saved_state32': '0x868',
                              'decoded_parent_phase32': '0xc2b1dbf2',
                              'success_status32': '0x0', 'null_allocation_status32': '0xffff5964',
                              'null_destination_status32': '0xffff5966',
                              'child_record_access_extent_B': 20, 'parent_record_access_extent_B': 48,
                              'parent_child_bounds_argument_offset_B': 64,
                              'reaching_native_parent_phase_established': False},
        'dependencies': {name: sha(ROOT / name) for name in [
            'kernel_native_reader.py', 'kext_port_tools.py', 'recover_kext_cold_init.py',
            'recover_aes_cleanup_epoch.py', 'lskd_values_symbolic.py',
            'verify_daemon_reader_record_payloads_publication.py',
            'lskd_continuations_contracts.json', 'cached_lock_origin_checks.json',
        ]},
        'verified_counts': {'kext_spans': len(spans), 'instructions': len(instructions),
                            'code_bytes': 4 * len(instructions), 'operand_anchors': len(ANCHORS),
                            'bank_rules': len(rules), 'byte_bank_inputs': 256 * len(rules),
                            'bank_pointer_roots': len(roots),
                            'control_slots': len(slots), 'exact_imports': len(bindings),
                            'queries_unsat': len(solved), 'lifted_instruction_instances': sum(counts.values()),
                            'reference_excerpts': len(excerpts), 'distinct_lock_cells': 2},
        'new_target_execution': False, 'new_IDA_access': False, 'native_epoch_matched': False,
        'full_goal_complete': False, 'all_checks_pass': True,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    result = build()
    output = ROOT / 'lskd_lock_origin_checks.json'
    if args.verify:
        assert json.loads(read(output)) == result
    else:
        output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['verified_counts']))
