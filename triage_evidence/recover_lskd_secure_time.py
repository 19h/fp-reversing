#!/usr/bin/env python3
"""Original-source SecureTime publication, embedded RW and clock-query handoff.

Static instruction lifting, compiler bounds, pointer chains and retained epochs.
No new target, allocation, synchronization, entropy, sysctl or IDB execution.
O(B+I+E+256R) extraction time/space plus chain decoding and solver cost.
"""
import argparse
import json
import struct

import z3

from kernel_native_reader import Kernel
from kext_port_tools import ROOT, SOURCE, IMAGE, selected
from lskd_values_symbolic import Lift, part, mem, cell, resize
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from verify_daemon_reader_record_payloads_publication import read, sha

TABLE = 0xfffffe000846c420
POOL = 0xfffffe00084716e0
GLOBAL = 0xfffffe000ccc78c0
VIEW = 0xfffffe000847aea0
A = (0xfffffe00079171c0, 0xfffffe0007919bb0)
B = (0xfffffe000791d3b0, 0xfffffe0007920e10)
C = (0xfffffe00079174c0, 0xfffffe0007919db0)
D = (0xfffffe0007920d10, 0xfffffe00079173c0)
E = (0xfffffe0007920c10, 0xfffffe00079170c0)
SPANS = {
    'completion_noop': (0xfffffe000a52f728, 0xfffffe000a52f730),
    'post_release_constants': (0xfffffe000a56bc54, 0xfffffe000a56bc78),
    'presence_gate': (0xfffffe000a535844, 0xfffffe000a535888),
    'allocation_publication': (0xfffffe000a5268dc, 0xfffffe000a5269b8),
    'embedded_constructor': (0xfffffe000a528a0c, 0xfffffe000a528b10),
    'acquire_and_fields': (0xfffffe000a55e334, 0xfffffe000a55e490),
    'clock_query_and_handoff': (0xfffffe000a511804, 0xfffffe000a511964),
    'random_and_sysctl_wrappers': (0xfffffe000a508d6c, 0xfffffe000a508d7c),
    'random_import_stub': (0xfffffe000a69f394, 0xfffffe000a69f3a4),
    'sysctl_import_stub': (0xfffffe000a69f3b4, 0xfffffe000a69f3c4),
    'common_return': (0xfffffe000a52e4b0, 0xfffffe000a52e4e4),
}
RULES = {
    'completion_noop': (C, 0x50, 0x951, TABLE, 0, 0xfffffe000a52f728, 0x6e7d),
    'typed_allocator': (A, 0xca, 0x930, TABLE, 0, 0xfffffe000c4ba154, 0xb389),
    'secure_time_view': (E, 0xaa, 0xf, POOL, -4, VIEW, None),
    'embedded_constructor': (B, 0xe3, 0x944, TABLE, 0, 0xfffffe000a552490, 0x86eb),
    'explicit_acquire': (C, 0x18, 0x8cf, TABLE, 0, 0xfffffe000a54e220, 0x560f),
    'four_byte_random': (C, 0x50, 0x95c, TABLE, 0, 0xfffffe000a508d6c, 0x6e7d),
    'clock_query': (D, 0x2f, 0x9e6, TABLE, 0, 0xfffffe000a508d74, 0x6e7d),
}
ANCHORS = {
    0xfffffe000a52f72c: ('ret', ''),
    0xfffffe000a526984: ('blraa', 'x10, x17'),
    0xfffffe000a52698c: ('str', 'x0, [x8]'),
    0xfffffe000a5269b4: ('braa', 'x9, x17'),
    0xfffffe000a528a2c: ('str', 'xzr, [x0, #0x18]'),
    0xfffffe000a528a64: ('str', 'x9, [x21, #8]'),
    0xfffffe000a528ac0: ('blraa', 'x8, x17'),
    0xfffffe000a528ac4: ('ldr', 'w8, [x21, #0x10]'),
    0xfffffe000a528b0c: ('braa', 'x9, x17'),
    0xfffffe000a55e398: ('str', 'w9, [x0, #8]'),
    0xfffffe000a55e39c: ('str', 'x8, [x0]'),
    0xfffffe000a55e3e0: ('blraa', 'x8, x17'),
    0xfffffe000a55e3e8: ('str', 'x8, [x8, #8]'),
    0xfffffe000a55e424: ('str', 'x9, [x8]'),
    0xfffffe000a55e46c: ('blraa', 'x8, x17'),
    0xfffffe000a55e48c: ('braa', 'x8, x17'),
    0xfffffe000a511918: ('blraa', 'x8, x17'),
    0xfffffe000a51194c: ('ldur', 'w15, [x23, #0x94]'),
    0xfffffe000a511960: ('braa', 'x21, x17'),
    0xfffffe000a52e4b8: ('str', 'w8, [x9, #0x38]'),
    0xfffffe000a508d70: ('b', '#0xfffffe000a69f394'),
    0xfffffe000a508d78: ('b', '#0xfffffe000a69f3b4'),
    0xfffffe000a69f398: ('add', 'x17, x17, #0x4f8'),
    0xfffffe000a69f39c: ('ldr', 'x16, [x17]'),
    0xfffffe000a69f3a0: ('braa', 'x16, x17'),
    0xfffffe000a69f3b8: ('add', 'x17, x17, #0x508'),
    0xfffffe000a69f3bc: ('ldr', 'x16, [x17]'),
    0xfffffe000a69f3c0: ('braa', 'x16, x17'),
}


def retained_frames(kernel):
    offsets = [0x10, 0x78, 0x80, 0xb0, 0xb8, 0x108, 0x110, 0x120, 0x128,
               0x150, 0x158, 0x168, 0x170, 0x178, 0x180, 0x188, 0x190, 0x198]
    result, checked = [], set()
    for index, case in enumerate(json.loads(read(ROOT / 'lskd_handlers_profiles.json'))['cases']):
        if case['boundary'].get('pc') != '0xfffffe000a50fd10':
            continue
        state = {}
        for write in case['source_writes']:
            for j, byte in enumerate(bytes.fromhex(write['after_hex'])):
                state[int(write['address'], 16) + j] = (byte, write)
        frame = int(case['boundary']['SP'], 16)
        fields = {}
        for offset in offsets:
            epochs = [state[frame + offset + j] for j in range(8)]
            producers = []
            for write in {v[1]['source_visit_index']: v[1] for v in epochs}.values():
                visit = case['source_visits'][write['source_visit_index']]
                assert visit['pc'] == write['pc']
                assert visit['bytes_hex'] == kernel.read(int(write['pc'], 16), 4).hex()
                checked.add(write['pc'])
                producers.append({'pc': write['pc'], 'bytes_hex': visit['bytes_hex']})
            fields[hex(offset)] = {'value': hex(int.from_bytes(bytes(v[0] for v in epochs), 'little')),
                                  'width_B': 8, 'producers': producers}
        w = int(case['workspace_pointer'], 16)
        expected = [GLOBAL, 0xfffffe000ccc78e0, 0xfffffe000ccc78b8, *B,
                    D[1], D[0], w + 0x80, w + 0xa8, *C, *E,
                    0xfffffe000ccc2d90, 0xfffffe000ccc2c60, *A, w + 0x40]
        assert [int(fields[hex(o)]['value'], 16) for o in offsets] == expected
        result.append({'prior_case_index': index, 'fields': fields, 'new_target_execution': False})
    assert len(result) == 13
    return result, len(checked)


def prove(capture):
    f = 0x51000000
    p, r, lock, output, seed64 = z3.BitVecs('secure_time64 reused_record64 embedded_RW64 workspace_child64 seed64', 64)
    status = z3.BitVec('constructor_status32', 32)
    queries, counts = {}, {}

    def run(name, start, end, seeds, cells=()):
        obj = Lift(part(capture, name, start, end))
        for reg, value in seeds.items():
            obj.seed(reg, value)
        for address, width, value in cells:
            mem(obj, address, width, value)
        obj.run(name)
        counts[name] = obj.count
        return obj

    obj = run('allocation_phase', 0xfffffe000a5268e0, 0xfffffe000a5268fc, {'w9': 0x1fb})
    queries['allocation_phase'] = z3.Or(obj.read('w19') != 0x30c, obj.read('w20') != 0x3be)
    obj = run('publish_before_null_gate', 0xfffffe000a526988, 0xfffffe000a5269a4,
              {'sp': f, 'x0': p, 'w19': 0x30c, 'w20': 0x3be}, [(f + 0x10, 8, GLOBAL)])
    queries['publish_before_null_gate'] = z3.Or(cell(obj, GLOBAL, 8) != p,
        obj.read('w8') != z3.If(p == 0, z3.BitVecVal(0x30c, 32), z3.BitVecVal(0x35b, 32)))
    obj = run('allocation_result_word', 0xfffffe000a5269a8, 0xfffffe000a5269b0, {})
    queries['allocation_result_word'] = obj.read('w8') != 0x5e561849
    obj = run('constructor_pointer_and_key_basis', 0xfffffe000a528a10, 0xfffffe000a528a5c,
              {'sp': f, 'w19': 0x30c, 'x0': p}, [(f + 0x128, 8, r)])
    queries['constructor_pointer_and_key_basis'] = z3.Or(obj.read('w19') != 0x1fb,
        obj.read('w8') != 8, obj.read('x9') != p + 0x18,
        cell(obj, p + 0x18, 8) != 0, obj.read('w10') != resize(r ^ 0xae0701e7, 32))
    obj = run('constructor_record_phase', 0xfffffe000a528a5c, 0xfffffe000a528a74,
              {'x21': r, 'x9': p + 0x18, 'w19': 0x1fb, 'w10': resize(r ^ 0xae0701e7, 32)})
    queries['constructor_record_phase'] = z3.Or(cell(obj, r + 8, 8) != p + 0x18,
        cell(obj, r, 4) - resize((r ^ 0xae0701e7) * 0x952f3cb7, 32) != 0x90d)
    obj = run('constructor_success_phase', 0xfffffe000a528aa4, 0xfffffe000a528aa8, {'w8': 8, 'w11': 0x43})
    queries['constructor_success_phase'] = obj.read('w20') != 0x4b
    obj = run('constructor_status_gate', 0xfffffe000a528ac4, 0xfffffe000a528afc,
              {'x21': r, 'w19': 0x1fb, 'w20': 0x4b}, [(r + 0x10, 4, status)])
    queries['constructor_status_gate'] = obj.read('w8') != z3.If(status == 0,
        z3.BitVecVal(0x32c, 32), z3.BitVecVal(0x1fb, 32))
    obj = run('constructor_result_word', 0xfffffe000a528b00, 0xfffffe000a528b08, {})
    queries['constructor_result_word'] = obj.read('w8') != 0x5e561849
    obj = run('explicit_acquisition_key_basis', 0xfffffe000a55e338, 0xfffffe000a55e388,
              {'sp': f}, [(f + 0x10, 8, GLOBAL), (GLOBAL, 8, p), (p + 0x18, 8, lock), (f + 0x128, 8, r)])
    queries['explicit_acquisition_key_basis'] = z3.Or(obj.read('x8') != lock,
        obj.read('w9') != resize(r ^ 0x1d65dad0, 32))
    obj = run('explicit_acquisition_record', 0xfffffe000a55e388, 0xfffffe000a55e3a0,
              {'x0': r, 'x8': lock, 'w20': 0x4b, 'w9': resize(r ^ 0x1d65dad0, 32)})
    queries['explicit_acquisition_record'] = z3.Or(cell(obj, r, 8) != lock,
        cell(obj, r + 8, 4) - resize((r ^ 0x1d65dad0) * 0xe9655f4d, 32) != 0x2d2)
    obj = run('post_acquire_self_reference', 0xfffffe000a55e3e4, 0xfffffe000a55e3ec,
              {'x24': GLOBAL}, [(GLOBAL, 8, p)])
    queries['post_acquire_self_reference'] = cell(obj, p + 8, 8) != p
    # LDRSW sign-extends the flag before the subsequent mask. With flag 255,
    # the exact signed extension remains 255. Interpret the following slice
    # from that source-defined register state.
    obj = run('selected_seed_qword', 0xfffffe000a55e3f8, 0xfffffe000a55e428,
              {'x8': p, 'x9': 255, 'x10': 0xfffffe000ccc78f4},
              [(0xfffffe000ccc78f4 + 0x98, 8, seed64)])
    queries['selected_seed_qword'] = cell(obj, p, 8) != (seed64 & 0x7fffffffffffffff) ^ 0x23c7e4b4853b50c4
    obj = run('four_byte_random_destination', 0xfffffe000a55e450, 0xfffffe000a55e454,
              {'x24': GLOBAL}, [(GLOBAL, 8, p)])
    queries['four_byte_random_destination'] = obj.read('x0') != p
    obj = run('four_byte_random_length', 0xfffffe000a55e464, 0xfffffe000a55e468, {})
    queries['four_byte_random_length'] = obj.read('w1') != 4
    obj = run('clock_continuation_index', 0xfffffe000a55e470, 0xfffffe000a55e47c, {'w19': 0x3be, 'w20': 0x4b})
    queries['clock_continuation_index'] = obj.read('w8') != 0x5b7
    obj = run('clock_name_and_output_preparation', 0xfffffe000a511824, 0xfffffe000a5118b4,
              {'sp': f}, [(f + 0x120, 8, output)])
    expected = b'kern.monotonicclock\0\0'
    stores = [s for s in obj.stores if s['size_bytes'] == 1]
    assert len(stores) == len(expected) == 21
    queries['clock_name_and_output_preparation'] = z3.Or(cell(obj, output + 0x94, 4) != 0,
        cell(obj, f + 0x1d8, 8) != 4,
        *[z3.Or(s['address'] != output + 0x104 + j, s['value'] != b)
          for j, (s, b) in enumerate(zip(stores, expected))])
    obj = run('clock_five_arguments', 0xfffffe000a511900, 0xfffffe000a511914, {'sp': f, 'x23': output})
    queries['clock_five_arguments'] = z3.Or(obj.read('x0') != output + 0x104,
        obj.read('x1') != output + 0x94, obj.read('x2') != f + 0x1d8,
        obj.read('x3') != 0, obj.read('x4') != 0)
    return_value = z3.BitVec('sysctl_return64', 64)
    output_word = z3.BitVec('clock_output32', 32)
    obj = run('clock_cleanup_and_output_reload', 0xfffffe000a51191c, 0xfffffe000a511950,
              {'x23': output, 'x0': return_value}, [(output + 0x94, 4, output_word)])
    queries['clock_cleanup_and_output_reload'] = z3.Or(obj.read('w15') != output_word,
        obj.read('x0') != return_value,
        *[z3.Or(s['address'] != output + 0x104 + 2*j, s['size_bytes'] != 2, s['value'] != 0)
          for j, s in enumerate(obj.stores)])
    obj = run('raw_success_receiver_store', 0xfffffe000a52e4b4, 0xfffffe000a52e4bc,
              {'sp': f, 'w8': 0x5e561849}, [(f + 0x198, 8, output)])
    queries['raw_success_receiver_store'] = cell(obj, output + 0x38, 4) != 0x5e561849
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
    k = Kernel()
    spans = []
    for label, bounds in SPANS.items():
        row = span(k, *bounds)
        row['bytes_hex'] = row.pop('bytes')
        row['label'] = label
        spans.append(row)
    ins = {int(i['ea'], 16): (i['mnemonic'], i['operands']) for s in spans for i in s['instructions']}
    assert all(ins[pc] == expected for pc, expected in ANCHORS.items())
    kext = next(e for e in k.entries if e['name'] == 'com.apple.driver.FairPlayIOKit')
    noop = function(k, kext, 0xfffffe000a52f728)
    assert noop['end'] == '0xfffffe000a52f730'
    assert noop['bytes_hex'] == '5f2403d5c0035fd6'
    assert [(i['mnemonic'], i['operands']) for i in noop['instructions']] == [('bti', 'c'), ('ret', '')]
    rules = {}
    for name, (banks, key, add, base, bias, target, diversity) in RULES.items():
        row = selected(*banks, key, add, base=base, bias=bias)
        original = pointer(k, int(row['slot'], 16))
        assert int(row['target'], 16) == int(original['target'], 16) + bias == target
        if diversity is not None:
            assert original['authenticated'] and int(original['diversity'], 16) == diversity
        assert all(IMAGE.read(a, 256) == k.read(a, 256) for a in banks)
        rules[name] = {**row, 'original_pointer': original,
                       'original_banks_hex': [k.read(a, 256).hex() for a in banks]}
    slots = {}
    for index, target, diversity in [(0x30c, 0xfffffe000a52e4b0, 0x343),
            (0x35b, 0xfffffe000a528a0c, 0x343), (0x1fb, 0xfffffe000a52e4b0, 0x2984),
            (0x32c, 0xfffffe000a55e334, 0x2984), (0x5b7, 0xfffffe000a511804, 0x40d9),
            (0x4b, 0xfffffe000a51c0e0, 0xf24b)]:
        row = pointer(k, TABLE + 8*index)
        assert row['target'] == hex(target) and row['authenticated'] and int(row['diversity'], 16) == diversity
        slots[hex(index)] = row
    raw, normalized = k.read(VIEW, 64), IMAGE.read(VIEW, 64)
    nameptr, sigptr = pointer(k, VIEW + 16), pointer(k, VIEW + 32)
    assert int.from_bytes(normalized[16:24], 'little') == int(nameptr['target'], 16)
    assert int.from_bytes(normalized[32:40], 'little') == int(sigptr['target'], 16)
    assert k.read(int(nameptr['target'], 16), 20) == IMAGE.read(int(nameptr['target'], 16), 20) == b'site.LSKDSecureTime\0'
    flags, size = struct.unpack_from('<II', normalized, 40)
    assert (flags, size) == (0x64, 64)
    assert raw[:16] == normalized[:16] == bytes(16)
    assert raw[24:32] == normalized[24:32] and raw[40:] == normalized[40:]
    typed = {'address': hex(VIEW), 'original64_hex': raw.hex(), 'normalized64_hex': normalized.hex(),
             'site_name': 'site.LSKDSecureTime', 'name_pointer': nameptr, 'signature_pointer': sigptr,
             'signature8_hex': k.read(int(sigptr['target'], 16), 8).hex(),
             'flags32': hex(flags), 'declared_size_B': size, 'runtime_metadata_initialization_established': False}
    bindings = {}
    for name, slot, target in [('read_random', 0xfffffe000847c4f8, 0xfffffe000be57d68),
                              ('kernel_sysctlbyname', 0xfffffe000847c508, 0xfffffe000c2de71c)]:
        row = pointer(k, slot)
        assert row['target'] == hex(target)
        symbols = k.symbols([target])[hex(target)]
        assert '_' + name in {s['name'] for s in symbols}
        bindings[name] = {'original_pointer': row, 'exact_symbols': symbols}
    alloc_symbols = k.symbols([0xfffffe000c4ba154])['0xfffffe000c4ba154']
    assert '_IOMallocTypeImpl' in {s['name'] for s in alloc_symbols}
    frames, producers = retained_frames(k)
    proofs, counts = prove({'spans': spans})
    excerpts = []
    path = ROOT.parent / 'com.apple.driver.FairPlayIOKit.c'
    lines = path.read_text().splitlines(keepends=True)
    for a, z in [(4355, 4372), (39705, 39815), (42416, 42501), (81431, 81534), (20816, 20932)]:
        excerpts.append({'path': path.name, 'sha256': sha(path), 'first_line': a, 'last_line': z,
                         'text': ''.join(lines[a-1:z])})
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'kernel_collection_sha256': k.sha256,
        'normalized_image_sha256': sha(SOURCE), 'spans': spans, 'completion_compiler_function': noop,
        'banks': rules, 'control_slots': slots, 'typed_view': typed, 'bindings': bindings,
        'allocator_exact_symbols': alloc_symbols, 'retained_frames': frames,
        'proofs': proofs, 'source_lift_counts': counts, 'solver_version': z3.get_version_string(),
        'supplied_reference_excerpts': excerpts,
        'selected_contract': {'global_pointer_cell': hex(GLOBAL), 'declared_size_B': 64,
            'pointer_publication_PC': '0xfffffe000a52698c', 'embedded_RW_offset_B': 24,
            'constructor_phase32': '0x90d', 'constructor_status_offset_B': 16,
            'explicit_acquisition_phase32': '0x2d2', 'raw_success_word32': '0x5e561849',
            'allocation_null_returns_raw_success': True, 'constructor_nonzero_returns_raw_success': True,
            'full_initialization_implied_by_raw_success': False,
            'self_reference_offset_B': 8, 'selected_seed_qword_offset_B': 152,
            'selected_seed_word_indices': [38, 39], 'random_output_offset_B': 0, 'random_request_B': 4,
            'clock_name': 'kern.monotonicclock', 'clock_requested_output_B': 4,
            'clock_new_pointer64': 0, 'clock_new_length64': 0,
            'next_source_target': '0xfffffe000a51c0e0', 'embedded_lock_retirement_known': False,
            'native_initialization_observed': False, 'completion_noop_semantics_known': True,
            'completion_record_consumed_by_selected_callee': False},
        'dependencies': {n: sha(ROOT / n) for n in ['kernel_native_reader.py', 'kext_port_tools.py',
            'lskd_values_symbolic.py', 'recover_aes_cleanup_epoch.py', 'recover_kext_cold_init.py',
            'recover_kext_aes_handoff.py', 'verify_daemon_reader_record_payloads_publication.py',
            'lskd_handlers_profiles.json', 'lskd_lock_origin_checks.json',
            'lskd_continuations_contracts.json', 'lskd_element_population_checks.json']},
        'verified_counts': {'kext_spans': len(spans), 'instructions': len(ins), 'code_B': 4*len(ins),
            'operand_anchors': len(ANCHORS), 'banks': len(rules), 'bank_inputs': 256*len(rules),
            'control_slots': len(slots), 'retained_frames': len(frames), 'fields_per_frame': 18,
            'original_frame_producer_PCs': producers, 'queries_unsat': len(proofs),
            'source_lifted_instances': sum(counts.values()), 'exact_imports': len(bindings),
            'compiler_noop_B': 8, 'typed_views': 1, 'reference_excerpts': len(excerpts)},
        'new_target_execution': False, 'new_IDA_access': False, 'native_epoch_matched': False,
        'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    result = build()
    path = ROOT / 'lskd_secure_time_checks.json'
    if args.verify:
        assert json.loads(read(path)) == result
    else:
        path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['verified_counts']))
