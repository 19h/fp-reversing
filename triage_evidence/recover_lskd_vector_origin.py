#!/usr/bin/env python3
"""Original LSKD vector publication, typed element initialization and failure release.

Static bytes, exhaustive byte banks, retained frame epochs and local source lifts.
No new target, allocator, synchronization, entropy or IDB execution.
O(B+I+E+256R) extraction time/space, plus chain decoding and solver cost.
"""
import argparse
import json
import struct

import z3

from kernel_native_reader import Kernel
from kext_port_tools import IMAGE, ROOT, SOURCE, selected
from lskd_values_symbolic import Lift, cell, mem, part, resize
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read, sha

TABLE = 0xfffffe000846c420
POOL = 0xfffffe00084716e0
VECTOR = 0xfffffe000ccc78d0
TAGS = 0xfffffe000ccc7b08
ARRAY_VIEW = 0xfffffe000847af20
ELEMENT_VIEW = 0xfffffe000847b060
C = (0xfffffe00079172c0, 0xfffffe0007919cb0)
B = (0xfffffe000791d3b0, 0xfffffe0007920e10)
D = (0xfffffe0007920d10, 0xfffffe00079173c0)
E = (0xfffffe0007920c10, 0xfffffe00079170c0)
SPANS = {
    'construction_control_root': (0xfffffe000a56e6f0, 0xfffffe000a56e6f8),
    'construction_handoff': (0xfffffe000a56e7d0, 0xfffffe000a56e840),
    'acquisition_selection': (0xfffffe000a54a214, 0xfffffe000a54a248),
    'acquisition_preparation': (0xfffffe000a531ca0, 0xfffffe000a531d74),
    'array_allocation_and_publication': (0xfffffe000a51162c, 0xfffffe000a51170c),
    'array_failure': (0xfffffe000a529758, 0xfffffe000a529774),
    'release_preparation': (0xfffffe000a56e020, 0xfffffe000a56e0e4),
    'post_release_gate': (0xfffffe000a56bc1c, 0xfffffe000a56bc78),
    'element_allocation_and_initialization': (0xfffffe000a5341f0, 0xfffffe000a5343e4),
    'raw_result_return': (0xfffffe000a52e4b0, 0xfffffe000a52e4e4),
}
RULES = {
    'array_allocator': (C, 0x8d, 0x99d, TABLE, 0, 0xfffffe000c4ba154),
    'array_type': (B, 0xe3, -0xdf, POOL, -12, ARRAY_VIEW),
    'element_allocator': (D, 0xbb, 0x906, TABLE, 0, 0xfffffe000c4ba154),
    'element_type': (C, 0x8d, 0x28, POOL, -8, ELEMENT_VIEW),
    'failure_release_adapter': (E, 0xaa, 0x96b, TABLE, 0, 0xfffffe000a551f38),
}
ANCHORS = {
    0xfffffe000a56e82c: ('mov', 'x28, x14'),
    0xfffffe000a54a238: ('ldr', 'x24, [sp, #0x110]'),
    0xfffffe000a531d08: ('mov', 'x27, x26'),
    0xfffffe000a531d40: ('mov', 'w21, #0xe3'),
    0xfffffe000a531d68: ('ldr', 'x26, [sp, #0x88]'),
    0xfffffe000a5116c8: ('blraa', 'x10, x17'),
    0xfffffe000a5116d0: ('str', 'x0, [x26]'),
    0xfffffe000a511708: ('braa', 'x8, x17'),
    0xfffffe000a529760: ('str', 'w9, [x22, #0x100]'),
    0xfffffe000a56e0c4: ('blraa', 'x8, x17'),
    0xfffffe000a56e0e0: ('braa', 'x19, x17'),
    0xfffffe000a56bc74: ('braa', 'x10, x17'),
    0xfffffe000a5342a0: ('blraa', 'x10, x17'),
    0xfffffe000a5342b0: ('str', 'x0, [x8, x21, lsl #3]'),
    0xfffffe000a5342b4: ('strb', 'wzr, [x0, #0x14c]'),
    0xfffffe000a5343b4: ('str', 'wzr, [x8, x21, lsl #2]'),
    0xfffffe000a5343c0: ('cmp', 'x13, #0'),
    0xfffffe000a52e4b8: ('str', 'w8, [x9, #0x38]'),
}
FIELDS = [8, 0x10, 0x18, 0x88, 0xa0, 0xa8, 0xb0, 0xb8, 0x100, 0x108,
          0x110, 0x120, 0x128, 0x160, 0x168, 0x170, 0x178, 0x180, 0x198, 0x1a0]


def frames(kernel):
    cases = json.loads(read(ROOT / 'lskd_handlers_profiles.json'))['cases']
    result, checked = [], set()
    for index, case in enumerate(cases):
        if case['boundary'].get('pc') != '0xfffffe000a50fd10':
            continue
        state = {}
        visits = case['source_visits']
        for write in case['source_writes']:
            assert visits[write['source_visit_index']]['pc'] == write['pc']
            for j, byte in enumerate(bytes.fromhex(write['after_hex'])):
                state[int(write['address'], 16) + j] = (byte, write)
        frame = int(case['boundary']['SP'], 16)
        fields = {}
        for offset in FIELDS:
            width = 4 if offset == 0x1a0 else 8
            epochs = [state[frame + offset + j] for j in range(width)]
            producers = []
            for write in {v[1]['source_visit_index']: v[1] for v in epochs}.values():
                visit = visits[write['source_visit_index']]
                assert visit['bytes_hex'] == kernel.read(int(write['pc'], 16), 4).hex()
                checked.add(write['pc'])
                producers.append({'pc': write['pc'], 'instruction_hex': visit['bytes_hex'],
                                  'source_visit_index': write['source_visit_index']})
            fields[hex(offset)] = {'value': hex(int.from_bytes(bytes(v[0] for v in epochs), 'little')),
                                  'width_B': width, 'producers': producers}
        value = lambda o: int(fields[hex(o)]['value'], 16)
        workspace = int(case['workspace_pointer'], 16)
        auxiliary = int(case['actual_auxiliary']['address'], 16)
        assert [value(o) for o in [8, 0x88, 0xa0, 0xa8, 0xb0, 0xb8, 0x100,
                0x108, 0x110, 0x168, 0x170, 0x178, 0x180, 0x1a0]] == [
            TAGS, VECTOR, *C, *B, TABLE, D[1], D[0], *E,
            0xfffffe000ccc2d90, 0xfffffe000ccc2c60, 0x3be]
        assert [value(o) for o in [0x120, 0x128, 0x160, 0x198]] == [
            workspace + 0x80, workspace + 0xa8, auxiliary, workspace + 0x40]
        assert not case['random_backend_executed']
        result.append({'prior_case_index': index, 'boundary_pc': case['boundary']['pc'],
                       'frame_fields': fields, 'new_target_execution': False})
    assert len(result) == 13
    return result, len(checked)


def proofs(capture):
    f = 0x51000000
    r, alloc, vector, i, raw_slot = z3.BitVecs(
        'release_record64 allocated_element64 allocated_vector64 slot_index64 reloaded_slot64', 64)
    status = z3.BitVec('stored_status32', 32)
    qs, counts = {}, {}

    def run(name, start, end, seeds, cells=()):
        v = Lift(part(capture, name, start, end))
        for reg, value in seeds.items():
            v.seed(reg, value)
        for address, width, value in cells:
            mem(v, address, width, value)
        v.run(name)
        counts[name] = v.count
        return v

    v = run('acquisition_register_roots', 0xfffffe000a54a228, 0xfffffe000a54a240,
            {'sp': f}, [(f + 0xa0, 8, C[0]), (f + 0xa8, 8, C[1]),
                         (f + 0x10, 8, 0xfffffe000ccc78c0), (f + 0x18, 8, 0x630000c000),
                         (f + 0x110, 8, D[0]), (f + 8, 8, TAGS)])
    qs['acquisition_register_roots'] = z3.Or(v.read('w23') != 0xea5ebdeb,
        v.read('x6') != C[0], v.read('x5') != C[1], v.read('x24') != D[0], v.read('x0') != TAGS)
    v = run('acquisition_frame_roundtrip', 0xfffffe000a531ca4, 0xfffffe000a531cb0,
            {'sp': f, 'x0': TAGS, 'x14': 0xfffffe000ccc78c0, 'x3': 0x630000c000,
             'x6': C[0], 'x5': C[1]})
    qs['acquisition_frame_roundtrip'] = z3.Or(cell(v, f + 8, 8) != TAGS,
        cell(v, f + 0xa0, 8) != C[0], cell(v, f + 0xa8, 8) != C[1])
    v = run('post_acquisition_destination', 0xfffffe000a531d64, 0xfffffe000a531d6c,
            {'sp': f}, [(f + 0x160, 8, 0x630000c000), (f + 0x88, 8, VECTOR)])
    qs['post_acquisition_destination'] = v.read('x26') != VECTOR
    v = run('array_state_constants', 0xfffffe000a511674, 0xfffffe000a51167c,
            {'sp': f}, [(f + 0x1a0, 4, 0x3be)])
    qs['array_state_constants'] = z3.Or(v.read('w22') != 0x3be, v.read('w19') != 0x7fe)
    v = run('array_success_index', 0xfffffe000a51168c, 0xfffffe000a511690, {'w22': 0x3be})
    qs['array_success_index'] = v.read('w20') != 0x4f7
    v = run('vector_publication_and_gate', 0xfffffe000a5116cc, 0xfffffe000a5116ec,
            {'x0': vector, 'x26': VECTOR, 'w19': 0x7fe, 'w20': 0x4f7})
    qs['vector_publication_and_gate'] = z3.Or(cell(v, VECTOR, 8) != vector,
        v.read('x21') != 0,
        v.read('w8') != z3.If(vector == 0, z3.BitVecVal(0x695, 32), z3.BitVecVal(0x4f7, 32)))
    v = run('array_failure_arguments', 0xfffffe000a5116f0, 0xfffffe000a511704,
            {'sp': f, 'w22': 0x3be}, [(f + 0x120, 8, 0x6300000080)])
    qs['array_failure_arguments'] = z3.Or(v.read('w9') != 0x5e5571ad,
        v.read('x26') != 0x3be, v.read('x22') != 0x6300000080)
    v = run('array_failure_record', 0xfffffe000a52975c, 0xfffffe000a529768,
            {'w26': 0x3be, 'x22': r, 'w9': 0x5e5571ad})
    qs['array_failure_record'] = z3.Or(v.read('w8') != 0x14, v.read('w9') != 0x579,
        cell(v, r + 0x100, 4) != 0x5e5571ad)
    v = run('release_key_basis', 0xfffffe000a56e028, 0xfffffe000a56e054,
            {'sp': f}, [(f + 0x128, 8, r)])
    qs['release_key_basis'] = v.read('w8') != resize(r ^ 0xdfb9786f, 32)
    v = run('release_record', 0xfffffe000a56e054, 0xfffffe000a56e06c,
            {'x0': r, 'w8': resize(r ^ 0xdfb9786f, 32), 'w26': 0x3be})
    qs['release_record'] = z3.Or(cell(v, r, 4) - resize((r ^ 0xdfb9786f) * 0x1e2776fd, 32) != 0x1d3,
                               cell(v, r + 8, 8) != 0)
    v = run('post_release_status_gate', 0xfffffe000a56bc20, 0xfffffe000a56bc50,
            {'sp': f, 'x22': r}, [(f + 0x1a0, 4, 0x3be), (r + 0x100, 4, status)])
    qs['post_release_status_gate'] = z3.Or(v.read('w8') != status,
        v.read('w10') != z3.If(status == 0x5e561849, z3.BitVecVal(0x458, 32), z3.BitVecVal(0x3be, 32)))
    qs['array_failure_returns_original_status'] = z3.And(status == 0x5e5571ad,
        z3.Or(v.read('w10') != 0x3be, v.read('w8') != 0x5e5571ad))
    v = run('element_entry_constants', 0xfffffe000a5341f4, 0xfffffe000a534210, {'w19': 0x7fe})
    qs['element_entry_constants'] = z3.Or(v.read('w26') != 0x4f7, v.read('w20') != 0x82c)
    v = run('element_initial_stores', 0xfffffe000a5342a4, 0xfffffe000a5343c0,
            {'sp': f, 'x0': alloc, 'x21': i, 'x26': 0x4f7},
            [(f + 0x88, 8, VECTOR), (VECTOR, 8, vector), (f + 8, 8, TAGS)])
    qs['element_slot_and_tag_stores'] = z3.Or(
        v.stores[0]['address'] != vector + 8 * i, v.stores[0]['value'] != alloc,
        v.stores[-1]['address'] != resize(TAGS, 64) + 4 * i, v.stores[-1]['value'] != 0,
        v.read('x13') != alloc)
    layout, touched = [], set()
    for store in v.stores[1:-1]:
        offset = z3.simplify(store['address'] - alloc).as_long()
        width = store['size_bytes']
        value = z3.simplify(store['value']).as_long()
        assert 0 <= offset < offset + width <= 512
        layout.append({'pc': hex(store['pc']), 'offset_B': offset, 'width_B': width, 'value_hex': hex(value)})
        touched.update(range(offset, offset + width))
    assert layout and layout[0]['pc'] == '0xfffffe000a5342b4'
    qs['bounded_slot_and_tag_extents'] = z3.And(z3.ULT(i, 1024),
        z3.Or(z3.UGT(8 * i + 8, 8192), z3.UGT(4 * i + 4, 4096)))
    v = run('element_reloaded_slot_gate', 0xfffffe000a5343c0, 0xfffffe000a5343d8,
            {'x13': raw_slot, 'w20': 0x82c, 'w26': 0x4f7, 'w19': 0x7fe})
    qs['element_reloaded_slot_gate'] = v.read('w8') != z3.If(
        raw_slot == 0, z3.BitVecVal(0x82c, 32), z3.BitVecVal(0x7fe, 32))
    results = {}
    for name, mismatch in qs.items():
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(mismatch)
        result = str(solver.check())
        assert result == 'unsat', (name, result)
        results[name] = {'query': solver.to_smt2(), 'result': result}
    return results, counts, {'stores': layout, 'store_count': len(layout),
        'unique_written_B': len(touched), 'exclusive_end_B': max(touched) + 1,
        'declared_size_B': 512, 'full_object_initialized': len(touched) == 512,
        'slot_store_pc': '0xfffffe000a5342b0', 'tag_zero_store_pc': '0xfffffe000a5343b4',
        'later_slot_test_pc': '0xfffffe000a5343c0'}


def build():
    k = Kernel()
    spans = []
    for label, bounds in SPANS.items():
        row = span(k, *bounds)
        row['bytes_hex'] = row.pop('bytes')
        row['label'] = label
        spans.append(row)
    instructions = {int(i['ea'], 16): (i['mnemonic'], i['operands'])
                    for s in spans for i in s['instructions']}
    assert all(instructions[pc] == expected for pc, expected in ANCHORS.items())
    banks = {}
    for label, (addresses, key, add, base, bias, target) in RULES.items():
        row = selected(*addresses, key, add, base=base, bias=bias)
        original = pointer(k, int(row['slot'], 16))
        assert int(row['target'], 16) == int(original['target'], 16) + bias == target
        assert all(IMAGE.read(a, 256) == k.read(a, 256) for a in addresses)
        banks[label] = {**row, 'original_pointer': original,
                        'original_banks_hex': [k.read(a, 256).hex() for a in addresses]}
    slots = {}
    for index, target, diversity in [
        (0x4f7, 0xfffffe000a5341f0, 0xb064), (0x695, 0xfffffe000a529758, 0xb064),
        (0x579, 0xfffffe000a56e020, 0x83c6), (0x14, 0xfffffe000a56bc1c, 0xc38e),
        (0x3be, 0xfffffe000a52e4b0, 0x62dc), (0x7fe, 0xfffffe000a51b9d8, 0xf019),
        (0x82c, 0xfffffe000a547fc8, 0xf019),
    ]:
        row = pointer(k, TABLE + 8 * index)
        assert row['authenticated'] and (int(row['target'], 16), int(row['diversity'], 16)) == (target, diversity)
        slots[hex(index)] = row
    views = []
    for address, name, flags, size in [
        (ARRAY_VIEW, 'site.KDDecryptParamsArray_t', 0xe4, 8192),
        (ELEMENT_VIEW, 'site.KDDecryptParams', 0x64, 512),
    ]:
        pointers = [pointer(k, address + offset) for offset in (16, 32)]
        name_bytes = k.read(int(pointers[0]['target'], 16), len(name) + 1)
        assert name_bytes == name.encode() + b'\0'
        assert struct.unpack('<II', k.read(address + 40, 8)) == (flags, size)
        assert k.read(address, 16) == bytes(16)
        views.append({'address': hex(address), 'original64_hex': k.read(address, 64).hex(),
                      'normalized64_hex': IMAGE.read(address, 64).hex(), 'pointer_fields': pointers,
                      'site_name': name, 'name_bytes_hex': name_bytes.hex(), 'flags32': hex(flags),
                      'size32_B': size, 'runtime_links_known': False})
    retained, source_pcs = frames(k)
    proof, counts, layout = proofs({'spans': spans})
    cpath = ROOT.parent / 'com.apple.driver.FairPlayIOKit.c'
    lines = cpath.read_text().splitlines(keepends=True)
    excerpts = [{'path': cpath.name, 'sha256': sha(cpath), 'first_line': a, 'last_line': z,
                 'text': ''.join(lines[a - 1:z])} for a, z in [
                     (20721, 20757), (43372, 43387), (52267, 52421), (95130, 95212)]]
    native = {label: k.function(address) for label, address in [
        ('typed_allocator', 0xfffffe000c4ba154), ('typed_delegate', 0xfffffe000bcfeb8c)]}
    symbols = k.symbols([0xfffffe000c4ba154, 0xfffffe000bcfeb8c])
    assert '_IOMallocTypeImpl' in {s['name'] for s in symbols['0xfffffe000c4ba154']}
    assert '_kalloc_type_impl' in {s['name'] for s in symbols['0xfffffe000bcfeb8c']}
    return {'scope': __doc__, 'generator_sha256': sha(__file__),
        'kernel_collection_sha256': k.sha256, 'normalized_image_sha256': sha(SOURCE),
        'spans': spans, 'banks': banks, 'control_slots': slots, 'typed_views': views,
        'native_allocator_source': native, 'exact_symbols': symbols,
        'retained_frames': retained, 'proofs': proof, 'source_lift_counts': counts,
        'solver_version': z3.get_version_string(), 'element_initialization': layout,
        'supplied_reference_excerpts': excerpts,
        'selected_contract': {'vector_cell': hex(VECTOR), 'tag_table': hex(TAGS),
            'array_call_pc': '0xfffffe000a5116c8', 'array_publication_pc': '0xfffffe000a5116d0',
            'array_declared_B': 8192, 'reader_slots': 1024, 'reader_stride_B': 8,
            'array_null_raw_status32': '0x5e5571ad', 'release_record_phase32': '0x1d3',
            'element_call_pc': '0xfffffe000a5342a0', 'first_element_index': 0,
            'element_declared_B': 512, 'all_elements_constructed': False,
            'final_daemon_reply_established': False},
        'dependencies': {name: sha(ROOT / name) for name in [
            'kernel_native_reader.py', 'kext_port_tools.py', 'lskd_values_symbolic.py',
            'recover_aes_cleanup_epoch.py', 'recover_kext_cold_init.py',
            'verify_daemon_reader_record_payloads_publication.py',
            'lskd_handlers_profiles.json', 'lskd_start_lock_flow_checks.json',
            'lskd_continuations_contracts.json', 'lskd_objects_contracts.json']},
        'verified_counts': {'kext_spans': len(spans), 'kext_instructions': len(instructions),
            'kext_code_B': 4 * len(instructions), 'operand_anchors': len(ANCHORS),
            'bank_rules': len(banks), 'byte_bank_inputs': 256 * len(banks),
            'control_slots': len(slots), 'typed_views': len(views), 'native_functions': len(native),
            'retained_start_frames': len(retained), 'frame_fields_per_case': len(FIELDS),
            'original_frame_producer_PCs': source_pcs, 'queries_unsat': len(proof),
            'source_lifted_instances': sum(counts.values()), 'element_store_count': layout['store_count'],
            'element_unique_written_B': layout['unique_written_B']},
        'new_target_execution': False, 'new_IDA_access': False, 'native_epoch_matched': False,
        'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    result = build()
    path = ROOT / 'lskd_vector_origin_checks.json'
    if args.verify:
        assert json.loads(read(path)) == result
    else:
        path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['verified_counts']))
