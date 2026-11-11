#!/usr/bin/env python3
"""Original start-handler seed writes, construction phase and lock handoff.

Static source lifting and retained-case frame reconstruction only. No new
target execution, random generation, lock operation, heap action or IDB access.
O(B+I+E+256R) source work and storage, plus pointer-chain and solver cost.
"""
import argparse
import json

import z3

from kernel_native_reader import Kernel
from kext_port_tools import IMAGE, ROOT, SOURCE, selected
from lskd_values_symbolic import Lift, cell, mem, part, resize
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read, sha

TABLE = 0xfffffe000846c420
POOL = 0xfffffe00084716e0
SEEDS = 0xfffffe000ccc78f4
SEED_CELL = 0xfffffe000ccc78b8
FLAG = 0xfffffe000ccc78e0
LOCK = 0xfffffe000ccc78a8
SPANS = {
    'named_start': (0xfffffe000a5053f4, 0xfffffe000a505480),
    'entropy_loop': (0xfffffe000a50fc90, 0xfffffe000a50fd98),
    'seed_gate_and_constructor_caller': (0xfffffe000a56e6f0, 0xfffffe000a56e874),
    'construction_success': (0xfffffe000a54a214, 0xfffffe000a54a248),
    'acquire_preparation': (0xfffffe000a531ca0, 0xfffffe000a531d74),
    'result_return': (0xfffffe000a52e4b0, 0xfffffe000a52e4e4),
    'random_wrapper': (0xfffffe000a508d6c, 0xfffffe000a508d74),
    'random_import_stub': (0xfffffe000a69f394, 0xfffffe000a69f3a4),
}
A = (0xfffffe00079171c0, 0xfffffe0007919bb0)
B = (0xfffffe000791d3b0, 0xfffffe0007920e10)
RULES = {
    'entropy_wrapper': (A, 0xea, 0x9ef, TABLE, 0, 0xfffffe000a508d6c),
    'seed_table': (A, 0xca, -0x8a, POOL, -12, SEEDS),
    'construction_preparer': (A, 0x58, 0x935, TABLE, 0, 0xfffffe000a52ea1c),
    'acquisition_adapter': (B, 0xe3, 0x8b6, TABLE, 0, 0xfffffe000a54e220),
}
ANCHORS = {
    0xfffffe000a50fd10: ('blraa', 'x8, x17'),
    0xfffffe000a50fd6c: ('str', 'w9, [x8, x19, lsl #2]'),
    0xfffffe000a50fd94: ('braa', 'x9, x17'),
    0xfffffe000a56e700: ('cbz', 'x9, #0xfffffe000a56e714'),
    0xfffffe000a56e710: ('b', '#0xfffffe000a52e4b0'),
    0xfffffe000a56e714: ('str', 'x8, [x10]'),
    0xfffffe000a56e720: ('str', 'w9, [x10]'),
    0xfffffe000a56e754: ('str', 'w12, [x11], #0x10'),
    0xfffffe000a56e760: ('b.lo', '#0xfffffe000a56e73c'),
    0xfffffe000a56e7cc: ('str', 'w10, [x22, #0x20]'),
    0xfffffe000a56e83c: ('blraa', 'x8, x17'),
    0xfffffe000a56e870: ('braa', 'x9, x17'),
    0xfffffe000a54a244: ('braa', 'x9, x17'),
    0xfffffe000a531cf8: ('str', 'xzr, [x0]'),
    0xfffffe000a531d04: ('str', 'w8, [x0, #8]'),
    0xfffffe000a531d60: ('blraa', 'x8, x17'),
    0xfffffe000a52e4b8: ('str', 'w8, [x9, #0x38]'),
}
FRAME_FIELDS = [0x78, 0x80, 0xb0, 0xb8, 0xf8, 0x100, 0x120, 0x128,
                0x130, 0x138, 0x140, 0x148, 0x178, 0x180, 0x188, 0x190, 0x198]


def retained_frames(kernel):
    prior = json.loads(read(ROOT / 'lskd_handlers_profiles.json'))
    results = []
    checked_instructions = set()
    for index, case in enumerate(prior['cases']):
        boundary = case['boundary']
        if boundary.get('pc') != '0xfffffe000a50fd10':
            continue
        registers = list(map(lambda s: int(s, 16), boundary['registers31']))
        assert registers[0] == int(case['workspace_pointer'], 16) + 0x9c
        assert registers[1] == 4 and registers[19] == 0 and registers[22] == 0x3be
        assert registers[23] == TABLE and registers[24] == A[0] and registers[26] == 0x1ee
        assert registers[28] == A[1]
        visits = case['source_visits']
        assert all(v['source_visit_index'] == j for j, v in enumerate(visits))
        state = {}
        for write in case['source_writes']:
            visit = visits[write['source_visit_index']]
            assert visit['pc'] == write['pc']
            for offset, value in enumerate(bytes.fromhex(write['after_hex'])):
                state[int(write['address'], 16) + offset] = (value, write)
        frame = int(boundary['SP'], 16)
        fields = {}
        for offset in FRAME_FIELDS:
            width = 4 if offset == 0xf8 else 8
            epochs = [state[frame + offset + j] for j in range(width)]
            value = int.from_bytes(bytes(row[0] for row in epochs), 'little')
            producers = []
            for write in {row[1]['source_visit_index']: row[1] for row in epochs}.values():
                visit = visits[write['source_visit_index']]
                assert visit['bytes_hex'] == kernel.read(int(write['pc'], 16), 4).hex()
                checked_instructions.add(write['pc'])
                producers.append({'pc': write['pc'], 'source_visit_index': write['source_visit_index'],
                                  'instruction_hex': visit['bytes_hex']})
            fields[hex(offset)] = {'value': hex(value), 'width_B': width, 'producers': producers}
        get = lambda offset: int(fields[hex(offset)]['value'], 16)
        workspace = int(case['workspace_pointer'], 16)
        auxiliary = int(case['actual_auxiliary']['address'], 16)
        assert [get(o) for o in [0x78, 0x80, 0xb0, 0xb8, 0xf8, 0x100]] == [
            FLAG, SEED_CELL, B[0], B[1], 0x1ee, TABLE]
        assert [get(o) for o in [0x120, 0x128, 0x130, 0x138, 0x140, 0x148]] == [
            workspace + 0x80, workspace + 0xa8, workspace + 0x4000,
            workspace + 0x1c0, auxiliary + 0x1000, auxiliary + 0xc0]
        assert [get(o) for o in [0x178, 0x180, 0x188, 0x190, 0x198]] == [
            0xfffffe000ccc2d90, 0xfffffe000ccc2c60, A[0], A[1], workspace + 0x40]
        assert get(0x138) + 64 <= get(0x130)
        for visit in visits:
            address = int(visit['pc'], 16)
            if 0xfffffe000a50fc90 <= address < 0xfffffe000a50fd10:
                assert visit['bytes_hex'] == kernel.read(address, 4).hex()
                checked_instructions.add(visit['pc'])
        assert case['random_backend_executed'] is False
        results.append({'prior_case_index': index, 'input': case['input'],
                        'boundary': boundary, 'frame_fields': fields,
                        'workspace': hex(workspace), 'auxiliary': hex(auxiliary),
                        'new_target_execution': False})
    assert len(results) == 13
    return results, len(checked_instructions)


def prove(capture):
    q = {}
    counts = {}
    f = 0x51000000
    i, j = z3.BitVecs('entropy_iteration64 mixing_iteration64', 64)
    r, out, child, limit, auxiliary_end, auxiliary_work = z3.BitVecs(
        'parent_record64 outer_result64 child_record64 workspace_limit64 auxiliary_end64 auxiliary_work64', 64)
    word, current, selected_word = z3.BitVecs('random_word32 current_word32 selected_word32', 32)
    status = z3.BitVec('parent_status32', 32)

    def run(name, start, end, seeds, memory=()):
        obj = Lift(part(capture, name, start, end))
        for reg, value in seeds.items():
            obj.seed(reg, value)
        for address, width, value in memory:
            mem(obj, address, width, value)
        obj.run(name)
        counts[name] = obj.count
        return obj

    v = run('handler_phase_load', 0xfffffe000a50fc94, 0xfffffe000a50fc9c,
            {'sp': f}, [(f + 0xf8, 4, 0x1ee)])
    q['handler_phase_load'] = z3.Or(v.read('w26') != 0x1ee, v.read('w8') != 0x2a6)
    v = run('handler_phase', 0xfffffe000a50fce8, 0xfffffe000a50fcec,
            {'w8': 0x2a6, 'w11': 0x118})
    q['handler_phase'] = v.read('w22') != 0x3be
    v = run('entropy_store_and_loop', 0xfffffe000a50fd64, 0xfffffe000a50fd8c,
            {'x8': SEEDS + 12, 'x27': f, 'x19': i, 'x22': 0x3be, 'w26': 0x1ee},
            [(f + 0x1c, 4, word)])
    assert len(v.stores) == 1 and v.stores[0]['size_bytes'] == 4
    q['entropy_store_and_loop'] = z3.And(z3.ULT(i, 128), z3.Or(
        v.stores[0]['address'] != resize(SEEDS, 64) + 4 * i,
        v.stores[0]['value'] != word, v.read('x8') != SEEDS,
        v.read('x19') != i + 1,
        v.read('w9') != z3.If(i == 127, z3.BitVecVal(0x1ee, 32), z3.BitVecVal(0x222, 32))))
    v = run('seed_publication_and_phase', 0xfffffe000a56e714, 0xfffffe000a56e73c,
            {'x8': SEEDS, 'x10': SEED_CELL, 'w22': 0x3be, 'sp': f}, [(f + 0x78, 8, FLAG)])
    q['seed_publication_and_phase'] = z3.Or(cell(v, SEED_CELL, 8) != SEEDS,
        cell(v, FLAG, 4) != 255, v.read('w19') != 0x1fb, v.read('x10') != 0x3b,
        v.read('x9') != z3.BitVecVal(-4, 64), v.read('x11') != SEEDS)
    v = run('mix_index', 0xfffffe000a56e73c, 0xfffffe000a56e748,
            {'x11': resize(SEEDS, 64) + 16 * j},
            [(resize(SEEDS, 64) + 16 * j, 4, current)])
    offset = v.read('x13')
    q['mix_index'] = z3.Or(offset != resize((current & 0x3e) * 4, 64),
                           z3.UGT(offset, 248), (offset & 7) != 0)
    v.c = part(capture, 'mix_word', 0xfffffe000a56e748, 0xfffffe000a56e754)
    v.seed('x8', SEEDS)
    mem(v, resize(SEEDS, 64) + offset, 4, selected_word)
    previous_count = v.count
    v.run('mix_word')
    counts['mix_word'] = v.count - previous_count
    expected = current | (~selected_word << 16)
    q['mix_word'] = z3.Or(v.read('w12') != expected,
                         z3.Extract(15, 0, v.read('w12')) != z3.Extract(15, 0, current))
    v = run('mix_counter', 0xfffffe000a56e758, 0xfffffe000a56e760,
            {'x9': 4 * j - 4, 'x10': 0x3b})
    q['mix_counter'] = z3.And(z3.ULT(j, 16), z3.Or(v.read('x9') != 4 * j,
        z3.ULT(v.read('x9'), 0x3b) != z3.ULT(j, 15)))
    original = z3.Array('original_seed_words', z3.BitVecSort(32), z3.BitVecSort(32))
    state = original
    for iteration in range(16):
        index = z3.BitVecVal(4 * iteration, 32)
        value = z3.Select(state, index)
        other = z3.Select(state, value & 0x3e)
        state = z3.Store(state, index, value | (~other << 16))
    expected_word = lambda n: (z3.Select(original, n) | (~z3.Select(
        original, z3.Select(original, n) & 0x3e) << 16)) if n in range(0, 64, 4) else z3.Select(original, n)
    q['sequential_mix_equals_original_snapshot'] = z3.Or(*[
        z3.Select(state, n) != expected_word(n) for n in range(128)])
    v = run('parent_key_basis', 0xfffffe000a56e76c, 0xfffffe000a56e798,
            {'sp': f}, [(f + 0x128, 8, r)])
    q['parent_key_basis'] = v.read('w10') != resize(r ^ 0xc410a4c0, 32)
    v = run('parent_record_phase', 0xfffffe000a56e798, 0xfffffe000a56e7d0,
            {'sp': f, 'x22': r, 'w10': resize(r ^ 0xc410a4c0, 32), 'w19': 0x1fb},
            [(f + 0x140, 8, auxiliary_end), (f + 0x130, 8, limit),
             (f + 0x138, 8, child), (f + 0x148, 8, auxiliary_work)])
    key = resize((r ^ 0xc410a4c0) * 0xaed3b63b, 32)
    q['parent_record_phase'] = z3.Or(cell(v, r + 0x20, 4) ^ key != 0xc2b1dbf2,
        cell(v, r + 8, 8) != child, cell(v, r + 0x28, 8) != limit,
        cell(v, r, 8) != auxiliary_work, cell(v, r + 0x18, 8) != auxiliary_end)
    q['child_phase_join'] = z3.BitVecVal(0xc2b1dbf2, 32) + 0x3d4e2d1b != 0x90d
    v = run('caller_saved_success_phase', 0xfffffe000a56e764, 0xfffffe000a56e76c, {'w19': 0x1fb})
    v.c = part(capture, 'caller_success_phase', 0xfffffe000a56e81c, 0xfffffe000a56e820)
    previous_count = v.count
    v.run('caller_success_phase')
    counts['caller_success_phase'] = v.count - previous_count
    q['caller_success_phase'] = v.read('w20') != 0x3be
    v = run('construction_status_gate', 0xfffffe000a56e840, 0xfffffe000a56e868,
            {'x22': r, 'w20': 0x3be, 'w19': 0x1fb}, [(r + 0x10, 4, status)])
    q['construction_status_gate'] = z3.Or(v.read('w8') != status,
        v.read('w9') != z3.If(status == 0x5e561849, z3.BitVecVal(0x243, 32), z3.BitVecVal(0x1fb, 32)))
    v = run('nonnull_seed_error', 0xfffffe000a56e704, 0xfffffe000a56e710, {})
    q['nonnull_seed_error'] = v.read('w8') != 0x5e5571ae
    v = run('success_acquire_phase', 0xfffffe000a54a218, 0xfffffe000a54a224, {'w19': 0x1fb})
    q['success_acquire_phase'] = z3.Or(v.read('w21') != 0x3be, v.read('w8') != 0x5b,
                                       v.read('w9') != 0x20d)
    v = run('acquire_key_basis', 0xfffffe000a531cb4, 0xfffffe000a531cf0,
            {'sp': f}, [(f + 0x128, 8, r)])
    q['acquire_key_basis'] = v.read('w8') != resize(r ^ 0x1d65dad0, 32)
    v = run('acquire_record', 0xfffffe000a531cf0, 0xfffffe000a531d08,
            {'x0': r, 'w8': resize(r ^ 0x1d65dad0, 32), 'w21': 0x3be})
    q['acquire_record'] = z3.Or(cell(v, r, 8) != 0,
        cell(v, r + 8, 4) - resize((r ^ 0x1d65dad0) * 0xe9655f4d, 32) != 0x2d2)
    v = run('raw_result_store', 0xfffffe000a52e4b4, 0xfffffe000a52e4bc,
            {'sp': f, 'w8': status}, [(f + 0x198, 8, out)])
    q['raw_result_store'] = cell(v, out + 0x38, 4) != status
    proofs = {}
    for name, mismatch in q.items():
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(mismatch)
        result = str(solver.check())
        assert result == 'unsat', (name, result)
        proofs[name] = {'query': solver.to_smt2(), 'result': result}
    return proofs, counts


def build():
    kernel = Kernel()
    spans = []
    for label, bounds in SPANS.items():
        row = span(kernel, *bounds)
        row['bytes_hex'] = row.pop('bytes')
        row['label'] = label
        spans.append(row)
    insns = {int(i['ea'], 16): (i['mnemonic'], i['operands']) for s in spans for i in s['instructions']}
    assert all(insns[address] == expected for address, expected in ANCHORS.items())
    banks = {}
    for label, (addresses, key, additive, base, bias, target) in RULES.items():
        row = selected(*addresses, key, additive, base=base, bias=bias)
        fixup = pointer(kernel, int(row['slot'], 16))
        assert int(row['target'], 16) == int(fixup['target'], 16) + bias == target
        assert all(IMAGE.read(a, 256) == kernel.read(a, 256) for a in addresses)
        banks[label] = {**row, 'original_pointer': fixup,
                        'original_banks_hex': [kernel.read(a, 256).hex() for a in addresses]}
    control = {}
    for index, target, diversity in [
        (0x222, 0xfffffe000a50fc90, 0xfac7), (0x1ee, 0xfffffe000a56e6f0, 0xfac7),
        (0x243, 0xfffffe000a54a214, 0x2984), (0x1fb, 0xfffffe000a52e4b0, 0x2984),
        (0x20d, 0xfffffe000a531ca0, 0x3fd3), (0x5b, 0xfffffe000a51162c, 0x2108),
    ]:
        row = pointer(kernel, TABLE + 8 * index)
        assert row['authenticated'] and (int(row['target'], 16), int(row['diversity'], 16)) == (target, diversity)
        control[hex(index)] = row
    random = pointer(kernel, 0xfffffe000847c4f8)
    assert random['target'] == '0xfffffe000be57d68'
    symbols = kernel.symbols([0xfffffe000a5053f4, 0xfffffe000be57d68])
    assert '__Z14LSKDKext_startv' in {s['name'] for s in symbols['0xfffffe000a5053f4']}
    assert '_read_random' in {s['name'] for s in symbols['0xfffffe000be57d68']}
    frames, frame_source_PCs = retained_frames(kernel)
    proofs, counts = prove({'spans': spans})
    prior = json.loads(read(ROOT / 'lskd_lock_origin_checks.json'))
    assert prior['selected_contract']['decoded_parent_phase32'] == '0xc2b1dbf2'
    assert prior['selected_contract']['decoded_child_phase32'] == '0x90d'
    assert prior['lock_domains']['LSKD_cell'] == hex(LOCK)
    cpath = ROOT.parent / 'com.apple.driver.FairPlayIOKit.c'
    lines = cpath.read_text().splitlines(keepends=True)
    excerpts = [{'path': cpath.name, 'sha256': sha(cpath), 'first_line': a, 'last_line': z,
                 'text': ''.join(lines[a - 1:z])} for a, z in [(95597, 95700), (9142, 9152)]]
    return {
        'scope': __doc__, 'generator_sha256': sha(__file__),
        'kernel_collection_sha256': kernel.sha256, 'normalized_image_sha256': sha(SOURCE),
        'spans': spans, 'banks': banks, 'control_slots': control, 'random_import': random,
        'exact_symbols': symbols, 'retained_start_frames': frames,
        'proofs': proofs, 'source_lift_counts': counts, 'solver_version': z3.get_version_string(),
        'supplied_reference_excerpts': excerpts,
        'source_effect_order': [
            {'stage': 0, 'effect': '128 returning 4 B entropy requests and u32 seed stores', 'native_executed': False},
            {'stage': 1, 'effect': 'seed pointer nonnull gate after all 128 seed stores', 'native_executed': False},
            {'stage': 2, 'effect': 'nonnull gate returns raw 0x5e5571ae with no new construction', 'native_executed': False},
            {'stage': 3, 'effect': 'null gate publishes seed pointer, stores flag255, edits 16 words', 'native_executed': False},
            {'stage': 4, 'effect': 'parent phase0xc2b1dbf2 invokes RW construction', 'native_executed': False},
            {'stage': 5, 'effect': 'construction failure returns raw status without resetting seed publication', 'native_executed': False},
            {'stage': 6, 'effect': 'construction success prepares null-explicit acquisition record phase0x2d2', 'native_executed': False},
        ],
        'seed_region': {'address': hex(SEEDS), 'extent_B': 512, 'u32_words': 128,
                        'file512_sha256': __import__('hashlib').sha256(kernel.read(SEEDS, 512)).hexdigest(),
                        'initial_file_zero': kernel.read(SEEDS, 512) == bytes(512),
                        'mix_written_word_indices': list(range(0, 64, 4)),
                        'mix_unique_written_B': 64, 'mix_max_selected_read_offset_B': 248,
                        'seed_pointer_cell': hex(SEED_CELL), 'flag_u32_cell': hex(FLAG),
                        'lock_pointer_cell': hex(LOCK), 'runtime_values_known': False},
        'dependencies': {name: sha(ROOT / name) for name in [
            'kernel_native_reader.py', 'kext_port_tools.py', 'recover_kext_cold_init.py',
            'recover_aes_cleanup_epoch.py', 'lskd_values_symbolic.py',
            'verify_daemon_reader_record_payloads_publication.py',
            'lskd_handlers_profiles.json', 'lskd_handlers_checks.json',
            'lskd_lock_origin_checks.json', 'lskd_continuations_contracts.json',
        ]},
        'verified_counts': {'kext_spans': len(spans), 'instructions': len(insns), 'code_bytes': 4 * len(insns),
                            'operand_anchors': len(ANCHORS), 'bank_rules': len(banks),
                            'byte_bank_inputs': 256 * len(banks), 'control_slots': len(control),
                            'exact_symbols': 2, 'retained_start_frames': len(frames),
                            'frame_fields_per_case': len(FRAME_FIELDS), 'frame_source_PCs_checked': frame_source_PCs,
                            'queries_unsat': len(proofs), 'lifted_instruction_instances': sum(counts.values()),
                            'array_composition_steps': 16, 'final_array_words_checked': 128},
        'new_target_execution': False, 'new_IDA_access': False, 'native_epoch_matched': False,
        'full_goal_complete': False, 'all_checks_pass': True,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    result = build()
    path = ROOT / 'lskd_start_lock_flow_checks.json'
    if args.verify:
        assert json.loads(read(path)) == result
    else:
        path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['verified_counts']))
