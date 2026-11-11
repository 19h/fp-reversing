#!/usr/bin/env python3
"""Original 1024-slot population loop, 512-byte rewrite and completion handoff.

Static source lifting only, including a bounded AdvSIMD byte-table interpreter.
No new target, allocation, entropy, synchronization or IDB execution.
O(B+I+E+256R) extraction; O(I) expression construction; solver cost separate.
The complete stack-byte pointer codec and completion helper remain unreduced.
"""
import argparse
import json
import re
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import z3

from kernel_native_reader import Kernel
from kext_port_tools import ROOT, SOURCE, IMAGE, selected
from lskd_values_symbolic import Lift, part, mem, cell, resize
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read, sha

TABLE = 0xfffffe000846c420
VECTOR = 0xfffffe000ccc78d0
SEEDS = 0xfffffe000ccc78f4
FLAG = 0xfffffe000ccc78e0
SEED_CELL = 0xfffffe000ccc78b8
SPANS = {
    'whole_element_transform': (0xfffffe000a51b9d8, 0xfffffe000a51bd54),
    'outer_loop_footer': (0xfffffe000a547fc8, 0xfffffe000a548014),
    'completion_preparation': (0xfffffe000a56e91c, 0xfffffe000a56e9fc),
    'shared_status_release': (0xfffffe000a529758, 0xfffffe000a529774),
    'release_preparation': (0xfffffe000a56e020, 0xfffffe000a56e0e4),
    'post_release_status': (0xfffffe000a56bc1c, 0xfffffe000a56bc78),
    'post_release_presence': (0xfffffe000a535844, 0xfffffe000a535888),
    'common_return': (0xfffffe000a52e4b0, 0xfffffe000a52e4e4),
}
ANCHORS = {
    0xfffffe000a51b9dc: ('mov', 'x8, #0'),
    0xfffffe000a51b9fc: ('ldr', 'w14, [x10, w9, sxtw]'),
    0xfffffe000a51bb00: ('stur', 'x13, [x29, #-0xb8]'),
    0xfffffe000a51bb6c: ('mul', 'w15, w13, w2'),
    0xfffffe000a51bb74: ('dup', 'v1.4s, w14'),
    0xfffffe000a51bb7c: ('ldr', 'q2, [x15, #0xf40]'),
    0xfffffe000a51bb84: ('ldr', 'q3, [x15, #0xf50]'),
    0xfffffe000a51bb8c: ('ldr', 'q4, [x15, #0xf60]'),
    0xfffffe000a51bb94: ('ldr', 'q5, [x15, #0xf70]'),
    0xfffffe000a51bc24: ('str', 'q6, [x15]'),
    0xfffffe000a51bc40: ('cmp', 'x8, #0x200'),
    0xfffffe000a51bc44: ('b.ne', '#0xfffffe000a51bb98'),
    0xfffffe000a51bc48: ('mov', 'w8, #0x3f'),
    0xfffffe000a51bc60: ('udiv', 'w16, w15, w8'),
    0xfffffe000a51bc64: ('msub', 'w15, w16, w8, w15'),
    0xfffffe000a51bc9c: ('cmp', 'x15, #2'),
    0xfffffe000a51bca0: ('b.gt', '#0xfffffe000a51bc54'),
    0xfffffe000a51bd44: ('str', 'x8, [x9, x21, lsl #3]'),
    0xfffffe000a51bd50: ('braa', 'x8, x17'),
    0xfffffe000a547fe8: ('add', 'x21, x21, #1'),
    0xfffffe000a548010: ('braa', 'x8, x17'),
    0xfffffe000a56e9e4: ('blraa', 'x8, x17'),
    0xfffffe000a56e9f8: ('braa', 'x8, x17'),
}


def pack(values):
    return z3.Concat(*reversed(values))


def lanes(value, width):
    return [z3.Extract(j + width - 1, j, value) for j in range(0, 128, width)]


def vector_body(kernel, offset, base, key, original):
    """Interpret every original instruction in the 16-byte rewrite body.

    A64 scalar address arithmetic plus 4s arithmetic, 16b EOR3/TBL/MUL and
    fixed image loads. Unsupported operands/instructions fail immediately.
    TBL indices are read from source-loaded vectors, never from a guessed map.
    """
    constants = {j: struct.unpack('<4I', kernel.read(0xfffffe0007920f40 + 16 * j, 16))
                 for j in range(4)}
    assert list(constants.values()) == [tuple(range(j, j + 4)) for j in (12, 8, 4, 0)]
    vectors = {1: pack([key] * 4)}
    for register, start in [(2, 12), (3, 8), (4, 4), (5, 0)]:
        vectors[register] = pack([resize(offset, 32) + n for n in range(start, start + 4)])
    scalars = {'x13': base, 'x8': offset}
    reads, stores = [], []
    count = 0
    for ins in kernel.cs.disasm(kernel.read(0xfffffe000a51bb98, 0xa8), 0xfffffe000a51bb98):
        m, op = ins.mnemonic, ins.op_str
        count += 1
        if m == 'adrp':
            register, address = op.split(', #')
            scalars[register] = int(address, 16)
        elif m == 'ldr':
            match = re.fullmatch(r'q(\d+), \[(x\d+)(?:, #(0x[0-9a-f]+))?\]', op)
            assert match, op
            destination, register, displacement = match.groups()
            address = scalars[register] + (int(displacement, 16) if displacement else 0)
            if isinstance(address, int):
                raw = kernel.read(address, 16)
                assert IMAGE.read(address, 16) == raw
                value = z3.BitVecVal(int.from_bytes(raw, 'little'), 128)
                reads.append({'pc': hex(ins.address), 'address': hex(address), 'bytes_hex': raw.hex()})
            else:
                assert ins.address == 0xfffffe000a51bb9c
                value = original
                reads.append({'pc': hex(ins.address), 'address_expression': z3.simplify(address).sexpr(), 'extent_B': 16})
            vectors[int(destination)] = value
        elif m == 'tbl':
            registers = list(map(int, re.findall(r'v(\d+)', op)))
            destination, *tables, index_register = registers
            indices = [z3.simplify(v).as_long() for v in lanes(vectors[index_register], 8)]
            source = sum([lanes(vectors[r], 8) for r in tables], [])
            vectors[destination] = pack([source[j] if j < len(source) else z3.BitVecVal(0, 8) for j in indices])
        elif m == 'eor3':
            destination, a, b, c = map(int, re.findall(r'v(\d+)', op))
            vectors[destination] = vectors[a] ^ vectors[b] ^ vectors[c]
        elif m == 'movi':
            match = re.fullmatch(r'v(\d+)\.(16b|4s), #(0x[0-9a-f]+)', op)
            assert match, op
            destination, shape, literal = match.groups()
            width = 8 if shape == '16b' else 32
            vectors[int(destination)] = pack([z3.BitVecVal(int(literal, 16), width)] * (128 // width))
        elif m in ('add', 'sub', 'mul') and op.startswith('v'):
            registers = list(map(int, re.findall(r'v(\d+)', op)))
            assert len(registers) == 3 and ('.4s' in op or '.16b' in op)
            destination, a, b = registers
            width = 32 if '.4s' in op else 8
            result = []
            for left, right in zip(lanes(vectors[a], width), lanes(vectors[b], width)):
                result.append(left + right if m == 'add' else left - right if m == 'sub' else left * right)
            vectors[destination] = pack(result)
        elif m == 'add' and op.startswith('x'):
            destination, left, right = op.split(', ')
            scalars[destination] = scalars[left] + (int(right[1:], 16) if right.startswith('#') else scalars[right])
        elif m == 'str':
            assert op == 'q6, [x15]'
            stores.append({'pc': hex(ins.address), 'address': scalars['x15'], 'value': vectors[6], 'extent_B': 16})
        else:
            raise AssertionError((hex(ins.address), m, op))
    assert len(stores) == 1 and len(reads) == 6
    return stores[0], reads, scalars, vectors, count


def frame_roots(kernel):
    result, checked = [], set()
    offsets = [0x10, 0x78, 0x80, 0x128, 0x130, 0x138, 0x140, 0x148, 0x150, 0x158, 0x1a0]
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
            width = 4 if offset == 0x1a0 else 8
            epochs = [state[frame + offset + j] for j in range(width)]
            producers = []
            for write in {v[1]['source_visit_index']: v[1] for v in epochs}.values():
                visit = case['source_visits'][write['source_visit_index']]
                assert visit['pc'] == write['pc'] and visit['bytes_hex'] == kernel.read(int(write['pc'], 16), 4).hex()
                checked.add(write['pc'])
                producers.append({'pc': write['pc'], 'bytes_hex': visit['bytes_hex']})
            fields[hex(offset)] = {'value': hex(int.from_bytes(bytes(v[0] for v in epochs), 'little')),
                                  'width_B': width, 'producers': producers}
        get = lambda o: int(fields[hex(o)]['value'], 16)
        w, a = int(case['workspace_pointer'], 16), int(case['actual_auxiliary']['address'], 16)
        assert [get(o) for o in offsets] == [0xfffffe000ccc78c0, FLAG, SEED_CELL,
            w + 0xa8, w + 0x4000, w + 0x1c0, a + 0x1000, a + 0xc0,
            0xfffffe00079174c0, 0xfffffe0007919db0, 0x3be]
        result.append({'prior_case_index': index, 'fields': fields, 'new_target_execution': False})
    assert len(result) == 13
    return result, len(checked)


def prove(kernel, capture):
    queries, counts = {}, {}
    f = 0x51000000
    p, vbase, index = z3.BitVecs('element64 vector_base64 outer_index64', 64)
    seed, key, original_word, quotient = z3.BitVecs('seed_word32 element_key32 shuffle_word32 quotient32', 32)
    first, second = z3.BitVecs('first_word64 second_word64', 64)
    r = z3.BitVec('completion_record64', 64)

    def run(name, start, end, seeds, cells=()):
        obj = Lift(part(capture, name, start, end))
        for register, value in seeds.items():
            obj.seed(register, value)
        for address, width, value in cells:
            mem(obj, address, width, value)
        obj.run(name)
        counts[name] = obj.count
        return obj

    obj = run('selected_seed_word', 0xfffffe000a51b9dc, 0xfffffe000a51ba08,
              {'sp': f, 'x29': f + 0x300}, [(f + 0x78, 8, FLAG), (f + 0x80, 8, SEED_CELL),
              (FLAG, 4, 255), (SEED_CELL, 8, SEEDS), (SEEDS + 28, 4, seed)])
    queries['selected_seed_word'] = z3.Or(obj.read('w14') != seed, obj.read('w15') != seed * 0x30c5e1f)
    obj = run('element_key', 0xfffffe000a51bb68, 0xfffffe000a51bb74,
              {'x29': f + 0x300, 'w2': 0x30c5e1f, 'w14': seed}, [(f + 0x248, 8, p)])
    queries['element_key'] = obj.read('w14') != (resize(p, 32) * 0x30c5e1f) ^ seed
    obj = run('footer_phase_carried_through_transform', 0xfffffe000a51bae8, 0xfffffe000a51bb00, {'w20': 0x82c})
    queries['footer_phase_carried_through_transform'] = obj.read('w3') != 0x4f7
    original = z3.BitVec('original_block128', 128)
    offset = 16 * index
    store, reads, scalars, vectors, count = vector_body(kernel, offset, p, key, original)
    counts['SIMD_rewrite_body'] = count
    expected = []
    for j, byte in enumerate(lanes(original, 8)):
        n = resize(offset + j, 32)
        expected.append((byte ^ resize(key, 8) ^ resize((n + key) * (n - key), 8)) * 0x93)
    queries['source_SIMD_byte_relation'] = z3.Or(store['value'] != pack(expected),
        store['address'] != p + offset, scalars['x8'] != offset + 16)
    queries['source_SIMD_coordinate_step'] = z3.Or(*[
        vectors[register] != pack([resize(offset + 16 + n, 32) for n in range(start, start + 4)])
        for register, start in [(2, 12), (3, 8), (4, 4), (5, 0)]])
    queries['SIMD_32_block_extent'] = z3.And(z3.ULT(index, 32),
        z3.Or(z3.UGT(offset + 16, 512), (offset + 16 == 512) != (index == 31)))
    byte = z3.BitVec('byte8', 8)
    queries['byte_multiplier_inverse'] = (byte * 0x93) * 0x9b != byte
    n = z3.BitVec('byte_coordinate32', 32)
    mask = lambda j: resize(key, 8) ^ resize((j + key) * (j - key), 8)
    queries['byte_relation_period256'] = mask(n + 256) != mask(n)
    queries['byte_relation_roundtrip'] = (((byte ^ mask(n)) * 0x93) * 0x9b) ^ mask(n) != byte
    obj = run('shuffle_numerator', 0xfffffe000a51bc54, 0xfffffe000a51bc60,
              {'w14': key, 'x8': index, 'w1': 0x1000193})
    numerator = (key + resize(index, 32)) ^ key
    queries['shuffle_numerator'] = obj.read('w15') != numerator * 0x1000193
    # UDIV + MSUB implements unsigned remainder. The range proof is over the
    # corresponding mathematical unsigned integers, not an assumed byte index.
    ni, ii = z3.Ints('unsigned_numerator unsigned_divisor')
    queries['shuffle_remainder_range'] = z3.And(ni >= 0, ni < 2 ** 32, ii >= 1, ii <= 63,
                                               z3.Or(ni % ii < 0, ni % ii >= ii))
    remainder = original_word - quotient * resize(index, 32)
    at_i = p + (index << 3)
    at_j = p + (resize(remainder, 64) << 3)
    obj = run('shuffle_distinct_cells', 0xfffffe000a51bc64, 0xfffffe000a51bc94,
              {'x13': p, 'x8': index, 'w15': original_word, 'w16': quotient},
              [(at_i, 8, first), (at_j, 8, second)])
    queries['shuffle_distinct_cells'] = z3.Or(cell(obj, at_i, 8) != second, cell(obj, at_j, 8) != first)
    obj = run('shuffle_counter', 0xfffffe000a51bc94, 0xfffffe000a51bc9c, {'x8': index})
    queries['shuffle_counter'] = z3.And(z3.UGE(index, 1), z3.ULE(index, 63),
        z3.Or(obj.read('x8') != index - 1, (obj.read('x15') > 2) != (index > 1)))
    obj = run('transformed_slot_publication', 0xfffffe000a51bd34, 0xfffffe000a51bd48,
              {'x29': f + 0x300, 'sp': f, 'x21': index},
              [(f + 0x240, 8, first), (f + 0x248, 8, second), (f + 0x88, 8, VECTOR), (VECTOR, 8, vbase)])
    queries['transformed_slot_publication'] = z3.Or(obj.stores[0]['address'] != vbase + 8 * index,
                                                  obj.stores[0]['value'] != first ^ second)
    obj = run('outer_loop_footer', 0xfffffe000a547fcc, 0xfffffe000a548008, {'w3': 0x4f7, 'x21': index})
    queries['outer_loop_footer'] = z3.And(z3.ULT(index, 1024), z3.Or(
        obj.read('x21') != index + 1, obj.read('w19') != 0x7fe, obj.read('w26') != 0x3be,
        obj.read('w8') != z3.If(index == 1023, z3.BitVecVal(0x521, 32), z3.BitVecVal(0x4f7, 32))))
    obj = run('completion_key_basis', 0xfffffe000a56e920, 0xfffffe000a56e960,
              {'sp': f}, [(f + 0x128, 8, r)])
    queries['completion_key_basis'] = obj.read('w9') != resize(r ^ 0xddd14603, 32)
    obj = run('completion_record', 0xfffffe000a56e960, 0xfffffe000a56e988,
              {'sp': f, 'x0': r, 'w26': 0x3be, 'w8': 0x1c8ff40a, 'w9': resize(r ^ 0xddd14603, 32)},
              [(f + 0x130, 8, f + 0x4000), (f + 0x138, 8, f + 0x1c0),
               (f + 0x140, 8, f + 0x9000), (f + 0x148, 8, f + 0x80c0)])
    qkey = resize((r ^ 0xddd14603) * 0xb90ee68b, 32)
    queries['completion_record'] = z3.Or(cell(obj, r, 4) ^ qkey != 0x1c8ff7c8,
        cell(obj, r + 0x20, 8) != f + 0x1c0, cell(obj, r + 0x28, 8) != f + 0x4000,
        cell(obj, r + 8, 8) != f + 0x80c0, cell(obj, r + 0x10, 8) != f + 0x9000)
    obj = run('completion_return_phase', 0xfffffe000a56e9cc, 0xfffffe000a56e9d0, {'w26': 0x3be})
    queries['completion_return_phase'] = obj.read('w19') != 0x15f
    obj = run('completion_success_word', 0xfffffe000a56e9ec, 0xfffffe000a56e9f4, {})
    queries['completion_success_word'] = obj.read('w9') != 0x5e561849
    obj = run('completion_success_scratch', 0xfffffe000a52975c, 0xfffffe000a529768,
              {'w26': 0x3be, 'x22': r, 'w9': 0x5e561849})
    queries['completion_success_scratch'] = z3.Or(cell(obj, r + 0x100, 4) != 0x5e561849,
                                                  obj.read('w8') != 0x14, obj.read('w9') != 0x579)
    obj = run('post_release_success_join', 0xfffffe000a56bc20, 0xfffffe000a56bc50,
              {'sp': f, 'x22': r}, [(f + 0x1a0, 4, 0x3be), (r + 0x100, 4, 0x5e561849)])
    queries['post_release_success_join'] = z3.Or(obj.read('w8') != 0x5e561849,
                                               obj.read('w9') != 0x1fb, obj.read('w10') != 0x458)
    presence = z3.BitVec('post_release_presence64', 64)
    obj = run('post_release_presence_gate', 0xfffffe000a535848, 0xfffffe000a535874,
              {'sp': f, 'w9': 0x1fb}, [(f + 0x10, 8, 0xfffffe000ccc78c0), (0xfffffe000ccc78c0, 8, presence)])
    queries['post_release_presence_gate'] = obj.read('w8') != z3.If(
        presence == 0, z3.BitVecVal(0x74c, 32), z3.BitVecVal(0x1fb, 32))
    proofs = {}
    for name, mismatch in queries.items():
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(mismatch)
        outcome = str(solver.check())
        assert outcome == 'unsat', (name, outcome)
        proofs[name] = {'query': solver.to_smt2(), 'result': outcome}
    return proofs, counts, reads


def build():
    kernel = Kernel()
    spans = []
    for label, bounds in SPANS.items():
        row = span(kernel, *bounds)
        row['bytes_hex'] = row.pop('bytes')
        row['label'] = label
        spans.append(row)
    instructions = {int(i['ea'], 16): (i['mnemonic'], i['operands']) for s in spans for i in s['instructions']}
    assert all(instructions[pc] == expected for pc, expected in ANCHORS.items())
    # The transform calls no callee and preserves the registers required by the
    # next element-allocation bank. This is a static explicit/implicit-write audit.
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    protected = {'x20', 'x21', 'x23', 'x24', 'x27', 'x28', 'sp'}
    written = set()
    prefix_counter_writes, phase_writes = [], []
    for ins in cs.disasm(kernel.read(0xfffffe000a51b9d8, 0x37c), 0xfffffe000a51b9d8):
        assert ins.mnemonic not in ('bl', 'blr', 'blraa', 'blrab')
        destinations = {re.sub(r'^w', 'x', ins.reg_name(r)) for r in ins.regs_access()[1]}
        written.update(destinations)
        if 'x8' in destinations and ins.address < 0xfffffe000a51bb98:
            prefix_counter_writes.append(hex(ins.address))
        if 'x3' in destinations:
            phase_writes.append(hex(ins.address))
    assert not protected & written
    assert prefix_counter_writes == ['0xfffffe000a51b9dc']
    assert phase_writes == ['0xfffffe000a51bafc']
    banks = {}
    for name, roots, key, add, target, diversity in [
        ('completion_helper', (0xfffffe00079174c0, 0xfffffe0007919db0), 0x50, 0x951, 0xfffffe000a52f728, 0x6e7d),
        ('release_adapter', (0xfffffe0007920c10, 0xfffffe00079170c0), 0xaa, 0x96b, 0xfffffe000a551f38, 0x84cc),
    ]:
        row = selected(*roots, key, add, base=TABLE)
        original = pointer(kernel, int(row['slot'], 16))
        assert row['target'] == original['target'] == hex(target)
        assert original['authenticated'] and int(original['diversity'], 16) == diversity
        assert all(IMAGE.read(a, 256) == kernel.read(a, 256) for a in roots)
        banks[name] = {**row, 'original_pointer': original, 'bank_bytes_hex': [kernel.read(a, 256).hex() for a in roots]}
    slots = {}
    for index, target, diversity in [
        (0x4f7, 0xfffffe000a5341f0, 0xb064), (0x521, 0xfffffe000a56e91c, 0xb064),
        (0x82c, 0xfffffe000a547fc8, 0xf019), (0x15f, 0xfffffe000a529758, 0x6a52),
        (0x579, 0xfffffe000a56e020, 0x83c6), (0x14, 0xfffffe000a56bc1c, 0xc38e),
        (0x458, 0xfffffe000a535844, 0x62dc), (0x1fb, 0xfffffe000a52e4b0, 0x2984),
        (0x74c, 0xfffffe000a5268dc, 0x2984),
    ]:
        row = pointer(kernel, TABLE + 8 * index)
        assert row['target'] == hex(target) and row['authenticated'] and int(row['diversity'], 16) == diversity
        slots[hex(index)] = row
    frames, producer_count = frame_roots(kernel)
    proofs, counts, reads = prove(kernel, {'spans': spans})
    cpath = ROOT.parent / 'com.apple.driver.FairPlayIOKit.c'
    lines = cpath.read_text().splitlines(keepends=True)
    references = [{'path': cpath.name, 'sha256': sha(cpath), 'first_line': a, 'last_line': z,
                   'text': ''.join(lines[a - 1:z])} for a, z in [
                       (29791, 30081), (66904, 66921), (53708, 53733), (95747, 95836)]]
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'kernel_collection_sha256': kernel.sha256,
        'normalized_image_sha256': sha(SOURCE), 'spans': spans, 'banks': banks, 'control_slots': slots,
        'retained_frames': frames, 'proofs': proofs, 'source_lift_counts': counts,
        'SIMD_source_reads': reads, 'source_register_write_audit': {'written': sorted(written), 'preserved': sorted(protected),
            'prefix_counter_writes': prefix_counter_writes, 'footer_phase_writes': phase_writes},
        'supplied_reference_excerpts': references, 'solver_version': z3.get_version_string(),
        'selected_contract': {'element_extent_B': 512, 'SIMD_iterations': 32, 'SIMD_store_B_per_iteration': 16,
            'shuffle_iterations': 63, 'shuffle_qword_count': 64, 'outer_iterations': 1024,
            'conditional_element_declared_total_B': 524288, 'vector_declared_B': 8192,
            'conditional_combined_declared_B': 532480, 'seed_word_index': 7,
            'element_key_factor32': '0x30c5e1f', 'byte_factor8': '0x93', 'byte_inverse8': '0x9b',
            'completion_helper_target': '0xfffffe000a52f728', 'completion_parent_phase32': '0x1c8ff7c8',
            'post_helper_raw_status32': '0x5e561849', 'pointer_codec_fully_proved': False,
            'completion_helper_semantics_known': False, 'native_population_observed': False},
        'dependencies': {name: sha(ROOT / name) for name in [
            'kernel_native_reader.py', 'kext_port_tools.py', 'lskd_values_symbolic.py',
            'recover_aes_cleanup_epoch.py', 'recover_kext_cold_init.py',
            'verify_daemon_reader_record_payloads_publication.py', 'lskd_handlers_profiles.json',
            'lskd_start_lock_flow_checks.json', 'lskd_vector_origin_checks.json', 'lskd_continuations_contracts.json']},
        'verified_counts': {'kext_spans': len(spans), 'instructions': len(instructions), 'code_B': 4 * len(instructions),
            'operand_anchors': len(ANCHORS), 'banks': len(banks), 'bank_inputs': 256 * len(banks),
            'control_slots': len(slots), 'retained_frames': len(frames), 'fields_per_frame': 11,
            'original_frame_producer_PCs': producer_count, 'queries_unsat': len(proofs),
            'source_lifted_instances': sum(counts.values()), 'SIMD_body_instructions': counts['SIMD_rewrite_body']},
        'new_target_execution': False, 'new_IDA_access': False, 'native_epoch_matched': False,
        'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    result = build()
    path = ROOT / 'lskd_element_population_checks.json'
    if args.verify:
        assert json.loads(read(path)) == result
    else:
        path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['verified_counts']))
