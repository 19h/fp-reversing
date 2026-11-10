#!/usr/bin/env python3
"""Verify source edges, flag gates and bounds for the backing zero check."""
import json
import shutil
import subprocess
from collections import deque

from recover_mixed_data_backing import ADDRESSES, DEPS, FLAGS, HEAP, P, ROOT, SCOPE, TAG, ZONES, build
from verify_daemon_reader_record_payloads_publication import read, sha

SOLVER = shutil.which('z3')
assert SOLVER


def index(source):
    return {int(row['ea'], 16): (row['mnemonic'], row['operands'])
            for f in source['functions'].values() for row in f['instructions']}


def source_gate(instructions, pc, flag):
    mnemonic, operands = instructions[pc]
    reg, bit, target = operands.split(', ')
    assert mnemonic in ('tbz', 'tbnz') and reg in ('w2', 'w28', 'w22', 'w8')
    is_set = bool(flag & (1 << int(bit[1:], 0)))
    return int(target[1:], 0) if is_set == (mnemonic == 'tbnz') else pc + 4


def graph(function, fixed, checked_edge, null_edge, terminals, allowed_tail=None):
    """Follow source edges with calls abstracted as returning unless terminal."""
    start, end = (int(function[key], 16) for key in ('start', 'end'))
    rows = {int(r['ea'], 16): (r['mnemonic'], r['operands'])
            for r in function['instructions']}
    visited = set()
    edges = set()
    outcomes = set()
    pending = deque([(start, 'pending')])
    while pending:
        pc, state = pending.popleft()
        if (pc, state) in visited:
            continue
        visited.add((pc, state))
        if pc == allowed_tail:
            outcomes.add(('tail', hex(pc), state))
            continue
        assert start <= pc < end, hex(pc)
        op, operands = rows[pc]
        if op in ('ret', 'retab'):
            outcomes.add(('return', hex(pc), state))
            continue
        if pc in terminals:
            assert op == 'bl'
            outcomes.add(('diagnostic', hex(pc), state))
            continue
        if pc in fixed:
            successors = [fixed[pc]]
        elif op == 'b':
            successors = [int(operands[1:], 0)]
        elif op.startswith('b.') or op in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            successors = [pc + 4, int(operands.split(', ')[-1][1:], 0)]
        else:
            assert op not in ('br', 'braa', 'brab', 'blr', 'blraa', 'blrab', 'udf'), (hex(pc), op)
            successors = [pc + 4]
        for dst in successors:
            next_state = 'checked' if (pc, dst) == checked_edge else state
            if (pc, dst) == null_edge:
                next_state = 'null'
            edges.add((hex(pc), state, hex(dst), next_state))
            pending.append((dst, next_state))
    assert all(kind != 'return' or state in ('checked', 'null') for kind, _, state in outcomes)
    return {'nodes': len(visited), 'edges': sorted(edges), 'outcomes': sorted(outcomes)}


def certificates(source):
    instructions = index(source)

    def expect(pc, mnemonic, operands):
        assert instructions[pc] == (mnemonic, operands), (hex(pc), instructions[pc])

    a = ADDRESSES['wrapper']
    for offset, mnemonic, operands in [
        (0x18, 'tbnz', 'w0, #0, #0xfffffe000bcfe5e0'),
        (0x28, 'and', 'x9, x0, #0xfffffffffffffffe'),
        (0x2c, 'ldr', 'w10, [x9, #0x48]'),
        (0x38, 'adrp', 'x11, #0xfffffe0007f36000'),
        (0x3c, 'add', 'x11, x11, #0x938'),
        (0x40, 'tst', 'w10, #0x8000'),
        (0x44, 'csel', 'x8, x11, x8, eq'),
        (0x50, 'tst', 'w10, #8'),
        (0x54, 'csel', 'x0, x8, x11, eq'),
        (0x58, 'ldr', 'x8, [x9, #8]'),
        (0x60, 'ldrh', 'w9, [x9, #0x20]'),
        (0x64, 'ldrh', 'w10, [x0, #0x16]'),
        (0x6c, 'csel', 'w9, w10, w9, eq'),
        (0x9c, 'orr', 'w2, w2, #0x40'),
        (0xa8, 'add', 'x10, x1, #0x1f'),
        (0xac, 'and', 'x10, x10, #0xffffffffffffffe0'),
        (0xb0, 'tst', 'w2, #0x100'),
        (0xb4, 'csel', 'x10, x1, x10, eq'),
        (0xbc, 'b.hi', '#0xfffffe000bcfe788'),
        (0xc0, 'sub', 'w11, w10, #1'),
        (0xc4, 'clz', 'w12, w11'),
        (0xc8, 'mov', 'w13, #0x1e'),
        (0xcc, 'sub', 'w13, w13, w12'),
        (0xd0, 'lsr', 'w11, w11, w13'),
        (0xd4, 'sub', 'w11, w11, w12, lsl #1'),
        (0xd8, 'add', 'w11, w9, w11'),
        (0xdc, 'add', 'w11, w11, #0x34'),
        (0xec, 'csel', 'w9, w11, w9, hi'),
        (0xf0, 'and', 'x9, x9, #0xffff'),
        (0xf4, 'mov', 'w10, #0xc0'),
        (0xf8, 'adrp', 'x11, #0xfffffe000caeb000'),
        (0xfc, 'add', 'x11, x11, #0x480'),
        (0x100, 'umaddl', 'x19, w9, w10, x11'),
        (0x11c, 'mov', 'x21, x2'),
        (0x120, 'bl', '#0xfffffe000bd75c64'),
        (0x124, 'mov', 'x2, x0'),
        (0x130, 'tst', 'w21, #0x300'),
        (0x134, 'csel', 'x0, x20, x1, eq'),
        (0x138, 'add', 'x9, x1, x2'),
        (0x158, 'ccmp', 'x1, x10, #4, eq'),
        (0x178, 'tbz', 'w12, #0xa, #0xfffffe000bcfe760'),
        (0x17c, 'sub', 'x10, x1, x10'),
        (0x190, 'add', 'x9, x2, x10'),
        (0x1a4, 'mov', 'x2, x9'),
        (0x1bc, 'mov', 'x0, x2'),
    ]:
        expect(a + offset, mnemonic, operands)

    for pc, mnemonic, operands in [
        (0xfffffe000c537410, 'adrp', 'x8, #0xfffffe0007f94000'),
        (0xfffffe000c537414, 'add', 'x8, x8, #0xf98'),
        (0xfffffe000c53741c, 'orr', 'x0, x8, #1'),
        (0xfffffe000c537424, 'mov', 'w2, #0x1004'),
        (0xfffffe000c537428, 'movk', 'w2, #3, lsl #16'),
        (0xfffffe000c537430, 'bl', '#0xfffffe000bcfe5b8'),
        (0xfffffe000c53743c, 'str', 'x8, [x20, #0x10]'),
        (0xfffffe000c537444, 'str', 'x19, [x0, #0x20]'),
        (0xfffffe000c5370f0, 'ldr', 'x20, [x8, #0x10]'),
        (0xfffffe000c53713c, 'ldrb', 'w8, [x20, #0x2d]'),
        (0xfffffe000c537140, 'and', 'w8, w8, #0xfc'),
        (0xfffffe000c537144, 'strb', 'w8, [x20, #0x2d]'),
        (0xfffffe000bd75cb8, 'ldrh', 'w19, [x0, #0x34]'),
        (0xfffffe000bd75ce0, 'ldr', 'x20, [x9, x8, lsl #3]'),
        (0xfffffe000bd75d14, 'mov', 'x0, x20'),
        (0xfffffe000bd75d18, 'mov', 'x1, x19'),
        (0xfffffe000bd75d1c, 'bl', '#0xfffffe000bc9d9c0'),
        (0xfffffe000bd75d20, 'cbnz', 'x0, #0xfffffe000bd75e10'),
        (0xfffffe000bd75d64, 'mov', 'x0, x20'),
        (0xfffffe000bd75d68, 'mov', 'x1, x19'),
        (0xfffffe000bd75e0c, 'b', '#0xfffffe000bd76394'),
        (0xfffffe000c633db4, 'bl', '#0xfffffe000c62a2b0'),
        (0xfffffe000c633970, 'bl', '#0xfffffe000c62a2b0'),
        (0xfffffe000bd76408, 'mov', 'x28, x2'),
        (0xfffffe000bd76718, 'ldrh', 'w24, [x19, #0x34]'),
        (0xfffffe000bd7674c, 'mov', 'x0, x25'),
        (0xfffffe000bd76750, 'mov', 'x1, x24'),
        (0xfffffe000bd76754, 'bl', '#0xfffffe000bc9d9c0'),
        (0xfffffe000bd76758, 'cbnz', 'x0, #0xfffffe000bd76974'),
        (0xfffffe000bd767a4, 'mov', 'x0, x25'),
        (0xfffffe000bd767a8, 'mov', 'x1, x24'),
        (0xfffffe000bd769c4, 'mov', 'x25, #0'),
        (0xfffffe000bd769c8, 'mov', 'x24, #0'),
    ]:
        expect(pc, mnemonic, operands)

    flag = 0x31004
    cache_gates = (0xfffffe000bd75d0c, 0xfffffe000bd75d24, 0xfffffe000bd75db8)
    fallback_gates = (0xfffffe000bd76748, 0xfffffe000bd7675c)
    for pc in cache_gates + fallback_gates:
        assert source_gate(instructions, pc, flag) == source_gate(instructions, pc, flag | 0x40)

    # Cache calls that can return preserve the flags explicitly across the call.
    # Fallback saves X2 before its retry calls and X28 across its element call.
    for pc, mnemonic, operands in [
        (0xfffffe000bd75dac, 'mov', 'x22, x2'),
        (0xfffffe000bd75db4, 'mov', 'x2, x22'),
        (0xfffffe000bd75ddc, 'mov', 'x20, x2'),
        (0xfffffe000bd75de8, 'mov', 'x2, x20'),
        (0xfffffe000bd767cc, 'mov', 'x20, x2'),
        (0xfffffe000bd767e0, 'mov', 'x2, x20'),
        (0xfffffe000bd76830, 'mov', 'x20, x2'),
        (0xfffffe000bd76854, 'mov', 'x20, x2'),
        (0xfffffe000bd7686c, 'mov', 'x2, x20'),
        (0xfffffe000bd768a0, 'mov', 'x20, x2'),
        (0xfffffe000bd768b8, 'mov', 'x2, x20'),
    ]:
        expect(pc, mnemonic, operands)

    cache = graph(source['functions']['cache'],
                  {pc: source_gate(instructions, pc, flag) for pc in cache_gates},
                  (0xfffffe000bd75d20, 0xfffffe000bd75d24), None,
                  {0xfffffe000bd75da8, 0xfffffe000bd75dcc, 0xfffffe000bd75e1c},
                  ADDRESSES['fallback'])
    fallback = graph(source['functions']['fallback'],
                     {pc: source_gate(instructions, pc, flag) for pc in fallback_gates},
                     (0xfffffe000bd76758, 0xfffffe000bd7675c),
                     (0xfffffe000bd769bc, 0xfffffe000bd769c0),
                     {0xfffffe000bd7693c, 0xfffffe000bd76960, 0xfffffe000bd76970,
                      0xfffffe000bd76990, 0xfffffe000bd769a0, 0xfffffe000bd769d4})
    assert ('return', '0xfffffe000bd75d7c', 'checked') in cache['outcomes']
    assert ('return', '0xfffffe000bd767c8', 'checked') in fallback['outcomes']
    assert ('return', '0xfffffe000bd767c8', 'null') in fallback['outcomes']

    queries = prove_arithmetic(source)
    semantics = {
        'request_bytes': 48,
        'request_flags': hex(flag),
        'selected_flag_values': [hex(flag), hex(flag | 0x40)],
        'tagged_view': hex(TAG),
        'selected_heap_under_source_flags': hex(HEAP),
        'zone_base': hex(ZONES),
        'zone_index_bias_delta': 2,
        'cache': cache,
        'fallback': fallback,
        'conditional_source_backing_zero_check_proved': True,
        'native_element_extent_observed': False,
        'native_allocation_or_transaction_proved': False,
        'Mach_port_emissions': 0,
    }
    return queries, semantics


def bv(value, width=64):
    return '(_ bv' + str(value % (1 << width)) + ' ' + str(width) + ')'


def prove_arithmetic(source):
    data = bytes.fromhex(source['source_data']['tagged_view_prefix'])
    descriptor_flags = int.from_bytes(data[0x48:0x4c], 'little')
    proofs = []

    def prove(name, declarations, assumptions, counterexample):
        query = '(set-option :timeout 45000)\n(set-logic QF_BV)\n'
        query += ''.join(f'(declare-const {var} (_ BitVec {width}))\n'
                         for var, width in declarations.items())
        query += ''.join(f'(assert {term})\n' for term in [*assumptions, counterexample])
        query += '(check-sat)\n'
        result = subprocess.run([SOLVER, '-in'], input=query, text=True,
                                capture_output=True, timeout=50)
        assert (result.returncode, result.stdout.strip(), result.stderr) == (0, 'unsat', ''), (
            name, result.stdout, result.stderr)
        proofs.append({'name': name, 'query': query, 'result': 'unsat'})
        print(name, 'unsat', flush=True)

    flags = 0x31004
    prove('source_view_routes_to_ordinary_heap', {}, [], f'''
        (or (distinct (bvand {bv(TAG)} {bv(-2)}) {bv(TAG & ~1)})
            (distinct (bvand {bv(descriptor_flags, 32)} #x00008008) #x00000000))''')
    prove('optional_bit6_does_not_change_selected_size_and_check_gates', {'F': 32}, [
        f'(or (= F {bv(flags, 32)}) (= F {bv(flags | 0x40, 32)}))'],
        '(or (distinct (bvand F #x00006300) #x00000000)'
        ' (distinct (bvand F #x00000004) #x00000004))')
    prove('requested_48_uses_small_size_class_bias_plus_2', {'B': 16}, [], f'''
        (let ((N (ite (= (bvand {bv(flags, 32)} #x00000100) #x00000000)
                       {bv(48)} (bvand (bvadd {bv(48)} {bv(31)}) {bv(-32)}))))
          (let ((T (bvlshr ((_ extract 31 0) (bvsub N {bv(1)})) {bv(4, 32)})))
            (or (bvugt {bv(48)} {bv(32768)})
                (distinct (bvsub N {bv(1)}) {bv(47)})
                (distinct ((_ extract 15 0)
                    (bvadd (bvadd (bvsub T {bv(52, 32)}) ((_ zero_extend 16) B)) {bv(52, 32)}))
                    (bvadd B {bv(2, 16)})))))''')
    # For the 48-byte class, 47 has CLZ32=26 and the source shift is 30-26=4.
    assert (32 - (48 - 1).bit_length(), 30 - (32 - (48 - 1).bit_length())) == (26, 4)

    prove('scalar_or_zero_implies_each_loaded_word_zero',
          {f'W{i}': 64 for i in range(8)}, [
              '(= (bvor W0 W1 W2 W3 W4 W5 W6 W7) #x0000000000000000)'],
          '(or ' + ' '.join(f'(distinct W{i} {bv(0)})' for i in range(8)) + ')')
    # Scalar iteration covers each 8-byte word for aligned extents 48 and 56.
    scalar = [i['operands'] for i in source['functions']['nonzero_check']['instructions']
              if 0xfffffe000bc9da5c <= int(i['ea'], 16) <= 0xfffffe000bc9da80]
    assert scalar == [
        'x1, #0xfffffe000bc9da84', 'x3, #0', 'x2, [x0], #8', 'x3, x3, x2',
        'x1, x1, #8', '#0xfffffe000bc9da64', 'x3, x3', 'x0, ne',
        'x29, x30, [sp], #0x10', '',
    ]
    vector = [i for i in source['functions']['nonzero_check']['instructions']
              if 0xfffffe000bc9d9d4 <= int(i['ea'], 16) <= 0xfffffe000bc9da50]
    assert [i['mnemonic'] for i in vector] == [
        'mov', 'add', 'and', 'ldp', 'ldp', 'sub', 'sub', 'subs', 'b.ls',
        'ldp', 'ldp', 'orr', 'orr', 'orr', 'orr', 'add', 'subs', 'b.hi',
        'add', 'ldp', 'ldp', 'orr', 'orr', 'orr', 'orr', 'orr', 'orr', 'orr',
        'umaxv', 'umov', 'tst', 'cset',
    ]
    prove('vector_initial_alignment_and_tail_cover_element',
          {'E': 64, 'D': 64, 'C': 64}, [
              f'(bvuge E {bv(64)})', f'(bvule E {bv(65535)})',
              f'(bvuge D {bv(1)})', f'(bvule D {bv(64)})',
              '(bvuge C D)', '(bvule C E)', f'(bvule (bvsub E C) {bv(64)})'],
          f'''(or (bvugt D {bv(64)})
                  (bvugt (bvsub E {bv(64)}) C)
                  (distinct (bvadd C (bvsub (bvsub E C) {bv(64)})) (bvsub E {bv(64)})))''')
    prove('vector_middle_block_preserves_coverage',
          {'E': 64, 'C': 64, 'H': 64}, [
              f'(bvule E {bv(65535)})', '(bvule C E)', '(bvuge H C)',
              '(bvule H E)', f'(bvugt (bvsub E C) {bv(64)})'],
          f'(or (bvugt (bvadd C {bv(64)}) E) (bvugt C H))')
    prove('vector_max_zero_implies_every_byte_lane_zero',
          {f'B{i}': 8 for i in range(16)}, [
              '(= (bvor ' + ' '.join(f'B{i}' for i in range(16)) + ') #x00)'],
          '(or ' + ' '.join(f'(distinct B{i} #x00)' for i in range(16)) + ')')
    prove('return_span_is_inside_checked_element_in_both_rebase_cases',
          {'E': 64, 'O': 64, 'I': 64}, [
              f'(bvuge E {bv(48)})', f'(bvule E {bv(65535)})',
              f'(or (= O {bv(0)}) (= O (bvsub E {bv(48)})))',
              f'(bvult I {bv(48)})'],
          '(bvuge (bvadd O I) E)')
    # Offsets are rederived from the predecessor's verified store order.
    prior = json.loads(read(ROOT / 'dma_map_constraints_checks.json'))
    assert prior['semantics']['metadata_initialization_written_bytes'] == 38
    assert prior['verified_counts']['metadata_bytes_fully_defined_without_old_contents'] == 37
    assert prior['semantics']['metadata_initialization_unwritten_byte_offsets'] == list(range(24, 32)) + [46, 47]
    prove('preserved_state_bits_are_zero_when_source_byte_passed_check', {'OLD': 8},
          ['(= OLD #x00)'], '(distinct (bvand OLD #xfc) #x00)')
    return proofs


def verify(source):
    return source == build()


def alterations(source):
    from copy import deepcopy

    fresh = build()
    output = []
    for name, address in [
        ('changed_cache_gate', 0xfffffe000bd75d0c),
        ('changed_fallback_gate', 0xfffffe000bd76748),
        ('changed_extent_operand', 0xfffffe000bd76750),
        ('changed_helper_state_mask', 0xfffffe000c537140),
    ]:
        modified = deepcopy(source)
        row = next(row for f in modified['functions'].values() for row in f['instructions']
                   if int(row['ea'], 16) == address)
        row['operands'] = 'altered'
        assert modified != fresh
        output.append(name)
    return output


def main():
    source = json.loads(read(ROOT / (P + '_source.json')))
    assert verify(source)
    proofs, semantics = certificates(source)
    rejected = alterations(source)
    counts = dict(source['verified_source_counts'])
    counts.update(queries_unsat=len(proofs), rejected_alterations=len(rejected))
    for name in ('cache', 'fallback'):
        counts[name + '_graph_nodes'] = semantics[name]['nodes']
        counts[name + '_graph_edges'] = len(semantics[name]['edges'])
    result = {
        'generator_sha256': sha(__file__),
        'static_scope': SCOPE,
        'dependencies': {name: sha(ROOT / name) for name in [P + '_source.json', *DEPS]},
        'proofs': proofs,
        'semantics': semantics,
        'alterations': rejected,
        'verified_counts': counts,
        'solver': {'executable': 'z3', 'sha256': sha(SOLVER)},
        'all_checks_pass': True,
        'MixedData_backing_check_proved': True,
        'complete_operation_proved': False,
        **{flag: False for flag in FLAGS},
    }
    (ROOT / (P + '_checks.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(counts), flush=True)


if __name__ == '__main__':
    main()
