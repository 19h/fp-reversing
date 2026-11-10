#!/usr/bin/env python3
"""Validate the selected preparation count transitions and teardown contracts."""
import json
import shutil
import subprocess
from copy import deepcopy

from recover_descriptor_prepare_lifecycle import DEPS, FLAGS, P, ROOT, SCOPE, build
from verify_daemon_reader_record_payloads_publication import read, sha

SOLVER = shutil.which('z3')
assert SOLVER


def source_contract(source):
    instructions = {
        int(i['ea'], 16): f"{i['mnemonic']} {i['operands']}".strip()
        for f in [*source['functions'].values(), *source['kext_fragments'].values()]
        for i in f['instructions']
    }

    def expect(pc, *rows):
        for row in rows:
            assert instructions[pc] == row, (hex(pc), instructions[pc], row)
            pc += 4

    assert [(s['offset'], int(s['target'], 16), int(s['diversity'], 16))
            for s in source['nominal_slots']] == [
        (0x28, 0xfffffe000c4451d0, 0x3a87), (0xb0, 0xfffffe000c525288, 0xedc5),
        (0x148, 0xfffffe000c531be4, 0xf96b), (0x1e8, 0xfffffe000c5316b8, 0xba55),
        (0x218, 0xfffffe000c5353b4, 0xf5b3), (0x220, 0xfffffe000c534a2c, 0x9285),
    ]

    expect(0xfffffe000c5353cc, 'ldr w21, [x0, #0x20]', 'and w19, w21, #0xf0',
           'cmp w19, #0x20', 'b.ne #0xfffffe000c5353e4')
    expect(0xfffffe000c5353ec, 'tbnz w21, #0x12, #0xfffffe000c53543c')
    expect(0xfffffe000c53541c, 'ands w8, w1, #0x600', 'b.eq #0xfffffe000c53546c')
    expect(0xfffffe000c53546c, 'mov w8, #0xb0', 'and w8, w21, w8', 'cmp w8, #0x10',
           'b.eq #0xfffffe000c5354e8')
    expect(0xfffffe000c5354e8, 'tbnz w1, #8, #0xfffffe000c535504', 'mov x19, x0',
           'bl #0xfffffe000c535624', 'mov x8, x0', 'mov x0, x19',
           'cbnz w8, #0xfffffe000c5355d0', 'b #0xfffffe000c535484')
    expect(0xfffffe000c535484, 'ldr w8, [x0, #0x88]', 'add w9, w8, #1',
           'str w9, [x0, #0x88]', 'cbnz w8, #0xfffffe000c5354e0')
    expect(0xfffffe000c5354d4, 'mov x19, x0', 'bl #0xfffffe000c536070', 'mov x0, x19',
           'mov w8, #0', 'b #0xfffffe000c5355d0')

    expect(0xfffffe000c5316bc, 'ldr w8, [x0, #0x20]', 'and w0, w8, #7', 'ret')
    expect(0xfffffe000c53567c, 'movk x16, #0xba55, lsl #48', 'blraa x8, x16',
           'orr w24, w0, w24', 'ldr x8, [x19, #0x90]', 'ldr x9, [x8, #0x18]')
    expect(0xfffffe000c5356f0, 'strb w8, [x21, #0x2d]', 'ldr w10, [x19, #0x88]',
           'cbz w10, #0xfffffe000c535714', 'ldrb w8, [x19, #0x21]',
           'tst w8, #0x80', 'csinc w8, w9, wzr, ne', 'tbz w8, #0, #0xfffffe000c535768',
           'mov w0, #0', 'b #0xfffffe000c535ffc')
    expect(0xfffffe000c5356cc, 'csel w12, w12, w14, ne', 'csel w14, wzr, w9, ne',
           'csel w13, w13, wzr, ne', 'csel x15, xzr, x9, ne', 'cmp w8, #1',
           'csel w8, w10, w12, eq', 'csel w9, wzr, w14, eq',
           'csel w20, w11, w13, eq', 'csel x26, xzr, x15, eq')
    expect(0xfffffe000c535d68, 'ldr x28, [x21, #0x18]', 'adds x22, x28, #0x28')
    expect(0xfffffe000c535d84, 'ldr x2, [x21, #0x20]', 'cbz x1, #0xfffffe000c535d94',
           'cmp x22, x2', 'b.ls #0xfffffe000c535dc4')
    expect(0xfffffe000c535db0, 'bl #0xfffffe000bcff0b8', 'cbz x0, #0xfffffe000c535ea0',
           'mov x1, x0', 'str x0, [x21, #0x10]', 'str x22, [x21, #0x20]',
           'str x22, [x21, #0x18]')
    expect(0xfffffe000c535ddc, 'ldp q0, q1, [sp, #0x60]', 'stp q0, q1, [x8]',
           'ldr x9, [sp, #0x80]', 'str x9, [x8, #0x20]')
    expect(0xfffffe000c535910, 'str w20, [sp, #0x20]')
    expect(0xfffffe000c535e74, 'ldr w8, [sp, #0x20]', 'tbnz w8, #0, #0xfffffe000c53570c',
           'mov w0, #0', 'ldr w8, [x19, #0x20]', 'orr w8, w8, #0x8000',
           'str w8, [x19, #0x20]')

    expect(0xfffffe000c534a94, 'ands w8, w1, #0x600', 'b.eq #0xfffffe000c534af0',
           'orr w1, w8, #2', 'mov x20, x0', 'bl #0xfffffe000c534e5c')
    expect(0xfffffe000c534af0, 'ldr w8, [x0, #0x88]', 'cbz w8, #0xfffffe000c534dd4',
           'ldr x9, [x0, #0x90]', 'ldr x10, [x9, #0x18]', 'cbz x10, #0xfffffe000c534dd4',
           'ldr x20, [x9, #0x10]', 'cbz x20, #0xfffffe000c534dd4',
           'tbz w1, #6, #0xfffffe000c534b20')
    expect(0xfffffe000c534b74, 'sub w8, w8, #1', 'str w8, [x0, #0x88]',
           'tbnz w1, #7, #0xfffffe000c534b84', 'cbnz w8, #0xfffffe000c534dd4')
    expect(0xfffffe000c534b84, 'add x10, x20, #0x30', 'ldr w9, [x20, #0x28]',
           'lsl x11, x9, #3')
    expect(0xfffffe000c534bbc, 'sub x9, x12, x9, lsl #3', 'sub x9, x9, #0x30',
           'mov x10, #-0x3333333333333334', 'movk x10, #0xcccd',
           'umulh x9, x9, x10', 'lsr x25, x9, #5')
    expect(0xfffffe000c534c60, 'ldrh w8, [x0, #0x34]', 'cbnz w8, #0xfffffe000c534e40')
    expect(0xfffffe000c534d2c, 'add x8, x19, x19, lsl #2', 'lsl x8, x8, #3',
           'cmp x8, w8, sxtw', 'add x25, x22, w8, sxtw', 'add x16, x22, x8',
           'movk x16, #0x2bad, lsl #48', 'csel x25, x25, x16, eq',
           'ldr x8, [x25]', 'cbz x8, #0xfffffe000c534d20')
    expect(0xfffffe000c534d10, 'bl #0xfffffe000be2b964', 'ldr x0, [x25]',
           'bl #0xfffffe000bdfc368')
    expect(0xfffffe000c534d78, 'ldr x8, [x0, #0x90]', 'mov x22, x0', 'mov x0, x8',
           'mov w1, #0x30', 'bl #0xfffffe000c5352b8', 'str xzr, [x20, #0x20]',
           'ldr w8, [x22, #0x20]', 'and w8, w8, #0xffff7fff', 'mov x19, x22',
           'str w8, [x22, #0x20]')
    expect(0xfffffe000c5352d0, 'ldr x1, [x0, #0x10]', 'ldr x2, [x0, #0x20]',
           'cmp x1, #0', 'ccmp x19, x2, #2, ne', 'b.ls #0xfffffe000c535310')
    expect(0xfffffe000c535310, 'str x19, [x20, #0x18]', 'mov w0, #1')

    expect(0xfffffe000c537840, 'blraa x8, x16', 'ldr w8, [x19, #0x88]',
           'cbnz w8, #0xfffffe000c537820')
    expect(0xfffffe000c537ec4, 'mov x0, x19', 'mov w1, #0',
           'movk x16, #0xf5b3, lsl #48', 'blraa x8, x16', 'cbnz w0, #0xfffffe000c537df0')
    expect(0xfffffe000a5080dc, 'str x0, [x19, #0xb10]', 'cbz x0, #0xfffffe000a508134')
    expect(0xfffffe000a508100, 'mov w1, #0', 'movk x16, #0xf5b3, lsl #48',
           'blraa x8, x16', 'cbz w0, #0xfffffe000a50814c')
    expect(0xfffffe000a5085f8, 'ldr x0, [x19, #0xb10]', 'cbz x0, #0xfffffe000a50865c',
           'adrp x20, #0xfffffe000ccc7000', 'ldr x8, [x20, #0x848]',
           'cbz x8, #0xfffffe000a50863c')
    expect(0xfffffe000a508628, 'mov w1, #0', 'movk x16, #0x9285, lsl #48',
           'blraa x8, x16', 'str xzr, [x20, #0x848]', 'ldr x0, [x19, #0xb10]')
    expect(0xfffffe000a508654, 'blraa x8, x16', 'str xzr, [x19, #0xb10]')
    expect(0xfffffe000c525370, 'mov x0, x22', 'bl #0xfffffe000c538044')
    expect(0xfffffe000c538174, 'ldr w8, [x19, #0x88]', 'cbz w8, #0xfffffe000c5381a4')
    expect(0xfffffe000c538190, 'mov x0, x19', 'mov w1, #0',
           'movk x16, #0x9285, lsl #48', 'blraa x8, x16', 'b #0xfffffe000c538174')
    expect(0xfffffe000c5381a4, 'ldr x8, [x19, #0x10]', 'cbz x8, #0xfffffe000c5381e0',
           'ldr x8, [x8, #0x28]', 'cbz x8, #0xfffffe000c5381e0')
    expect(0xfffffe000c5381d0, 'mov x0, x19', 'mov w1, #0x200',
           'movk x16, #0x9285, lsl #48', 'blraa x8, x16',
           'ldr x0, [x19, #0x90]', 'cbz x0, #0xfffffe000c538208')
    expect(0xfffffe000c538200, 'blraa x8, x16', 'str xzr, [x19, #0x90]')
    return instructions


def certificates(source):
    source_contract(source)
    proofs = []
    definitions = """
(declare-const C (_ BitVec 32))
(declare-const F (_ BitVec 32))
(declare-const D (_ BitVec 32))
(declare-const S (_ BitVec 32))
(declare-const W (_ BitVec 32))
(declare-const USED (_ BitVec 64))
(declare-const CAP (_ BitVec 64))
(declare-const N (_ BitVec 64))
(declare-const ENTRY_COUNT (_ BitVec 64))
(define-fun PREPARE () (_ BitVec 32)
  (ite (= W #x00000000) (bvadd C #x00000001) C))
(define-fun COMPLETE () (_ BitVec 32)
  (ite (= C #x00000000) C (bvsub C #x00000001)))
(define-fun FINAL () Bool (and (distinct C #x00000000) (= COMPLETE #x00000000)))
(define-fun PREFIX () (_ BitVec 64)
  (bvadd #x0000000000000030 (bvshl N #x0000000000000003)))
"""

    def prove(name, premises, counterexample, prefix=definitions, logic='QF_BV'):
        query = '(set-option :timeout 45000)\n(set-logic ' + logic + ')\n' + prefix
        query += ''.join(f'(assert {item})\n' for item in [*premises, counterexample])
        query += '(check-sat)\n'
        r = subprocess.run([SOLVER, '-in'], input=query, text=True, capture_output=True, timeout=50)
        assert (r.returncode, r.stdout.strip(), r.stderr) == (0, 'unsat', ''), (
            name, r.stdout, r.stderr)
        proofs.append({'name': name, 'query': query, 'result': 'unsat'})
        print(name, 'unsat', flush=True)

    prove('type11b_and_argument_zero_select_virtual_wiring_path',
          ['(= F #x0000011b)', '(= D #x00000000)'],
          '(or (distinct (bvand F #x000000b0) #x00000010)'
          ' (distinct (bvand F #x00040000) #x00000000)'
          ' (distinct (bvand D #x00000700) #x00000000)'
          ' (distinct (bvand F #x00000007) #x00000003))')
    prove('effective_direction_three_selects_wire_success_without_setting_bit15',
          ['(= D #x00000003)'],
          '(let ((W13 (ite (= D #x00000002) #x00000000 #x00000001)))'
          ' (distinct (ite (= D #x00000001) #x00000001 W13) #x00000001))')
    prove('nonzero_prepare_count_and_clear_mode_bit_use_short_success',
          ['(distinct C #x00000000)', '(= (bvand F #x00008000) #x00000000)'],
          '(distinct (ite (distinct (bvand F #x00008000) #x00000000) S #x00000001)'
          ' #x00000001)')
    prove('wire_failure_skips_increment', ['(distinct W #x00000000)'],
          '(distinct PREPARE C)')
    prove('two_successful_prepares_increment_zero_to_two', ['(= C #x00000000)', '(= W #x00000000)'],
          '(or (distinct PREPARE #x00000001)'
          ' (distinct (bvadd PREPARE #x00000001) #x00000002))')
    prove('complete_zero_is_final_exactly_when_entering_count_is_one', [],
          '(distinct FINAL (= C #x00000001))')
    prove('complete_two_leaves_one_and_skips_final_metadata_path', ['(= C #x00000002)'],
          '(or FINAL (distinct COMPLETE #x00000001))')
    prove('admitted_free_drain_iteration_strictly_decreases_nonzero_count',
          ['(distinct C #x00000000)'], '(not (bvult COMPLETE C))')
    prove('admitted_free_drain_from_one_reaches_zero', ['(= C #x00000001)'],
          '(or (not FINAL) (distinct COMPLETE #x00000000))')
    prove('auxiliary_complete_preserves_selected_mask_and_adds_low_two',
          ['(= D #x00000200)'], '(distinct (bvor (bvand D #x00000600) #x00000002) #x00000202)')
    prove('append_after_48_byte_header_increases_used_to_88',
          ['(= USED #x0000000000000030)', '(= CAP #x0000000000000030)'],
          '(let ((NEW (bvadd USED #x0000000000000028)))'
          ' (or (distinct NEW #x0000000000000058) (bvule NEW CAP)))')
    prove('entry_address_after_header_and_table_matches_40_byte_stride', [],
          '(distinct (bvadd PREFIX (bvshl (bvadd ENTRY_COUNT (bvshl ENTRY_COUNT #x0000000000000002))'
          ' #x0000000000000003)) (bvadd #x0000000000000030 (bvmul N #x0000000000000008)'
          ' (bvmul ENTRY_COUNT #x0000000000000028)))')
    divisor_shift = 1 << 69
    reciprocal = 0xcccccccccccccccd
    assert 40 * reciprocal == divisor_shift + 8
    prove('complete_reciprocal_quotient_equals_floor_division_by_40',
          ['(<= 0 X)', f'(< X {1 << 64})', '(= X (+ (* 40 Q) R))',
           '(<= 0 R)', '(< R 40)'],
          f'(or (< (* {reciprocal} X) (* {divisor_shift} Q))'
          f' (>= (* {reciprocal} X) (* {divisor_shift} (+ Q 1))))',
          prefix='\n(declare-const X Int)\n(declare-const Q Int)\n(declare-const R Int)\n',
          logic='QF_LIA')
    prove('final_used_48_fits_any_admitted_existing_capacity',
          ['(bvuge CAP #x0000000000000030)'],
          '(bvugt #x0000000000000030 CAP)')
    prove('final_completion_clears_mode_bit_preserving_type_and_direction', [],
          '(or (distinct (bvand (bvand F #xffff7fff) #x000000f7) (bvand F #x000000f7))'
          ' (distinct (bvand (bvand F #xffff7fff) #x00008000) #x00000000))')
    return proofs, {
        'prepare_count_offset': 0x88,
        'ordinary_prepare_sites': ['0xfffffe000c537ed0', '0xfffffe000a508108'],
        'kext_complete_site': '0xfffffe000a508630',
        'reinitialize_complete_site': '0xfffffe000c537840',
        'free_complete_site': '0xfffffe000c53819c',
        'free_auxiliary_complete_site': '0xfffffe000c5381dc',
        'free_owner_release_site': '0xfffffe000c538200',
        'admitted_cached_teardown_counts': [0, 1, 2, 1, 0],
        'admitted_uncached_teardown_counts': [0, 1, 2, 2, 1, 0],
        'wire_append_record_bytes': 40,
        'ordinary_final_used_bytes': 48,
        'descriptor_prepare_complete_source_proved': True,
        'actual_prepare_count_or_VM_effect_observed': False,
        'Mach_port_emissions': 0,
    }


def verify(source):
    return source == build()


def alterations(source):
    baseline = build()
    mutations = [
        ('prepare', 0xfffffe000c53548c),
        ('wire_virtual', 0xfffffe000c5356f4),
        ('complete', 0xfffffe000c534b78),
        ('complete', 0xfffffe000c534bcc),
        ('general_free', 0xfffffe000c5381a0),
        ('general_free', 0xfffffe000c538200),
    ]
    for name, pc in mutations:
        changed = deepcopy(source)
        row = next(r for r in changed['functions'][name]['instructions'] if r['ea'] == hex(pc))
        row['operands'] += ' altered'
        assert changed != baseline
    return [hex(pc) for _, pc in mutations]


def main():
    source = json.loads(read(ROOT / (P + '_source.json')))
    assert verify(source)
    proofs, semantics = certificates(source)
    rejected = alterations(source)
    counts = {**source['verified_source_counts'], 'queries_unsat': len(proofs),
              'rejected_alterations': len(rejected)}
    result = {
        'generator_sha256': sha(__file__),
        'static_scope': SCOPE,
        'dependencies': {n: sha(ROOT / n) for n in [P + '_source.json', *DEPS]},
        'proofs': proofs,
        'semantics': semantics,
        'alterations': rejected,
        'verified_counts': counts,
        'solver': {'executable': 'z3', 'sha256': sha(SOLVER)},
        'all_checks_pass': True,
        'Descriptor_prepare_lifecycle_proved': True,
        'complete_operation_proved': False,
        **{flag: False for flag in FLAGS},
    }
    (ROOT / (P + '_checks.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(counts), flush=True)


if __name__ == '__main__':
    main()
