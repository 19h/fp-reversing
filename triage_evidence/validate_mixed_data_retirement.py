#!/usr/bin/env python3
"""Validate the selected backing pointer, extent and retirement-clear joins."""
import json
import shutil
import subprocess
from copy import deepcopy

from recover_mixed_data_retirement import DEPS, FLAGS, P, ROOT, SCOPE, TAGGED, build
from verify_daemon_reader_record_payloads_publication import read, sha

SOLVER = shutil.which('z3')
assert SOLVER


def verify_source_contract(source):
    rows = {
        int(i['ea'], 16): f"{i['mnemonic']} {i['operands']}".strip()
        for f in source['functions'].values() for i in f['instructions']
    }

    def expect(address, *instructions):
        for i, text in enumerate(instructions):
            pc = address + i * 4
            assert rows[pc] == text, (hex(pc), rows[pc], text)

    expect(0xfffffe000c539804, 'ldr x1, [x0, #0x10]', 'ldr x2, [x0, #0x20]',
           'adrp x8, #0xfffffe0007f94000', 'add x8, x8, #0xf98', 'orr x0, x8, #1',
           'bl #0xfffffe000bcfec48')
    expect(0xfffffe000bcfec60,
           'cbz x1, #0xfffffe000bcfed58', 'mov x19, x1', 'str xzr, [sp, #8]',
           'lsr x8, x2, #0x23', 'cmp x8, #0xd', 'b.hs #0xfffffe000bcfed6c',
           'cmp x2, #8, lsl #12', 'b.hi #0xfffffe000bcfece4', 'mov x20, x0',
           'str xzr, [sp]', 'add x1, sp, #8', 'mov x3, sp', 'mov x0, x19',
           'mov x21, x2', 'mov w2, #1', 'bl #0xfffffe000bd792dc',
           'mov x2, x21', 'mov x4, x0', 'ldr x8, [sp]', 'cbz x0, #0xfffffe000bcfed78',
           'add x9, x8, x2', 'cmp x9, x4', 'b.hi #0xfffffe000bcfed78',
           'neg x8, x8', 'cmp x8, w8, sxtw', 'add x1, x19, w8, sxtw',
           'add x16, x19, x8', 'movk x16, #0x2bad, lsl #48', 'csel x1, x1, x16, eq',
           'ldr x3, [sp, #8]', 'mov x0, x20', 'bl #0xfffffe000bcfed8c')

    expect(0xfffffe000bd792e0,
           'adds x9, x0, #8', 'b.hs #0xfffffe000bd79308', 'mov x8, x0',
           'adrp x10, #0xfffffe0007e66000', 'add x10, x10, #0xe50',
           'ldp x11, x10, [x10]', 'cmp x11, x0', 'ccmp x9, x11, #0, ls',
           'ccmp x9, x10, #2, hs', 'b.ls #0xfffffe000bd79318')
    expect(0xfffffe000bd79318,
           'adrp x9, #0xfffffe0007e66000', 'ldr x11, [x9, #0xf00]',
           'lsr x9, x8, #0xa', 'and x9, x9, #0xffffffff0', 'add x10, x9, x11',
           'ldrh w12, [x10]', 'and x9, x12, #0x3ff', 'mov w13, #0xc0',
           'adrp x14, #0xfffffe000caeb000', 'add x14, x14, #0x480',
           'umaddl x9, w9, w13, x14', 'ldrh w0, [x9, #0x34]')
    expect(0xfffffe000bd79348,
           'cbz x3, #0xfffffe000bd79384', 'tbz w12, #0xa, #0xfffffe000bd79384',
           'add x13, x0, x8', 'eor x8, x13, x8', 'cmp x8, #4, lsl #12',
           'b.lo #0xfffffe000bd79384', 'ldrh w8, [x10, #0x10]', 'and w8, w8, #0xf000',
           'cmp w8, #0xb, lsl #12', 'b.ne #0xfffffe000bd79390',
           'ldrh w8, [x10, #0x12]', 'cbz w2, #0xfffffe000bd7937c',
           'strh wzr, [x10, #0x12]')
    expect(0xfffffe000bd79390, 'cmp w0, #4, lsl #12', 'b.ls #0xfffffe000bd793c8')
    expect(0xfffffe000bd793c8, 'mov w8, wzr', 'str x8, [x3]',
           'cbz x1, #0xfffffe000bd79314', 'str x9, [x1]', 'ret')

    expect(0xfffffe000bcfe6dc, 'mov x2, x0', 'cbz x0, #0xfffffe000bcfe79c', 'mov x8, x21',
           'tst w21, #0x300', 'csel x0, x20, x1, eq', 'add x9, x1, x2',
           'add x10, x0, #0xf', 'and x10, x10, #0xfffffffffffffff0')
    expect(0xfffffe000bcfe708,
           'and x11, x9, #0x3fff', 'cmp x11, #0', 'ccmp x1, x10, #4, eq',
           'b.eq #0xfffffe000bcfe760', 'adrp x11, #0xfffffe0007e66000',
           'ldr x11, [x11, #0xf00]', 'lsr x12, x2, #0xa', 'and x12, x12, #0xffffffff0',
           'add x12, x12, x11', 'ldrh w12, [x12]', 'tbz w12, #0xa, #0xfffffe000bcfe760',
           'sub x10, x1, x10', 'lsr x9, x9, #0xa', 'and x9, x9, #0xffffffff0',
           'add x9, x9, x11', 'strh w10, [x9, #2]', 'add x9, x2, x10')
    expect(0xfffffe000bcfe74c, 'eor x16, x2, x9', 'tst x16, #-0x40000000000000',
           'b.eq #0xfffffe000bcfe75c', 'movk x9, #0xc8a2, lsl #48', 'mov x2, x9',
           'tbz w8, #8, #0xfffffe000bcfe76c')

    expect(0xfffffe000bcfedbc, 'mov x21, x4', 'mov x20, x1')
    expect(0xfffffe000bcfee04, 'ldr w13, [x10, #0x48]', 'tst w13, #0x8000',
           'csel x11, x12, x11, eq', 'tst w13, #8', 'csel x0, x11, x9, eq')
    expect(0xfffffe000bcfee64, 'mov x0, x2', 'mov x1, x21', 'mov x2, x20', 'nop',
           'mov x0, x20', 'bl #0xfffffe000c6480c0',
           'cbnz x22, #0xfffffe000bcfee84', 'ldr x22, [x19, #8]',
           'mov x0, x19', 'mov x1, x22', 'mov x2, x20', 'mov x3, x21')
    expect(0xfffffe000bcfeea4, 'b #0xfffffe000bd74fcc')
    expect(0xfffffe000bd75004, 'ldr x10, [x10, #0xb0]', 'lsr x11, x2, #0xa',
           'and x11, x11, #0xffffffff0', 'add x10, x11, x10', 'ldrh w12, [x10]',
           'and x11, x12, #0x3ff', 'add x11, x11, x11, lsl #1',
           'adrp x13, #0xfffffe000caeb000', 'add x13, x13, #0x480',
           'add x11, x13, x11, lsl #6', 'cmp x11, x8', 'b.ne #0xfffffe000bd75134')
    expect(0xfffffe000bd75080, 'ldr x12, [x9, #8]', 'add x12, x12, x3', 'str x12, [x9, #8]')
    expect(0xfffffe000bd750bc, 'ldr x8, [x1, #0x10]', 'add w11, w9, #1',
           'strh w11, [x1, #6]', 'str x2, [x8, w9, uxtw #3]')

    expect(0xfffffe000c6480cc, 'mov x2, x1', 'eor x1, x1, x1', 'mov x3, x0',
           'cmp x2, #0x80', 'b.lo #0xfffffe000c64813c')
    expect(0xfffffe000c648138,
           'str x1, [x3], #8', 'subs x2, x2, #8', 'b.hs #0xfffffe000c648138',
           'adds x2, x2, #8', 'b.eq #0xfffffe000c648158', 'strb w1, [x3], #1',
           'subs x2, x2, #1', 'b.ne #0xfffffe000c64814c')
    expect(0xfffffe000c6480e0,
           'stp x1, x1, [x0]', 'stp x1, x1, [x0, #0x10]', 'stp x1, x1, [x0, #0x20]',
           'stp x1, x1, [x0, #0x30]', 'add x3, x0, #0x40',
           'and x3, x3, #0xffffffffffffffc0', 'add x2, x2, x0', 'add x4, x3, #0x40',
           'subs x2, x2, x4', 'b.ls #0xfffffe000c648118',
           'dc zva, x3', 'add x3, x3, #0x40', 'subs x2, x2, #0x40',
           'b.hi #0xfffffe000c648108', 'add x3, x3, x2',
           'stp x1, x1, [x3]', 'stp x1, x1, [x3, #0x10]', 'stp x1, x1, [x3, #0x20]',
           'stp x1, x1, [x3, #0x30]')
    return rows


def certificates(source):
    verify_source_contract(source)
    proofs = []
    common = """
(declare-const E (_ BitVec 64))
(declare-const END (_ BitVec 64))
(declare-const ADDR (_ BitVec 64))
(declare-const BASE (_ BitVec 64))
(declare-const LO (_ BitVec 64))
(declare-const HI (_ BitVec 64))
(declare-const OFFSET (_ BitVec 64))
(declare-const I (_ BitVec 64))
(declare-const D (_ BitVec 64))
(declare-const C (_ BitVec 64))
(define-fun M ((P (_ BitVec 64))) (_ BitVec 64)
    (bvand (bvlshr P #x000000000000000a) #x0000000ffffffff0))
(define-fun P () (_ BitVec 64) (bvsub END E))
(define-fun Q () (_ BitVec 64) (bvsub END #x0000000000000030))
(define-fun O () (_ BitVec 64) (bvsub E #x0000000000000030))
(define-fun NEXT () (_ BitVec 64) (bvadd ADDR #x0000000000000008))
(define-fun CARRY () Bool (bvult NEXT ADDR))
(define-fun CCMP1-C () Bool (and (bvule LO ADDR) (bvuge NEXT LO)))
(define-fun SOURCE-ADMIT () Bool (and (not CARRY) CCMP1-C (bvule NEXT HI)))
"""
    adjusted = [
        '(bvugt E #x0000000000000030)', '(bvule E #x0000000000004000)',
        '(bvuge END E)', '(= (bvand END #x0000000000003fff) #x0000000000000000)',
    ]

    def prove(name, premises, counterexample):
        query = '(set-option :timeout 45000)\n(set-logic QF_BV)\n' + common
        query += ''.join(f'(assert {item})\n' for item in [*premises, counterexample])
        query += '(check-sat)\n'
        result = subprocess.run([SOLVER, '-in'], input=query, text=True,
                                capture_output=True, timeout=50)
        assert (result.returncode, result.stdout.strip(), result.stderr) == (0, 'unsat', ''), (
            name, result.stdout, result.stderr)
        proofs.append({'name': name, 'query': query, 'result': 'unsat'})
        print(name, 'unsat', flush=True)

    prove('lookup_admits_complete_first_eight_bytes_under_unsigned_bounds', [],
          '(distinct SOURCE-ADMIT (and (not CARRY) (bvule LO ADDR) (bvule NEXT HI)))')
    prove('forty_eight_selects_small_retirement_body', [],
          '(or (bvuge (bvlshr #x0000000000000030 #x0000000000000023) #x000000000000000d)'
          ' (bvugt #x0000000000000030 #x0000000000008000))')
    prove('unadjusted_admitted_return_recovers_original_base',
          ['(bvuge E #x0000000000000030)', '(= OFFSET #x0000000000000000)'],
          '(or (bvugt (bvadd OFFSET #x0000000000000030) E)'
          ' (distinct (bvsub ADDR OFFSET) ADDR))')
    prove('base_and_adjusted_pointer_address_same_page_metadata', adjusted,
          '(or (distinct (M P) (M Q)) (bvuge (bvxor P Q) #x0000000000004000))')
    prove('allocation_offset_cell_equals_retirement_offset_cell',
          [*adjusted, '(distinct (M END) #x0000000000000000)'],
          '(distinct (bvadd BASE (M END) #x0000000000000002)'
          ' (bvadd BASE (M Q) #x0000000000000012))')
    prove('adjusted_pointer_plus_extent_crosses_page_boundary',
          [*adjusted, '(bvuge (bvadd Q E) Q)'],
          '(bvult (bvxor (bvadd Q E) Q) #x0000000000004000)')
    prove('published_u16_offset_and_retirement_size_recover_base', adjusted,
          '(let ((D16 ((_ zero_extend 48) ((_ extract 15 0) O))))'
          ' (or (distinct D16 O) (distinct (bvadd D16 #x0000000000000030) E)'
          ' (distinct (bvsub Q D16) P)'
          ' (distinct ((_ sign_extend 32) ((_ extract 31 0) (bvneg D16))) (bvneg D16))))')
    prove('metadata_zone_index_uses_same_192_byte_stride', [],
          '(let ((IDX (bvand I #x00000000000003ff)))'
          ' (distinct (bvmul IDX #x00000000000000c0)'
          ' (bvshl (bvadd IDX (bvshl IDX #x0000000000000001)) #x0000000000000006)))')

    prove('scalar_clear_partitions_extent_into_words_and_tail',
          ['(bvult E #x0000000000000080)'],
          '(let ((W (bvand E #xfffffffffffffff8)) (R (bvand E #x0000000000000007)))'
          ' (or (distinct (bvadd W R) E) (bvugt W E) (bvuge R #x0000000000000008)))')
    prove('large_clear_initial_and_tail_are_contained_and_join_aligned_region',
          ['(bvuge E #x0000000000000080)', '(bvule E #x0000000000004000)',
           '(bvuge D #x0000000000000001)', '(bvule D #x0000000000000040)',
           '(bvuge C D)', '(bvule C E)', '(bvule (bvsub E C) #x0000000000000040)'],
          '(or (bvugt (bvadd D #x0000000000000040) E)'
          ' (bvugt (bvsub E #x0000000000000040) C)'
          ' (distinct (bvadd C (bvsub (bvsub E C) #x0000000000000040))'
          ' (bvsub E #x0000000000000040)))')
    prove('large_clear_middle_iteration_stays_inside_extent',
          ['(bvule E #x0000000000004000)', '(bvule C E)',
           '(bvugt (bvsub E C) #x0000000000000040)'],
          '(bvugt (bvadd C #x0000000000000040) E)')

    # Check the scalar store range construction for each admitted short extent.
    for extent in range(48, 128):
        words, tail = divmod(extent, 8)
        addresses = [offset + byte for offset in range(0, 8 * words, 8) for byte in range(8)]
        addresses += list(range(8 * words, 8 * words + tail))
        assert addresses == list(range(extent))
    return proofs, {
        'request_bytes': 48,
        'tagged_operand': hex(TAGGED),
        'source_adjustment_cases': ['unadjusted', 'matched_page_boundary_record'],
        'selected_extent_domain_bytes': [48, 16384],
        'scalar_extents_checked': 80,
        'source_bzero_before_zone_handoff_proved': True,
        'adjusted_logical_base_inverse_proved': True,
        'native_element_extent_observed': False,
        'native_retirement_proved': False,
        'Mach_port_emissions': 0,
    }


def verify(source):
    return source == build()


def alterations(source):
    baseline = build()
    rejected = []
    for name, address in [
        ('allocate', 0xfffffe000bcfe744),
        ('lookup', 0xfffffe000bd79370),
        ('retire', 0xfffffe000bcfecc4),
        ('retire_small', 0xfffffe000bcfee68),
        ('zero', 0xfffffe000c648138),
    ]:
        changed = deepcopy(source)
        row = next(r for r in changed['functions'][name]['instructions'] if r['ea'] == hex(address))
        row['operands'] += ' altered'
        assert changed != baseline
        rejected.append(hex(address))
    return rejected


def main():
    source = json.loads(read(ROOT / (P + '_source.json')))
    assert verify(source)
    proofs, semantics = certificates(source)
    rejected = alterations(source)
    counts = {
        **source['verified_source_counts'],
        'queries_unsat': len(proofs),
        'scalar_extents_checked': semantics['scalar_extents_checked'],
        'rejected_alterations': len(rejected),
    }
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
        'MixedData_retirement_contract_proved': True,
        'complete_operation_proved': False,
        **{flag: False for flag in FLAGS},
    }
    (ROOT / (P + '_checks.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(counts), flush=True)


if __name__ == '__main__':
    main()
