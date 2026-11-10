#!/usr/bin/env python3
"""Check startup producer fields and their original allocation consumers."""
import json
import shutil
import struct
import subprocess
from copy import deepcopy

from recover_mixed_data_zone_geometry import DEPS, FLAGS, P, ROOT, SCOPE, TABLE, build
from verify_daemon_reader_record_payloads_publication import read, sha

SOLVER = shutil.which('z3')
assert SOLVER


def contracts(source):
    rows = {
        int(i['ea'], 16): f"{i['mnemonic']} {i['operands']}".strip()
        for f in source['functions'].values() for i in f['instructions']
    }

    def expect(pc, *texts):
        for text in texts:
            assert rows[pc] == text, (hex(pc), rows[pc], text)
            pc += 4

    expect(0xfffffe000c62a8a0, 'adrp x9, #0xfffffe000700d000', 'ldr d0, [x9, #0xcf8]',
           'adrp x9, #0xfffffe000cbc8000', 'add x9, x9, #0xa40', 'str d0, [x9]',
           'mov w10, #0x20', 'mov w12, #0x10', 'mov w11, #0xa',
           'add w13, w12, w10', 'lsl x14, x8, #3', 'add x15, x14, #8',
           'str w13, [x9, x15]', 'add w10, w10, w12, lsl #1', 'lsl w12, w12, #1',
           'add x13, x14, #0xc', 'str w10, [x9, x13]', 'add x8, x8, #1',
           'subs x11, x11, #1', 'b.ne #0xfffffe000c62a8c0')
    expect(0xfffffe000c62a940, 'adrp x2, #0xfffffe0007e63000', 'add x2, x2, #0x360',
           'ldrb w1, [x2], #6', 'mov x0, x19', 'mov x3, #0', 'bl #0xfffffe000c62cbf0')
    expect(0xfffffe000c62a9a4, 'bl #0xfffffe000c62c548')
    expect(0xfffffe000c62c58c, 'bl #0xfffffe000c62baa8', 'mov w0, #2', 'bl #0xfffffe000c62c7f8')
    expect(0xfffffe000c62badc, 'adrp x8, #0xfffffe0007e63000', 'ldrh w20, [x8, #0x398]',
           'cbz x20, #0xfffffe000c62bb3c', 'mov w21, #2')
    expect(0xfffffe000c62bb18, 'add x8, x21, x21, lsl #1', 'add x2, x23, x8, lsl #3',
           'add x0, sp, #0x10', 'mov w1, #4', 'mov x3, #0x400000000000000',
           'bl #0xfffffe000c62cbf0', 'add x21, x21, #1', 'subs x20, x20, #1',
           'b.ne #0xfffffe000c62bb00')
    expect(0xfffffe000c62bb4c, 'bl #0xfffffe000bd71a20', 'adrp x8, #0xfffffe0007e6a000',
           'str x0, [x8, #0x780]')

    expect(0xfffffe000c62cc64, 'adrp x8, #0xfffffe000cbc8000', 'add x8, x8, #0xa40',
           'ldr w25, [x8, x28, lsl #2]')
    expect(0xfffffe000c62cd14, 'adrp x16, #0xfffffe000bcfe000', 'add x16, x16, #0x21c',
           'pacia x16, x24', 'str x16, [sp, #0x28]')
    expect(0xfffffe000c62cd3c, 'stp w25, w28, [sp, #0x40]', 'stp x16, x19, [sp, #0x30]',
           'add x4, sp, #0x18', 'mov x0, x26', 'mov x1, x25', 'mov x2, x22',
           'mov w3, #0xffff', 'bl #0xfffffe000bd772b4', 'add x28, x28, #1',
           'cmp x28, #0x16', 'b.ne #0xfffffe000c62cc64')
    expect(0xfffffe000bd772f0, 'cmp x1, #1', 'csinc x8, x1, xzr, hi', 'add x27, x8, #7')
    expect(0xfffffe000bd7731c, 'and x25, x27, #0x1fff8', 'mov w8, #0xffff',
           'cmp w23, w8', 'str x22, [sp, #0x28]', 'b.eq #0xfffffe000bd7737c')
    expect(0xfffffe000bd77308, 'adrp x8, #0xfffffe000caeb000',
           'ldrh w9, [x8, #0x45a]', 'mov x21, x9')
    expect(0xfffffe000bd77380, 'mov w8, #0xc0', 'umull x8, w21, w8',
           'adrp x9, #0xfffffe000caeb000', 'add x9, x9, #0x480', 'add x22, x9, x8',
           'add w8, w21, #1')
    expect(0xfffffe000bd773cc, 'adrp x9, #0xfffffe000caeb000',
           'add x9, x9, #0x45a', 'stlrh w8, [x9]')
    for pc in [0xfffffe000bd77520, 0xfffffe000bd77590]:
        expect(pc, 'strh w25, [x22, #0x34]')
    expect(0xfffffe000bd776b0, 'ldr x9, [x8, #0x10]!', 'mov x1, x22', 'blraa x9, x8')
    expect(0xfffffe000bcfe2a4, 'ldr w9, [x0, #0x2c]', 'cbnz w9, #0xfffffe000bcfe2b8',
           'lsr x8, x8, #0x20', 'ldr x9, [x0, #0x20]', 'strh w8, [x9]')

    expect(0xfffffe000c62c940, 'adrp x8, #0xfffffe0007f8d000', 'add x8, x8, #0xb58')
    expect(0xfffffe000c62c954, 'csel x1, x9, x8, eq', 'adrp x8, #0xfffffe0007f95000',
           'add x8, x8, #0xad8')
    expect(0xfffffe000c62c968, 'csel x2, x9, x8, eq', 'add x3, sp, #0x18', 'mov x0, x19',
           'mov w4, #0', 'mov x5, #0', 'bl #0xfffffe000c62c1b8')
    expect(0xfffffe000c62c374, 'ldr w8, [x21, #0x48]', 'bics wzr, w27, w8',
           'b.ne #0xfffffe000c62c40c', 'orr w9, w8, #0x8000', 'stur w9, [x21, #0x48]',
           'tbz w8, #4, #0xfffffe000c62c394', 'mov w8, #0x50', 'b #0xfffffe000c62c3b8',
           'tbnz w8, #3, #0xfffffe000c62c3c8', 'ldp x1, x0, [x21, #0x38]',
           'add x2, x21, #0x48', 'bl #0xfffffe000c62be28', 'mov w8, #0x50',
           'b #0xfffffe000c62c2d4')
    expect(0xfffffe000c62bed4, 'orr w8, w8, w9, lsl #16', 'orr w8, w8, #0x40000000',
           'str w8, [x19]')
    expect(0xfffffe000c62ab1c, 'ldr x26, [x20]', 'ldrh w8, [x22]', 'strh w8, [x26, #0x20]')
    expect(0xfffffe000c62abb0, 'str x0, [x26, #8]')
    expect(0xfffffe000c62c608, 'sub w8, w24, #4', 'sub w9, w24, #5',
           'and w9, w9, #0xffff', 'add w9, w9, #1', 'udiv w10, w21, w9',
           'msub w21, w10, w9, w21')
    expect(0xfffffe000c62c724, 'ldrh w8, [x9]', 'add w2, w8, #4')
    expect(0xfffffe000c62c768, 'cmp w2, w21', 'b.ne #0xfffffe000c62c77c',
           'mov x2, x21', 'bl #0xfffffe000c62bfd4')
    expect(0xfffffe000c62c078, 'ldrh w9, [x26, #0x398]', 'tst x0, #1',
           'csel w2, w20, w9, eq')
    expect(0xfffffe000bcfe708, 'and x11, x9, #0x3fff', 'cmp x11, #0',
           'ccmp x1, x10, #4, eq', 'b.eq #0xfffffe000bcfe760')
    expect(0xfffffe000bcfe5f8, 'tst w10, #0x8000', 'csel x8, x11, x8, eq',
           'adrp x11, #0xfffffe0007f8b000', 'add x11, x11, #0xfb0',
           'tst w10, #8', 'csel x0, x8, x11, eq')
    expect(0xfffffe000bcfe618, 'ldrh w9, [x9, #0x20]', 'ldrh w10, [x0, #0x16]',
           'cmp w9, #0', 'csel w9, w10, w9, eq')
    expect(0xfffffe000bcfe650, 'cbnz w10, #0xfffffe000bcfe660',
           'orr w2, w2, #0x40', 'adrp x9, #0xfffffe0007e63000', 'ldrh w9, [x9, #0x366]')
    expect(0xfffffe000bcfee04, 'ldr w13, [x10, #0x48]', 'tst w13, #0x8000',
           'csel x11, x12, x11, eq', 'tst w13, #8', 'csel x0, x11, x9, eq')

    sizes = list(struct.unpack('<II', bytes.fromhex(source['data']['size_table_seed']['bytes'])))
    size, step = sizes[1], 16
    for _ in range(10):
        sizes.extend((size + step, size + 2 * step))
        size += 2 * step
        step *= 2
    assert sizes == [16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024,
                     1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768]
    return sizes


def certificates(source):
    sizes = contracts(source)
    proofs = []
    common = """
(declare-const FLAGS (_ BitVec 32))
(declare-const HASH (_ BitVec 32))
(declare-const ID (_ BitVec 64))
(declare-const I (_ BitVec 64))
(declare-const BIAS (_ BitVec 64))
(declare-const T (_ BitVec 32))
(declare-const RND (_ BitVec 32))
(declare-const EXTENT (_ BitVec 64))
(declare-const PAGE_REM (_ BitVec 64))
(define-fun PARSED () (_ BitVec 32) (bvor FLAGS #x00008000))
(define-fun HASHED () (_ BitVec 32)
  (bvor PARSED #x40000000 (bvshl HASH #x00000010)))
(define-fun OFF () (_ BitVec 64) (bvmul ID #x00000000000000c0))
(define-fun FAMILY () (_ BitVec 32)
  (ite (= (bvand RND #x00000001) #x00000000) (bvadd T #x00000004) #x00000006))
(define-fun SIZE32 () (_ BitVec 64) (bvand (bvadd EXTENT #x0000000000000007) #x000000000001fff8))
"""
    def prove(name, premises, mismatch):
        query = '(set-option :timeout 45000)\n(set-logic QF_BV)\n' + common
        query += ''.join(f'(assert {term})\n' for term in [*premises, mismatch])
        query += '(check-sat)\n'
        r = subprocess.run([SOLVER, '-in'], input=query, text=True, capture_output=True, timeout=50)
        assert (r.returncode, r.stdout.strip(), r.stderr) == (0, 'unsat', ''), (name, r.stdout, r.stderr)
        proofs.append({'name': name, 'query': query, 'result': 'unsat'})
        print(name, 'unsat', flush=True)

    prove('source_view_passes_variable_parser_masks_and_keeps_80_byte_stride',
          ['(= FLAGS #x00000061)'],
          '(or (distinct (bvand FLAGS #x00000060) #x00000060)'
          ' (distinct (bvand FLAGS #x00000018) #x00000000))')
    prove('parser_and_hash_preserve_tagged_heap_selectors',
          ['(= FLAGS #x00000061)'],
          '(or (distinct (bvand HASHED #x0000ffff) #x00008061)'
          ' (distinct (bvand HASHED #x00008008) #x00008000)'
          ' (distinct (bvand HASHED #x00000080) #x00000000))')
    prove('permitted_group_permutation_values_select_initialized_variable_families',
          ['(bvule T #x00000001)'],
          '(or (bvult FAMILY #x00000004) (bvugt FAMILY #x00000006))')
    prove('family_table_loop_reads_the_third_entry_at_table_plus_8',
          ['(= I #x0000000000000002)'],
          '(distinct (bvshl I #x0000000000000002) #x0000000000000008)')
    prove('creator_rounds_48_to_48', ['(= EXTENT #x0000000000000030)'],
          '(distinct SIZE32 #x0000000000000030)')
    prove('dynamic_zone_cursor_and_consumer_index_agree_for_class_2',
          ['(bvule BIAS #x000000000000ffea)', '(= I #x0000000000000002)'],
          '(distinct (bvand (bvadd BIAS I) #x000000000000ffff) (bvadd BIAS I))')
    prove('setup_callback_recovers_dynamic_id_from_record_address',
          ['(bvult ID #x00000000000002b2)'],
          '(distinct (bvlshr (bvmul OFF #x0000000001555556) #x0000000000000020) ID)')
    prove('allocation_class_term_for_48_is_two', [],
          '(distinct (bvadd (bvsub (bvlshr #x0000002f #x00000004) #x00000034) #x00000034)'
          ' #x00000002)')
    prove('exact_48_element_uses_unadjusted_return_for_any_page_remainder',
          ['(= EXTENT #x0000000000000030)'],
          '(not (ite (= PAGE_REM #x0000000000000000) (= EXTENT #x0000000000000030) true))')
    prove('retirement_scalar_extent_is_six_words_with_no_remainder',
          ['(= EXTENT #x0000000000000030)'],
          '(or (distinct (bvlshr EXTENT #x0000000000000003) #x0000000000000006)'
          ' (distinct (bvand EXTENT #x0000000000000007) #x0000000000000000))')
    return proofs, {
        'table_address': hex(TABLE),
        'size_table_bytes_per_element': sizes,
        'file_flags': '0x61',
        'selected_post_startup_flags_low16': '0x8061',
        'selected_post_startup_heap': '0xfffffe0007e6a780',
        'alternate_heap_bias_address': '0xfffffe0007e63366',
        'default_family_count': 6,
        'default_created_variable_family_indices': list(range(2, 8)),
        'selected_nonpointer_group_family_indices': [4, 5, 6],
        'class_index_relative_to_family_start': 2,
        'matched_startup_element_extent_bytes': 48,
        'matched_startup_source_geometry_proved': True,
        'native_zone_id_observed': False,
        'native_allocation_observed': False,
        'Mach_port_emissions': 0,
    }


def verify(source):
    return source == build()


def alterations(source):
    baseline = build()
    mutations = [
        ('startup', 0xfffffe000c62a8cc),
        ('family_create', 0xfffffe000c62cc6c),
        ('family_setup', 0xfffffe000bcfe2b4),
        ('view_register', 0xfffffe000c62c384),
        ('view_assign', 0xfffffe000c62ab24),
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
              'size_table_entries': len(semantics['size_table_bytes_per_element']),
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
        'MixedData_zone_geometry_proved': True,
        'complete_operation_proved': False,
        **{flag: False for flag in FLAGS},
    }
    (ROOT / (P + '_checks.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(counts), flush=True)


if __name__ == '__main__':
    main()
