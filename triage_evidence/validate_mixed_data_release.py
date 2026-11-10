#!/usr/bin/env python3
"""Check release call sites, original slot dispatch and bounded atomic relations."""
import json
import shutil
import subprocess
from copy import deepcopy

from recover_mixed_data_release import (
    BASE, BUFFER, CALLERS, COLLECTION_TAG, DEPS, FLAGS, FUNCTIONS,
    OWNER, P, ROOT, SCOPE, WRAPPERS, build,
)
from verify_daemon_reader_record_payloads_publication import read, sha

SOLVER = shutil.which('z3')
assert SOLVER


def original_contract(source):
    instructions = {
        int(r['ea'], 16): f"{r['mnemonic']} {r['operands']}".strip()
        for f in [*source['functions'].values(), source['kext_cleanup']]
        for r in f['instructions']
    }

    def expect(start, *lines):
        for index, text in enumerate(lines):
            pc = start + 4 * index
            assert instructions[pc] == text, (hex(pc), instructions[pc], text)

    slots = {(int(r['vptr'], 16), r['offset']): r for r in source['slots']}

    def target(table, offset, name, diversity):
        row = slots[table, offset]
        assert int(row['target'], 16) == FUNCTIONS[name]
        assert int(row['diversity'], 16) == diversity
        return row

    for table in (OWNER, BASE):
        for offset, name, diversity in [
            (0x10, 'release_threshold', 0xbaa2), (0x18, 'getter', 0x3607),
            (0x20, 'retain', 0x2e4a), (0x28, 'release', 0x3a87),
            (0x48, 'tagged_retain', 0x5635), (0x50, 'tagged_release', 0xbe60),
            (0x58, 'tagged_release_threshold', 0x32e5),
        ]:
            target(table, offset, name, diversity)
    target(OWNER, 0xb0, 'free', 0xedc5)
    target(OWNER, 8, 'delete', 0x56b7)
    for offset, name, diversity in [
        (0x28, 'release', 0x3a87), (0x50, 'tagged_release', 0xbe60),
        (0x58, 'tagged_release_threshold', 0x32e5), (0xb0, 'buffer_free', 0xedc5),
        (8, 'buffer_delete', 0x56b7),
    ]:
        target(BUFFER, offset, name, diversity)

    for name, (offset, diversity) in WRAPPERS.items():
        start = FUNCTIONS[name]
        expect(start, 'bti c')
        extra = name == 'release_threshold'
        if extra:
            expect(start + 4, 'mov x2, x1')
        register = 'x2' if name in ('release', 'retain') else 'x3'
        sequence = [
            'ldr x16, [x0]', 'mov x17, x0', 'movk x17, #0xcda1, lsl #48',
            'autda x16, x17', f'ldr x8, [x16, #{offset:#x}]!',
            f'mov {register}, x16', 'mov x16, x8',
            'mov w2, #1' if name == 'tagged_release' else 'mov x1, #0',
            f'mov x17, {register}', f'movk x17, #{diversity:#x}, lsl #48', 'braa x16, x17',
        ]
        expect(start + (8 if extra else 4), *sequence)

    # The complete successful and retry decision prefix of taggedRelease(tag, when).
    expect(0xfffffe000c444e2c,
           'adrp x8, #0xfffffe000cb51000', 'add x8, x8, #0xce8', 'cmp x1, x8',
           'mov w8, #-0x10001', 'csinv w8, w8, wzr, eq',
           'mov w9, #0xfffe', 'mov w10, #0xffff', 'ldr w11, [x0, #8]',
           'bics wzr, w9, w11', 'b.eq #0xfffffe000c444ec4', 'add w13, w11, w8',
           'and w14, w13, #0xffff', 'cmp w14, w2', 'csel w12, w10, w13, lt',
           'add x15, x0, #8', 'mov x16, x11', 'casal w16, w12, [x15]',
           'cmp w16, w11', 'b.ne #0xfffffe000c444e48',
           'cmp w14, w13, lsr #16', 'b.lo #0xfffffe000c444ed4',
           'mov w8, #0xffff', 'cmp w12, w8', 'b.ne #0xfffffe000c444ec4')
    expect(0xfffffe000c444e8c,
           'ldr x16, [x0]', 'mov x17, x0', 'movk x17, #0xcda1, lsl #48',
           'autda x16, x17', 'ldr x8, [x16, #0xb0]!', 'mov x1, x16', 'mov x16, x8',
           'ldp x29, x30, [sp, #0x30]', 'ldp x20, x19, [sp, #0x20]',
           'add sp, sp, #0x40', 'autibsp', 'mov x17, x1',
           'movk x17, #0xedc5, lsl #48', 'braa x16, x17')
    expect(0xfffffe000c444ed0, 'retab')
    expect(0xfffffe000c444ef8, 'bl #0xfffffe000c62a2b0')

    expect(0xfffffe000c444fb8,
           'adrp x8, #0xfffffe000cb51000', 'add x8, x8, #0xce8', 'cmp x1, x8',
           'mov w8, #0x10001', 'csinc w8, w8, wzr, eq', 'mov w9, #0xfffe',
           'ldr w10, [x0, #8]', 'bics wzr, w9, w10', 'b.eq #0xfffffe000c444ff8',
           'add w11, w10, w8', 'add x12, x0, #8', 'mov x13, x10',
           'casal w13, w11, [x12]', 'cmp w13, w10', 'b.ne #0xfffffe000c444fd0')
    expect(0xfffffe000c445230, 'bti c', 'ldrh w0, [x0, #8]', 'ret')

    for name, gate, call in CALLERS:
        assert int(source['functions'][name]['start'], 16) <= gate < call
        expect(call - 24, 'ldr x16, [x0]', 'mov x17, x0',
               'movk x17, #0xcda1, lsl #48', 'autda x16, x17',
               'ldr x8, [x16, #0x28]!', 'movk x16, #0x3a87, lsl #48',
               'blraa x8, x16')

    expect(0xfffffe000c537434, 'mov x8, x0', 'mov x0, x20', 'str x8, [x20, #0x10]',
           'cbz x8, #0xfffffe000c537458', 'str x19, [x0, #0x20]')
    expect(0xfffffe000c537474, 'mov x0, #0', 'b #0xfffffe000c53744c')
    expect(0xfffffe000c53704c, 'bl #0xfffffe000c537394', 'mov x21, x0',
           'ldr x0, [x20, #0x90]', 'cbz x0, #0xfffffe000c537078')
    expect(0xfffffe000c537078, 'str x21, [x20, #0x90]')
    expect(0xfffffe000c5381e0, 'ldr x0, [x19, #0x90]', 'cbz x0, #0xfffffe000c538208')
    expect(0xfffffe000c538204, 'str xzr, [x19, #0x90]')
    expect(0xfffffe000c538344, 'ldr x16, [x19]', 'autda x16, x22',
           'ldr x8, [x16, #8]!', 'mov x1, x16', 'mov x16, x8', 'mov x0, x19')
    expect(0xfffffe000c538370, 'mov x17, x1', 'movk x17, #0x56b7, lsl #48',
           'braa x16, x17')
    expect(0xfffffe000c538c0c, 'ldr x0, [x0, #0x90]', 'cbz x0, #0xfffffe000c538c30')
    expect(0xfffffe000c538c3c, 'str xzr, [x19, #0x90]')
    expect(0xfffffe000c5254fc, 'ldr x0, [x0, #0x90]', 'cbz x0, #0xfffffe000c525520')
    expect(0xfffffe000c52552c, 'str xzr, [x19, #0x90]')
    expect(0xfffffe000c5252ac, 'mov x22, x0')
    expect(0xfffffe000c525370, 'mov x0, x22', 'bl #0xfffffe000c538044')
    expect(0xfffffe000c539804, 'ldr x1, [x0, #0x10]', 'ldr x2, [x0, #0x20]')
    expect(0xfffffe000c539818, 'bl #0xfffffe000bcfec48')
    expect(0xfffffe000bcfec60, 'cbz x1, #0xfffffe000bcfed58')
    expect(0xfffffe000bcfed58, 'ldp x29, x30, [sp, #0x30]',
           'ldp x20, x19, [sp, #0x20]', 'ldp x22, x21, [sp, #0x10]',
           'add sp, sp, #0x40', 'retab')
    expect(0xfffffe000a5085f4, 'adrp x19, #0xfffffe000ccce000',
           'ldr x0, [x19, #0xb10]', 'cbz x0, #0xfffffe000a50865c')
    expect(0xfffffe000a508638, 'ldr x0, [x19, #0xb10]', 'ldr x16, [x0]',
           'mov x17, x0', 'movk x17, #0xcda1, lsl #48', 'autda x16, x17',
           'ldr x8, [x16, #0x28]!', 'movk x16, #0x3a87, lsl #48',
           'blraa x8, x16', 'str xzr, [x19, #0xb10]')
    return [{'body': name, 'gate': hex(gate), 'call': hex(call)} for name, gate, call in CALLERS]


def certificates(source):
    sites = original_contract(source)
    definitions = """
(declare-const OLD (_ BitVec 32))
(declare-const OBSERVED (_ BitVec 32))
(declare-const WHEN (_ BitVec 32))
(declare-const TAG (_ BitVec 64))
(define-fun COLLECTION () Bool (= TAG #xfffffe000cb51ce8))
(define-fun LOW () (_ BitVec 32) (bvand OLD #x0000ffff))
(define-fun HIGH () (_ BitVec 32) (bvlshr OLD #x00000010))
(define-fun ACTIVE () Bool (distinct (bvand #x0000fffe (bvnot OLD)) #x00000000))
(define-fun DELTA () (_ BitVec 32) (ite COLLECTION #xfffeffff (bvnot #x00000000)))
(define-fun RAW () (_ BitVec 32) (bvadd OLD DELTA))
(define-fun L () (_ BitVec 32) (bvand RAW #x0000ffff))
(define-fun H () (_ BitVec 32) (bvlshr RAW #x00000010))
(define-fun REPLACEMENT () (_ BitVec 32) (ite (bvslt L WHEN) #x0000ffff RAW))
(define-fun CAS_SUCCESS () Bool (= OBSERVED OLD))
(define-fun COMMITTED () (_ BitVec 32) (ite (and ACTIVE CAS_SUCCESS) REPLACEMENT OBSERVED))
(define-fun DIAGNOSTIC () Bool (and ACTIVE CAS_SUCCESS (bvult L H)))
(define-fun FREE () Bool (and ACTIVE CAS_SUCCESS (bvuge L H) (= REPLACEMENT #x0000ffff)))
(define-fun RETAIN_DELTA () (_ BitVec 32) (ite COLLECTION #x00010001 #x00000001))
(define-fun RETAIN_WORD () (_ BitVec 32) (bvadd OLD RETAIN_DELTA))
"""
    ordinary = '(= TAG #x0000000000000000)'
    valid = '(and (bvuge LOW #x00000001) (bvule LOW #x0000fffd) (bvule HIGH LOW))'
    one = '(= WHEN #x00000001)'
    success = 'CAS_SUCCESS'
    proofs = []

    def prove(name, premises, mismatch):
        query = '(set-option :timeout 45000)\n(set-logic QF_BV)\n' + definitions
        query += ''.join(f'(assert {term})\n' for term in [*premises, mismatch])
        query += '(check-sat)\n'
        r = subprocess.run([SOLVER, '-in'], input=query, text=True,
                           capture_output=True, timeout=50)
        assert (r.returncode, r.stdout.strip(), r.stderr) == (0, 'unsat', ''), (name, r.stdout, r.stderr)
        proofs.append({'name': name, 'query': query, 'result': 'unsat'})
        print(name, 'unsat', flush=True)

    prove('plain_release_decrements_low_preserving_high', [ordinary, valid],
          '(or (distinct L (bvsub LOW #x00000001)) (distinct H HIGH))')
    prove('collection_release_decrements_both_halves', ['COLLECTION', valid, '(bvugt HIGH #x00000000)'],
          '(or (distinct L (bvsub LOW #x00000001)) (distinct H (bvsub HIGH #x00000001)))')
    prove('fresh_word_one_selects_private_free_at_default_threshold',
          [ordinary, one, success, '(= OLD #x00000001)'],
          '(or (not FREE) DIAGNOSTIC (distinct COMMITTED #x0000ffff))')
    prove('matching_collection_last_reference_has_same_free_outcome',
          ['COLLECTION', one, success, '(= OLD #x00010001)'],
          '(or (not FREE) DIAGNOSTIC (distinct COMMITTED #x0000ffff))')
    prove('ordinary_release_with_remaining_references_does_not_free',
          [ordinary, one, success, valid, '(bvugt LOW #x00000001)', '(bvult HIGH LOW)'],
          '(or FREE DIAGNOSTIC (distinct COMMITTED RAW) (= L #x00000000))')
    prove('valid_default_release_frees_exactly_on_last_reference',
          [ordinary, one, success, valid, '(bvult HIGH LOW)'],
          '(distinct FREE (= LOW #x00000001))')
    prove('general_threshold_uses_signed_W2',
          [ordinary, success, valid, '(bvult HIGH LOW)'],
          '(distinct FREE (bvslt (bvsub LOW #x00000001) WHEN))')
    prove('failed_compare_exchange_cannot_dispatch_using_stale_word',
          ['(not CAS_SUCCESS)'],
          '(or FREE DIAGNOSTIC (distinct COMMITTED OBSERVED))')
    prove('committed_finalization_word_suppresses_another_attempt_in_same_epoch',
          ['(= OLD #x0000ffff)'], '(or ACTIVE FREE DIAGNOSTIC)')
    prove('collection_subset_violation_uses_diagnostic_before_free',
          [ordinary, one, success, valid, '(= HIGH LOW)'],
          '(or (not DIAGNOSTIC) FREE)')
    prove('ordinary_retain_increases_low_preserving_high',
          [ordinary, valid, '(bvult LOW #x0000fffd)'],
          '(or (distinct (bvand RETAIN_WORD #x0000ffff) (bvadd LOW #x00000001))'
          ' (distinct (bvlshr RETAIN_WORD #x00000010) HIGH))')
    prove('collection_retain_increases_both_halves',
          ['COLLECTION', valid, '(bvult LOW #x0000fffd)'],
          '(or (distinct (bvand RETAIN_WORD #x0000ffff) (bvadd LOW #x00000001))'
          ' (distinct (bvlshr RETAIN_WORD #x00000010) (bvadd HIGH #x00000001)))')
    prove('admitted_matching_retain_and_release_operands_cancel',
          [valid, '(bvult LOW #x0000fffd)'], '(distinct (bvadd RETAIN_WORD DELTA) OLD)')
    prove('getter_projection_excludes_upper_half', [],
          '(distinct ((_ zero_extend 16) ((_ extract 15 0) OLD)) LOW)')
    return proofs, {
        'sites': sites,
        'slot_vptr_owner': hex(OWNER),
        'special_tag_identity': hex(COLLECTION_TAG),
        'reference_word_width_bits': 32,
        'getter_width_bits': 16,
        'finalization_word_u32': 0xffff,
        'plain_release_threshold': 1,
        'descriptor_global_release_site': '0xfffffe000a508654',
        'owner_private_free_site': hex(FUNCTIONS['free']),
        'native_reference_lifetime_proved': False,
        'conditional_source_release_proved': True,
        'Mach_port_emissions': 0,
    }


def verify(source):
    return source == build()


def alterations(source):
    baseline = build()
    rejected = []
    for function, pc in [
        ('release', 0xfffffe000c4451f0),
        ('tagged_release', 0xfffffe000c444f98),
        ('tagged_release_threshold', 0xfffffe000c444e6c),
        ('tagged_release_threshold', 0xfffffe000c444e78),
        ('buffer_delete', 0xfffffe000c52552c),
    ]:
        changed = deepcopy(source)
        row = next(r for r in changed['functions'][function]['instructions'] if r['ea'] == hex(pc))
        row['operands'] += ' altered'
        assert changed != baseline
        rejected.append(hex(pc))
    return rejected


def main():
    source = json.loads(read(ROOT / (P + '_source.json')))
    assert verify(source)
    proofs, semantics = certificates(source)
    rejected = alterations(source)
    counts = {
        **source['verified_source_counts'],
        'queries_unsat': len(proofs),
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
        'MixedData_release_contract_proved': True,
        'complete_operation_proved': False,
        **{flag: False for flag in FLAGS},
    }
    (ROOT / (P + '_checks.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(counts), flush=True)


if __name__ == '__main__':
    main()
