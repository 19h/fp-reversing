#!/usr/bin/env python3
"""Validate init publications and the selected source cleanup continuation."""
import itertools
import json
import shutil
import subprocess
from copy import deepcopy

from recover_aes_cleanup_epoch import DEPS, FLAGS, P, ROOT, SCOPE, build
from verify_daemon_reader_record_payloads_publication import read, sha

SOLVER = shutil.which('z3')
assert SOLVER


def source_contract(source):
    rows = {
        int(i['ea'], 16): f"{i['mnemonic']} {i['operands']}".strip()
        for f in [*source['functions'].values(), *source['spans'].values()]
        for i in f['instructions']
    }

    def expect(pc, *instructions):
        for text in instructions:
            assert rows[pc] == text, (hex(pc), rows[pc], text)
            pc += 4

    expect(0xfffffe000a50804c, 'ldrb w8, [x20, #0xb00]', 'tbz w8, #0, #0xfffffe000a50805c',
           'mov w19, #0', 'b #0xfffffe000a508138')
    expect(0xfffffe000a508078, 'bl #0xfffffe000a69f244', 'cbz x0, #0xfffffe000a508134',
           'adrp x8, #0xfffffe000ccce000', 'str x0, [x8, #0xb08]')
    expect(0xfffffe000a508098, 'ldr x8, [x16, #0x20]!', 'movk x16, #0x2e4a, lsl #48',
           'blraa x8, x16')
    expect(0xfffffe000a5080d4, 'bl #0xfffffe000a69f1f4', 'adrp x19, #0xfffffe000ccce000',
           'str x0, [x19, #0xb10]', 'cbz x0, #0xfffffe000a508134')
    expect(0xfffffe000a508108, 'blraa x8, x16', 'cbz w0, #0xfffffe000a50814c')
    expect(0xfffffe000a508120, 'mov w19, #-0x16', 'mov w0, #-0x16', 'mov w3, #0x73',
           'bl #0xfffffe000a508c78', 'b #0xfffffe000a508138', 'mov w19, #-0x28', 'mov x0, x19')
    expect(0xfffffe000a508170, 'blraa x8, x16', 'adrp x8, #0xfffffe000ccc7000',
           'str x0, [x8, #0x848]')
    expect(0xfffffe000a50818c, 'mov w0, #0', 'mov w3, #0x6c', 'bl #0xfffffe000a508c78',
           'mov w19, #0', 'cbz w0, #0xfffffe000a508138', 'mov w19, #0', 'mov w8, #1',
           'strb w8, [x20, #0xb00]')
    expect(0xfffffe000a508c90, 'mov x19, x0', 'cbz w0, #0xfffffe000a508cac')
    expect(0xfffffe000a508cac, 'cmp w19, #0', 'cset w0, eq')
    expect(0xfffffe000c4eb638, 'blraa x8, x16', 'cbz x19, #0xfffffe000c4eb660')
    expect(0xfffffe000c4eb654, 'mov x0, x19', 'movk x16, #0x3a87, lsl #48',
           'blraa x8, x16', 'mov x0, x19')
    expect(0xfffffe000c526124, 'blraa x8, x16', 'mov x0, #0')

    expect(0xfffffe000a5085f8, 'ldr x0, [x19, #0xb10]', 'cbz x0, #0xfffffe000a50865c',
           'adrp x20, #0xfffffe000ccc7000', 'ldr x8, [x20, #0x848]',
           'cbz x8, #0xfffffe000a50863c')
    expect(0xfffffe000a508630, 'blraa x8, x16', 'str xzr, [x20, #0x848]',
           'ldr x0, [x19, #0xb10]')
    expect(0xfffffe000a508654, 'blraa x8, x16', 'str xzr, [x19, #0xb10]',
           'adrp x19, #0xfffffe000ccce000', 'ldr x0, [x19, #0xb08]',
           'cbz x0, #0xfffffe000a508688')
    expect(0xfffffe000a508680, 'blraa x8, x16', 'str xzr, [x19, #0xb08]',
           'adrp x8, #0xfffffe000ccce000', 'strb wzr, [x8, #0xb00]', 'mov w0, #0')

    expect(0xfffffe000a66b1d8, 'mov w0, #0x200', 'mov x17, #0xca0c', 'blraa x8, x17')
    expect(0xfffffe000a66b214, 'mov w10, #0xac', 'eor w9, w9, w10',
           'ldrb w9, [x22, w9, uxtw]', 'eor w8, w8, w9', 'and w8, w8, #0xff',
           'add w8, w8, #0x165', 'ldr x8, [x23, w8, uxtw #3]', 'str x0, [x8, #-4]!')
    expect(0xfffffe000c4ba620, 'adrp x0, #0xfffffe0007f8b000', 'add x0, x0, #0xfb0',
           'mov x1, x19', 'mov w2, #0x1000', 'movk w2, #3, lsl #16', 'mov x3, #0',
           'bl #0xfffffe000bcfe5b8')
    expect(0xfffffe000c4ba864, 'mov x1, x0', 'adrp x0, #0xfffffe0007f8b000',
           'add x0, x0, #0xfb0', 'mov x2, x19', 'bl #0xfffffe000bcfec48')

    expect(0xfffffe000a608050, 'madd w8, w8, w9, w19', 'add w8, w8, #0x451',
           'str w8, [x24, #0x18]')
    expect(0xfffffe000a6080ac, 'blraa x8, x17', 'ldr x8, [x20, w19, sxtw #3]',
           'mov w30, #0x66', 'movk w30, #0x31ae, lsl #16', 'mov x17, #0x58fd', 'braa x8, x17')
    expect(0xfffffe000a60ec64, 'bti j', 'ldur x8, [x29, #-0xd8]', 'str w30, [x8, #0x14]')
    expect(0xfffffe000a6227b4, 'blraa x8, x17')
    expect(0xfffffe000a6227f4, 'add w10, w10, #0x165', 'ldr x25, [x24, w10, uxtw #3]',
           'ldr x0, [x25, #-4]!', 'cmp x0, #0', 'cset w10, ne')
    expect(0xfffffe000a622818, 'add w11, w28, w11', 'and w26, w11, w12',
           'sub w11, w26, #0xd70', 'mul w10, w10, w11', 'eor w10, w10, w28',
           'ldr x10, [x27, w10, sxtw #3]', 'mov x17, #0x283c', 'braa x10, x17')
    expect(0xfffffe000a622884, 'mov w1, #0x200', 'mov x17, #0x85d',
           'blraa x8, x17', 'str xzr, [x25]', 'ldr x8, [x27, w28, sxtw #3]')
    expect(0xfffffe000a6228e0, 'add w9, w9, #0x6c', 'ldr x9, [x24, w9, uxtw #3]',
           'ldur x9, [x9, #-4]', 'cmp x9, #0', 'cset w10, eq',
           'sub w11, w8, #0x6a2', 'mul w10, w10, w11', 'eor w10, w10, w26')
    expect(0xfffffe000a622910, 'add w24, w8, #0x43d', 'mov w8, #0x1ce2',
           'movk w8, #0x2392, lsl #16', 'orr w8, w8, w19, lsl #1',
           'mov w10, #0xf18f', 'movk w10, #0x6e36, lsl #16', 'sub w8, w8, w19',
           'add w8, w8, w10', 'mov w10, #0x97b0', 'movk w10, #0x6d6b, lsl #16',
           'eor w8, w8, w10', 'mov w10, #0x7e73', 'movk w10, #0xc69a, lsl #16',
           'msub w8, w8, w10, w24', 'sub w8, w8, #0x46d', 'str w8, [x19, #4]',
           'str x9, [x19, #8]')
    expect(0xfffffe000a62298c, 'mov x0, x19', 'mov x17, #0xd0c8', 'blraa x8, x17')
    expect(0xfffffe000a622abc, 'mov w15, #0x99c1', 'movk w15, #0xfca2, lsl #16',
           'eor w15, w19, w15', 'mov w16, #0x7e73', 'movk w16, #0xc69a, lsl #16',
           'ldr w17, [x0, #4]', 'madd w15, w15, w16, w17',
           'ldr x0, [x0, #8]', 'cmp x0, #0', 'cset w16, eq')
    expect(0xfffffe000a622b40, 'mov w11, #-0xa427', 'mov x17, #0x1ac4',
           'braa x12, x17', 'bti j', 'add w21, w15, #0x4f')
    expect(0xfffffe000a622ba4, 'blraa x8, x17', 'mov w11, #0',
           'ldr x8, [x20, w21, sxtw #3]', 'mov x17, #0x1ac4', 'braa x8, x17',
           'bti j', 'str w11, [x19]')
    expect(0xfffffe000a508dd0, 'b #0xfffffe000a69f084')
    expect(0xfffffe000a69f084, 'adrp x17, #0xfffffe000847c000', 'add x17, x17, #0x370',
           'ldr x16, [x17]', 'braa x16, x17')
    assert source['exact_symbols'][source['lock_import']['target']][0]['name'] == '_IOLockFree'


def certificates(source):
    source_contract(source)
    proofs = []
    prefix = """
(declare-const P (_ BitVec 32))
(declare-const AUX_PRESENT Bool)
(declare-const LOCK_PRESENT Bool)
(declare-const STATUS (_ BitVec 32))
(define-fun F () (_ BitVec 32)
  (bvxor (bvadd (bvsub (bvor #x23921ce2 (bvshl P #x00000001)) P)
    #x6e36f18f) #x6d6b97b0))
(define-fun W28 () (_ BitVec 32) (bvadd #x00000335 #x00000451))
(define-fun W26a () (_ BitVec 32) (bvand (bvadd W28 #x325565f5) #xcdaa9fff))
(define-fun W26b () (_ BitVec 32) (bvmul (bvxor W28 #x00000781) #x000001ed))
(define-fun W26 () (_ BitVec 32) (ite AUX_PRESENT W26b W26a))
(define-fun FIRST () (_ BitVec 32)
  (bvxor (ite AUX_PRESENT (bvsub W26a #x00000d70) #x00000000) W28))
(define-fun W8 () (_ BitVec 32) (bvxor W26 #x00000afd))
(define-fun SECOND () (_ BitVec 32)
  (bvxor (ite LOCK_PRESENT #x00000000 (bvsub W8 #x000006a2)) W26))
(define-fun RET_IDX () (_ BitVec 32) (bvadd W8 #x0000043d))
(define-fun ENCODED () (_ BitVec 32)
  (bvsub (bvsub RET_IDX (bvmul F #xc69a7e73)) #x0000046d))
(define-fun DECODED () (_ BitVec 32)
  (bvadd (bvmul (bvxor P #xfca299c1) #xc69a7e73) ENCODED))
(define-fun THIRD () (_ BitVec 32)
  (bvxor (ite LOCK_PRESENT #x00000000 (bvsub DECODED #x00000663)) DECODED))
"""
    def prove(name, claim, premises=(), query_prefix=prefix, depends_on=()):
        query = ('(set-option :timeout 45000)\n(set-logic QF_BV)\n' + query_prefix
                 + ''.join('(assert ' + term + ')\n' for term in premises)
                 + '(assert (not ' + claim + '))\n'
                 + '(check-sat-using (then simplify propagate-values solve-eqs simplify bit-blast sat))\n')
        result = subprocess.run([SOLVER, '-in'], input=query, text=True,
                                capture_output=True, timeout=50)
        assert (result.returncode, result.stdout.strip(), result.stderr) == (0, 'unsat', ''), (
            name, result.stdout, result.stderr)
        proofs.append({'name': name, 'query': query, 'result': 'unsat', 'depends_on': list(depends_on)})
        print(name, 'unsat', flush=True)

    prove('producer_state_and_control_word_correspond', '(= W28 #x00000786)')
    prove('selected_auxiliary_presence_routes_to_original_blocks',
          '(= FIRST (ite AUX_PRESENT #x0000078d #x00000786))')
    prove('auxiliary_release_and_skip_converge_on_same_saved_state', '(= W26 #x00000d7b)')
    prove('selected_lock_presence_routes_to_helper_or_direct_return',
          '(= SECOND (ite LOCK_PRESENT #x00000d7b #x00000d9f))')
    prove('adapter_address_expression_cancels_helper_address_key', '(= F (bvxor P #xfca299c1))')
    prove('helper_decodes_constant_control_for_all_low32_object_addresses',
          '(and (= RET_IDX #x00000bc3) (= DECODED #x00000756))',
          ['(= F (bvxor P #xfca299c1))'])
    normalized = prefix.replace(
        '(bvadd (bvmul (bvxor P #xfca299c1) #xc69a7e73) ENCODED))',
        '#x00000756)')
    assert normalized != prefix
    prove('helper_null_and_nonnull_paths_select_original_slots',
          '(and (= THIRD (ite LOCK_PRESENT #x00000756 #x000007a5))'
          ' (= (bvadd DECODED #x0000004f) #x000007a5))',
          query_prefix=normalized,
          depends_on=['helper_decodes_constant_control_for_all_low32_object_addresses'])
    prove('prepare_failure_is_remapped_using_low32_status',
          '(= (ite (= STATUS #x00000000) #x00000000 #xffffffea)'
          ' (ite (distinct STATUS #x00000000) (bvneg #x00000016) #x00000000))')

    # Enumerate cold, warm, and cleanup state cases as source summaries.
    # Booleans denote presence of a value in the named cell.
    initializers = []
    for ready, provider, descriptor, prepared, getter in itertools.product((False, True), repeat=5):
        if ready:
            exit_kind = 'warm_return'
            status, stores = 0, []
        elif not provider:
            exit_kind = 'provider_absent'
            status, stores = -40, []
        elif not descriptor:
            exit_kind = 'factory_null'
            status, stores = -40, ['provider=result', 'descriptor=0']
        elif not prepared:
            exit_kind = 'prepare_error'
            status, stores = -22, ['provider=result', 'descriptor=result']
        else:
            exit_kind = 'prepared'
            status, stores = 0, ['provider=result', 'descriptor=result',
                                'bytes=' + ('result' if getter else '0'), 'ready=1']
        initializers.append({'ready_at_entry': ready, 'waiter_nonnull': provider,
                             'factory_nonnull': descriptor, 'prepare_zero': prepared,
                             'getter_nonnull': getter, 'case': exit_kind,
                             'status_s32': status, 'ordered_global_stores': stores})

    cleanups = []
    for provider, descriptor, byte_pointer in itertools.product((False, True), repeat=3):
        operations = []
        if descriptor and byte_pointer:
            operations += ['complete_descriptor_0', 'clear_bytes']
        if descriptor:
            operations += ['release_descriptor', 'clear_descriptor']
        if provider:
            operations += ['release_provider', 'clear_provider']
        operations += ['clear_ready']
        cleanups.append({'provider_present': provider, 'descriptor_present': descriptor,
                         'cached_bytes_present': byte_pointer, 'ordered_effects': operations})

    return proofs, {
        'initializer_cases': initializers, 'cleanup_cases': cleanups,
        'auxiliary_request_bytes': 512,
        'matched_publication_cell': '0xfffffe000cccba48',
        'separate_lock_operand_cell': '0xfffffe000ccceab8',
        'selected_post_cleanup_lock_boundary': 'IOLockFree',
        'core_selected_continuation_state': '0x335',
        'conditional_aes_cleanup_source_proved': True,
        'native_ownership_or_cleanup_observed': False,
        'Mach_port_emissions': 0,
    }


def verify(source):
    return source == build()


def alterations(source):
    baseline = build()
    modifications = [
        ('functions', 'init', '0xfffffe000a5080dc'),
        ('spans', 'producer', '0xfffffe000a66b230'),
        ('functions', 'adapter', '0xfffffe000a622884'),
        ('functions', 'adapter_tail_helper', '0xfffffe000a622bbc'),
        ('spans', 'core_return', '0xfffffe000a60ec6c'),
    ]
    for category, function, address in modifications:
        altered = deepcopy(source)
        row = next(i for i in altered[category][function]['instructions'] if i['ea'] == address)
        row['operands'] += ' altered'
        assert altered != baseline
    return [address for _, _, address in modifications]


def main():
    source = json.loads(read(ROOT / (P + '_source.json')))
    assert verify(source)
    proofs, semantics = certificates(source)
    rejected = alterations(source)
    counts = {**source['verified_source_counts'], 'queries_unsat': len(proofs),
              'initialization_cases': len(semantics['initializer_cases']),
              'cleanup_cases': len(semantics['cleanup_cases']), 'rejected_alterations': len(rejected)}
    result = {
        'generator_sha256': sha(__file__),
        'static_scope': SCOPE,
        'dependencies': {n: sha(ROOT / n) for n in [P + '_source.json', *DEPS]},
        'proofs': proofs, 'semantics': semantics, 'alterations': rejected,
        'verified_counts': counts,
        'solver': {'executable': 'z3', 'sha256': sha(SOLVER)},
        'all_checks_pass': True,
        'AES_cleanup_source_proved': True,
        'complete_operation_proved': False,
        **{flag: False for flag in FLAGS},
    }
    (ROOT / (P + '_checks.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(counts), flush=True)


if __name__ == '__main__':
    main()
