#!/usr/bin/env python3
"""Source-only constructor descriptor and feedback phase contracts.

Retained initializer profiles and frozen constructor frontiers qualify the
equations. No new execution path, native operation or initializer epoch join
is asserted. O(source words + profile events + terminal bytes + query DAG)
time; O(largest input receipt + terminal byte map + query DAG) space.
Solver timeout is 30 s per query.
"""
import json
from collections import Counter
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT, SOURCE, IMAGE, CS, qword, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_state_table_mixing import Scalar
from audit_daemon_network_record import state_bytes
from lskd_values_symbolic import mem, cell
from recover_daemon_constructor_buffer import unpack, S

P = 'daemon_constructor_descriptor'
MASK = (1 << 64) - 1
ENC = 0x1c0b9f7ce10f2255
WORD_BIAS = 0xb5caf0c6
ROOT_CELL = 0x1010b7cc0
POOL_SLOT = 0x1010a3eb0
PINS = {
    'daemon_return_bank_origins_checks.json': '9e5d75cb4a1f452a8499a3a917351283e8763335a44f264809024aaaeded3c69',
    'daemon_constructor_buffer_checks.json': 'fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07',
}
DEPS = ['daemon_receive_tools.py', 'daemon_receive_fixups.txt', 'audit_daemon_state_table_mixing.py',
        'audit_daemon_network_record.py', 'lskd_values_symbolic.py',
        'recover_daemon_constructor_buffer.py']
SPANS = [
    ('root_pool_writer', 0x1004c3550, 0x1004c3570),
    ('descriptor_initializer', 0x10061a464, 0x10061a4bc),
    ('root_consumer', 0x1008a2704, 0x1008a2714),
    ('feedback_prologue', 0x100b211f4, 0x100b21210),
    ('feedback_phase', 0x100b21308, 0x100b2139c),
    ('feedback_return', 0x100b2143c, 0x100b21450),
    ('nested_seed_restore', 0x100b0051c, 0x100b00528),
    ('descriptor_consumer', 0x100a5eac8, 0x100a5eb00),
]
DEC = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
DEC.detail = True


def source():
    return [{'label': label, 'start': hex(a), 'end': hex(b),
             'bytes_hex': IMAGE.read(a, b-a).hex(),
             'instructions': [{'pc': hex(i.address), 'bytes_hex': bytes(i.bytes).hex(),
                               'mnemonic': i.mnemonic, 'operands': i.op_str}
                              for i in CS.disasm(IMAGE.read(a, b-a), a)]}
            for label, a, b in SPANS]


def overlap(w, a, n):
    return int(w['address'], 16) < a+n and a < int(w['address'], 16)+w['size_bytes']


def profiles():
    parent = json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'))
    out = []
    for j, c in enumerate(parent['upstream_cases']):
        sp = int(c['frame_base'], 16)
        counter = c['configuration']['counter64']
        assert sp % 16 == 0
        expected = [(0x2b0, 8, 0x1004c356c, ROOT_CELL),
                    (0x9e0, 4, 0x10061a4b8, (sp+0x9e0+counter+WORD_BIAS) & 0xffffffff),
                    (0x9e8, 8, 0x10061a4a8, (sp+0x9e0+counter) & MASK)]
        writers = []
        for offset, width, pc, value in expected:
            ww = [w for w in c['source_writes'] if overlap(w, sp+offset, width)]
            assert len(ww) == 1
            w = ww[0]
            assert (w['pc'], w['address'], w['size_bytes'], w['after_hex']) == (
                hex(pc), hex(sp+offset), width, value.to_bytes(width, 'little').hex())
            assert c['source_visits'][w['source_visit_index']]['pc'] == hex(pc)
            writers.append(w)
        assert not any(overlap(w, sp+0x9e4, 4) for w in c['source_writes'])
        reads = []
        for pc, address, value in [(0x10061a464, int(c['record_address'], 16), counter ^ ENC),
                                   (0x1004c355c, POOL_SLOT, qword(POOL_SLOT))]:
            rr = [r for r in c['source_reads'] if r['pc'] == hex(pc)]
            assert len(rr) == 1
            r = rr[0]
            assert (r['address'], r['size_bytes'], r['bytes_hex']) == (hex(address), 8, value.to_bytes(8, 'little').hex())
            assert c['source_visits'][r['source_visit_index']]['pc'] == hex(pc)
            reads.append(r)
        for event in writers+reads:
            v = c['source_visits'][event['source_visit_index']]
            assert v['bytes_hex'] == IMAGE.read(int(v['pc'], 16), 4).hex()
        out.append({'profile_index': j, 'variant': c['variant'], 'frame_base': hex(sp),
                    'declared_counter64': hex(counter), 'writers': writers, 'reads': reads,
                    'SP9e4_padding_has_no_retained_writer': True})
    assert len(out) == 12
    assert len({(x['frame_base'], x['declared_counter64']) for x in out}) == 4
    return out


def frontiers():
    parent = json.loads(read(ROOT/'daemon_constructor_buffer_checks.json'))
    out = Counter()
    for c in parent['coverage']:
        terminal = unpack(c['derived_terminal_state_packed'])
        sp = int(terminal['boundary']['SP'], 16)
        m = state_bytes(terminal)
        if terminal['boundary']['pc'] == '0x1008a2704':
            for offset, n in [(0x2b0, 8), (0x9e0, 16)]:
                assert all(sp+offset+j not in m for j in range(n))
            out['success_exports_with_undefined_root_and_descriptor'] += 1
        else:
            assert terminal['boundary']['pc'] == '0x10074abc8'
            assert all(S+48+j not in m for j in range(8))
            out['NULL_exports_with_undefined_S30'] += 1
    assert dict(out) == {'NULL_exports_with_undefined_S30': 152,
                         'success_exports_with_undefined_root_and_descriptor': 152}
    return dict(out)


def descriptor(sp, counter):
    v = Scalar()
    v.seed('sp', sp)
    v.seed('x0', 0x6900001000)
    mem(v, 0x6900001000, 8, counter ^ ENC)
    v.run_block(0x10061a464, 0x10061a4bc)
    return v


def obligations():
    out = []
    def prove(label, bad, premises=()):
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*premises)
        assert s.check() == z3.sat, label
        s.add(z3.simplify(bad))
        assert s.check() == z3.unsat, label
        out.append({'label': label, 'premises_nonvacuous': True,
                    'query': s.to_smt2(), 'result': 'unsat'})

    sp, counter, pool = z3.BitVecs('descriptor_SP64 descriptor_counter64 descriptor_pool64', 64)
    b = sp+0x9e0
    v = descriptor(sp, counter)
    general = b+counter+2*(b & counter & 2)-(b & 2)
    prove('all_u64_initializer_pair_exact_including_unaligned_SP', z3.Or(
        v.stores[0]['address'] != sp+0x9e8, v.stores[0]['value'] != general,
        v.stores[1]['address'] != b,
        v.stores[1]['value'] != z3.Extract(31, 0, general)+WORD_BIAS))
    prove('aligned_SP_initializer_pair_is_address_plus_counter', z3.Or(
        v.stores[0]['value'] != b+counter,
        v.stores[1]['value'] != z3.Extract(31, 0, b+counter)+WORD_BIAS), [sp & 15 == 0])

    v = Scalar()
    v.seed('sp', sp)
    v.seed('x11', pool)
    v.run_block(0x1004c3560, 0x1004c3570)
    prove('all_u64_root_pool_signed_bias', z3.Or(v.stores[-1]['address'] != sp+0x2b0,
                                               v.stores[-1]['value'] != pool+0xffffffff85bfe8be))

    q = b+counter
    v = Scalar()
    v.seed('x14', b)
    mem(v, b, 4, z3.Extract(31, 0, q)+WORD_BIAS)
    mem(v, b+8, 8, q)
    v.run_block(0x100a5eac8, 0x100a5ead4)
    decoded_bias = v.read('w15')
    # Intervening instructions define W15/W8/W5, but neither X17 nor X14.
    for i in DEC.disasm(IMAGE.read(0x100a5ead4, 0x100a5eaec-0x100a5ead4), 0x100a5ead4):
        assert not {'x17', 'w17', 'x14', 'w14'} & {i.reg_name(r) for r in i.regs_access()[1]}
    v.run_block(0x100a5eaec, 0x100a5eaf0)
    prove('all_u64_compatible_consumer_recovers_counter_and_word_bias',
          z3.Or(v.read('x14') != counter, decoded_bias != WORD_BIAS))

    old, local, returned = z3.BitVecs('feedback_old64 feedback_local_SP64 feedback_returned64', 64)
    v = Scalar()
    v.seed('x19', 0x6900002000)
    mem(v, 0x6900002000, 8, old)
    v.run_block(0x100b21308, 0x100b21318)
    new = old*0x2ecd+1
    prove('all_u64_feedback_phase_value', z3.Or(v.read('x21') != old, v.read('x2') != new))
    # Exact skipped source def-use: controller/table operations preserve X2.
    for i in DEC.disasm(IMAGE.read(0x100b21318, 0x100b21374-0x100b21318), 0x100b21318):
        assert not {'x2', 'w2', 'x21', 'w21', 'sp'} & {i.reg_name(r) for r in i.regs_access()[1]}

    v = Scalar()
    v.seed('x2', new)
    v.seed('x21', old)
    v.seed('sp', local)
    v.run_block(0x100b21378, 0x100b2139c)
    extent = (z3.LShR(new, 60)+1)*16
    prove('all_u64_feedback_stack_extent_and_seed', z3.Or(
        v.read('sp') != local-extent, v.read('x20') != local-extent,
        v.stores[-1]['address'] != local-extent, v.stores[-1]['value'] != old-0xd0,
        z3.ULT(extent, 16), z3.UGT(extent, 256), extent & 15 != 0))

    v = Scalar()
    v.seed('x1', 0x6900003000)
    mem(v, 0x6900003000, 8, old-0xd0)
    v.run_block(0x100b0051c, 0x100b00528)
    prove('all_u64_nested_seed_restore_phase', cell(v, 0x6900003000, 8) != old)

    v = Scalar()
    v.seed('x20', 0x6900003000)
    v.seed('x19', 0x6900002000)
    v.seed('x21', old)
    mem(v, 0x6900003000, 4, z3.Extract(31, 0, returned))
    v.run_block(0x100b2143c, 0x100b2144c)
    want = z3.ZeroExt(48, z3.Extract(15, 0, returned-old)) << 4
    prove('all_u64_feedback_return_quantization', z3.Or(
        v.stores[-1]['address'] != 0x6900002000, v.stores[-1]['value'] != want))
    assert len(out) == 8
    return out


def controls():
    # Falsifies the initially plausible unrestricted q=SP+0x9e0+counter.
    v = descriptor(z3.BitVecVal(2, 64), z3.BitVecVal(0, 64))
    got = z3.simplify(v.stores[0]['value']).as_long()
    assert got == 0x9e0 and got != 2+0x9e0
    return {'unaligned_SP': '0x2', 'counter64': '0x0', 'actual_q64': hex(got),
            'unrestricted_address_plus_counter_prediction': '0x9e2',
            'unrestricted_formula_rejected': True}


def build():
    for name, digest in PINS.items():
        assert sha(ROOT/name) == digest, (name, sha(ROOT/name))
    slot = qword(POOL_SLOT)
    assert (slot+0xffffffff85bfe8be) & MASK == ROOT_CELL
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'dependencies': {n: sha(ROOT/n) for n in DEPS}, 'parent_pins': PINS,
            'source_regions': source(), 'initializer_profiles': profiles(),
            'inherited_frontiers': frontiers(), 'source_proofs': obligations(),
            'negative_control': controls(),
            'root_pool': {'address': hex(POOL_SLOT), 'decoded_rebase_target64': hex(slot),
                          'original_slot_bytes_hex': IMAGE.read(POOL_SLOT, 8).hex(),
                          'fixup_verification': verify_original_fixups([POOL_SLOT]),
                          'signed_bias64': '0xffffffff85bfe8be', 'target': hex(ROOT_CELL),
                          'original_target_bytes_hex': IMAGE.read(ROOT_CELL, 8).hex()},
            'verified_counts': {'initializer_profiles': 12, 'distinct_frame_counter_pairs': 4,
                                'initializer_writers_checked': 36, 'initializer_reads_checked': 24,
                                'inherited_terminal_exports_checked': 304,
                                'source_queries_unsat': 8, 'negative_controls': 1},
            'new_guest_execution_intervals': 0, 'native_API_executed': False,
            'initializer_to_current_caller_epoch_join_established': False,
            'feedback_store_destination_join_established': False,
            'native_daemon_kext_pairing_established': False,
            'all_checks_pass': True, 'full_goal_complete': False}


if __name__ == '__main__':
    result = build()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']), flush=True)
