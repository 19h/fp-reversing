#!/usr/bin/env python3
"""Independent full root-prefix replay, 152 admissions and walk equations.
O(visits*frame state + parents*demands + query DAG) time; O(receipts+parent
maps+largest interval+query DAG) space, excluding solver search complexity.
All operations are source/model checks; no native target operation executes.
"""
import json
from collections import Counter
import z3
from copy import deepcopy
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT, SOURCE, IMAGE, CS, qword, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_network_record import state_bytes
from audit_daemon_state_table_mixing import Scalar, admission, expected, requirement_receipt
from audit_daemon_state_emitter_completion import requirements
from lskd_values_symbolic import mem
import recover_daemon_descriptor_walk as R
import replay_daemon_constructor_buffer as Replay

DEPS = ['replay_daemon_constructor_buffer.py', 'audit_daemon_state_table_mixing.py',
        'audit_daemon_state_emitter_completion.py', 'lskd_values_symbolic.py']
TABLE = 0x101039ef0
SLOTS = [TABLE+0x77dd*8, TABLE+0x77ec*8]


def obligations():
    out = []
    def prove(label, bad):
        s = z3.Solver()
        s.set(timeout=30000)
        assert s.check() == z3.sat
        s.add(z3.simplify(bad))
        result = s.check()
        assert result == z3.unsat, (label, str(result), s.reason_unknown())
        out.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': s.to_smt2()})
    cursor, limit, word, acc = z3.BitVecs('walk_cursor32 walk_limit32 walk_word32 walk_acc32', 32)
    node, nxt, key, a, y = z3.BitVecs('walk_node64 walk_next64 walk_key64 walk_A64 walk_y64', 64)
    b = z3.BitVec('walk_B32', 32)
    v = Scalar()
    v.seed('w8', cursor)
    v.run_block(0x100a5ead8, 0x100a5eae8)
    prove('all_u32_cursor_increments_one', z3.Or(v.read('w8') != cursor+1,
                                               v.read('x8') != z3.ZeroExt(32, cursor+1)))
    v = Scalar()
    for n, x in {'x14': node, 'w10': acc, 'x1': key, 'x2': key*2, 'x3': -key}.items():
        v.seed(n, x)
    mem(v, node, 4, word)
    mem(v, node+8, 8, node+nxt)
    v.run_block(0x100a5eac8, 0x100a5ead8)
    decoded_acc = v.read('w10')
    v.run_block(0x100a5eaec, 0x100a5eb00)
    prove('all_u64_node_delta_and_affine_mix_recover_next', z3.Or(v.read('x14') != nxt,
          decoded_acc != acc ^ (word-z3.Extract(31, 0, node+nxt))))
    v = Scalar()
    v.seed('x17', a)
    v.seed('w15', b)
    v.run_block(0x100a5eb04, 0x100a5eb10)
    prove('all_u64_A_u32_B_signed_OR_detects_inequality',
          (z3.Extract(63, 63, v.read('x15')) == 1) != (a != z3.ZeroExt(32, b)))
    v = Scalar()
    v.seed('x14', node)
    v.seed('x17', node+nxt)
    v.seed('x15', y)
    v.run_block(0x100a5eaec, 0x100a5eaf0)
    v.run_block(0x100a5eb10, 0x100a5eb18)
    prove('all_u64_CCMP_CSET_zero_next_or_negative_OR',
          v.read('w15') != z3.If(z3.Or(nxt == 0, y < 0), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32)))
    v = Scalar()
    v.seed('x0', z3.ZeroExt(32, limit))
    v.seed('w16', limit)
    v.seed('w8', cursor)
    v.run_block(0x100a5eae8, 0x100a5eaec)
    v.run_block(0x100a5eb00, 0x100a5eb04)
    prove('all_u32_zeroextended_limit_width_test_is_unsigned_bound',
          (v.read('x17') != v.read('x15')) != z3.UGT(cursor, limit))
    bad = []
    for decision, slot, target in [(0, SLOTS[0], 0x100a5eac4), (1, SLOTS[1], 0x100bd9408)]:
        v = Scalar()
        for n, x in {'w15': decision, 'w4': 0x31, 'w13': 0x77dd, 'x20': TABLE}.items():
            v.seed(n, x)
        for s in SLOTS:
            mem(v, s, 8, qword(s))
        v.run_block(0x100a5eb18, 0x100a5eb2c)
        bad.extend([v.read('x5') != target, v.read('x17') != 0x957, v.read('w15') != 1])
    prove('both_original_walk_dispatches_and_IA_modifier', z3.Or(*bad))
    assert len(out) == 6
    return out


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    incoming = R.parents()
    for p, digest in R.PINS.items():
        assert sha(ROOT/p) == digest
    totals, admissions = Counter(), Counter()
    classes = []
    views = {x['cohort_index']: x for x in e['coverage']}
    seen = set()
    for ci, c in enumerate(e['classes']):
        rep, root = R.premised(incoming[c['representative_cohort_index']]['state'])
        assert root == c['root_premise']
        row = R.unpack(c['interval_packed'])
        Replay.GS.joined(rep, row)
        journal, tags, pointer_counts = Replay.origins(row)
        deps = {'required': set(), 'written': set()}
        lift = Replay.Lift(row, deps, journal).run()
        assert lift['all_checks_pass']
        totals.update(lift['verified_counts'])
        projection = R.B.registers([row])
        assert projection == c['register_projection'] and projection['vector_accesses'] == 0
        assert deps['required'] <= set(projection['required']) and deps['written'] == set(projection['written'])
        need, effects, _ = requirements(rep, [row])
        root_address = int(root['address'], 16)
        for remove in [False, True]:
            bad = state_bytes(rep)
            if remove:
                del bad[root_address]
            else:
                bad[root_address] ^= 1
            try:
                admission(rep, rep, need, projection, memory=bad)
            except AssertionError:
                admissions['root_fault_controls_rejected'] += 1
            else:
                raise AssertionError('bad root admitted')
        bad = R.B.machine(rep)
        bad['SP'] = hex(int(bad['SP'], 16)^16)
        try:
            admission(rep, rep, need, projection, values=bad)
        except AssertionError:
            admissions['changed_SP_rejected'] += 1
        else:
            raise AssertionError('changed SP admitted')
        try:
            admission({**rep, 'foreign_owners': rep['foreign_owners'][:-1]}, rep, need, projection)
        except AssertionError:
            admissions['changed_owner_rejected'] += 1
        else:
            raise AssertionError('changed owner admitted')
        assert 'Q0' not in projection['required'] and 'Q0' not in projection['written']
        probe = deepcopy(rep)
        probe['boundary']['Q_registers32'][0] = hex(int(probe['boundary']['Q_registers32'][0], 16)^1)
        memory, values = admission(probe, rep, need, projection)
        terminal = R.B.export(probe, row, projection)
        expected(probe, terminal, effects, projection, row, memory, values)
        admissions['unused_Q0_preservation_controls'] += 1
        phase = row['boundary']['registers31']
        for reg, value in {0: 19, 1: 0xd839aac13e909dd4, 2: 0xb07355827d213ba8,
                           3: 0x27c6553ec16f622c, 4: 0x31, 8: 1, 10: 0x6773dea5,
                           13: 0x77dd, 16: 19, 20: TABLE}.items():
            assert int(phase[reg], 16) == value
        for j in c['member_cohort_indices']:
            assert j not in seen
            seen.add(j)
            entry, f = R.premised(incoming[j]['state'])
            m, values = admission(entry, rep, need, projection)
            terminal = R.B.export(entry, row, projection)
            expected(entry, terminal, effects, projection, row, m, values)
            assert terminal == R.unpack(views[j]['derived_terminal_state_packed']) and views[j]['class_index'] == ci
            outer = int(entry['boundary']['SP'], 16)
            memory = state_bytes(terminal)
            assert int(phase[14], 16) == outer+0x9e0
            assert all(outer+0x9e0+k not in memory for k in range(16))
            for base, size in [(R.B.S, 64), (R.B.U, 48), (R.B.F, 57), (R.B.J, 552)]:
                assert {a: b for a, b in m.items() if base <= a < base+size} == {a: b for a, b in memory.items() if base <= a < base+size}
            admissions.update(parent_admissions=1, incoming_byte_demands=len(need),
                              incoming_register_demands=len(projection['required']), terminal_exports=1)
        classes.append({'class_index': ci, 'full_replay': lift, 'pointer_counts': pointer_counts,
                        'required_bytes': requirement_receipt(need), 'phase_registers31': phase,
                        'member_cohort_indices': c['member_cohort_indices'], 'all_checks_pass': True})
    assert seen == set(range(152))
    proofs = obligations()
    fixups = verify_original_fixups(SLOTS)
    i = next(CS.disasm(IMAGE.read(0x100a5eb2c, 4), 0x100a5eb2c))
    assert i.mnemonic == 'braa' and i.op_str == 'x5, x17'
    dec = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    dec.detail = True
    invariants = {'x0', 'w0', 'x1', 'w1', 'x2', 'w2', 'x3', 'w3', 'x4', 'w4',
                  'x13', 'w13', 'x16', 'w16', 'x20', 'w20'}
    for i in dec.disasm(IMAGE.read(0x100a5eac4, 0x6c), 0x100a5eac4):
        assert not invariants & {i.reg_name(r) for r in i.regs_access()[1]}
        assert not i.mnemonic.startswith('st')
    return {'scope': __doc__, 'replayer_sha256': sha(__file__), 'generator_sha256': sha(R.__file__),
            'checks_sha256': sha(ROOT/(R.P+'_checks.json')), 'source_sha256': sha(SOURCE),
            'replayer_dependencies': {p: sha(ROOT/p) for p in DEPS},
            'verified_counts': e['verified_counts'], 'independent_totals': dict(totals),
            'admissions': dict(admissions), 'classes': classes, 'source_proofs': proofs,
            'outgoing_fixups': fixups,
            'consumer_source': {'start': '0x100a5eac4', 'end': '0x100a5eb30',
                                'bytes_hex': IMAGE.read(0x100a5eac4, 0x6c).hex()},
            'composed_contract': {'exit': 'next64 == 0 OR unsigned(u32(cursor32+1)) > limit32',
                                 'next_node': 'u64(qword_at_node_plus8-node_address)',
                                 'accumulator': 'acc32 XOR u32(word_at_node-low32(qword_at_node_plus8))',
                                 'source_lemmas': [p['label'] for p in proofs[:5]],
                                 'initial_cursor32': 1, 'limit32': 19, 'max_readable_node_visits': 19},
            'loop_source_invariants': {'preserved_register_names': sorted(invariants),
                                       'no_source_stores': True, 'max_back_edges': 18,
                                       'decoded_input_word_address_role_established': True},
            'source_queries_unsat': 6, 'native_API_executed': False,
            'native_ownership_established': False, 'native_daemon_kext_pairing_established': False,
            'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    result = audit()
    (ROOT/(R.P+'_replay.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'independent_totals': result['independent_totals'], 'admissions': result['admissions'],
                      'source_queries_unsat': result['source_queries_unsat']}), flush=True)
