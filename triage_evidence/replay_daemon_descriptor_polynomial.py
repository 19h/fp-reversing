#!/usr/bin/env python3
"""Independent terminal-node replay, admissions and composed polynomial proof.
O(visits*frame state + parents*demands + proof DAG) time; O(receipts+parent
maps+largest interval+proof DAG) space, excluding solver search complexity.
Source bit identities and exact ring normalizations are composed explicitly;
no unsupported monolithic nonlinear SMT result is claimed. No native API runs.
"""
import json
from copy import deepcopy
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, CS, qword, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_network_record import state_bytes
from audit_daemon_state_table_mixing import Scalar, admission, expected, requirement_receipt
from audit_daemon_state_emitter_completion import requirements
from lskd_values_symbolic import mem
import recover_daemon_descriptor_polynomial as R
import replay_daemon_constructor_buffer as Replay

DEPS = ['replay_daemon_constructor_buffer.py', 'audit_daemon_state_table_mixing.py',
        'audit_daemon_state_emitter_completion.py', 'lskd_values_symbolic.py']
TABLE, COEFFICIENTS = 0x101039ef0, 0x100eee6f0
SLOTS = [TABLE+index*8 for index in [0x77ec, 0xaefd]]
MASK = (1 << 32)-1


def obligations():
    proofs, normalizations = [], []
    def prove(label, bad):
        solver = z3.Solver()
        solver.set(timeout=30000)
        assert solver.check() == z3.sat
        solver.add(z3.simplify(bad))
        result = solver.check()
        assert result == z3.unsat, (label, str(result), solver.reason_unknown())
        proofs.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': solver.to_smt2()})
    def normalize(label, source, target):
        delta = z3.simplify(source-target, som=True)
        assert z3.is_bv_value(delta) and delta.as_long() == 0, (label, delta)
        normalizations.append({'label': label, 'source': source.sexpr(), 'target': target.sexpr(),
                               'difference_normal_form': delta.sexpr(), 'width_bits': 32})
    t, s, z, total, h, even_s, even_z = z3.BitVecs('poly_t32 poly_s32 poly_z32 poly_total32 poly_h32 poly_even_s32 poly_even_z32', 32)
    v = Scalar()
    v.seed('w13', t)
    v.run_block(0x100bd9418, 0x100bd941c)
    prove('all_u32_source_ASR_and_parity_reconstruct_product', t != 2*v.read('w14')+(t&1))
    k, inverse, addend = 0x03c473bb, 0x054c5973, 0xfc3b8c45
    for bit in [0, 1]:
        v = Scalar()
        v.seed('w13', bit)
        v.seed('w14', h)
        v.run_block(0x100bd941c, 0x100bd9438)
        normalize('source_quadratic_parity_'+str(bit), v.read('w16'), k*(2*h+bit)+k*k)
    assert k*inverse & MASK == 1 and (k*k*inverse+addend)&MASK == 0
    v = Scalar()
    v.seed('w16', k*t+k*k)
    v.seed('w17', inverse)
    v.seed('w1', addend)
    v.run_block(0x100bd94cc, 0x100bd94d0)
    normalize('composed_source_power_update_recovers_product', v.read('w16'), t)
    v = Scalar()
    for name, value in {'w0': z, 'w15': s, 'w9': total, 'w16': 0, 'w17': inverse, 'w8': 0x92f2}.items():
        v.seed(name, value)
    v.run_block(0x100bd94b4, 0x100bd94f8)
    source_formula = (total+z3.If(s&1 != 0, z, 0)+z3.If(z&1 != 0, s, 0)
                      +(z&0x7ffffffe)*(s&0xfffffffe)-((s&1)&(z&1)))
    prove('all_u32_source_coefficient_update_matches_masked_formula', v.read('w9') != source_formula)
    prove('all_u32_even_parity_decompositions', z3.Or(s != (s&0xfffffffe)+(s&1), z != (z&0xfffffffe)+(z&1)))
    prove('all_u32_coefficient_mask_splits_high_bit', (z&0x7ffffffe) != (z&0xfffffffe)-(z&0x80000000))
    prove('all_u32_discarded_high_bit_times_even_is_zero', (z&0x80000000)*(s&0xfffffffe) != 0)
    for sb in [0, 1]:
        for zb in [0, 1]:
            source = total+sb*(even_z+zb)+zb*(even_s+sb)+even_s*even_z-sb*zb
            normalize('coefficient_ring_parities_'+str(sb)+'_'+str(zb), source, total+(even_s+sb)*(even_z+zb))
    n = z3.BitVec('poly_counter64', 64)
    v = Scalar()
    v.seed('x12', n)
    v.seed('x11', 0)
    v.run_block(0x100bd94f8, 0x100bd9524)
    prove('all_u64_countdown_dispatch_tests_zero', z3.Or(v.read('w12') != z3.If(n == 0, z3.BitVecVal(0xaefd, 32), z3.BitVecVal(0x77ec, 32)), v.read('x17') != n-1))
    bad = []
    for index, target in [(0x77ec, 0x100bd9408), (0xaefd, 0x1009e4018)]:
        v = Scalar()
        for name, value in {'x20': TABLE, 'w12': index, 'x17': n-1, 'w16': s}.items():
            v.seed(name, value)
        for slot in SLOTS:
            mem(v, slot, 8, qword(slot))
        v.run_block(0x100bd9524, 0x100bd9534)
        bad.extend([v.read('x0') != target, v.read('x17') != 0x957, v.read('x12') != n-1, v.read('w15') != s])
    prove('both_original_polynomial_dispatches_and_IA_modifier', z3.Or(*bad))
    old_raw = z3.BitVec('poly_old_extent_raw32', 32)
    v = Scalar()
    for name, value in {'w8': 0x74c239e7, 'w21': 0x4c, 'w22': old_raw}.items():
        v.seed(name, value)
    v.run_block(0x100c05638, 0x100c0564c)
    prove('all_u32_new_extent_adds_twenty_in_recovered_phase', v.read('w8') != old_raw+20)
    raw = z3.BitVec('poly_new_extent_raw32', 32)
    v = Scalar()
    v.seed('w8', raw)
    v.seed('w10', 0xc4eb)
    v.run_block(0x100d64024, 0x100d64054)
    prove('all_u32_pending_allocation_count_in_recovered_phase', z3.Or(v.read('x0') != z3.ZeroExt(32, raw+0xef133bef), v.read('w25') != 0x9436, v.read('w28') != 0xa10b))
    assert len(proofs) == 9 and len(normalizations) == 7
    return proofs, normalizations


def semantics(row):
    frames = row['source_frames']
    entries = [f for f in frames if f['pc'] == '0x100bd9408']
    exits = [f for f in frames if f['pc'] == '0x100bd9534']
    loads = [r for r in row['source_reads'] if r['pc'] == '0x100bd94b0']
    assert len(entries) == len(exits) == len(loads) == 11
    coefficients = [int.from_bytes(IMAGE.read(COEFFICIENTS+4*j, 4), 'little') for j in range(11)]
    power, acc, value, visits = 1, 0xd2b92e63, 0, []
    for j, (entry, exit_frame, load) in enumerate(zip(entries, exits, loads)):
        a, b = ([int(x, 16) for x in f['registers31']] for f in [entry, exit_frame])
        assert a[9] == value and a[10] == acc and a[11] == 0 and a[12] == 10-j and a[15] == power
        assert int(load['address'], 16) == COEFFICIENTS+4*(10-j)
        assert load['bytes_hex'] == IMAGE.read(int(load['address'], 16), 4).hex()
        value = (value+coefficients[10-j]*power)&MASK
        power = (power*acc)&MASK
        assert b[9] == value and b[15] == b[16] == power and b[12] == ((9-j)&((1<<64)-1))
        edge = next(x for x in row['logical_edges'] if x['pc'] == exit_frame['pc'] and row['source_frames'][x['source_visit_index']] == exit_frame)
        assert edge['target'] == hex(0x100bd9408 if j < 10 else 0x1009e4018)
        assert edge['modifier'] == '0x957'
        visits.append({'coefficient_index': 10-j, 'coefficient': hex(coefficients[10-j]),
                       'power_before': hex(a[15]), 'sum_after': hex(value), 'power_after': hex(power), 'edge': edge})
    assert value == 0 and power == 0x4f26eb1b
    # Resolve the constant bank through source reads of inherited mutable roots
    # and original chained-rebase slots. Roots are not initial-image constants.
    resolver_pcs = [0x100bd9440, 0x100bd9444, 0x100bd9460, 0x100bd9474,
                    0x100bd9480, 0x100bd9490, 0x100bd94a0]
    resolver = []
    for pc in resolver_pcs:
        reads = [r for r in row['source_reads'] if r['pc'] == hex(pc)]
        assert len(reads) == 11 and len({(r['address'], r['size_bytes'], r['bytes_hex']) for r in reads}) == 1
        resolver.append(reads[0])
    # Source replay checks address arithmetic and decoded original fixups.
    phase_reads = [{'address': r['address'], 'size_bytes': r['size_bytes'], 'bytes_hex': r['bytes_hex']} for r in resolver]
    pending = row['boundary']
    assert pending['pc'] == hex(R.STOP) and pending['detail'] == {'target': '0x7c009800', 'symbol': 'libSystem/_malloc', 'modifier': '0x6aa4'}
    assert int(pending['registers31'][0], 16) == 77
    allocator_entry = next(f for f in frames if f['pc'] == '0x100d64014')
    extent_entry = next(f for f in frames if f['pc'] == '0x100c05638')
    assert int(extent_entry['registers31'][8], 16) == 0x74c239e7
    assert int(extent_entry['registers31'][21], 16) == 0x4c
    regs = [int(x, 16) for x in allocator_entry['registers31']]
    assert regs[8] == 0x10ecc45e and regs[10] == 0xc4eb and regs[22] == regs[23] == 0x10ecc44a
    assert regs[8] == (regs[22]+20)&MASK and (regs[22]+0xef133bef)&MASK == 57
    assert (regs[8]+0xef133bef)&MASK == 77
    malloc_read = next(r for r in row['source_reads'] if r['pc'] == '0x100d640a4')
    assert malloc_read['address'] == '0x10109ff58'
    return {'coefficient_base': hex(COEFFICIENTS), 'coefficients_index_0_to_10': [hex(x) for x in coefficients],
            'coefficient_bytes_hex': IMAGE.read(COEFFICIENTS, 44).hex(), 'selector_phase_reads': phase_reads,
            'polynomial': 'u32(sum(C[10-j]*a**j for j in range(11)))', 'argument32': hex(acc),
            'result32': hex(value), 'final_power32': hex(power), 'iterations': visits,
            'allocation_phase': {'entry': allocator_entry['pc'], 'raw_old32': hex(regs[22]), 'raw_new32': hex(regs[8]),
                                 'extent_update_PC': extent_entry['pc'], 'extent_phase_W8': '0x74c239e7', 'extent_phase_W21': '0x4c',
                                 'observed_raw_delta_bytes': 20, 'decoded_old_bytes': 57, 'pending_requested_bytes': 77,
                                 'decode_bias32': '0xef133bef', 'phase_W10': '0xc4eb', 'pending_import_read': malloc_read},
            'internal_calls': row['source_calls'], 'malloc_executed': False}


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    incoming = R.parents()
    old = json.loads(read(ROOT/'daemon_descriptor_walk_checks.json'))
    for p, digest in R.PINS.items():
        assert sha(ROOT/p) == digest
    totals, admissions = Counter(), Counter()
    classes, seen, parent_tags = [], set(), {}
    views = {x['cohort_index']: x for x in e['coverage']}
    for ci, c in enumerate(e['classes']):
        j = c['representative_cohort_index']
        rep, fixtures = R.premised(incoming[j]['state'])
        assert fixtures == c['node_premises']
        row = R.unpack(c['interval_packed'])
        Replay.GS.joined(rep, row)
        old_ci = incoming[j]['parent_class_index']
        if old_ci not in parent_tags:
            prefix = R.unpack(old['classes'][old_ci]['interval_packed'])
            _, parent_tags[old_ci], _ = Replay.origins(prefix)
        journal, tags, pointer_counts = Replay.origins(row, parent_tags[old_ci])
        assert tags[0]['X8'] == (0x10109ff58, 0x7c009800)
        deps = {'required': set(), 'written': set()}
        lift = Replay.Lift(row, deps, journal).run()
        assert lift['all_checks_pass']
        totals.update(lift['verified_counts'])
        projection = R.B.registers([row])
        assert projection == c['register_projection'] and projection['vector_accesses'] == 0
        assert deps['required'] <= set(projection['required']) and deps['written'] == set(projection['written'])
        need, effects, _ = requirements(rep, [row])
        node = int(fixtures[0]['address'], 16)
        assert all(node+k not in need and node+k not in effects for k in range(4, 8))
        for fixture in fixtures:
            address = int(fixture['address'], 16)
            for remove in [False, True]:
                bad = state_bytes(rep)
                if remove:
                    del bad[address]
                else:
                    bad[address] ^= 1
                try:
                    admission(rep, rep, need, projection, memory=bad)
                except AssertionError:
                    admissions['node_fault_controls_rejected'] += 1
                else:
                    raise AssertionError('bad node admitted')
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
        meaning = semantics(row)
        for j in c['member_cohort_indices']:
            assert j not in seen
            seen.add(j)
            entry, f = R.premised(incoming[j]['state'])
            m, values = admission(entry, rep, need, projection)
            terminal = R.B.export(entry, row, projection)
            expected(entry, terminal, effects, projection, row, m, values)
            assert terminal == R.unpack(views[j]['derived_terminal_state_packed']) and views[j]['class_index'] == ci
            memory = state_bytes(terminal)
            assert all(node+k not in memory for k in range(4, 8))
            for base, size in [(R.B.S, 64), (R.B.U, 48), (R.B.F, 57), (R.B.J, 552)]:
                assert {a: b for a, b in m.items() if base <= a < base+size} == {a: b for a, b in memory.items() if base <= a < base+size}
                assert not any(base <= int(w['address'], 16)+k < base+size for w in row['source_writes'] for k in range(w['size_bytes']))
            admissions.update(parent_admissions=1, incoming_byte_demands=len(need),
                              incoming_register_demands=len(projection['required']), terminal_exports=1)
        classes.append({'class_index': ci, 'full_replay': lift, 'pointer_counts': pointer_counts,
                        'pending_malloc_pointer_origin': {'slot': '0x10109ff58', 'model_target': '0x7c009800'},
                        'parent_pointer_class_index': old_ci, 'required_bytes': requirement_receipt(need),
                        'semantics': meaning, 'member_cohort_indices': c['member_cohort_indices'], 'all_checks_pass': True})
    assert seen == set(range(152))
    proofs, normalizations = obligations()
    pending_instruction = next(CS.disasm(IMAGE.read(R.STOP, 4), R.STOP))
    assert pending_instruction.mnemonic == 'blraa' and pending_instruction.op_str == 'x8, x17'
    invariants = {'X7', 'X10', 'X11', 'X19', 'X20', 'X22'}
    for instruction in CS.disasm(IMAGE.read(0x100bd9408, 0x130), 0x100bd9408):
        assert not invariants & set(R.B.accesses(instruction.address)[1])
        assert not instruction.mnemonic.startswith('st')
    return {'scope': __doc__, 'replayer_sha256': sha(__file__), 'generator_sha256': sha(R.__file__),
            'checks_sha256': sha(ROOT/(R.P+'_checks.json')), 'source_sha256': sha(SOURCE),
            'replayer_dependencies': {p: sha(ROOT/p) for p in DEPS},
            'verified_counts': e['verified_counts'], 'independent_totals': dict(totals),
            'admissions': dict(admissions), 'classes': classes, 'source_proofs': proofs,
            'source_normalizations': normalizations, 'outgoing_fixups': verify_original_fixups([*SLOTS, 0x10109ff58]),
            'pending_call_source': {'pc': hex(R.STOP), 'bytes_hex': IMAGE.read(R.STOP, 4).hex(),
                                    'mnemonic': 'blraa', 'operands': 'x8, x17', 'executed': False},
            'composed_contract': {'power_update': 'u32(power32*argument32)',
                                 'sum_update': 'u32(sum32+coefficient32*power32)',
                                 'entry_counter': 10, 'iterations': 11, 'degree': 10,
                                 'coefficient_composition': 'source masked formula + parity decomposition + high-bit/even lemma + four ring cases',
                                 'power_composition': 'source ASR/parity decomposition + two source square normalizations + inverse constants + source affine update'},
            'source_queries_unsat': len(proofs), 'exact_ring_normalizations': len(normalizations),
            'loop_invariants': {'preserved_registers': sorted(invariants), 'no_source_stores': True},
            'native_API_executed': False, 'native_ownership_established': False,
            'native_daemon_kext_pairing_established': False, 'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    result = audit()
    (ROOT/(R.P+'_replay.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'independent_totals': result['independent_totals'], 'admissions': result['admissions'],
                      'source_queries_unsat': result['source_queries_unsat'], 'exact_ring_normalizations': result['exact_ring_normalizations']}), flush=True)
