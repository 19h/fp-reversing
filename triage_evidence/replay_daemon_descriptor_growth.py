#!/usr/bin/env python3
"""Independent growth/cleanup replay, all608 admissions and byte custody.
O(visits*frame state + admissions*demands + proof DAG) time;
O(receipts+parent maps+largest interval+proof DAG) space, excluding solver
search complexity. ABI/owner effects are declared premises; no native API.
"""
import json
from copy import deepcopy
from collections import Counter
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, CS, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_network_record import state_bytes
from audit_daemon_state_table_mixing import Scalar, admission, expected, requirement_receipt
from audit_daemon_state_emitter_completion import requirements
from lskd_values_symbolic import mem
import recover_daemon_descriptor_growth as R
import replay_daemon_constructor_buffer as Replay

DEPS = ['replay_daemon_constructor_buffer.py', 'audit_daemon_state_table_mixing.py',
        'audit_daemon_state_emitter_completion.py', 'lskd_values_symbolic.py']
OBJECTS = [('S', R.B.S, 64), ('U', R.B.U, 48), ('F', R.B.F, 57), ('H', R.H, 77), ('J', R.B.J, 552)]


def obligations():
    out = []
    def prove(label, bad):
        solver = z3.Solver()
        solver.set(timeout=30000)
        assert solver.check() == z3.sat
        solver.add(z3.simplify(bad))
        result = solver.check()
        assert result == z3.unsat, (label, str(result), solver.reason_unknown())
        out.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': solver.to_smt2()})
    i, src, dst = z3.BitVecs('growth_i64 growth_src64 growth_dst64', 64)
    byte = z3.BitVec('growth_byte8', 8)
    v = Scalar()
    for name, value in {'x9': i+1, 'x24': src, 'x10': dst}.items():
        v.seed(name, value)
    mem(v, src+i, 1, byte)
    v.run_block(0x100b5c9b0, 0x100b5c9bc)
    assert len(v.stores) == 1
    w = v.stores[0]
    prove('all_u64_indices_original_byte_copy_step', z3.Or(v.read('x9') != i, w['address'] != dst+i, w['value'] != byte))
    old, a, b = z3.BitVecs('growth_old_raw32 growth_phase_a32 growth_phase_b32', 32)
    v = Scalar()
    for name, value in {'w22': old, 'w8': a, 'w21': b}.items():
        v.seed(name, value)
    v.run_block(0x100c05638, 0x100c0564c)
    prove('all_u32_original_extent_update_equation', v.read('w8') != old-a+b+0x74c239af)
    raw = z3.BitVec('growth_new_raw32', 32)
    v = Scalar()
    v.seed('w8', raw)
    v.seed('w10', 0xc4eb)
    v.run_block(0x100d64024, 0x100d64054)
    prove('all_u32_original_allocation_count_in_recovered_phase', v.read('x0') != z3.ZeroExt(32, raw+0xef133bef))
    return out


def abi_tags(tags, event):
    regs = {n: o for n, o in tags[0].items() if n.startswith('X') and 18 <= int(n[1:]) <= 29}
    memory = dict(tags[1])
    for span in event['invalidated_spans']:
        a, n = int(span['address'], 16), span['size_bytes']
        memory = {at: o for at, o in memory.items() if not a <= at < a+n}
    if event.get('allocated_owner_premise'):
        o = event['allocated_owner_premise']
        a, n = int(o['address'], 16), o['size_bytes']
        assert not any(a <= at < a+n for at in memory)
    return regs, memory


def snapshot(row):
    m = state_bytes(row)
    out = {}
    for name, a, n in OBJECTS:
        raw = bytes(m.get(a+j, 0) for j in range(n))
        mask = bytes(int(a+j in m) for j in range(n))
        out[name] = {'address': hex(a), 'extent_bytes': n, 'known_bytes': sum(mask), 'known_mask_hex': mask.hex(),
                     'bytes_hex': raw.hex() if name != 'J' else None, 'masked_bytes_sha256': sha256(raw).hexdigest(),
                     'owner_present': {'address': hex(a), 'size_bytes': n} in row['foreign_owners']}
    return out


def semantics(c, rows, entries, terminals):
    pointer = int(c['pointer_return64'], 16)
    timeline = []
    for item, row, terminal in zip(c['intervals'], rows, terminals):
        writes = {}
        for name, base, n in OBJECTS:
            selected = [w for w in row['source_writes'] if base <= int(w['address'], 16) < base+n]
            writes[name] = {'stores': len(selected), 'source_PCs': dict(Counter(w['pc'] for w in selected)),
                            'distinct_bytes_written': len({int(w['address'], 16)+j for w in selected for j in range(w['size_bytes'])})}
        timeline.append({'API_return_premise': item['API_return_premise'], 'snapshot': snapshot(terminal),
                         'object_writes': writes, 'boundary': terminal['boundary']})
    j0 = snapshot(entries[0])['J']
    assert all(t['snapshot']['J'] == j0 and t['object_writes']['J']['stores'] == 0 for t in timeline)
    if not pointer:
        assert len(rows) == 3
        assert timeline[0]['object_writes']['F']['distinct_bytes_written'] == 57
        assert timeline[1]['object_writes']['U']['distinct_bytes_written'] == 48
        assert timeline[0]['boundary']['pc'] == '0x1003174d0' and timeline[1]['boundary']['pc'] == '0x100336dec'
        final = terminals[-1]
        assert final['boundary']['pc'] == '0x10074abc8'
        assert final['boundary']['detail'] == {'address': hex(R.B.S+0x30), 'size_bytes': 8}
        m = state_bytes(final)
        assert bytes(m[R.B.S+j] for j in range(8)) == bytes(8)
        assert all(R.B.S+0x30+j not in m for j in range(8))
        assert not timeline[-1]['snapshot']['U']['owner_present'] and not timeline[-1]['snapshot']['F']['owner_present']
        assert timeline[-1]['snapshot']['S']['owner_present']
        return {'timeline': timeline, 'retirement_sequence': ['F57', 'U48'], 'S_pointer_cleared': True,
                'new_payload_supplied': False, 'native_execution': False}
    assert len(rows) == 2
    first = rows[0]
    loads = [r for r in first['source_reads'] if r['pc'] == '0x100b5c9b4']
    stores = [w for w in first['source_writes'] if w['pc'] == '0x100b5c9b8']
    assert len(loads) == len(stores) == 57
    copy_pairs = []
    for j, (load, store) in enumerate(zip(loads, stores)):
        index = 56-j
        assert load['address'] == hex(R.B.F+index) and store['address'] == hex(R.H+index)
        assert load['bytes_hex'] == store['after_hex'] and load['size_bytes'] == store['size_bytes'] == 1
        assert load['source_visit_index']+1 == store['source_visit_index']
        copy_pairs.append({'index': index, 'read': load, 'write': store})
    assert timeline[0]['snapshot']['H']['known_bytes'] == 57 and timeline[1]['snapshot']['H']['known_bytes'] == 77
    assert timeline[0]['snapshot']['U']['known_bytes'] == timeline[1]['snapshot']['U']['known_bytes'] == 40
    assert not timeline[1]['snapshot']['F']['owner_present'] and timeline[1]['snapshot']['H']['owner_present']
    tail = [w for w in rows[1]['source_writes'] if R.H+57 <= int(w['address'], 16) < R.H+77]
    assert len(tail) == 20 and {int(w['address'], 16) for w in tail} == set(range(R.H+57, R.H+77))
    final_memory = state_bytes(terminals[-1])
    assert bytes(final_memory[R.H+57+j] for j in range(20)).hex() == '9e6fd1e444283e0c873eed801e6d07049b2d3b36'
    assert int.from_bytes(bytes(final_memory[R.B.U+8+j] for j in range(8)), 'little') == R.H
    assert bytes(final_memory[R.B.U+0x10+j] for j in range(8)).hex() == '5ec4ec105ec4ec10'
    assert terminals[-1]['boundary']['pc'] == '0x100d640ac' and terminals[-1]['boundary']['registers31'][0] == '0x61'
    phase = next(f for f in rows[1]['source_frames'] if f['pc'] == '0x100c05638')['registers31']
    allocator = next(f for f in rows[1]['source_frames'] if f['pc'] == '0x100d64014')['registers31']
    assert [int(phase[j], 16) for j in [8, 21, 22]] == [0x74c239c3, 0x28, 0x10ecc45e]
    assert int(allocator[8], 16) == 0x10ecc472 and int(allocator[10], 16) == 0xc4eb
    # The later walk consumes one source-built node and the inherited terminal node.
    word_reads = [r for r in rows[1]['source_reads'] if r['pc'] == '0x100a5eac8']
    q_reads = [r for r in rows[1]['source_reads'] if r['pc'] == '0x100a5eacc']
    assert len(word_reads) == len(q_reads) == 2
    nodes = []
    for word, q in zip(word_reads, q_reads):
        b = int(word['address'], 16)
        assert int(q['address'], 16) == b+8
        next_address = (int.from_bytes(bytes.fromhex(q['bytes_hex']), 'little')-b)&((1<<64)-1)
        origins = []
        for read in [word, q]:
            a, n, visit = int(read['address'], 16), read['size_bytes'], read['source_visit_index']
            per_byte = []
            for j in range(n):
                previous = [w for w in rows[1]['source_writes'] if w['source_visit_index'] < visit and int(w['address'], 16) <= a+j < int(w['address'], 16)+w['size_bytes']]
                per_byte.append(previous[-1] if previous else None)
            origins.append({'read': read, 'last_source_writers_by_byte': per_byte})
        nodes.append({'address': hex(b), 'decoded_next': hex(next_address), 'fields': origins})
    assert nodes[0]['decoded_next'] == nodes[1]['address'] and nodes[1]['decoded_next'] == '0x0'
    assert all(w is not None for field in nodes[0]['fields'] for w in field['last_source_writers_by_byte'])
    assert all(w is None for field in nodes[1]['fields'] for w in field['last_source_writers_by_byte'])
    return {'timeline': timeline, 'retirement_sequence': ['F57'], 'copy_pairs': copy_pairs, 'tail_writes': tail,
            'tail20_hex': '9e6fd1e444283e0c873eed801e6d07049b2d3b36', 'later_node_chain': nodes,
            'next_allocation': {'pending_bytes': 97, 'old_raw32': '0x10ecc45e', 'new_raw32': '0x10ecc472',
                                'phase_W8': '0x74c239c3', 'phase_W21': '0x28', 'decode_bias32': '0xef133bef'},
            'new_payload_supplied': False, 'native_execution': False}


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    incoming = R.parents()
    for p, digest in R.PINS.items():
        assert sha(ROOT/p) == digest
    poly = json.loads(read(ROOT/'daemon_descriptor_polynomial_checks.json'))
    walk = json.loads(read(ROOT/'daemon_descriptor_walk_checks.json'))
    walk_views = {c['cohort_index']: c for c in walk['coverage']}
    initial_tags = {}
    for ci, c in enumerate(poly['classes']):
        old_ci = walk_views[c['representative_cohort_index']]['class_index']
        _, tags, _ = Replay.origins(R.unpack(walk['classes'][old_ci]['interval_packed']))
        _, initial_tags[ci], _ = Replay.origins(R.unpack(c['interval_packed']), tags)
    totals, admissions = Counter(), Counter()
    classes, seen, slots = [], set(), set()
    views = {(c['cohort_index'], c['ABI_clobber_pattern'], c['pointer_return64']): c for c in e['coverage']}
    for ci, c in enumerate(e['classes']):
        rep = incoming[c['representative_cohort_index']]['state']
        tags_by_parent = {k: initial_tags[k] for k in {incoming[m['cohort_index']]['polynomial_class_index'] for m in c['members']}}
        steps, rows, entries, terminals, lifts = [], [], [], [], []
        current = rep
        for ii, item in enumerate(c['intervals']):
            entry, ev = R.returned(current, item['API_return_premise'])
            assert ev == item['API_return_premise']
            for pattern in [0, 1]:
                _, fresh = R.event(current, pattern, int(c['pointer_return64'],16) if ii == 0 else None)
                _, constructed = R.returned(current, item['API_return_premise'], pattern)
                assert fresh == constructed
                admissions['fresh_ABI_recipe_checks'] += 1
            row = R.unpack(item['interval_packed'])
            Replay.GS.joined(entry, row)
            journal = None
            origins = []
            for parent_ci, tags in list(tags_by_parent.items()):
                own_journal, tags_by_parent[parent_ci], counts = Replay.origins(row, abi_tags(tags, ev))
                assert journal is None or journal == own_journal
                journal = own_journal
                origins.append({'polynomial_class_index': parent_ci, 'verified_counts': counts})
            deps = {'required': set(), 'written': set()}
            lift = Replay.Lift(row, deps, journal).run()
            totals.update(lift['verified_counts'])
            projection = R.B.registers([row])
            assert projection == item['register_projection'] and projection['vector_accesses'] == 0
            assert 'NZCV' not in projection['required']
            assert not set(projection['required']) & {'X'+str(j) for j in range(1,18)}
            assert deps['required'] <= set(projection['required']) and deps['written'] == set(projection['written'])
            need, effects, _ = requirements(entry, [row])
            terminal = R.B.export(entry, row, projection)
            rows.append(row);entries.append(entry);terminals.append(terminal)
            steps.append((entry, row, projection, need, effects))
            lifts.append({'full_replay': lift, 'pointer_origins': origins, 'required_bytes': requirement_receipt(need)})
            if terminal['boundary']['kind'] == 'before_unmodeled_import_call':
                instruction = next(CS.disasm(IMAGE.read(int(terminal['boundary']['pc'],16),4),int(terminal['boundary']['pc'],16)))
                assert instruction.mnemonic == 'blraa'
                name = instruction.op_str.split(',')[0].upper()
                pending_origins = {tags[0][name] for tags in tags_by_parent.values()}
                assert len(pending_origins) == 1
                slot, target = pending_origins.pop()
                assert target == int(terminal['boundary']['detail']['target'],16)
                slots.add(slot)
                lifts[-1]['pending_import_origin'] = {'slot': hex(slot), 'model_target': hex(target), 'source_word_hex': IMAGE.read(instruction.address,4).hex()}
            current = terminal
        meaning = semantics(c, rows, entries, terminals)
        for member in c['members']:
            j, pattern = member['cohort_index'], member['ABI_clobber_pattern']
            key = j, pattern, c['pointer_return64']
            assert key not in seen
            seen.add(key)
            current = incoming[j]['state']
            for item, (rep_entry, row, projection, need, effects) in zip(c['intervals'], steps):
                entry, ev = R.returned(current, item['API_return_premise'], pattern)
                memory, values = admission(entry, rep_entry, need, projection)
                terminal = R.B.export(entry, row, projection)
                expected(entry, terminal, effects, projection, row, memory, values)
                admissions.update(interval_admissions=1, incoming_byte_demands=len(need), incoming_register_demands=len(projection['required']))
                current = terminal
            assert current == R.unpack(views[key]['derived_terminal_state_packed']) and views[key]['class_index'] == ci
            admissions.update(branch_admissions=1, terminal_exports=1)
        # Fault controls reject one demanded byte, a changed SP and a missing owner.
        entry, row, projection, need, effects = steps[0]
        demanded = next(a for a, (b, origin) in need.items() if origin == 'incoming')
        for remove in [False, True]:
            memory = state_bytes(entry)
            if remove: del memory[demanded]
            else: memory[demanded] ^= 1
            try: admission(entry, entry, need, projection, memory=memory)
            except AssertionError: admissions['incoming_byte_fault_controls_rejected'] += 1
            else: raise AssertionError('bad demanded byte admitted')
        values = R.B.machine(entry);values['SP'] = hex(int(values['SP'],16)^16)
        try: admission(entry, entry, need, projection, values=values)
        except AssertionError: admissions['changed_SP_rejected'] += 1
        else: raise AssertionError('bad SP admitted')
        try: admission({**entry, 'foreign_owners': entry['foreign_owners'][:-1]}, entry, need, projection)
        except AssertionError: admissions['changed_owner_rejected'] += 1
        else: raise AssertionError('bad owner admitted')
        # A reserved saved register survives both ABI and each source interval.
        probe = deepcopy(rep)
        probe['boundary']['registers31'][18] = hex(int(probe['boundary']['registers31'][18],16)^1)
        for item, (rep_entry, row, projection, need, effects) in zip(c['intervals'], steps):
            assert 'X18' not in projection['required'] and 'X18' not in projection['written']
            entry, _ = R.returned(probe, item['API_return_premise'])
            memory, values = admission(entry, rep_entry, need, projection)
            probe = R.B.export(entry, row, projection)
            expected(entry, probe, effects, projection, row, memory, values)
        assert probe['boundary']['registers31'][18] != terminals[-1]['boundary']['registers31'][18]
        admissions['per_parent_saved_X18_controls'] += 1
        classes.append({'class_index': ci, 'intervals': lifts, 'semantics': meaning, 'all_checks_pass': True})
        print(json.dumps({'class': ci, 'source_visits_replayed': totals['source_visits'], 'admitted_branches': admissions['branch_admissions']}), flush=True)
    assert seen == set(views) and len(seen) == 608
    proofs = obligations()
    return {'scope': __doc__, 'replayer_sha256': sha(__file__), 'generator_sha256': sha(R.__file__),
            'checks_sha256': sha(ROOT/(R.P+'_checks.json')), 'source_sha256': sha(SOURCE),
            'replayer_dependencies': {p: sha(ROOT/p) for p in DEPS}, 'verified_counts': e['verified_counts'],
            'independent_totals': dict(totals), 'admissions': dict(admissions), 'classes': classes,
            'source_proofs': proofs, 'source_queries_unsat': len(proofs), 'pending_import_fixups': verify_original_fixups(sorted(slots)),
            'native_API_executed': False, 'native_daemon_kext_pairing_established': False,
            'initializer_to_current_caller_join_established': False, 'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    result = audit()
    (ROOT/(R.P+'_replay.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'independent_totals': result['independent_totals'], 'admissions': result['admissions'],
                      'source_queries_unsat': result['source_queries_unsat']}), flush=True)
