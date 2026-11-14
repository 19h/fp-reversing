#!/usr/bin/env python3
"""Conditional malloc77 NULL/fresh returns, buffer use and cleanup frontiers.
All 152 inherited states cross two declared SIMD/NZCV ABI patterns and
NULL/fresh77B returns. Fresh memory starts undefined. Every continued free
retires only its declared matching owner and invalidates its bytes.
No new roots, node fields, payload bytes or native target operations occur.
O(parent bytes + representative visits + parents*demands) time;
O(receipts+parent maps+largest interval) space.
"""
import json
from collections import defaultdict, Counter
from copy import deepcopy
from daemon_receive_tools import ROOT, SOURCE, IMAGE, FIXUPS
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_network_record import state_bytes
from audit_daemon_state_table_mixing import admission
from audit_daemon_state_emitter_completion import requirements
import recover_daemon_descriptor_polynomial as Parent

P = 'daemon_descriptor_growth'
B = Parent.B
pack, unpack = B.pack, B.unpack
H, N = 0x6600080000, 77
PINS = {'daemon_descriptor_polynomial_checks.json': 'a43e977f7a9b786f44427b67e8152ba8e64ad940014c6cf821a800b9479b60c6',
        'daemon_descriptor_polynomial_replay.json': '7acd16ed49134447d3588f8c2d4a00b0adfb0cd734217f8b939af82d03fd954c'}
DEPS = ['daemon_receive_tools.py', 'daemon_receive_fixups.txt', 'recover_daemon_descriptor_polynomial.py',
        'recover_daemon_constructor_buffer.py', 'recover_daemon_state_file_admission.py',
        'recover_daemon_context_lock_use.py', 'recover_daemon_context_state_publish.py',
        'audit_daemon_network_record.py', 'audit_daemon_state_table_mixing.py', 'audit_daemon_state_emitter_completion.py']


def parents():
    old = json.loads(read(ROOT/'daemon_descriptor_polynomial_checks.json'))
    return [{'cohort_index': c['cohort_index'], 'polynomial_class_index': c['class_index'],
             'state': unpack(c['derived_terminal_state_packed'])} for c in sorted(old['coverage'], key=lambda c: c['cohort_index'])]


def event(before, pattern, pointer=None):
    b = before['boundary']
    v = B.restore(before)
    invalid = [(B.APIParent.E, 4)]
    retired = None
    if pointer is None:
        assert b['kind'] == 'before_unmodeled_import_call' and b['detail']['symbol'] == 'libSystem/_free'
        a = int(b['registers31'][0], 16)
        owners = [(p, n) for p, n in v.foreign_owners if p == a]
        assert len(owners) == 1
        retired = owners[0]
        invalid.append(retired)
    else:
        assert b['pc'] == hex(Parent.STOP) and b['detail']['symbol'] == 'libSystem/_malloc'
        assert b['registers31'][0] == hex(N) and pointer in [0, H]
    ev = B.API.event(v, before, pattern, invalid=invalid)
    ev.pop('return32')
    ev.pop('int_return_upper32_unspecified_fixture')
    ev['ABI_clobber_pattern'] = pattern
    if pointer is None:
        v.set(0, 0xa5b6c7d8e9f01234^pattern)
        v.foreign_owners.remove(retired)
        ev.update(void_return_premise=True, retired_owner_premise={'address': hex(retired[0]), 'size_bytes': retired[1]},
                  effect_kind='declared_free_return')
    else:
        v.set(0, pointer)
        allocated = None
        if pointer:
            assert all(not(a < H+N and H < a+n) for a, n in v.foreign_owners)
            assert all(H+j not in state_bytes(before) for j in range(N))
            B.APIParent.owner(v, H, N)
            allocated = {'address': hex(H), 'size_bytes': N, 'initial_bytes_defined': False}
        ev.update(pointer_return64=hex(pointer), allocated_owner_premise=allocated, effect_kind='declared_malloc77_return')
    ev['return_registers31'] = [hex(v.reg(j)) for j in range(31)]
    return v, ev


def transition(before, pattern, pointer=None):
    v, ev = event(before, pattern, pointer)
    B.API.compact(v)
    v.cut_stops = set()
    row = B.interval(v, int(before['boundary']['pc'], 16)+4, ev['effect_kind'])
    return ev, row


def returned(parent, template, pattern=None):
    """Instantiate the ABI premise while preserving each parent's ABI saves."""
    ev = deepcopy(template)
    pattern = ev['ABI_clobber_pattern'] if pattern is None else pattern
    assert pattern in [0, 1]
    ev['ABI_clobber_pattern'] = pattern
    assert parent['boundary']['pc'] == ev['call_site']
    assert parent['boundary']['detail']['symbol'] == ev['symbol']
    for j in range(18, 30):
        ev['return_registers31'][j] = parent['boundary']['registers31'][j]
    for j in range(32):
        bits = ((j+1)*0x123456789abcdef0123456789abcdef+pattern*0xfedcba9876543210fedcba9876543210)&((1<<128)-1)
        if 8 <= j < 16:
            bits = (bits&~((1<<64)-1))|(int(parent['boundary']['Q_registers32'][j], 16)&((1<<64)-1))
        ev['return_Q_registers32'][j] = hex(bits)
    ev['return_NZCV'] = '0x50000000' if pattern else '0xa0000000'
    if ev.get('void_return_premise'):
        ev['return_registers31'][0] = hex(0xa5b6c7d8e9f01234^pattern)
    if ev.get('allocated_owner_premise'):
        assert all(not(int(o['address'], 16) < H+N and H < int(o['address'], 16)+o['size_bytes']) for o in parent['foreign_owners'])
        assert all(H+j not in state_bytes(parent) for j in range(N))
    entry = B.fixture_state(parent, ev)
    return entry, ev


def build():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest
    incoming = parents()
    groups = defaultdict(list)
    for j, x in enumerate(incoming):
        state = x['state']
        candidate_key = json.dumps({'configuration': state['configuration'], 'owners': state['foreign_owners']}, sort_keys=True)
        groups[candidate_key].extend((j, pattern) for pattern in [0, 1])
    classes, coverage = [], []
    counts = Counter()
    used, pcs = set(), set()
    for pointer in [0, H]:
        for members in groups.values():
            pending = members.copy()
            while pending:
                representative, pattern = pending[0]
                current = incoming[representative]['state']
                intervals, replay_data = [], []
                while True:
                    ev, row = transition(current, pattern, pointer if not intervals else None)
                    entry, own_event = returned(current, ev)
                    assert own_event == ev
                    projection = B.registers([row])
                    need, effects, _ = requirements(entry, [row])
                    replay_data.append((entry, row, need, projection))
                    intervals.append({'API_return_premise': ev, 'interval_packed': pack(row), 'register_projection': projection})
                    current = B.export(entry, row, projection)
                    if row['boundary']['kind'] != 'before_unmodeled_import_call' or row['boundary']['detail']['symbol'] != 'libSystem/_free':
                        break
                    assert len(intervals) < 8
                ci = len(classes)
                accepted, rejected = [], []
                for j, member_pattern in pending:
                    current = incoming[j]['state']
                    try:
                        for item, (rep_entry, row, need, projection) in zip(intervals, replay_data):
                            entry, ev = returned(current, item['API_return_premise'], member_pattern)
                            admission(entry, rep_entry, need, projection)
                            current = B.export(entry, row, projection)
                    except AssertionError:
                        assert (j, member_pattern) != (representative, pattern)
                        rejected.append((j, member_pattern))
                        continue
                    coverage.append({'cohort_index': j, 'class_index': ci, 'ABI_clobber_pattern': member_pattern,
                                     'pointer_return64': hex(pointer), 'derived_terminal_state_packed': pack(current)})
                    accepted.append({'cohort_index': j, 'ABI_clobber_pattern': member_pattern})
                classes.append({'representative_cohort_index': representative, 'members': accepted,
                                'polynomial_class_index': incoming[representative]['polynomial_class_index'],
                                'representative_ABI_pattern': pattern, 'pointer_return64': hex(pointer), 'intervals': intervals})
                for _, row, _, _ in replay_data:
                    counts.update(B.rc(row))
                    used.update(int(r['address'], 16) for r in row['source_reads'] if int(r['address'], 16) in FIXUPS)
                    pcs.update(int(v['pc'], 16) for v in row['source_visits'])
                print(json.dumps({'class': ci, 'members': len(accepted), 'pattern': pattern, 'pointer': hex(pointer),
                                  'intervals': len(intervals), 'terminal': row['boundary']['pc']}), flush=True)
                pending = rejected
    assert len(coverage) == 608 and {(c['cohort_index'], c['ABI_clobber_pattern'], c['pointer_return64']) for c in coverage} == {(j, p, hex(a)) for j in range(152) for p in [0, 1] for a in [0, H]}
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'parent_pins': PINS, 'classes': classes, 'coverage': coverage,
            'source_words': [{'start': hex(pc), 'bytes_hex': IMAGE.read(pc, 4).hex()} for pc in sorted(pcs)],
            'source_fixups': B.APIParent.API.Parent.fixups(used),
            'verified_counts': {'incoming_parents': 152, 'branch_classes': len(classes), 'terminal_exports': 608,
                                'ABI_patterns': 2, 'malloc_return_cases': 2, 'new_payload_bytes_supplied': 0,
                                'new_root_bytes_supplied': 0, 'fresh_owner_extent_bytes': 77, **counts},
            'native_API_executed': False, 'native_daemon_kext_pairing_established': False,
            'initializer_to_current_caller_join_established': False, 'full_goal_complete': False}


if __name__ == '__main__':
    result = build()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']), flush=True)
