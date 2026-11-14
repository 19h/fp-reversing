#!/usr/bin/env python3
"""Conditional terminal descriptor, degree-ten u32 polynomial and malloc frontier.
Adds 12 B of separately declared initializer-compatible node fields to each
of 152 walk exports; the 4 B gap stays undefined. Inherited conditional
roots total 104 B; roots plus node definitions total 116 B per parent.
O(parent bytes + classes*visits + admissions*demands) time;
O(receipts+parent maps+largest interval) space. No native target operation.
"""
import json
from copy import deepcopy
from collections import defaultdict, Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE, FIXUPS
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_network_record import state_bytes
from audit_daemon_state_table_mixing import admission
from audit_daemon_state_emitter_completion import requirements
import recover_daemon_descriptor_walk as Parent

P = 'daemon_descriptor_polynomial'
ENTRY, STOP = 0x100a5eac8, 0x100d640ac
B = Parent.B
pack, unpack = B.pack, B.unpack
PINS = {'daemon_descriptor_walk_checks.json': 'f11399df1f9b98d5b06ee61996c335d749a33b14ad764fe442cc47a03c419a50',
        'daemon_descriptor_walk_replay.json': 'd09df40f234c9391aaaade51e397f69dbcc536063f4738fdaade624822ade023',
        'daemon_constructor_descriptor_checks.json': '9d044ed5285d1fb392fb01eb10e016b19d8ba312435793760e28376c9bc50d3f'}
DEPS = ['daemon_receive_tools.py', 'daemon_receive_fixups.txt', 'recover_daemon_descriptor_walk.py',
        'recover_daemon_constructor_buffer.py', 'audit_daemon_network_record.py',
        'audit_daemon_state_table_mixing.py', 'audit_daemon_state_emitter_completion.py']


def parents():
    old = json.loads(read(ROOT/'daemon_descriptor_walk_checks.json'))
    return [{'cohort_index': c['cohort_index'], 'parent_class_index': c['class_index'],
             'state': unpack(c['derived_terminal_state_packed'])} for c in sorted(old['coverage'], key=lambda c: c['cohort_index'])]


def premised(parent):
    p = deepcopy(parent)
    assert p['boundary']['pc'] == hex(ENTRY)
    node = int(p['boundary']['registers31'][14], 16)
    m = state_bytes(p)
    assert all(node+j not in m for j in range(16))
    fixtures = [{'address': hex(node+offset), 'bytes_hex': value.to_bytes(width, 'little').hex(),
                 'provenance': 'explicit_separate_initializer_compatible_terminal_node_epoch_unknown'}
                for offset, width, value in [(0, 4, (node+0xb5caf0c6)&0xffffffff), (8, 8, node)]]
    p['initial_private_fixtures'].extend(fixtures)
    p['role'] = 'conditional_terminal_node_entry'
    assert all(node+j not in state_bytes(p) for j in range(4, 8))
    return p, fixtures


def build():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest
    incoming = parents()
    groups = defaultdict(list)
    for j, x in enumerate(incoming):
        groups[B.key(x['state'])].append(j)
    classes, coverage = [], []
    counts = Counter()
    used, pcs = set(), set()
    for members in groups.values():
        pending = members.copy()
        while pending:
            representative = pending[0]
            before, fixtures = premised(incoming[representative]['state'])
            v = B.restore(before)
            v.cut_stops = set()
            row = B.interval(v, ENTRY, 'conditional_terminal_descriptor_to_pending_malloc')
            assert row['boundary']['pc'] == hex(STOP) and len(row['source_visits']) == 5151
            assert row['boundary']['detail']['symbol'] == 'libSystem/_malloc'
            assert row['boundary']['registers31'][0] == '0x4d'
            projection = B.registers([row])
            need, effects, _ = requirements(before, [row])
            accepted, rejected = [], []
            ci = len(classes)
            for j in pending:
                entry, f = premised(incoming[j]['state'])
                assert f == fixtures
                try:
                    admission(entry, before, need, projection)
                except AssertionError:
                    assert j != representative
                    rejected.append(j)
                    continue
                terminal = B.export(entry, row, projection)
                coverage.append({'cohort_index': j, 'parent_class_index': incoming[j]['parent_class_index'],
                                 'class_index': ci, 'derived_terminal_state_packed': pack(terminal)})
                accepted.append(j)
            classes.append({'representative_cohort_index': representative, 'member_cohort_indices': accepted,
                            'node_premises': fixtures, 'interval_packed': pack(row), 'register_projection': projection})
            counts.update(B.rc(row))
            used.update(int(r['address'], 16) for r in row['source_reads'] if int(r['address'], 16) in FIXUPS)
            pcs.update(int(v['pc'], 16) for v in row['source_visits'])
            pending = rejected
    assert len(coverage) == 152 and sorted(c['cohort_index'] for c in coverage) == list(range(152))
    regions = [{'start': hex(pc), 'bytes_hex': IMAGE.read(pc, 4).hex()} for pc in sorted(pcs)]
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'parent_pins': PINS,
            'classes': classes, 'coverage': coverage, 'source_words': regions,
            'source_fixups': B.APIParent.API.Parent.fixups(used),
            'verified_counts': {'incoming_parents': 152, 'representative_classes': len(classes),
                                'terminal_exports': 152, 'new_node_bytes_per_parent': 12,
                                'inherited_conditional_root_bytes_per_parent': 104,
                                'combined_conditional_entry_bytes_per_parent': 116, **counts},
            'node_gap_bytes_supplied': 0, 'malloc_return_supplied': False, 'native_API_executed': False,
            'initializer_to_current_caller_join_established': False,
            'native_daemon_kext_pairing_established': False, 'full_goal_complete': False}


if __name__ == '__main__':
    result = build()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']), flush=True)
