#!/usr/bin/env python3
"""Conditional root-only prefix to the still-undefined descriptor read.
One additional source-compatible 8 B root is declared at outer SP+0x2b0.
All 152 success parents remain conditional; no descriptor bytes are supplied.
O(parent bytes + classes*visits + admissions*demands) time; O(receipts+
parent maps+largest interval) space. No native target operation executes.
"""
import json
from copy import deepcopy
from collections import defaultdict, Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE, CS, FIXUPS
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_network_record import state_bytes
from audit_daemon_state_table_mixing import admission
from audit_daemon_state_emitter_completion import requirements
import recover_daemon_constructor_buffer as B

P = 'daemon_descriptor_walk'
ENTRY, STOP, CELL = 0x1008a2704, 0x100a5eac8, 0x1010b7cc0
PINS = {'daemon_constructor_buffer_checks.json': 'fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07',
        'daemon_feedback_callers_checks.json': '9e36fc89e77e5188c9ec46a2d9c499044b0c8ad15fed160591b97e1a16f659b0',
        'daemon_constructor_descriptor_checks.json': '9d044ed5285d1fb392fb01eb10e016b19d8ba312435793760e28376c9bc50d3f'}
DEPS = ['daemon_receive_tools.py', 'daemon_receive_fixups.txt', 'recover_daemon_constructor_buffer.py',
        'audit_daemon_network_record.py', 'audit_daemon_state_table_mixing.py', 'audit_daemon_state_emitter_completion.py']
pack, unpack = B.pack, B.unpack


def parents():
    old = json.loads(read(ROOT/'daemon_constructor_buffer_checks.json'))
    out = []
    for c in old['coverage']:
        p = unpack(c['derived_terminal_state_packed'])
        if p['boundary']['pc'] == hex(ENTRY):
            out.append({'parent_index': c['parent_index'], 'parent_branch_index': c['branch_index'], 'state': p})
    assert len(out) == 152
    return out


def premised(parent):
    p = deepcopy(parent)
    sp = int(p['boundary']['SP'], 16)
    m = state_bytes(parent)
    assert p['boundary']['pc'] == hex(ENTRY) and all(sp+0x2b0+j not in m for j in range(8))
    f = {'address': hex(sp+0x2b0), 'bytes_hex': CELL.to_bytes(8, 'little').hex(),
         'provenance': 'explicit_separate_initializer_compatible_root_current_epoch_unknown'}
    p['initial_private_fixtures'].append(f)
    p['role'] = 'conditional_root_only_walk_entry'
    return p, f


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
        # Candidate grouping is accepted only by exact incoming demands.
        pending = members.copy()
        while pending:
            representative = pending[0]
            before, root = premised(incoming[representative]['state'])
            v = B.restore(before)
            v.cut_stops = set()
            row = B.interval(v, ENTRY, 'conditional_root_only_descriptor_walk_prefix')
            assert row['boundary']['pc'] == hex(STOP) and len(row['source_visits']) == 383
            projection = B.registers([row])
            need, effects, _ = requirements(before, [row])
            accepted, rejected = [], []
            ci = len(classes)
            for j in pending:
                entry, f = premised(incoming[j]['state'])
                assert f == root
                try:
                    admission(entry, before, need, projection)
                except AssertionError:
                    assert j != representative
                    rejected.append(j)
                    continue
                terminal = B.export(entry, row, projection)
                coverage.append({'cohort_index': j, 'parent_index': incoming[j]['parent_index'],
                                 'parent_branch_index': incoming[j]['parent_branch_index'], 'class_index': ci,
                                 'derived_terminal_state_packed': pack(terminal)})
                accepted.append(j)
            classes.append({'representative_cohort_index': representative, 'member_cohort_indices': accepted,
                            'root_premise': root, 'interval_packed': pack(row), 'register_projection': projection})
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
                                'terminal_exports': 152, 'new_root_bytes_per_parent': 8,
                                'combined_conditional_root_bytes_per_parent': 104, **counts},
            'descriptor_bytes_supplied': 0, 'native_API_executed': False,
            'initializer_to_current_caller_join_established': False,
            'native_daemon_kext_pairing_established': False, 'full_goal_complete': False}


if __name__ == '__main__':
    result = build()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']), flush=True)
