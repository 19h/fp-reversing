#!/usr/bin/env python3
"""Join the old halfword decoder/store to the later regenerated field.
O(parent bytes + selected visits + exports*state bytes + custody scans)
time/space. Reuses retained journals; no new target interval or premise.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_network_record import state_bytes
import recover_daemon_packed_halves as Half
import recover_daemon_constructor_buffer as Buffer

P = 'daemon_halfword_update'
CELL = 0x680005fe24
PINS = {'daemon_descriptor_polynomial_checks.json': 'a43e977f7a9b786f44427b67e8152ba8e64ad940014c6cf821a800b9479b60c6',
        'daemon_descriptor_polynomial_replay.json': '7acd16ed49134447d3588f8c2d4a00b0adfb0cd734217f8b939af82d03fd954c',
        'daemon_descriptor_growth_checks.json': 'b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2',
        'daemon_descriptor_growth_replay.json': 'bee4ab3224710559fefdd8bca070110e48c03ab52d01c92b617988b9b3d5bd67',
        'daemon_packed_halves_checks.json': '12d8bf65c7c1140e5a842764cc68e850eccbdc7a6075304059ec01f8f8ca7fe4',
        'daemon_packed_halves_audit.json': '1a0bf1c95a128654d1e20469bd88c710f7871fef0d5b9853c0635b6fe8de3f53'}
DEPS = ['daemon_receive_tools.py', 'recover_daemon_packed_halves.py', 'recover_daemon_constructor_buffer.py',
        'recover_daemon_append_fields.py', 'audit_daemon_network_record.py']
SPANS = {'reader': (0x100ae22e0, 0x100ae24dc), 'byte_unmask': (0x100ae22e0, 0x100ae2398),
         'assemble': (0x100ae2398, 0x100ae23c0), 'count': (0x100ae23c0, 0x100ae2478),
         'product_shift': (0x100ae2478, 0x100ae248c), 'product_unmix': (0x100ae248c, 0x100ae24c0),
         'scalar_extract': (0x100ae24c0, 0x100ae24dc),
         'increment': (0x100d7ef80, 0x100d7f008), 'increment_math': (0x100d7ef80, 0x100d7efec),
         'gate': (0x100d7efec, 0x100d7f000), 'dispatch': (0x100d7f000, 0x100d7f008),
         'branch': (0x100d7f008, 0x100d7f00c), 'store': (0x100a68310, 0x100a6831c)}
SLOTS = [0x101066c40, 0x10106d880]


def parents():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest
    return [json.loads(read(ROOT/p)) for p in ['daemon_descriptor_polynomial_checks.json',
            'daemon_descriptor_growth_checks.json', 'daemon_packed_halves_checks.json']]


def overlap(w, a=CELL, n=2):
    return int(w['address'], 16) < a+n and a < int(w['address'], 16)+w['size_bytes']


def slice_row(row, kind):
    a, b = SPANS[kind]
    lo = next(j for j, v in enumerate(row['source_visits']) if v['pc'] == hex(a))
    hi = lo+(b-a)//4
    assert [int(v['pc'], 16) for v in row['source_visits'][lo:hi]] == list(range(a, b, 4))
    return {'kind': kind, 'start_visit': lo, 'end_visit_exclusive': hi,
            'entry': row['source_frames'][lo], 'exit': row['source_frames'][hi],
            'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
            'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]}


def extract():
    polynomial, growth, halves = parents()
    cases, joins, coverage, counts = [], [], [], Counter()
    for ci, c in enumerate(polynomial['classes']):
        row = Buffer.unpack(c['interval_packed'])
        slices = [slice_row(row, kind) for kind in ['reader', 'increment', 'store']]
        r, inc, store = slices
        bytes_read = [x for x in r['reads'] if x['pc'] in ['0x100ae22ec', '0x100ae234c']]
        assert [(x['address'], x['bytes_hex']) for x in bytes_read] == [('0x660007000f', '56'), ('0x6600070010', 'ee')]
        assert r['entry']['SP'] == inc['entry']['SP'] == store['entry']['SP'] == '0x680005fb70'
        assert r['exit']['registers31'][8] == inc['entry']['registers31'][8] == '0x7391'
        assert inc['entry']['registers31'][9] == '0x59aa' and inc['entry']['registers31'][16] == '0x7390'
        assert inc['exit']['registers31'][11] == store['entry']['registers31'][11] == '0xffff8c71'
        assert all(f['registers31'][11] == '0xffff8c71' for f in row['source_frames'][inc['end_visit_exclusive']:store['start_visit']+1])
        assert len(store['writes']) == 1
        w = store['writes'][0]
        assert (w['pc'], w['address'], w['size_bytes'], w['after_hex']) == ('0x100a68318', hex(CELL), 4, '02000000')
        assert [x for x in row['source_writes'] if overlap(x) and x['source_visit_index'] >= w['source_visit_index']] == [w]
        edge = next(e for e in row['logical_edges'] if e['source_visit_index'] == inc['end_visit_exclusive'])
        assert edge['pc'] == '0x100d7f008' and edge['target'] == '0x100a682e4' and edge['modifier'] == '0xfd0f'
        cases.append({'polynomial_class_index': ci, 'member_cohort_indices': c['member_cohort_indices'],
                      'slices': slices, 'old_source_bytes_hex': '56ee', 'old_packed16': '0x1937', 'old_scalar16': 1,
                      'new_scalar32': 2, 'cell_store': w, 'edge': edge, 'later_overwrites_in_polynomial_interval': 0})
        for s in slices:
            counts.update(selected_slices=1, selected_visits=s['end_visit_exclusive']-s['start_visit'],
                          selected_reads=len(s['reads']), selected_writes=len(s['writes']))
    for c in polynomial['coverage']:
        state = Buffer.unpack(c['derived_terminal_state_packed'])
        m = state_bytes(state)
        assert bytes(m[CELL+j] for j in range(4)) == bytes.fromhex('02000000')
        coverage.append({'cohort_index': c['cohort_index'], 'polynomial_class_index': c['class_index'],
                         'exported_cell32': 2, 'cell_bytes_checked': 4})
    by_cohort = {c['cohort_index']: c for c in coverage}
    assert set(by_cohort) == set(range(152))
    for ci in [2, 3]:
        c = growth['classes'][ci]
        assert c['pointer_return64'] == '0x6600080000'
        for ii, item in enumerate(c['intervals']):
            row = Buffer.unpack(item['interval_packed'])
            assert not any(overlap(w) for w in row['source_writes'])
            assert not any(overlap(w) for w in item['API_return_premise']['invalidated_spans'])
        f = next(f for f in halves['fields'] if f['class_index'] == ci and f['offset32'] == 15)
        read_cell = f['scalar_read_custody'][0]['read']
        assert (read_cell['address'], read_cell['size_bytes'], read_cell['bytes_hex']) == (hex(CELL), 2, '0200')
        assert f['decoded_scalar16'] == 2 and f['count32'] == 2 and f['packed16'] == '0x2f6a'
        joins.append({'growth_class_index': ci, 'members': c['members'], 'field_offset_bytes': 15,
                      'consumer_read': read_cell, 'raw_scalar32': f['raw_scalar32'], 'new_packed16': f['packed16'],
                      'new_mixed16': f['mixed16'], 'new_stored_bytes_hex': '60b3',
                      'growth_intervals_without_overwrites': len(c['intervals']),
                      'polynomial_classes': sorted({by_cohort[x['cohort_index']]['polynomial_class_index'] for x in c['members']})})
    assert len(cases) == 4 and len(coverage) == 152 and sum(len(j['members']) for j in joins) == 304
    counts.update(polynomial_classes=4, parent_exports=152, exported_cell_bytes=608,
                  growth_field_joins=2, inherited_nonnull_members=304, retained_logical_edges=4)
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE), 'parent_pins': PINS,
            'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'source_spans': [{'kind': k, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': IMAGE.read(a, b-a).hex()}
                             for k, (a, b) in SPANS.items()],
            'original_fixups': verify_original_fixups(SLOTS), 'cases': cases, 'export_coverage': coverage,
            'consumer_joins': joins, 'verified_counts': dict(counts), 'inherited_admissions_rerun': False,
            'new_target_intervals': 0, 'new_guest_input_bytes': 0, 'new_API_return_premises': 0,
            'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    result = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']), flush=True)
