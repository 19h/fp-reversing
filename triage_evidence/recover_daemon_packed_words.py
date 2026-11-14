#!/usr/bin/env python3
"""Recover packed-word values and the retained bit-count loop.
O(parent bytes + retained visits + loop evidence) time/space.
No new target interval, guest input, owner or API-return premise occurs.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE, qword, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_append_fields as Parent

P = 'daemon_packed_words'
PINS = {'daemon_append_fields_checks.json': 'bac22d45750863b7d3bce0993bc891b70a60f43548907c1135a64f89c50e91f7',
        'daemon_append_fields_audit.json': 'a79919e954824d1e1716e3298b455d6f8f03966cfc5ef6242c80d97dad903049',
        'daemon_descriptor_growth_checks.json': 'b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2'}
DEPS = ['daemon_receive_tools.py', 'recover_daemon_append_fields.py', 'recover_daemon_descriptor_growth.py']
SPANS = {'shift': (0x100c29254, 0x100c29268), 'products': (0x100c29268, 0x100c29294),
         'combiner': (0x100c29294, 0x100c292b8), 'inverse': (0x100c292b8, 0x100c292c8),
         'count_pack': (0x100c292c8, 0x100c29340), 'bias': (0x100c29340, 0x100c2943c),
         'scalar_add': (0x100c2943c, 0x100c29520), 'mask': (0x100c29520, 0x100c29804),
         'quotient_cancel': (0x100c29718, 0x100c2972c),
         'count_math': (0x100cc81e0, 0x100cc8220), 'count_dispatch': (0x100cc8220, 0x100cc822c),
         'count_loop': (0x100cc81e0, 0x100cc822c), 'count_branch': (0x100cc822c, 0x100cc8230),
         'count_init': (0x100a30df0, 0x100a30df4), 'raw_store': (0x100a30dfc, 0x100a30e00),
         'count_store': (0x100add458, 0x100add460)}
PHASE = {0: 0xf381d5c9, 1: 0x0c7e2a37, 2: 0xe73d, 3: 0xcea32579, 4: 0x8b3dc651,
         5: 0x6c2afa1c, 7: 0x93d505e4, 8: 0x7550, 9: 1, 15: 0x1496e984,
         16: 0xeb69167c, 20: 0x101039ef0}
SLOTS = [0x101074970, 0x101083258]
MASK = 0x07ffffff


def parents():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest
    return json.loads(read(ROOT/'daemon_append_fields_checks.json')), json.loads(read(ROOT/'daemon_descriptor_growth_checks.json'))


def slice_row(row, kind, lo, hi):
    a, b = SPANS[kind]
    assert [int(v['pc'], 16) for v in row['source_visits'][lo:hi]] == list(range(a, b, 4))
    return {'kind': kind, 'start_visit': lo, 'end_visit_exclusive': hi,
            'entry': row['source_frames'][lo], 'exit': row['source_frames'][hi],
            'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
            'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]}


def extract():
    old, growth = parents()
    rows, fields, counts = {}, [], Counter()
    for o in old['occurrences']:
        if o['kind'] != 'packed_word_producer':
            continue
        ci, ii = o['class_index'], o['interval_index']
        if (ci, ii) not in rows:
            rows[ci, ii] = Parent.Parent.unpack(growth['classes'][ci]['intervals'][ii]['interval_packed'])
        row = rows[ci, ii]
        count_writer = o['read_custody'][0]['custody'][0]['last_writer_in_this_interval']
        raw_writer = o['read_custody'][1]['custody'][0]['last_writer_in_this_interval']
        lo, hi = raw_writer['source_visit_index'], count_writer['source_visit_index']
        assert row['source_visits'][lo-3]['pc'] == '0x100a30df0'
        spans = [slice_row(row, 'count_init', lo-3, lo-2), slice_row(row, 'raw_store', lo, lo+1),
                 slice_row(row, 'count_store', hi-1, hi+1)]
        steps = []
        for j in range(lo, hi):
            if row['source_visits'][j]['pc'] != '0x100cc81e0':
                continue
            s = slice_row(row, 'count_loop', j, j+19)
            r = [int(x, 16) for x in s['entry']['registers31']]
            assert all(r[k] == value for k, value in PHASE.items())
            edge = next(e for e in row['logical_edges'] if e['source_visit_index'] == j+19)
            assert edge['pc'] == '0x100cc822c' and edge['kind'] == 'braa' and edge['modifier'] == '0x73a4'
            steps.append({'slice': s, 'edge': edge, 'decoded_before32': hex(r[11]^0x8b3dc651),
                          'counter_before32': r[10]})
        n = o['values']['count32']
        d = int(o['values']['second_stack_word32'], 16)^0x8b3dc651
        raw = int(o['values']['entry_word32'], 16)
        assert n == len(steps) == max(1, d.bit_length())
        assert [s['counter_before32'] for s in steps] == list(range(n))
        assert [int(s['decoded_before32'], 16) for s in steps] == [d >> j for j in range(n)]
        assert all(s['edge']['target'] == ('0x100add458' if j == n-1 else '0x100cc81e0') for j, s in enumerate(steps))
        assert int(steps[0]['slice']['entry']['registers31'][11], 16) == int.from_bytes(bytes.fromhex(raw_writer['after_hex']), 'little')
        joins = [x for x in old['producer_writer_joins'] if x['class_index'] == ci and x['interval_index'] == ii and x['producer_start_visit'] == o['start_visit']]
        assert len(joins) == 1
        j = joins[0]
        auxiliary = raw^0x6703cce9
        packed = ((((auxiliary << (n&31))&MASK)|((n<<27)&0xffffffff))+d)&0xffffffff
        assert packed^0xc156f94e == int(j['producer_output32'], 16)
        assert packed^0xe4b5bf34 == int(j['writer_input32'], 16)
        fields.append({'class_index': ci, 'interval_index': ii, 'offset32': j['offset32'],
                       'source_raw32': hex(raw), 'decoded_scalar32': d, 'count32': n,
                       'auxiliary32': hex(auxiliary), 'retained_auxiliary_bits': 27-n,
                       'retained_auxiliary_value': hex(auxiliary&((1 << (27-n))-1)),
                       'packed32': hex(packed), 'producer_output32': j['producer_output32'], 'writer_input32': j['writer_input32'],
                       'source_occurrence': o, 'count_slices': spans, 'count_steps': steps})
        counts.update(fields=1, count_iterations=n, count_branches=n,
                      selected_slices=len(spans)+n, selected_visits=4+19*n,
                      selected_reads=sum(len(s['reads']) for s in spans)+sum(len(s['slice']['reads']) for s in steps),
                      selected_writes=sum(len(s['writes']) for s in spans)+sum(len(s['slice']['writes']) for s in steps))
    assert len(fields) == 6 and counts['count_iterations'] == 26
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE), 'parent_pins': PINS,
            'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'source_spans': [{'kind': k, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': IMAGE.read(a, b-a).hex()}
                             for k, (a, b) in SPANS.items()],
            'loop_phase': {str(k): hex(v) for k, v in PHASE.items()},
            'loop_targets': {hex(s): hex(qword(s)) for s in SLOTS}, 'original_fixups': verify_original_fixups(SLOTS),
            'fields': fields, 'verified_counts': dict(counts), 'inherited_nonnull_members': 304,
            'new_target_intervals': 0, 'new_guest_input_bytes': 0, 'new_API_return_premises': 0,
            'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    result = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']), flush=True)
