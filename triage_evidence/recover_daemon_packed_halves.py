#!/usr/bin/env python3
"""Recover halfword packing, bit counts and saved-register/byte custody.
O(parent bytes + retained visits + reads*writes) time;
O(parent receipts + selected evidence) space. No new target execution.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE, qword, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_append_fields as Parent

P = 'daemon_packed_halves'
PINS = {'daemon_append_fields_checks.json': 'bac22d45750863b7d3bce0993bc891b70a60f43548907c1135a64f89c50e91f7',
        'daemon_append_fields_audit.json': 'a79919e954824d1e1716e3298b455d6f8f03966cfc5ef6242c80d97dad903049',
        'daemon_descriptor_growth_checks.json': 'b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2'}
DEPS = ['daemon_receive_tools.py', 'recover_daemon_append_fields.py', 'recover_daemon_descriptor_growth.py']
SPANS = {'producer': (0x100b75220, 0x100b75548), 'shift': (0x100b75240, 0x100b75274),
         'mask': (0x100b75274, 0x100b752d8), 'pack': (0x100b752d8, 0x100b75304),
         'scalar_add': (0x100b75304, 0x100b753b4), 'final': (0x100b753b4, 0x100b75548),
         'count_setup': (0x100b6e64c, 0x100b6e6ac), 'count_init': (0x100b6e64c, 0x100b6e650),
         'count_seed': (0x100b6e67c, 0x100b6e6ac), 'count_math': (0x100b787c8, 0x100b78808),
         'count_dispatch': (0x100b78808, 0x100b78814), 'count_loop': (0x100b787c8, 0x100b78814),
         'count_branch': (0x100b78814, 0x100b78818), 'phase': (0x100b75148, 0x100b75154),
         'save': (0x100acd9cc, 0x100acd9d4), 'restore': (0x100a6d3bc, 0x100a6d3c4),
         'scalar_zero': (0x100c19e6c, 0x100c19e70), 'scalar_cell': (0x1009a3080, 0x1009a30a4)}
PHASE = {0: 0xa925, 1: 0x56db, 2: 0x2b78, 3: 0xffffd488, 4: 0xb04,
         8: 0x296e, 9: 0x705b, 14: 0xf208, 15: 0xf9, 16: 0x8fa5, 20: 0x101039ef0}
SLOTS = [0x10104ea60, 0x10104eba8]


def parents():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest
    return (json.loads(read(ROOT/'daemon_append_fields_checks.json')),
            json.loads(read(ROOT/'daemon_descriptor_growth_checks.json')))


def slice_row(row, kind, lo):
    a, b = SPANS[kind]
    hi = lo+(b-a)//4
    assert [int(v['pc'], 16) for v in row['source_visits'][lo:hi]] == list(range(a, b, 4))
    return {'kind': kind, 'start_visit': lo, 'end_visit_exclusive': hi,
            'entry': row['source_frames'][lo], 'exit': row['source_frames'][hi],
            'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
            'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]}


def extract():
    old, growth = parents()
    rows, fields, counts = {}, [], Counter()
    for o in old['occurrences']:
        if o['kind'] != 'half_producer':
            continue
        ci, ii, lo = o['class_index'], o['interval_index'], o['start_visit']
        if (ci, ii) not in rows:
            rows[ci, ii] = Parent.Parent.unpack(growth['classes'][ci]['intervals'][ii]['interval_packed'])
        row = rows[ci, ii]
        def last(kind, before=lo):
            return max(j for j in range(before) if row['source_visits'][j]['pc'] == hex(SPANS[kind][0]))
        init, phase = last('count_setup'), last('phase')
        scalar_kind = 'scalar_cell' if o['values']['phase_W23'] != '0xdf8' else 'scalar_zero'
        scalar = last(scalar_kind, init)
        slices = [slice_row(row, 'producer', lo), slice_row(row, 'count_setup', init),
                  slice_row(row, 'phase', phase), slice_row(row, 'save', last('save')),
                  slice_row(row, 'restore', last('restore')), slice_row(row, scalar_kind, scalar)]
        steps = []
        for j in range(init, phase):
            if row['source_visits'][j]['pc'] != hex(SPANS['count_loop'][0]):
                continue
            s = slice_row(row, 'count_loop', j)
            r = [int(x, 16) for x in s['entry']['registers31']]
            assert all(r[k] == value for k, value in PHASE.items())
            edge = next(e for e in row['logical_edges'] if e['source_visit_index'] == s['end_visit_exclusive'])
            assert edge['pc'] == '0x100b78814' and edge['modifier'] == '0x1590' and edge['kind'] == 'braa'
            steps.append({'slice': s, 'edge': edge, 'decoded_before16': (r[10]&65535)^0xdf8,
                          'counter_before32': r[24]})
        k, n, phase25 = [int(o['values'][x], 16) for x in ['phase_W23', 'phase_W24', 'phase_W25']]
        d = (k^0xdf8)&65535
        assert n == len(steps) == max(1, d.bit_length()) and phase25 == 0x7a6302fa
        assert int(slices[5]['exit']['registers31'][23], 16) == k
        assert int(slices[1]['entry']['registers31'][23], 16) == k
        assert int(slices[1]['exit']['registers31'][10], 16) == k
        assert int(slices[2]['exit']['registers31'][25], 16) == phase25
        assert [s['counter_before32'] for s in steps] == list(range(n))
        assert [s['decoded_before16'] for s in steps] == [d >> j for j in range(n)]
        assert all(s['edge']['target'] == ('0x100b75148' if j == n-1 else '0x100b787c8') for j, s in enumerate(steps))
        byte_reads = [r for r in o['reads'] if r['size_bytes'] == 1]
        assert [r['pc'] for r in byte_reads] == ['0x100b75238', '0x100b7523c']
        delta = next(r for r in o['reads'] if r['pc'] == '0x100b7522c')
        assert int.from_bytes(bytes.fromhex(delta['bytes_hex']), 'little') == 0
        for r in byte_reads:
            c = Parent.custody(row, r)
            assert c == next(x['custody'] for x in o['read_custody'] if x['read'] == r)
            assert len(c) == 1 and c[0]['last_writer_in_this_interval']['pc'] == '0x100a0ca74'
        auxiliary = int.from_bytes(b''.join(bytes.fromhex(r['bytes_hex']) for r in byte_reads), 'big')
        value = ((((auxiliary << (n&31))&0xfff)|((n<<12)&65535))+d)&65535
        mixed = value^0x534c
        writer = next(w for w in old['occurrences'] if w['kind'] == 'half_writer' and w['class_index'] == ci
                      and w['interval_index'] == ii and w['start_visit'] == o['end_visit_exclusive'])
        assert int(writer['values']['consumed16'], 16) == mixed
        saved = slices[3]
        restored = slices[4]
        bridge = []
        for register, index in [('X24', 0), ('X23', 1), ('X25', 3)]:
            r = restored['reads'][index]
            c = Parent.custody(row, r)
            assert all(x['last_writer_in_this_interval'] in saved['writes'] for x in c)
            expected = {'X24': n, 'X23': k, 'X25': phase25}[register]
            assert int.from_bytes(bytes.fromhex(r['bytes_hex']), 'little') == expected
            assert int(saved['entry']['registers31'][int(register[1:])], 16) == expected
            assert int(restored['exit']['registers31'][int(register[1:])], 16) == expected
            bridge.append({'register': register, 'restore_read': r, 'custody': c})
        fields.append({'class_index': ci, 'interval_index': ii, 'offset32': writer['values']['offset32'],
                       'raw_scalar32': hex(k), 'decoded_scalar16': d, 'count32': n,
                       'auxiliary_bytes_hex': ''.join(r['bytes_hex'] for r in byte_reads), 'auxiliary16': hex(auxiliary),
                       'retained_auxiliary_bits': 12-n, 'retained_auxiliary_value': hex(auxiliary&((1 << (12-n))-1)),
                       'packed16': hex(value), 'mixed16': hex(mixed), 'writer': writer,
                       'source_occurrence': o, 'slices': slices, 'count_steps': steps, 'register_bridge': bridge,
                       'scalar_read_custody': [{'read': r, 'custody': Parent.custody(row, r)} for r in slices[5]['reads']]})
        for s in slices+[x['slice'] for x in steps]:
            counts.update(selected_slices=1, selected_visits=s['end_visit_exclusive']-s['start_visit'],
                          selected_reads=len(s['reads']), selected_writes=len(s['writes']))
        counts.update(fields=1, count_iterations=n, count_branches=n, register_bridges=len(bridge), auxiliary_byte_custodies=2)
    assert len(fields) == 4 and counts['count_iterations'] == 6
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
