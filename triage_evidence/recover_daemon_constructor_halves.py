#!/usr/bin/env python3
"""Recover the constructor's zero reader, two halfword producers and custody.
O(parent bytes + selected visits + selected reads*writes + exported states)
time/space. Retained journals only; no new target interval or entry premise.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE, qword, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_network_record import state_bytes
import recover_daemon_constructor_buffer as B
from recover_daemon_append_fields import custody

P = 'daemon_constructor_halves'
PINS = {'daemon_constructor_buffer_checks.json': 'fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07',
        'daemon_constructor_buffer_replay.json': '61f012a43cbae9cf2ff8a5207603a30b9bbf82c7b2d92811e0c1a2ff7505c107',
        'daemon_constructor_buffer_audit.json': '47108bdf5bedbb6a9aec1397ae777d6317a689cdea625638da5fb94a3c86e252',
        'daemon_halfword_update_checks.json': '5f53bea42c88b3bdc516321e318f4ca5da94c4e2a6eff64e51c12b349726f9d4',
        'daemon_packed_halves_checks.json': '12d8bf65c7c1140e5a842764cc68e850eccbdc7a6075304059ec01f8f8ca7fe4'}
DEPS = ['daemon_receive_tools.py', 'recover_daemon_constructor_buffer.py',
        'recover_daemon_append_fields.py', 'audit_daemon_network_record.py']
SP = 0x6800060100
CELL = SP+0x46b4
BANKS = {'D': (0x420, 0x100f21190, 16), 'E': (0x418, 0x100fa38b0, 20), 'K': (0x428, 0x100ffc9e0, 17)}
SPANS = {'reader': (0x100755878, 0x1007559ac), 'reader_bytes': (0x100755878, 0x100755964),
         'reader_assembly': (0x100755964, 0x10075598c), 'reader_scalar': (0x10075598c, 0x1007559a0),
         'zero_gate': (0x1008c881c, 0x1008c8890), 'zero_header_gate': (0x10084db18, 0x10084dbb8),
         'scalar_store': (0x10083629c, 0x100836348), 'scalar_prepare': (0x1006615b8, 0x1006615cc),
         'producer': (0x10095c7f8, 0x10095cc30), 'auxiliary': (0x10095c81c, 0x10095c840),
         'shift': (0x10095c840, 0x10095c85c), 'pack': (0x10095c85c, 0x10095c884),
         'scalar_add': (0x10095c884, 0x10095ca2c), 'producer_tail': (0x10095ca2c, 0x10095cc2c),
         'writer': (0x100878944, 0x100878a24), 'writer_math': (0x10087895c, 0x100878a24),
         'save': (0x100add598, 0x100add5a0), 'restore': (0x100add7ec, 0x100add7f8)}


def parents():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest, p
    return json.loads(read(ROOT/'daemon_constructor_buffer_checks.json'))


def overlap(item, address=CELL, size=2):
    a = int(item['address'], 16)
    return a < address+size and address < a+item['size_bytes']


def sliced(row, kind, lo=None):
    a, b = SPANS[kind]
    if lo is None:
        lo = next(j for j, v in enumerate(row['source_visits']) if v['pc'] == hex(a))
    hi = lo+(b-a)//4
    assert [v['pc'] for v in row['source_visits'][lo:hi]] == [hex(pc) for pc in range(a, b, 4)]
    return {'kind': kind, 'start_visit': lo, 'end_visit_exclusive': hi,
            'entry': row['source_frames'][lo], 'exit': row['source_frames'][hi],
            'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
            'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]}


def extract():
    old = parents()
    prefixes, fields, exported, counts, slots = [], [], [], Counter(), set()
    def count(s):
        counts.update(selected_slices=1, selected_visits=s['end_visit_exclusive']-s['start_visit'],
                      selected_reads=len(s['reads']), selected_writes=len(s['writes']))
    for ci, c in enumerate(old['prefixes']):
        row = B.unpack(c['interval_packed'])
        slices = [sliced(row, k) for k in ['reader', 'zero_gate', 'zero_header_gate', 'scalar_store']]
        reader, gate, header, store = slices
        assert reader['entry']['SP'] == hex(SP)
        assert reader['exit']['registers31'][9] == '0x0'
        assert gate['entry']['registers31'][9] == '0x0'
        assert store['entry']['registers31'][10:14] == ['0xe6eef3fb', '0x10083629c', '0x0', '0x7ff7cfe0']
        reads = [r for r in reader['reads'] if r['pc'] in ['0x1007558b8', '0x100755924']]
        assert [(r['address'], r['bytes_hex']) for r in reads] == [(hex(B.T+15), '55'), (hex(B.T+16), '89')]
        w = next(w for w in store['writes'] if overlap(w))
        assert (w['pc'], w['address'], w['size_bytes'], w['after_hex']) == ('0x100836344', hex(CELL), 4, '4b6ae328')
        assert [x for x in row['source_writes'] if overlap(x) and x['source_visit_index'] >= w['source_visit_index']] == [w]
        edges = []
        for s in [gate, header]:
            edge = next(x for x in row['logical_edges'] if x['source_visit_index'] == s['end_visit_exclusive'])
            assert edge['target'] == ('0x10084db18' if s is gate else '0x10083629c')
            dispatch = next(r for r in s['reads'] if int(r['address'], 16) >= 0x101039ef0 and r['size_bytes'] == 8
                            and int(r['address'], 16) < 0x101039ef0+0x100000)
            slots.add(int(dispatch['address'], 16))
            edges.append({'edge': edge, 'slot_read': dispatch})
        prefixes.append({'prefix_class_index': ci, 'members': c['member_parent_indices'], 'slices': slices,
                         'old_bytes_hex': '5589', 'decoded_scalar16': 0, 'scalar_store': w, 'edges': edges})
        for s in slices:
            count(s)
    for bi, c in enumerate(old['branches']):
        if c['pointer_return64'] == '0x0':
            continue
        rows = [B.unpack(i['interval_packed']) for i in c['intervals']]
        assert len(rows) == 2
        for item in c['intervals']:
            assert not any(overlap(x) for x in item['API_return_premise']['invalidated_spans'])
        assert not any(overlap(w) for w in rows[0]['source_writes'])
        row = rows[1]
        prep = sliced(row, 'scalar_prepare')
        rr = next(r for r in prep['reads'] if r['pc'] == '0x1006615c0')
        assert (rr['address'], rr['size_bytes'], rr['bytes_hex']) == (hex(CELL), 2, '4b6a')
        assert not any(overlap(w) for w in row['source_writes'] if w['source_visit_index'] < rr['source_visit_index'])
        assert prep['exit']['registers31'][20] == '0xdf9'
        positions = [j for j, v in enumerate(row['source_visits']) if v['pc'] == hex(SPANS['producer'][0])]
        assert len(positions) == 2
        branch_fields = []
        for lo in positions:
            producer = sliced(row, 'producer', lo)
            writer = sliced(row, 'writer', producer['end_visit_exclusive']+1)
            k, n = [int(producer['entry']['registers31'][j], 16) for j in [20, 21]]
            d = (k^0xdf8)&65535
            assert n == 1 and d in [0, 1]
            assert producer['entry']['SP'] == hex(SP)
            ar = [r for r in producer['reads'] if r['size_bytes'] == 1]
            assert [r['pc'] for r in ar] == ['0x10095c80c', '0x10095c814']
            auxiliary = int.from_bytes(b''.join(bytes.fromhex(r['bytes_hex']) for r in ar), 'big')
            value = ((((auxiliary << (n&31))&0xfff)|((n<<12)&65535))+d)&65535
            assert (int(producer['exit']['registers31'][8], 16)&65535) == value^0xdf8
            writes = writer['writes']
            offset = int(writes[0]['address'], 16)-B.F
            assert offset == (35 if d == 0 else 15)
            assert [(int(w['address'], 16), w['size_bytes']) for w in writes] == [(B.F+offset, 1), (B.F+offset+1, 1)]
            assert (value >> 12) == n and (value&((1 << n)-1)) == d
            ac = [{'read': r, 'custody': custody(row, r)} for r in ar]
            assert all(len(x['custody']) == 1 and x['custody'][0]['last_writer_in_this_interval']['pc'] == '0x100a0ca74' for x in ac)
            saved_pos = max(j for j in range(lo) if row['source_visits'][j]['pc'] == hex(SPANS['save'][0]))
            restore_pos = max(j for j in range(lo) if row['source_visits'][j]['pc'] == hex(SPANS['restore'][0]))
            save, restore = sliced(row, 'save', saved_pos), sliced(row, 'restore', restore_pos)
            bridges = []
            for register, expected in [(20, k), (21, n)]:
                sr = next(r for r in restore['reads'] if int.from_bytes(bytes.fromhex(r['bytes_hex']), 'little') == expected)
                cu = custody(row, sr)
                assert all(x['last_writer_in_this_interval'] in save['writes'] for x in cu)
                assert int(save['entry']['registers31'][register], 16) == expected
                assert int(restore['exit']['registers31'][register], 16) == expected
                bridges.append({'register': 'X'+str(register), 'restore_read': sr, 'custody': cu})
            if d == 1:
                assert all(f['registers31'][20] == '0xdf9' for f in row['source_frames'][prep['end_visit_exclusive']:save['start_visit']+1])
            slices = [producer, writer, save, restore]+([prep] if d == 1 else [])
            field = {'branch_index': bi, 'prefix_class_index': c['prefix_class_index'], 'members': c['member_parent_indices'],
                     'ABI_clobber_pattern': c['ABI_clobber_pattern'], 'offset_bytes': offset,
                     'scalar16': d, 'encoded_scalar32': hex(k), 'count32': n, 'auxiliary_bytes_hex': ''.join(r['bytes_hex'] for r in ar),
                     'packed16': hex(value), 'producer_result_low16': hex(value^0xdf8),
                     'stored_bytes_hex': ''.join(w['after_hex'] for w in writes), 'slices': slices,
                     'auxiliary_custody': ac, 'register_bridges': bridges,
                     'scalar_one_read': rr if d else None}
            fields.append(field)
            branch_fields.append(field)
            for s in slices:
                count(s)
        header = next(f for f in branch_fields if f['offset_bytes'] == 15)
        assert header['stored_bytes_hex'] == '56ee' and header['packed16'] == '0x1937'
        for address in [B.F+15, B.F+16, B.F+35, B.F+36]:
            expected = next(w for f in branch_fields for w in f['slices'][1]['writes'] if w['address'] == hex(address))
            assert [w for w in row['source_writes'] if overlap(w, address, 1) and w['source_visit_index'] >= expected['source_visit_index']] == [expected]
    by_branch = {f['branch_index']: [x for x in fields if x['branch_index'] == f['branch_index']] for f in fields}
    for c in old['coverage']:
        if c['branch_index'] not in by_branch:
            continue
        m = state_bytes(B.unpack(c['derived_terminal_state_packed']))
        values = []
        for f in by_branch[c['branch_index']]:
            a = B.F+f['offset_bytes']
            assert bytes(m[a+j] for j in range(2)).hex() == f['stored_bytes_hex']
            values.append({'offset_bytes': f['offset_bytes'], 'bytes_hex': f['stored_bytes_hex'], 'scalar16': f['scalar16']})
        exported.append({'parent_index': c['parent_index'], 'branch_index': c['branch_index'], 'fields': values})
    assert len(prefixes) == 4 and len(fields) == 16 and len(exported) == 152
    routes = []
    for condition, index in [('decoded_scalar_nonzero_or_zero_header_q_below_21', 0xa05f),
                             ('decoded_scalar_zero', 0xa085), ('zero_header_q_at_least_21', 0xbc52)]:
        slot = 0x101039ef0+index*8
        slots.add(slot)
        routes.append({'condition': condition, 'index': hex(index), 'slot': hex(slot), 'target': hex(qword(slot)),
                       'logical_modifier': '0x62ce'})
    counts.update(prefix_classes=4, success_branch_classes=8, fields=16, register_bridges=32,
                  exported_states=152, exported_field_bytes=608, original_zero_edges=8)
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'parent_pins': PINS,
            'source_spans': [{'kind': k, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': IMAGE.read(a, b-a).hex()} for k, (a, b) in SPANS.items()],
            'original_fixups': verify_original_fixups(sorted(slots)), 'static_routes': routes,
            'prefixes': prefixes, 'fields': fields, 'export_coverage': exported,
            'verified_counts': dict(counts), 'prior_admissions_rerun': False,
            'new_target_intervals': 0, 'new_guest_input_bytes': 0, 'new_API_return_premises': 0,
            'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    e = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
