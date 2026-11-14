#!/usr/bin/env python3
"""Normalize scalar byte masks and recover the constructor word-to-gate join.
O(parent bytes + selected visits + custody scans + decoded state bytes) time/space.
Retained journals only; no new target interval, input, root or API premise.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_network_record import state_bytes
from audit_daemon_append_fields import masks
from recover_daemon_append_fields import custody
import recover_daemon_constructor_halves as C

P = 'daemon_scalar_serialization'
B = C.B
SP = C.SP
CELL = SP+0x64a8
STREAM = bytes.fromhex('d98c9317498b221182b3198570dd904f')
PINS = {**C.PINS,
        'daemon_constructor_halves_checks.json': '801ca3b1a59a9017a3f9b42f32b35956b91d16fa506b3a85548d2f914d3e97b8',
        'daemon_constructor_halves_audit.json': '0dc9ccbc8d74f9caaa2bb78d34ae7c745ba6710a9a05df0b9098e29e9f2a51e7',
        'daemon_descriptor_growth_checks.json': 'b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2',
        'daemon_packed_words_checks.json': 'e8d3a4ffe60b0a28944a5d4a47227f6d313c609e00ab8dcc304c38fc00734554',
        'daemon_packed_words_audit.json': 'fc68105796266bb76dbf92fa3c8efc35fed3d970b4bd6aa11ed08aedd4bd2aaa'}
DEPS = ['daemon_receive_tools.py', 'recover_daemon_constructor_halves.py', 'recover_daemon_constructor_buffer.py',
        'recover_daemon_append_fields.py', 'audit_daemon_append_fields.py', 'audit_daemon_network_record.py']
SPANS = {'word_reader': (0x1008c6110, 0x1008c629c), 'word_decoder': (0x10076c4b8, 0x10076c570),
         'decoder_math': (0x10076c4c4, 0x10076c564), 'word_store': (0x10085552c, 0x100855538)}
SLOTS = [0x101039ef0+index*8 for index in [0x1305, 0x941]]


def parents():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest, p
    return (json.loads(read(ROOT/'daemon_constructor_buffer_checks.json')),
            json.loads(read(ROOT/'daemon_constructor_halves_checks.json')),
            json.loads(read(ROOT/'daemon_descriptor_growth_checks.json')))


def sliced(row, kind):
    a, b = SPANS[kind]
    lo = next(j for j, v in enumerate(row['source_visits']) if v['pc'] == hex(a))
    hi = lo+(b-a)//4
    assert [v['pc'] for v in row['source_visits'][lo:hi]] == [hex(pc) for pc in range(a, b, 4)]
    return {'kind': kind, 'start_visit': lo, 'end_visit_exclusive': hi,
            'entry': row['source_frames'][lo], 'exit': row['source_frames'][hi],
            'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
            'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]}


def decode(raw, offset=1):
    value = int.from_bytes(bytes(b^STREAM[(offset+j)&15] for j, b in enumerate(raw)), 'big')
    n = value >> 27
    scalar = value if n == 0 else value&((1 << n)-1)
    return value, n, scalar


def extract():
    old, halves, growth = parents()
    masks_checked = []
    for offset in range(16):
        for kind, xor in [('word_writer', bytes.fromhex('e4b5bf34')), ('half_writer', bytes.fromhex('534c'))]:
            normalized = bytes(a^b for a, b in zip(masks(kind, offset), xor))
            expected = bytes(STREAM[(offset+j)&15] for j in range(len(xor)))
            assert normalized == expected
            masks_checked.append({'offset_residue': offset, 'kind': kind, 'normalized_mask_hex': normalized.hex()})
    prefixes, exports, snapshots, counts = [], [], [], Counter()
    for ci, c in enumerate(old['prefixes']):
        row = B.unpack(c['interval_packed'])
        slices = [sliced(row, k) for k in ['word_reader', 'word_decoder', 'word_store']]
        reader, decoder, store = slices
        rr = [r for r in reader['reads'] if r['pc'] in ['0x1008c6128', '0x1008c6184', '0x1008c61dc', '0x1008c6230']]
        assert [(int(r['address'], 16), r['size_bytes']) for r in rr] == [(B.T+j, 1) for j in range(1, 5)]
        raw = b''.join(bytes.fromhex(r['bytes_hex']) for r in rr)
        assert raw.hex() == 'a2b5113d'
        value, n, scalar = decode(raw)
        assert (value, n, scalar) == (0x2e260674, 5, 20)
        assert reader['exit']['registers31'][9] == decoder['entry']['registers31'][9] == hex(value^0x8b3dc651)
        assert decoder['exit']['registers31'][20] == store['entry']['registers31'][20] == '0x8b3dc645'
        assert all(f['registers31'][20] == '0x8b3dc645' for f in row['source_frames'][decoder['end_visit_exclusive']:store['start_visit']+1])
        assert len(store['writes']) == 1
        w = store['writes'][0]
        assert (w['pc'], w['address'], w['size_bytes'], w['after_hex']) == ('0x100855534', hex(CELL), 4, '45c63d8b')
        gate = next(p for p in halves['prefixes'] if p['prefix_class_index'] == ci)['slices'][2]
        gr = next(r for r in gate['reads'] if r['pc'] == '0x10084db2c')
        cu = custody(row, gr)
        assert (gr['address'], gr['bytes_hex']) == (hex(CELL), w['after_hex'])
        assert all(x['last_writer_in_this_interval'] == w for x in cu)
        edges = []
        for s, dest, reg, modifier in [(reader, '0x10076c4b8', 10, '0x1890'), (decoder, '0x10080d8bc', 8, '0x7eeb')]:
            edge = next(x for x in row['logical_edges'] if x['source_visit_index'] == s['end_visit_exclusive'])
            assert edge['target'] == s['exit']['registers31'][reg] == dest
            assert edge['modifier'] == modifier and s['exit']['registers31'][17] == modifier
            edges.append({'edge': edge, 'target_register': reg})
        prefixes.append({'prefix_class_index': ci, 'members': c['member_parent_indices'], 'slices': slices,
                         'stored_word_hex': raw.hex(), 'packed32': hex(value), 'count32': n, 'scalar32': scalar,
                         'gate_read': gr, 'gate_read_custody': cu, 'edges': edges})
        for s in slices:
            counts.update(selected_slices=1, selected_visits=s['end_visit_exclusive']-s['start_visit'],
                          selected_reads=len(s['reads']), selected_writes=len(s['writes']))
    for c in old['prefix_coverage']:
        state = B.unpack(c['derived_terminal_state_packed'])
        m = state_bytes(state)
        assert bytes(m[CELL+j] for j in range(4)).hex() == '45c63d8b'
        exports.append({'parent_index': c['parent_index'], 'prefix_class_index': c['class_index'], 'encoded_cell32': '0x8b3dc645'})
    def snapshot(c, cohort, address, extent, expected):
        state = B.unpack(c['derived_terminal_state_packed'])
        assert {'address': hex(address), 'size_bytes': extent} in state['foreign_owners']
        m = state_bytes(state)
        raw = bytes(m[address+j] for j in range(1, 5))
        value, n, scalar = decode(raw)
        assert raw.hex() == expected and scalar+1 == extent
        snapshots.append({'cohort': cohort, 'parent_index': c.get('parent_index', c.get('cohort_index')),
                          'branch_or_class_index': c.get('branch_index', c.get('class_index')),
                          'ABI_clobber_pattern': c.get('ABI_clobber_pattern'), 'address': hex(address), 'extent_bytes': extent,
                          'stored_word_hex': raw.hex(), 'packed32': hex(value), 'count32': n, 'scalar32': scalar})
    for c in old['prefix_coverage']:
        snapshot(c, 'T', B.T, 21, 'a2b5113d')
    success = {j for j, c in enumerate(old['branches']) if c['pointer_return64'] != '0x0'}
    for c in old['coverage']:
        if c['branch_index'] in success:
            snapshot(c, 'F', B.F, 57, 'b96706b1')
    for c in growth['coverage']:
        if c['pointer_return64'] == '0x6600080000':
            snapshot(c, 'H', 0x6600080000, 77, 'b7151d05')
    assert len(exports) == 76 and Counter(s['cohort'] for s in snapshots) == {'T': 76, 'F': 152, 'H': 304}
    counts.update(mask_identities=32, normalized_mask_bytes=96, prefix_classes=4, cell_exports=76,
                  exported_cell_bytes=304, snapshot_headers=532, snapshot_header_bytes=2128, logical_edges=8)
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE), 'parent_pins': PINS,
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'stream_hex': STREAM.hex(), 'mask_identities': masks_checked,
            'source_spans': [{'kind': k, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': IMAGE.read(a, b-a).hex()} for k, (a, b) in SPANS.items()],
            'original_fixups': verify_original_fixups(SLOTS), 'prefixes': prefixes, 'cell_exports': exports,
            'header_snapshots': snapshots, 'verified_counts': dict(counts), 'prior_admissions_rerun': False,
            'new_target_intervals': 0, 'new_guest_input_bytes': 0, 'new_API_return_premises': 0,
            'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    e = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
