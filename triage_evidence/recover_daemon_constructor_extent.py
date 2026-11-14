#!/usr/bin/env python3
"""Recover constructor allocation/header coupling and the earlier word producer.
O(parent bytes + selected visits + read/write custody scans + decoded state
bytes) time/space. Retained journals only; no new target interval or premise.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_append_fields import custody
import recover_daemon_scalar_serialization as S

P = 'daemon_constructor_extent'
B = S.B
SP = S.SP
PINS = {**S.PINS,
        'daemon_scalar_serialization_checks.json': '93e4930867d43d4daf701fca44736ccac31ff8a678e2df479a792669b243e017',
        'daemon_scalar_serialization_audit.json': '7896c81d547255b4e2b63e17ea39b5e370b2c5b65c2a0ea1d9a2b0fe80add001'}
DEPS = ['daemon_receive_tools.py', 'recover_daemon_constructor_buffer.py', 'recover_daemon_scalar_serialization.py',
        'recover_daemon_append_fields.py']
SPANS = {**{k: S.SPANS[k] for k in ['word_reader', 'word_decoder']},
         'operand_store': (0x100765f24, 0x100765f28), 'old_word_copy': (0x100709a18, 0x100709a1c),
         'growth': (0x100709a64, 0x100709ad4), 'malloc_head': (0x10083dd08, 0x10083dd10),
         'malloc_tail': (0x10083dd18, 0x10083dd20),
         'header_prepare': (0x1006886ac, 0x1006888d8), 'header_inputs': (0x1006886ac, 0x100688778),
         'header_tail': (0x100688778, 0x1006888d8),
         'scalar_store': (0x1008f393c, 0x1008f3944), 'count_store': (0x100a78a68, 0x100a78a70),
         'producer': (0x100618764, 0x100618c20), 'producer_prefix': (0x100618764, 0x100618880),
         'producer_add': (0x100618880, 0x100618960), 'producer_final': (0x100618960, 0x100618c18),
         'quotient_cancel': (0x100618b6c, 0x100618b80),
         'caller': (0x1006153e8, 0x10061543c), 'caller_xor': (0x100615414, 0x100615420),
         'writer_phase': (0x1009a2280, 0x1009a22fc), 'writer': (0x1006bd140, 0x1006bd2a8),
         'writer_math': (0x1006bd150, 0x1006bd294)}


def parents():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest, p
    return json.loads(read(ROOT/'daemon_constructor_buffer_checks.json'))


def sliced(row, kind, last=False):
    a, b = SPANS[kind]
    matches = [j for j, v in enumerate(row['source_visits']) if v['pc'] == hex(a)]
    lo = matches[-1] if last else matches[0]
    hi = lo+(b-a)//4
    assert [v['pc'] for v in row['source_visits'][lo:hi]] == [hex(pc) for pc in range(a, b, 4)]
    return {'kind': kind, 'start_visit': lo, 'end_visit_exclusive': hi,
            'entry': row['source_frames'][lo], 'exit': row['source_frames'][hi],
            'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
            'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]}


def extract():
    old = parents()
    prefixes, branches, coverage, counts = [], [], [], Counter()
    def collect(s):
        counts.update(selected_slices=1, selected_visits=s['end_visit_exclusive']-s['start_visit'],
                      selected_reads=len(s['reads']), selected_writes=len(s['writes']))
    for ci, c in enumerate(old['prefixes']):
        row = B.unpack(c['interval_packed'])
        kinds = ['word_reader', 'word_decoder', 'operand_store', 'old_word_copy', 'growth', 'malloc_head', 'malloc_tail']
        ss = {k: sliced(row, k, last=k in ['word_reader', 'word_decoder']) for k in kinds}
        rr = [r for r in ss['word_reader']['reads'] if r['pc'] in ['0x1008c6128', '0x1008c6184', '0x1008c61dc', '0x1008c6230']]
        assert [(r['address'], r['bytes_hex']) for r in rr] == [(hex(B.T+j), b) for j, b in enumerate(['a2', 'b5', '11', '3d'], 1)]
        assert ss['word_decoder']['exit']['registers31'][20] == '0x8b3dc645'
        copy = ss['old_word_copy']['writes'][0]
        operand = ss['operand_store']['writes'][0]
        assert (copy['address'], copy['after_hex']) == (hex(SP+0x70b4), '45c63d8b')
        assert (operand['address'], operand['after_hex']) == (hex(SP+0x312c), '38000000')
        assert all(f['registers31'][20] == '0x8b3dc645' for f in row['source_frames'][ss['word_decoder']['end_visit_exclusive']:ss['growth']['end_visit_exclusive']+1])
        gr = ss['growth']
        assert gr['entry']['registers31'][8] == '0x10ecc426'
        assert gr['writes'][0]['after_hex'] == '4ac4ec10'
        assert ss['malloc_tail']['exit']['registers31'][0] == row['boundary']['registers31'][0] == '0x39'
        prefixes.append({'prefix_class_index': ci, 'members': c['member_parent_indices'], 'slices': list(ss.values()),
                         'old_header_scalar32': 20, 'operand32': 56, 'old_extent32': 21,
                         'new_extent32': 57, 'old_header_copy': copy, 'operand_store': operand})
        for s in ss.values():
            collect(s)
    for bi, c in enumerate(old['branches']):
        if c['pointer_return64'] == '0x0':
            continue
        row = B.unpack(c['intervals'][0]['interval_packed'])
        kinds = ['word_reader', 'word_decoder', 'header_prepare', 'scalar_store', 'count_store', 'producer', 'caller', 'writer_phase', 'writer']
        ss = {k: sliced(row, k) for k in kinds}
        prep, producer, writer = (ss[k] for k in ['header_prepare', 'producer', 'writer'])
        rr = [r for r in ss['word_reader']['reads'] if r['pc'] in ['0x1008c6128', '0x1008c6184', '0x1008c61dc', '0x1008c6230']]
        assert [(r['address'], r['bytes_hex']) for r in rr] == [(hex(B.F+j), b) for j, b in enumerate(['a2', 'b5', '11', '3d'], 1)]
        assert ss['word_decoder']['exit']['registers31'][20] == prep['entry']['registers31'][20] == '0x8b3dc645'
        assert all(f['registers31'][20] == '0x8b3dc645' for f in row['source_frames'][ss['word_decoder']['end_visit_exclusive']:prep['start_visit']+1])
        inputs = [r for r in prep['reads'] if r['pc'] in ['0x1006886c8', '0x100688724']]
        prefix = prefixes[c['prefix_class_index']]
        joins = []
        for r, w in zip(inputs, [prefix['operand_store'], prefix['old_header_copy']]):
            assert (r['address'], r['bytes_hex']) == (w['address'], w['after_hex'])
            assert all(x['last_writer_in_this_interval'] is None for x in custody(row, r))
            a = int(r['address'], 16)
            assert not any(int(x['address'], 16) < a+4 and a < int(x['address'], 16)+x['size_bytes'] for x in c['intervals'][0]['API_return_premise']['invalidated_spans'])
            joins.append({'read': r, 'prefix_writer': w, 'no_intervening_write_or_invalidation': True})
        assert prep['exit']['registers31'][23] == '0x8b3dc669'
        scalar = ss['scalar_store']['writes'][0]
        count = ss['count_store']['writes'][0]
        assert (scalar['address'], scalar['after_hex']) == (hex(SP+0xab28), '69c63d8b')
        assert (count['address'], count['after_hex']) == (hex(SP+0xab2c), '06000000')
        assert all(f['registers31'][23] == '0x8b3dc669' for f in row['source_frames'][prep['end_visit_exclusive']:ss['scalar_store']['start_visit']+1])
        reads = [r for r in producer['reads'] if r['pc'] in ['0x100618784', '0x100618880']]
        for r, w in zip(reads, [count, scalar]):
            assert all(x['last_writer_in_this_interval'] == w for x in custody(row, r))
        auxiliary = int(producer['entry']['registers31'][19], 16)^0x6703cce9
        value = (((auxiliary << 6)&0x07ffffff)|(6<<27))+56
        assert value == 0x35f411f8
        assert producer['exit']['registers31'][12] == hex(value^0xc12b4f72)
        assert ss['caller']['exit']['registers31'][12] == writer['entry']['registers31'][12] == hex(value^0xe4b5bf34)
        assert [(w['address'], w['after_hex']) for w in writer['writes'][1:]] == [(hex(B.F+j), b) for j, b in enumerate(['b9', '67', '06', 'b1'], 1)]
        branches.append({'branch_index': bi, 'prefix_class_index': c['prefix_class_index'], 'members': c['member_parent_indices'],
                         'ABI_clobber_pattern': c['ABI_clobber_pattern'], 'slices': list(ss.values()), 'input_joins': joins,
                         'producer_read_custody': [{'read': r, 'custody': custody(row, r)} for r in reads],
                         'auxiliary32': hex(auxiliary), 'new_header_scalar32': 56, 'count32': 6, 'packed32': hex(value),
                         'stored_header_hex': 'b96706b1'})
        for s in ss.values():
            collect(s)
    for c in old['coverage']:
        match = next((b for b in branches if b['branch_index'] == c['branch_index']), None)
        if match:
            state = B.unpack(c['derived_terminal_state_packed'])
            memory = S.state_bytes(state)
            header = bytes(memory[B.F+j] for j in range(1, 5))
            assert header.hex() == 'b96706b1'
            assert S.decode(header) == (0x35f411f8, 6, 56)
            assert {'address': hex(B.F), 'size_bytes': 57} in state['foreign_owners']
            coverage.append({'parent_index': c['parent_index'], 'branch_index': c['branch_index'],
                             'new_header_scalar32': 56, 'request_extent32': 57, 'numeric_gap32': 1})
    assert len(prefixes) == 4 and len(branches) == 8 and len(coverage) == 152
    counts.update(prefix_classes=4, success_classes=8, successful_exports=152,
                  exported_header_bytes=608, cross_API_cell_joins=16, producer_cell_joins=16)
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE), 'parent_pins': PINS,
            'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'source_spans': [{'kind': k, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': IMAGE.read(a, b-a).hex()} for k, (a, b) in SPANS.items()],
            'prefixes': prefixes, 'branches': branches, 'coverage': coverage, 'verified_counts': dict(counts),
            'prior_admissions_rerun': False, 'new_target_intervals': 0, 'new_guest_input_bytes': 0,
            'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    e = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
