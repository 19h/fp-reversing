#!/usr/bin/env python3
"""Recover private resize caller records, coordinate selection and span custody.
O(parent bytes + selected visits + reads*writes + exports) time;
O(parent bytes + selected evidence) space. Retained journals only.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from recover_daemon_append_fields import custody
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_record_spans as Parent

P = 'daemon_resize_callers'
B, S, SP, LSP, H = Parent.B, Parent.S, Parent.SP, Parent.LSP, Parent.H
U, A, V = 0x6600060000, SP+0x10cb8, 0x6800060008
PINS = {**Parent.PINS,
        'daemon_record_spans_checks.json': 'c86a7ff3de166cae5034ee4543dc13cd27f6fc13076221ecb94788491f1ffb99',
        'daemon_record_spans_audit.json': '2e5259ad78e740d82a91d1310d8a3c4991d0f843427bf2ac93e09144b77c1a89'}
DEPS = ['recover_daemon_record_spans.py', 'recover_daemon_append_fields.py', 'daemon_receive_tools.py']
SPANS = {
    'caller_build': (0x1007104a0, 0x100710510),
    'precall_word_read': (0x1008a2798, 0x1008a279c),
    'precall_word_write': (0x100b20fd8, 0x100b20fdc),
    'record_pull': (0x100bab30c, 0x100bab364),
    'pointer_bindings': (0x100babb08, 0x100babb28),
    'validation_build': (0x1009d0f40, 0x1009d0f6c),
    'validation_arguments': (0x1009d0fc0, 0x1009d0fc8),
    'validation_inputs': (0x10045fa98, 0x10045faa0),
    'validation_selection': (0x1004983ec, 0x100498444),
    'validation_return_store': (0x1004aa840, 0x1004aa844),
    'validation_return_load': (0x10048d3dc, 0x10048d3e0),
    'validation_caller_result': (0x1009d0fcc, 0x1009d0fec),
    'coordinate': (0x100a8bfc0, 0x100a8bff8),
    'coordinate_math': (0x100a8bfdc, 0x100a8bfe8),
    'coordinate_transfer': (0x100a5dfb0, 0x100a5dfb4),
    'reader': Parent.SPANS['later_reader'], 'decoder': Parent.SPANS['later_decoder'],
    'span_save': (0x100d2bfcc, 0x100d2bfd0),
    'span_input_save': (0x100babb74, 0x100babb78),
    'span_input_load': (0x100a66e24, 0x100a66e28),
    'new_span': (0x100ca350c, 0x100ca35b0),
    'coordinate_reload': (0x100ca35b4, 0x100ca35b8),
    'sum_prefix': (0x100b32954, 0x100b32a0c),
    'sum_tail': (0x100d95a6c, 0x100d95a9c),
    'target_save': (0x100d95aac, 0x100d95ab0),
    'resize': Parent.SPANS['later_growth']}


def parents():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest, p
    return Parent.parents()


def extract():
    _, growth = parents()
    slices, classes, exports, totals = [], [], [], Counter()
    for ci in [2, 3]:
        c = growth['classes'][ci]
        ii = len(c['intervals'])-1
        row = B.unpack(c['intervals'][ii]['interval_packed'])
        def select(kind, lo=None, pc=None):
            a, b = (pc, pc+4) if pc is not None else SPANS[kind]
            if lo is None:
                lo = next(j for j, v in enumerate(row['source_visits']) if v['pc'] == hex(a))
            hi = lo+(b-a)//4
            assert [v['pc'] for v in row['source_visits'][lo:hi]] == [hex(t) for t in range(a, b, 4)]
            s = {'group': 'growth', 'class_index': ci, 'interval_index': ii, 'kind': kind,
                 'start_visit': lo, 'end_visit_exclusive': hi, 'entry': row['source_frames'][lo],
                 'exit': row['source_frames'][hi],
                 'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
                 'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]}
            slices.append(s)
            totals.update(selected_slices=1, selected_visits=hi-lo, selected_reads=len(s['reads']), selected_writes=len(s['writes']))
            return s
        ss = {k: select(k) for k in SPANS}
        for kind in ['coordinate', 'reader', 'decoder']:
            matches = [j for j, v in enumerate(row['source_visits']) if v['pc'] == hex(SPANS[kind][0])]
            assert len(matches) == 2
            select(kind, lo=matches[1])
        calls = [x for x in row['source_calls'] if x['pc'] in ['0x100710588', '0x100b21438', '0x1009d0fc8']]
        assert [x['target'] for x in calls] == ['0x100b211f4', '0x100b003c8', '0x10045f984']
        for x in calls:
            j = x['source_visit_index']
            assert x['arguments8'] == row['source_frames'][j]['registers31'][:8]
            assert row['source_visits'][j+1]['pc'] == x['target']
            assert int(row['source_frames'][j]['registers31'][17], 16) == int(x['modifier'], 16)
        record = []
        for r in row['source_reads']:
            address = int(r['address'], 16)
            if r['source_visit_index'] <= calls[0]['source_visit_index'] or not A <= address < A+0x3c:
                continue
            cu = custody(row, r)
            w = cu[0]['last_writer_in_this_interval']
            assert w is not None and all(t['last_writer_in_this_interval'] == w for t in cu)
            assert w['after_hex'] == r['bytes_hex'] and w['size_bytes'] == r['size_bytes']
            select('record_read', lo=r['source_visit_index'], pc=int(r['pc'], 16))
            select('record_write', lo=w['source_visit_index'], pc=int(w['pc'], 16))
            record.append({'offset_bytes': address-A, 'read': r, 'custody': cu})
        assert sorted((r['offset_bytes'], r['read']['size_bytes']) for r in record) == [
            (0, 4), (4, 4), (8, 8), (16, 8), (28, 4), (32, 8), (40, 2), (44, 4), (48, 8), (56, 4)]
        pre = ss['precall_word_read']['reads'][0]
        assert pre['address'] == hex(A+0x18) and pre['bytes_hex'] == '51c63d8b'
        assert all(t['last_writer_in_this_interval'] == ss['precall_word_write']['writes'][0] for t in custody(row, pre))
        chains = []
        for pc, writer in [(0x10045fa98, 0x1009d0f64), (0x10045fa9c, 0x1009d0f50),
                           (0x1004983ec, 0x1009d0f68),
                           (0x100bab314, 0x100b00588), (0x100a66e24, 0x100babb74),
                           (0x10048d3dc, 0x100498440), (0x1009d0fe4, 0x1004aa840),
                           (0x100ca35b4, 0x1009d0fe8), (0x100b32960, 0x100d2bfcc),
                           (0x100a44578, 0x100babb14), (0x100c055e8, 0x100d95aac)]:
            rr = [r for r in row['source_reads'] if r['pc'] == hex(pc)]
            for r in rr:
                cu = custody(row, r)
                w = cu[0]['last_writer_in_this_interval']
                assert w is not None and w['pc'] == hex(writer)
                assert all(t['last_writer_in_this_interval'] == w for t in cu)
                select('custody_read', lo=r['source_visit_index'], pc=pc)
                select('custody_write', lo=w['source_visit_index'], pc=writer)
                chains.append({'read': r, 'custody': cu})
        pair = next(r for r in row['source_reads'] if r['pc'] == '0x100c055b0')
        cu = custody(row, pair)
        assert {t['last_writer_in_this_interval']['pc'] for t in cu} == {'0x100babb24'}
        # LDP is represented as two separate eight-byte reads.
        pairs = [r for r in row['source_reads'] if r['pc'] == '0x100c055b0']
        assert len(pairs) == 2
        for r, pc in zip(pairs, [0x100babb24, 0x100babb1c]):
            cu = custody(row, r)
            assert all(t['last_writer_in_this_interval']['pc'] == hex(pc) for t in cu)
            chains.append({'read': r, 'custody': cu})
        def stable(reg, a, b, value):
            assert all(f['registers31'][reg] == hex(value) for f in row['source_frames'][a:b+1])
        stable(0, ss['record_pull']['end_visit_exclusive'], ss['span_input_save']['start_visit'], 0x0d38177c)
        stable(2, ss['validation_return_load']['end_visit_exclusive'], ss['validation_return_store']['start_visit'], 0x76d8eab9)
        stable(8, ss['validation_caller_result']['end_visit_exclusive'], ss['coordinate_transfer']['start_visit'], 0x76d8eab9)
        stable(9, ss['coordinate_transfer']['end_visit_exclusive'], ss['coordinate']['start_visit'], 0x76d8eab9)
        stable(13, ss['span_input_load']['end_visit_exclusive'], ss['new_span']['start_visit'], 0x0d38177c)
        stable(12, ss['new_span']['end_visit_exclusive'], ss['sum_prefix']['start_visit'], 0x8b3dc645)
        stable(27, ss['decoder']['end_visit_exclusive'], ss['span_save']['start_visit'], 0x8b3dc645)
        stable(13, ss['sum_prefix']['end_visit_exclusive'], ss['sum_tail']['start_visit'], 0xe9847386)
        stable(13, ss['sum_tail']['end_visit_exclusive'], ss['target_save']['start_visit'], 40)
        assert ss['validation_selection']['exit']['registers31'][5] == '0x76d8eab9'
        assert ss['validation_selection']['entry']['registers31'][16] == '0xac4a2e8320e0bdc2'
        assert [(r['address'], r['bytes_hex']) for r in ss['validation_selection']['reads']] == [
            (hex(V+0x10), 'f72cf855'), (hex(U+0x14), '5ec4ec10'), (hex(U+0x18), '81ead876')]
        assert next(r for r in row['source_reads'] if r['pc'] == '0x100bab314')['bytes_hex'] == '148b6db5d6c0c98a'
        assert next(r for r in record if r['offset_bytes'] == 0x2c)['read']['bytes_hex'] == '688cca57'
        assert ss['coordinate_math']['exit']['registers31'][8] == '0x4225556d'
        for start in [j for j, v in enumerate(row['source_visits']) if v['pc'] == hex(SPANS['coordinate'][0])]:
            if start > ss['coordinate_reload']['end_visit_exclusive']:
                stable(9, ss['coordinate_reload']['end_visit_exclusive'], start, 0x76d8eab9)
            end = start+(SPANS['coordinate'][1]-SPANS['coordinate'][0])//4
            reader = next(j for j in range(end, len(row['source_visits'])) if row['source_visits'][j]['pc'] == hex(SPANS['reader'][0]))
            stable(8, end, reader, 0x4225556d)
            reads = [r for r in row['source_reads'] if reader <= r['source_visit_index'] < reader+99 and r['pc'] in
                     ['0x100a44590', '0x100a445ec', '0x100a44644', '0x100a44698']]
            assert [(r['address'], r['bytes_hex']) for r in reads] == [(hex(H+57+j), b) for j, b in enumerate(['9e', '6f', 'd1', 'e4'])]
        assert ss['target_save']['writes'][0]['after_hex'] == '28000000'
        assert row['boundary']['registers31'][0] == '0x61'
        classes.append({'class_index': ci, 'calls': calls, 'caller_record_fields': record,
                        'precall_word': {'read': pre, 'custody': custody(row, pre)},
                        'custody_chains': chains, 'record_input_bias64': '0x8ac9c0d6b56d8b14',
                        'record_word_at_2c': '0x57ca8c68', 'span_input32': '0x0d38177c',
                        'decoded_payload_contribution32': 0, 'new_span32': 20, 'old_span32': 20,
                        'requested_span32': 40, 'selected_offset_bytes': 57, 'pending_extent_bytes': 97})
    for c in growth['coverage']:
        if c['pointer_return64'] == '0x0':
            continue
        state = B.unpack(c['derived_terminal_state_packed'])
        m = S.state_bytes(state)
        def word(a, n):
            return int.from_bytes(bytes(m[a+j] for j in range(n)), 'little')
        assert word(U+8, 8) == H and word(U+0x10, 4) == word(U+0x14, 4) == 0x10ecc45e
        assert word(LSP+0x3dc, 4) == 40 and word(LSP+0x364, 4) == 0x8b3dc645
        assert word(LSP+0x38c, 4) == 0x76d8eab9 and word(LSP+0x260, 4) == 0x0d38177c
        exports.append({k: c[k] for k in ['parent_index', 'branch_index', 'cohort_index', 'class_index', 'ABI_clobber_pattern'] if k in c})
    assert len(exports) == 304
    totals.update(caller_classes=2, caller_record_reads=20, caller_record_bytes_read=108,
                  checked_exports=304, export_words_checked=2128)
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE), 'parent_pins': PINS,
            'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'source_spans': [{'kind': k, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': IMAGE.read(a, b-a).hex()} for k, (a, b) in SPANS.items()],
            'slices': slices, 'classes': classes, 'exports': exports, 'verified_counts': dict(totals),
            'prior_admissions_rerun': False, 'new_target_intervals': 0, 'new_guest_input_bytes': 0,
            'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    e = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
