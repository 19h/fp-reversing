#!/usr/bin/env python3
"""Recover record-selection gates, default-coordinate custody and read roles.
O(parent bytes + journal visits + custody scans + text words + exports) time;
O(parent receipts + selected evidence + largest journal) space. No new target
interval, guest input, owner/root definition or API-return premise.
"""
import json
import struct
from collections import Counter
from hashlib import sha256
from daemon_receive_tools import ROOT, SOURCE, IMAGE, FIXUPS, TABLE, verify_original_fixups
from recover_daemon_iokit_census import text_section
from recover_daemon_append_fields import custody
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_resize_callers as Parent

P = 'daemon_record_selection'
B, S, SP, U, H = Parent.B, Parent.S, Parent.SP, Parent.U, Parent.H
PINS = {**Parent.PINS,
        'daemon_resize_callers_checks.json': '421f899bf25a3ac563aa923545423c65aa6c2cb19ffa5ccc45aa928bb2049ac1',
        'daemon_resize_callers_audit.json': '727dcee019edfe6bf0f49e8f3f89e138839f7b23eca502cbdf859a452d0faa3e',
        'daemon_constructor_gate_checks.json': '9c4ad519628142f228742dd3a011a6b10f94aa106783bd6ba30caffad70af6ff',
        'daemon_constructor_gate_replay.json': 'fc62eda40f7eeb4750c193183740342c223f684247ade9713b7fcd5decb047dc',
        'daemon_constructor_gate_audit.json': 'd95e9e56e1fef1cd3f2fcf610670abcaa98e03159995d478d166e572d97d5b34'}
DEPS = ['recover_daemon_resize_callers.py', 'recover_daemon_iokit_census.py', 'recover_daemon_append_fields.py',
        'daemon_receive_tools.py', 'daemon_receive_fixups.txt']
SPANS = {'initializer': (0x100825894, 0x1008258b0),
         'availability0': (0x1005275c4, 0x100527608), 'availability8': (0x100534460, 0x100534490),
         'availability_zero': (0x100534494, 0x10053449c),
         'coordinate_and_first_bound': (0x1004983ec, 0x10049847c),
         'saved_operands': (0x10049f6a8, 0x10049f6e8),
         'word_reader': (0x100405d98, 0x100405fa4),
         'positive_span': (0x100470afc, 0x100470bc8),
         'span_zero': (0x100470bcc, 0x100470bd4),
         'span_end_bound': (0x1003f8a58, 0x1003f8acc),
         'extent_zero': (0x1003f8ad0, 0x1003f8ad8),
         'flag_gate': (0x10048e9f4, 0x10048ea28),
         'half_reader_decoder': (0x1003cbb0c, 0x1003cbd2c),
         'transformed_half_gate': (0x1003209ac, 0x1003209f0),
         'selected_reload': (0x10048d3dc, 0x10048d3e0),
         'return_store': (0x1004aa840, 0x1004aa844)}
ROUTES = [('availability0', 0x8ecf, 0x100534460, 0x90b4), ('availability0', 0x8ee5, 0x1004983ec, 0x90b4),
          ('availability8', 0xb760, 0x1004aa840, 0x90b4),
          ('first_bound', 0x6fc3, 0x10049f6a8, 0xfb0f), ('first_bound', 0x6993, 0x1004aa840, 0xfb0f),
          ('positive_span', 0x1ffb, 0x1003f8a58, 0xcb9a), ('positive_span', 0x1bc3, 0x1004aa840, 0xcb9a),
          ('span_end_bound', 0xa743, 0x1004aa840, 0xf01d), ('span_end_bound', 0xa71d, 0x10048e9f4, 0xf01d),
          ('flag_gate', 0x6ce1, 0x1003cbb0c, 0xe0aa), ('flag_gate', 0x6ce6, 0x100495c3c, 0xe0aa),
          ('half_gate', 0x83da, 0x10048d3d0, 0xd137), ('half_gate', 0x3a61, 0x1004bad90, 0xd137)]


def parents():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest, p
    old, growth = Parent.parents()
    return json.loads(read(ROOT/'daemon_constructor_gate_checks.json')), old, growth


def journals(data):
    cg, old, growth = data
    for ci, c in enumerate(cg['classes']):
        yield 'initializer', ci, 0, B.unpack(c['interval_packed'])
    for ci, c in enumerate(old['prefixes']):
        yield 'prefix', ci, 0, B.unpack(c['interval_packed'])
    for ci, c in enumerate(old['branches']):
        for ii, x in enumerate(c['intervals']):
            yield 'branch', ci, ii, B.unpack(x['interval_packed'])
    for ci, c in enumerate(growth['classes']):
        for ii, x in enumerate(c['intervals']):
            yield 'growth', ci, ii, B.unpack(x['interval_packed'])


def extract():
    data = parents()
    slices, defaults, helpers, census, exports, totals = [], [], [], [], [], Counter()
    for group, ci, ii, row in journals(data):
        writes = [w for w in row['source_writes'] if int(w['address'], 16) < U+0x1c and U+0x18 < int(w['address'], 16)+w['size_bytes']]
        census.append({'group': group, 'class_index': ci, 'interval_index': ii, 'source_visits': len(row['source_visits']), 'overlapping_writes': writes})
        totals.update(journals_scanned=1, journal_visits_scanned=len(row['source_visits']), default_overlapping_write_events=len(writes))
        def select(kind, lo=None, pc=None):
            a, b = (pc, pc+4) if pc is not None else SPANS[kind]
            if lo is None:
                lo = next(j for j, v in enumerate(row['source_visits']) if v['pc'] == hex(a))
            hi = lo+(b-a)//4
            assert [v['pc'] for v in row['source_visits'][lo:hi]] == [hex(t) for t in range(a, b, 4)]
            s = {'group': group, 'class_index': ci, 'interval_index': ii, 'kind': kind,
                 'start_visit': lo, 'end_visit_exclusive': hi, 'entry': row['source_frames'][lo], 'exit': row['source_frames'][hi],
                 'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
                 'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]}
            slices.append(s)
            totals.update(selected_slices=1, selected_visits=hi-lo, selected_reads=len(s['reads']), selected_writes=len(s['writes']))
            return s
        if group == 'initializer':
            s = select('initializer')
            r = s['reads'][0]
            assert r['address'] == hex(SP+0x3608) and r['bytes_hex'] == '81ead876'
            cu = custody(row, r)
            assert all(t['last_writer_in_this_interval'] is None for t in cu)
            assert writes == [w for w in s['writes'] if w['address'] == hex(U+0x18)]
            assert writes[0]['after_hex'] == '81ead876'
            defaults.append({'class_index': ci, 'source_read': r, 'custody': cu, 'store': writes[0], 'earlier_word_producer_established': False})
            continue
        if group == 'branch' or group == 'growth' and ci < 2:
            if writes:
                assert len(writes) == 4 and {w['pc'] for w in writes} == {'0x1002a9a04'}
                assert [w['address'] for w in writes] == [hex(U+j) for j in [0x1b, 0x1a, 0x19, 0x18]]
            continue
        if group not in ['prefix', 'growth'] or group == 'growth' and ii != 1:
            continue
        ss = {k: select(k) for k in SPANS if k != 'initializer'}
        s = ss['coordinate_and_first_bound']
        hsp = int(s['entry']['SP'], 16)
        raw_selected = int(s['exit']['registers31'][5], 16)
        offset = (raw_selected+0x89271580)&0xffffffff
        buffer, extent = (0x6600050000, 21) if group == 'prefix' else (H, 77)
        assert offset == (1 if group == 'prefix' else 57)
        for kind, reg, value in [('availability0', 15, 0x6968), ('availability8', 2, 0x8ee5),
                                 ('coordinate_and_first_bound', 1, 0x6993), ('saved_operands', 1, 0x6993),
                                 ('span_end_bound', 1, 0xa71d), ('flag_gate', 6, 0x6ce1),
                                 ('transformed_half_gate', 6, 0x3a61)]:
            assert ss[kind]['entry']['registers31'][reg] == hex(value)
        assert [(int.from_bytes(bytes.fromhex(r['bytes_hex']), 'little')) for r in ss['positive_span']['reads']] == [
            offset+0x79396704, 0x1bc3, offset+0x36fe01a4]
        assert ss['span_end_bound']['entry']['registers31'][15] == hex(offset+20+0xabc03b53)
        assert ss['positive_span']['entry']['registers31'][16] == '0x8b3dc645'
        assert ss['positive_span']['exit']['registers31'][16] == '0x1ffb'
        assert ss['span_end_bound']['exit']['registers31'][16] == '0xa71d'
        assert ss['flag_gate']['exit']['registers31'][17] == '0x6ce1'
        assert ss['transformed_half_gate']['entry']['registers31'][1] == '0x739e'
        assert ss['transformed_half_gate']['exit']['registers31'][15] == '0x83da'
        first = ss['availability0']['start_visit']
        last = ss['return_store']['end_visit_exclusive']
        buffer_reads = [r for r in row['source_reads'] if first <= r['source_visit_index'] < last and buffer <= int(r['address'], 16) < buffer+extent]
        assert [(int(r['address'], 16)-buffer, r['size_bytes']) for r in buffer_reads] == [(offset+j, 1) for j in [0, 1, 2, 3, 14, 15]]
        raw = bytes.fromhex(''.join(r['bytes_hex'] for r in buffer_reads[:4]))
        assert S.decode(raw, offset)[2] == 20
        half_raw = bytes.fromhex(''.join(r['bytes_hex'] for r in buffer_reads[4:]))
        half_packed = int.from_bytes(bytes(b^S.STREAM[(offset+14+j)&15] for j, b in enumerate(half_raw)), 'big')
        assert half_packed & ((1 << (half_packed >> 12))-1) == 0
        chains = []
        for s in [ss['positive_span'], ss['selected_reload']]:
            for r in s['reads']:
                cu = custody(row, r)
                assert all(t['last_writer_in_this_interval'] is not None for t in cu)
                chains.append({'read': r, 'custody': cu})
                for w in {t['last_writer_in_this_interval']['source_visit_index']:t['last_writer_in_this_interval'] for t in cu}.values():
                    select('operand_writer', lo=w['source_visit_index'], pc=int(w['pc'], 16))
        assert ss['selected_reload']['exit']['registers31'][2] == hex(raw_selected)
        assert ss['return_store']['writes'][0]['after_hex'] == raw_selected.to_bytes(4, 'little').hex()
        helpers.append({'group': group, 'class_index': ci, 'helper_SP': hex(hsp), 'selected_offset_bytes': offset,
                        'extent_bytes': extent, 'span_bytes': 20, 'default_offset_bytes': 1,
                        'buffer_reads': buffer_reads, 'halfword_decoded_scalar16': 0,
                        'operand_custody': chains, 'returned_coordinate32': hex(raw_selected)})
    for group, coverage, extent, buffer in [('initializer', data[0]['coverage'], 21, 0x6600050000),
                                           ('prefix', data[1]['prefix_coverage'], 21, 0x6600050000),
                                           ('constructor', data[1]['coverage'], 57, B.F),
                                           ('growth', data[2]['coverage'], 77, H)]:
        for c in coverage:
            if group == 'constructor' and data[1]['branches'][c['branch_index']]['pointer_return64'] == '0x0':
                continue
            if group == 'growth' and c['pointer_return64'] == '0x0':
                continue
            state = B.unpack(c['derived_terminal_state_packed'])
            m = S.state_bytes(state)
            word = lambda a, n: int.from_bytes(bytes(m[a+j] for j in range(n)), 'little')
            assert {'address': hex(U), 'size_bytes': 48} in state['foreign_owners']
            assert word(U+0x18, 4) == 0x76d8ea81 and word(U+8, 8) == buffer
            assert (word(U+0x14, 4)+0xef133bef)&0xffffffff == extent
            exports.append({'group': group, 'member': {k:c[k] for k in ['parent_index', 'class_index', 'branch_index', 'cohort_index'] if k in c}, 'extent_bytes': extent})
    routes = []
    for kind, index, target, modifier in ROUTES:
        slot = TABLE+8*index
        raw = int.from_bytes(IMAGE.read(slot, 8), 'little')
        assert FIXUPS[slot]['target'] == target and (raw >> 32)&65535 == modifier and (raw >> 48)&7 == 0
        routes.append({'kind': kind, 'index32': hex(index), 'slot': hex(slot), 'target': hex(target),
                       'IA_modifier': hex(modifier), 'word_hex': IMAGE.read(slot, 8).hex()})
    a, n = text_section()
    raw = IMAGE.read(a, n)
    pattern = 0xb9000000|((0x3608//4) << 10)|(31 << 5)
    candidates = [{'pc': hex(a+4*j), 'word_hex': struct.pack('<I', w).hex(), 'source_register': w&31}
                  for j, (w,) in enumerate(struct.iter_unpack('<I', raw)) if w&0xffffffe0 == pattern]
    assert [x['pc'] for x in candidates] == ['0x10070a320']
    assert len(helpers) == 6 and len(defaults) == 4 and len(census) == 58 and len(exports) == 608
    totals.update(helper_classes=6, initializer_classes=4, checked_exports=608, export_words_checked=1824,
                  dispatch_routes=13, exact_store_candidates=1, text_words_scanned=n//4)
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE), 'parent_pins': PINS,
            'dependencies': {p:sha(ROOT/p) for p in DEPS}, 'slices': slices, 'default_initializers': defaults,
            'helper_classes': helpers, 'journal_write_census': census, 'exports': exports, 'routes': routes,
            'original_fixups': verify_original_fixups(int(r['slot'], 16) for r in routes),
            'exact_SP_store_census': {'text_size_bytes': n, 'text_sha256': sha256(raw).hexdigest(), 'candidates': candidates,
                                    'scope': 'Aligned direct unsigned-immediate STR Wn,[SP,#0x3608] only; other bases/forms and frame epochs excluded.'},
            'source_spans': [{'kind': k, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': IMAGE.read(a, b-a).hex()} for k, (a, b) in SPANS.items()],
            'verified_counts': dict(totals), 'prior_admissions_rerun': False, 'new_target_intervals': 0,
            'new_guest_input_bytes': 0, 'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    e = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
