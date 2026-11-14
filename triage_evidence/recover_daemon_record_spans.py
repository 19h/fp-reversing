#!/usr/bin/env python3
"""Recover local record spans, four scalar payloads and selected resize inputs.
O(parent bytes + selected visits + custody scans + decoded exports) time/space.
Retained journals only; no new target interval, guest input or API premise.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from audit_daemon_environment_outputs import DEC
from recover_daemon_append_fields import custody
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_constructor_extent as E

P = 'daemon_record_spans'
B, S, SP = E.B, E.S, E.SP
LSP, H = 0x680005fb50, 0x6600080000
PINS = {**E.PINS,
        'daemon_constructor_extent_checks.json': '6bbd9bba929ade62267d9dbe0a39bc0ec4944e98077df56e87ee4805a4122209',
        'daemon_constructor_extent_audit.json': '2b6cb82792deb42dee210fad77363caddf499c9f44d9991ac4163868771f303d',
        'daemon_descriptor_growth_replay.json': 'bee4ab3224710559fefdd8bca070110e48c03ab52d01c92b617988b9b3d5bd67',
        'daemon_halfword_update_audit.json': '8a981f149dc127d4079eaeed525a90630b14712cea3c24c12119ac3f287e7883',
        'daemon_packed_halves_audit.json': '1a0bf1c95a128654d1e20469bd88c710f7871fef0d5b9853c0635b6fe8de3f53'}
DEPS = ['daemon_receive_tools.py', 'recover_daemon_constructor_extent.py', 'recover_daemon_scalar_serialization.py',
        'recover_daemon_append_fields.py', 'audit_daemon_environment_outputs.py']
SPANS = {'count_read': (0x1006c306c, 0x1006c3070), 'scale': (0x1006ce4a8, 0x1006ce4c8),
         'overhead': (0x10077cff0, 0x10077d1b4), 'sum': (0x1008d8314, 0x1008d83ec),
         'operand_store': E.SPANS['operand_store'], 'producer': E.SPANS['producer'], 'writer': E.SPANS['writer'],
         'span_read': (0x1008ca578, 0x1008ca57c),
         'later_reader': (0x100a44574, 0x100a446fc), 'later_reader_math': (0x100a44580, 0x100a446f8),
         'later_decoder': (0x100a2ec30, 0x100a2edc4), 'later_extract': (0x100a2ec30, 0x100a2ecf0),
         'later_encode': (0x100a2ecf0, 0x100a2edc4), 'later_growth': (0x100c055ac, 0x100c0564c),
         'later_growth_math': (0x100c055ec, 0x100c0564c), 'later_operand_store': (0x100d95aac, 0x100d95ab0)}


def parents():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest, p
    return (json.loads(read(ROOT/'daemon_constructor_buffer_checks.json')),
            json.loads(read(ROOT/'daemon_descriptor_growth_checks.json')))


def overlap(a, n, event):
    b = int(event['address'], 16)
    return b < a+n and a < b+event['size_bytes']


def extract():
    old, growth = parents()
    slices, prefixes, fields, later, exports, counts = [], [], [], [], [], Counter()
    def select(group, ci, ii, row, kind, lo=None, dynamic_pc=None):
        a, b = (dynamic_pc, dynamic_pc+4) if dynamic_pc is not None else SPANS[kind]
        if lo is None:
            lo = next(j for j, v in enumerate(row['source_visits']) if v['pc'] == hex(a))
        hi = lo+(b-a)//4
        assert [v['pc'] for v in row['source_visits'][lo:hi]] == [hex(pc) for pc in range(a, b, 4)]
        s = {'group': group, 'class_index': ci, 'interval_index': ii, 'kind': kind,
             'start_visit': lo, 'end_visit_exclusive': hi, 'entry': row['source_frames'][lo],
             'exit': row['source_frames'][hi],
             'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
             'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]}
        counts.update(selected_slices=1, selected_visits=hi-lo, selected_reads=len(s['reads']), selected_writes=len(s['writes']))
        slices.append(s)
        return s
    for ci, c in enumerate(old['prefixes']):
        row = B.unpack(c['interval_packed'])
        ss = {k: select('prefix', ci, 0, row, k) for k in ['count_read', 'scale', 'overhead', 'sum', 'operand_store']}
        inp, scale, overhead, total = (ss[k] for k in ['count_read', 'scale', 'overhead', 'sum'])
        r = inp['reads'][0]
        cu = custody(row, r)
        w = cu[0]['last_writer_in_this_interval']
        assert w['pc'] == '0x100501614' and w['after_hex'] == r['bytes_hex'] == '55c63d8b'
        assert all(x['last_writer_in_this_interval'] == w for x in cu)
        select('prefix', ci, 0, row, 'count_writer', lo=w['source_visit_index'], dynamic_pc=int(w['pc'], 16))
        assert inp['exit']['registers31'][8] == scale['entry']['registers31'][8] == '0x8b3dc655'
        assert scale['exit']['registers31'][8] == overhead['entry']['registers31'][8] == '0x8b3dc641'
        assert scale['exit']['registers31'][10] == overhead['entry']['registers31'][10] == '0xca23'
        assert overhead['exit']['registers31'][13] == total['entry']['registers31'][13] == '0x8b3dc675'
        assert all(f['registers31'][13] == '0x8b3dc675' for f in row['source_frames'][overhead['end_visit_exclusive']:total['start_visit']+1])
        span_store = overhead['writes'][0]
        assert (span_store['address'], span_store['after_hex']) == (hex(SP+0x48cc), '75c63d8b')
        assert not any(overlap(SP+0x48cc, 4, w) for w in row['source_writes'] if w['source_visit_index'] > span_store['source_visit_index'])
        old_read = total['reads'][0]
        assert old_read['address'] == hex(SP+0x64a8) and old_read['bytes_hex'] == '45c63d8b'
        assert all(x['last_writer_in_this_interval']['pc'] == '0x100855534' for x in custody(row, old_read))
        assert total['exit']['registers31'][12] == '0x38'
        assert all(f['registers31'][12] == '0x38' for f in row['source_frames'][total['end_visit_exclusive']:ss['operand_store']['end_visit_exclusive']+1])
        prefixes.append({'prefix_class_index': ci, 'member_parent_indices': c['member_parent_indices'],
                         'count_input': r, 'count_custody': cu, 'span_store': span_store,
                         'old_header_read': old_read, 'old_header_custody': custody(row, old_read),
                         'count32': 4, 'scaled32': 16, 'record_span32': 36, 'old_header32': 20, 'operand32': 56})
    for ci, c in enumerate(old['branches']):
        if c['pointer_return64'] == '0x0':
            continue
        row0 = B.unpack(c['intervals'][0]['interval_packed'])
        row = B.unpack(c['intervals'][1]['interval_packed'])
        sr = select('branch', ci, 1, row, 'span_read')['reads'][0]
        sw = prefixes[c['prefix_class_index']]['span_store']
        assert (sr['address'], sr['bytes_hex']) == (sw['address'], sw['after_hex'])
        assert all(x['last_writer_in_this_interval'] is None for x in custody(row, sr))
        for rr, end in [(row0, len(row0['source_visits'])), (row, sr['source_visit_index'])]:
            assert not any(overlap(SP+0x48cc, 4, w) for w in rr['source_writes'] if w['source_visit_index'] < end)
        for item in c['intervals'][:2]:
            assert not any(overlap(SP+0x48cc, 4, x) for x in item['API_return_premise']['invalidated_spans'])
        producers = [j for j, v in enumerate(row['source_visits']) if v['pc'] == '0x100618764']
        actual_offsets = []
        for j, visit in enumerate(row['source_visits']):
            if visit['pc'] != '0x1006bd140':
                continue
            end = j+(SPANS['writer'][1]-SPANS['writer'][0])//4
            ww = [w for w in row['source_writes'] if j <= w['source_visit_index'] < end]
            assert len(ww) == 5
            off = int(ww[1]['address'], 16)-B.F
            expected = {21: 36, 29: 1, 41: 0, 45: 1, 49: 0, 53: 1}
            if off not in expected:
                continue
            writer = select('branch', ci, 1, row, 'writer', lo=j)
            start = max(k for k in producers if k < j)
            producer = select('branch', ci, 1, row, 'producer', lo=start)
            rr = [r for r in producer['reads'] if r['pc'] in ['0x100618784', '0x100618880']]
            n, key = [int.from_bytes(bytes.fromhex(r['bytes_hex']), 'little') for r in rr]
            d = key^0x8b3dc651
            assert d == expected[off] and n == max(1, d.bit_length())
            aux = int(producer['entry']['registers31'][19], 16)^0x6703cce9
            packed = ((((aux << (n&31))&0x07ffffff)|(n<<27))+d)&0xffffffff
            assert producer['exit']['registers31'][12] == hex(packed^0xc12b4f72)
            changes = [k for k in range(producer['end_visit_exclusive'], j) if row['source_frames'][k]['registers31'][12] != row['source_frames'][k+1]['registers31'][12]]
            assert len(changes) == 1
            k = changes[0]
            pc = int(row['source_visits'][k]['pc'], 16)
            ins = next(DEC.disasm(IMAGE.read(pc, 4), pc))
            assert ins.mnemonic == 'eor' and ins.reg_name(ins.operands[0].reg) == 'w12'
            caller = select('branch', ci, 1, row, 'caller_xor', lo=k, dynamic_pc=pc)
            assert int(caller['entry']['registers31'][12], 16)^int(caller['exit']['registers31'][12], 16) == 0x259ef046
            assert writer['entry']['registers31'][12] == hex(packed^0xe4b5bf34)
            raw = b''.join(bytes.fromhex(w['after_hex']) for w in ww[1:])
            assert [(int(w['address'], 16), w['size_bytes']) for w in ww[1:]] == [(B.F+off+t, 1) for t in range(4)]
            assert S.decode(raw, off) == (packed, n, d)
            cu = [{'read': r, 'custody': custody(row, r)} for r in rr]
            assert all(all(x['last_writer_in_this_interval'] is not None for x in c['custody']) for c in cu)
            if off == 21:
                scalar_writer = cu[1]['custody'][0]['last_writer_in_this_interval']
                assert scalar_writer['pc'] == '0x1008f3940'
                assert all(f['registers31'][23] == '0x8b3dc675' for f in row['source_frames'][sr['source_visit_index']+1:scalar_writer['source_visit_index']+1])
            fields.append({'branch_index': ci, 'offset_bytes': off, 'scalar32': d, 'count32': n,
                           'packed32': hex(packed), 'stored_hex': raw.hex(), 'producer_read_custody': cu})
            actual_offsets.append(off)
        assert sorted(actual_offsets) == [21, 29, 41, 45, 49, 53]
    for ci, c in enumerate(growth['classes']):
        if c['pointer_return64'] == '0x0':
            continue
        row = B.unpack(c['intervals'][-1]['interval_packed'])
        ss = {}
        for kind in ['later_reader', 'later_decoder', 'later_growth', 'later_operand_store']:
            a, _ = SPANS[kind]
            matches = [j for j, v in enumerate(row['source_visits']) if v['pc'] == hex(a)]
            ss[kind] = select('growth', ci, len(c['intervals'])-1, row, kind, lo=matches[-1])
        reader, decoder, gr = (ss[k] for k in ['later_reader', 'later_decoder', 'later_growth'])
        rr = [r for r in reader['reads'] if r['pc'] in ['0x100a44590', '0x100a445ec', '0x100a44644', '0x100a44698']]
        assert [(r['address'], r['bytes_hex']) for r in rr] == [(hex(H+57+j), b) for j, b in enumerate(['9e', '6f', 'd1', 'e4'])]
        for r, pc in zip(rr, ['0x100c70e28', '0x100c70e80', '0x100c70ed0', '0x100c70f18']):
            assert all(x['last_writer_in_this_interval']['pc'] == pc for x in custody(row, r))
        assert reader['entry']['SP'] == hex(LSP) and reader['entry']['registers31'][8] == '0x4225556d'
        assert reader['exit']['registers31'][10] == decoder['entry']['registers31'][10] == '0xa64b92c5'
        assert decoder['exit']['registers31'][27] == gr['entry']['registers31'][27] == '0x8b3dc645'
        assert all(f['registers31'][27] == '0x8b3dc645' for f in row['source_frames'][decoder['end_visit_exclusive']:gr['start_visit']+1])
        operand = next(r for r in gr['reads'] if r['pc'] == '0x100c055e8')
        phase = next(r for r in gr['reads'] if r['pc'] == '0x100c0562c')
        assert operand['bytes_hex'] == '28000000' and phase['bytes_hex'] == 'e813c50e'
        assert all(x['last_writer_in_this_interval'] == ss['later_operand_store']['writes'][0] for x in custody(row, operand))
        assert gr['exit']['registers31'][8] == '0x10ecc472' and row['boundary']['registers31'][0] == '0x61'
        later.append({'class_index': ci, 'header_offset_bytes': 57, 'old_header32': 20, 'root_header32': 76,
                      'old_extent_bytes': 77, 'requested_header32': 40, 'pending_extent_bytes': 97,
                      'header_reads': [{'read': r, 'custody': custody(row, r)} for r in rr],
                      'operand_read': operand, 'operand_custody': custody(row, operand),
                      'phase_read': phase, 'phase_custody': custody(row, phase)})
    def check_export(c, owner, extent, expected, halves, group):
        state = B.unpack(c['derived_terminal_state_packed'])
        m = S.state_bytes(state)
        assert {'address': hex(owner), 'size_bytes': extent} in state['foreign_owners']
        values = []
        for off, d in expected.items():
            raw = bytes(m[owner+off+j] for j in range(4))
            packed, n, actual = S.decode(raw, off)
            assert actual == d
            item = {'offset_bytes': off, 'size_bytes': 4, 'stored_hex': raw.hex(), 'scalar32': d}
            if off in [1, 21, 57]:
                item['span_end_offset'] = off+d
            values.append(item)
        for off, d in halves.items():
            raw = bytes(m[owner+off+j] for j in range(2))
            packed = int.from_bytes(bytes(b^S.STREAM[(off+j)&15] for j, b in enumerate(raw)), 'big')
            n = packed>>12
            assert 1 <= n <= 12 and packed&((1<<n)-1) == d
            values.append({'offset_bytes': off, 'size_bytes': 2, 'stored_hex': raw.hex(), 'scalar16': d})
        exports.append({'group': group, 'member': {k: c[k] for k in ['parent_index', 'branch_index', 'cohort_index', 'class_index', 'ABI_clobber_pattern'] if k in c},
                        'owner_address': hex(owner), 'owner_extent_bytes': extent, 'fields': values})
        counts.update(exported_word_fields=len(expected), exported_word_bytes=4*len(expected))
        counts.update(exported_half_fields=len(halves), exported_half_bytes=2*len(halves))
    for c in old['coverage']:
        if old['branches'][c['branch_index']]['pointer_return64'] != '0x0':
            check_export(c, B.F, 57, {1: 56, 21: 36, 29: 1, 41: 0, 45: 1, 49: 0, 53: 1}, {15: 1, 35: 0}, 'F')
    for c in growth['coverage']:
        if c['pointer_return64'] != '0x0':
            check_export(c, H, 77, {1: 76, 21: 36, 57: 20}, {15: 2, 35: 0, 71: 0}, 'H')
    assert len(prefixes) == 4 and len(fields) == 48 and len(later) == 2 and len(exports) == 456
    counts.update(prefix_classes=4, constructor_field_occurrences=48, later_resize_classes=2,
                  constructor_exports=152, growth_exports=304, total_exports=456)
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE), 'parent_pins': PINS,
            'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'source_spans': [{'kind': k, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': IMAGE.read(a, b-a).hex()} for k, (a, b) in SPANS.items()],
            'slices': slices, 'prefixes': prefixes, 'constructor_fields': fields, 'later_resizes': later, 'exports': exports,
            'verified_counts': dict(counts), 'prior_admissions_rerun': False, 'new_target_intervals': 0,
            'new_guest_input_bytes': 0, 'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    e = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
