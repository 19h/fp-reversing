#!/usr/bin/env python3
"""Recover counted record-span walking and distinguish cursor from endpoint.
O(parent receipt bytes + six selected journals + source words) time/space.
No new target interval, guest bytes, owner definition or API-return premise.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE, TABLE, FIXUPS, verify_original_fixups
from audit_daemon_environment_outputs import DEC
from recover_daemon_append_fields import custody
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_record_storage as Prior

P = 'daemon_record_walk'
Parent = Prior.Parent
PINS = {**Prior.PINS,
        'daemon_record_storage_checks.json': '08dd5c2d5d3c14efd4ec744f35267c1d9f879d2a93c3d4ea8ca68f3c22e31337',
        'daemon_record_storage_audit.json': '1be9029f3b67f0d543db412982617378cae7064ff4a9ade39f503b4da5f0eac4'}
DEPS = ['recover_daemon_record_storage.py', 'recover_daemon_record_selection.py', 'recover_daemon_append_fields.py',
        'recover_daemon_scalar_serialization.py', 'daemon_receive_tools.py', 'daemon_receive_fixups.txt',
        'audit_daemon_environment_outputs.py']
SPANS = {'cursor_initializer': (0x10049f880, 0x10049f888),
         'initial_minimum': (0x100333948, 0x1003339d4),
         'half_join': (0x1003209ac, 0x100320a00),
         'cursor_room': (0x1004bad90, 0x1004badf8),
         'header_room': (0x10063b9bc, 0x10063ba34),
         'reader_prepare': (0x100333920, 0x100333948),
         'reader_config': (0x1005320f8, 0x100532150),
         'plain_word_reader': (0x100405d98, 0x100405fa8),
         'plain_half_reader': (0x1003cbb0c, 0x1003cbd38),
         'word_bridge': (0x1003ec410, 0x1003ec418),
         'advance_positive': (0x1003fb284, 0x1003fb344),
         'advance_bound': (0x10031424c, 0x1003142ec),
         'count_step': (0x1003f0f58, 0x1003f1080),
         'finish': (0x1004a86e8, 0x1004a8744)}
BANKS = {'D': (0x100f21190, 16), 'E': (0x100fa38b0, 20), 'K': (0x100ffc9e0, 17)}
ROUTES = [(0x1bc3, 0x1004aa840, 0xcb9a), (0xc94c, 0x100470afc, 0xcb9a),
          (0x1bec, 0x10063b9bc, 0xcb9a), (0xc68b, 0x100333920, 0x2712), (0xc6dd, 0x1004aa840, 0x2712),
          (0x25e0, 0x1005320f8, 0x8216), (0xbff7, 0x100405d98, 0x43b0), (0xc00f, 0x100357e2c, 0x43b0),
          (0xc4, 0x1003fb284, 0x352e), (0x602d, 0x1003ec410, 0x143b),
          (0xa743, 0x1004aa840, 0xf01d), (0xb243, 0x10031424c, 0xf01d),
          (0xca3b, 0x1003f0f58, 0x62c0), (0xca8a, 0x1004aa840, 0x62c0),
          (0x3a47, 0x1004a86e8, 0xd137), (0x3a61, 0x1004bad90, 0xd137),
          (0xac30, 0x10048d3d0, 0xfb0f), (0x6993, 0x1004aa840, 0xfb0f), (0x83da, 0x10048d3d0, 0xd137)]


def extract():
    for name, digest in PINS.items():
        assert sha(ROOT/name) == digest
    old = json.loads(read(ROOT/'daemon_record_selection_checks.json'))
    data = Parent.parents()
    cases, slices, totals = [], [], Counter()
    for entry in old['slices']:
        if entry['kind'] != 'half_reader_decoder':
            continue
        group, ci, ii = entry['group'], entry['class_index'], entry['interval_index']
        packed = data[1]['prefixes'][ci]['interval_packed'] if group == 'prefix' else data[2]['classes'][ci]['intervals'][ii]['interval_packed']
        row = Parent.B.unpack(packed)
        frame = int(entry['entry']['SP'], 16)
        gate = entry['start_visit']
        helper = next(h for h in old['helper_classes'] if h['group'] == group and h['class_index'] == ci)
        o = helper['selected_offset_bytes']
        expected = [(0x6c, 4, (o+20-0x89271580)&0xffffffff), (0x74, 4, 0xca3b), (0x98, 4, 0x5c01a05e),
                    (0xa0, 4, 0xa743), (0x9c, 4, 0x93f3cc4d), (0xa4, 4, 0x1bc3),
                    (0x80, 8, BANKS['K'][0]), (0x88, 8, BANKS['E'][0]), (0x90, 8, BANKS['D'][0])]
        writers, cells = {}, []
        for off, n, value in expected:
            request = {'address': hex(frame+off), 'size_bytes': n, 'source_visit_index': gate}
            chain = custody(row, request)
            raw = []
            for c in chain:
                w = c['last_writer_in_this_interval']
                assert w is not None
                raw.append(bytes.fromhex(w['after_hex'])[int(c['address'], 16)-int(w['address'], 16)])
                writers[w['source_visit_index']] = w
            assert int.from_bytes(bytes(raw), 'little') == value
            cells.append({**request, 'bytes_hex': bytes(raw).hex(), 'custody': chain})
        def select(a, b):
            lo = next(j for j, visit in enumerate(row['source_visits']) if visit['pc'] == hex(a))
            hi = lo+(b-a)//4
            assert [v['pc'] for v in row['source_visits'][lo:hi]] == [hex(pc) for pc in range(a, b, 4)]
            s = {'group': group, 'class_index': ci, 'interval_index': ii, 'start_visit': lo, 'end_visit_exclusive': hi,
                 'entry': row['source_frames'][lo], 'exit': row['source_frames'][hi],
                 'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
                 'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]}
            slices.append(s)
            return s
        for j in sorted(writers):
            pc = int(row['source_visits'][j]['pc'], 16)
            select(pc, pc+4)
        init = select(*SPANS['cursor_initializer'])
        assert int(init['entry']['registers31'][23], 16) == (o-0x89271580)&0xffffffff
        minimum = select(0x100333948, 0x1003339d0)
        assert minimum['entry']['registers31'][16] == '0x8b3dc645'
        word = select(0x100405d98, 0x100405fa4)
        half = select(0x1003cbb0c, 0x1003cbd2c)
        join = select(0x1003209ac, 0x1003209f8)
        assert word['entry']['registers31'][2] == word['entry']['registers31'][6] == '0x602d'
        assert word['entry']['registers31'][19:21] == ['0x89271582', '0x89271583']
        assert half['entry']['registers31'][16] == '0x4dc0'
        assert int(join['exit']['registers31'][25], 16) == o+20
        assert not any(v['pc'] in ['0x10063b9bc', '0x1003fb284'] for v in row['source_visits'])
        cases.append({'group': group, 'class_index': ci, 'helper_SP': hex(frame), 'selected_offset_bytes': o,
                      'span_bytes': 20, 'initial_cursor_bytes': o+20, 'enclosing_end_bytes': o+20,
                      'walk_count16': 0, 'nonzero_walk_observed': False, 'saved_cells': cells})
        totals.update(helper_cases=1, saved_cells_checked=len(cells), saved_bytes_checked=sum(n for off, n, value in expected),
                      last_writer_instructions=len(writers))
    routes = []
    for index, target, modifier in ROUTES:
        at = TABLE+8*index
        raw = IMAGE.read(at, 8)
        w = int.from_bytes(raw, 'little')
        assert FIXUPS[at]['target'] == target and (w >> 32)&65535 == modifier and (w >> 48)&7 == 0
        routes.append({'index32': hex(index), 'slot': hex(at), 'target': hex(target), 'IA_modifier': hex(modifier), 'word_hex': raw.hex()})
    source = []
    for name, (a, b) in SPANS.items():
        raw = IMAGE.read(a, b-a)
        ins = [{'pc': hex(i.address), 'bytes_hex': bytes(i.bytes).hex(), 'mnemonic': i.mnemonic, 'operands': i.op_str}
               for i in DEC.disasm(raw, a)]
        assert len(ins)*4 == len(raw)
        source.append({'kind': name, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': raw.hex(), 'instructions': ins})
    totals.update(dispatch_routes=len(routes), source_instructions=sum(len(s['instructions']) for s in source),
                  replay_slices=len(slices), bank_bytes_checked=sum(n for a, n in BANKS.values()))
    assert len(cases) == 6
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE), 'parent_pins': PINS,
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'source_spans': source, 'cases': cases, 'slices': slices,
            'routes': routes, 'original_fixups': verify_original_fixups(int(r['slot'], 16) for r in routes),
            'banks': {name: {'address': hex(a), 'size_bytes': n, 'bytes_hex': IMAGE.read(a, n).hex()} for name, (a, n) in BANKS.items()},
            'periodic_mask16_hex': bytes(Parent.S.STREAM).hex(), 'verified_counts': dict(totals),
            'prior_admissions_rerun': False, 'new_target_intervals': 0, 'new_guest_input_bytes': 0,
            'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    e = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
