#!/usr/bin/env python3
"""Recover the alternate two-byte record reader and immediate mismatch gate.
O(parent receipt bytes + six selected journals + source words) time/space.
No new target interval, guest input, owner definition or API-return premise.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE, TABLE, FIXUPS, verify_original_fixups
from audit_daemon_environment_outputs import DEC
from recover_daemon_append_fields import custody
from verify_daemon_reader_record_payloads_publication import read, sha
from daemon_cache_publication_model import KEYS as CACHE_KEYS, DECODER_CONSTANTS, word_index
import recover_daemon_record_selection as Parent

P = 'daemon_record_storage'
PINS = {'daemon_record_selection_checks.json': '21a7744f9ad61f2a00d2f83941f9af190040427a655ae24507300386eb4b5108',
        'daemon_record_selection_audit.json': '174b389bf7f0f11595520d7b8f9360afe69cb506a0efcb0b73235edc5ac7e3bd',
        'daemon_cache_publication_contracts.json': '86546e78cc28c2d710b420d2f2aaea4e17422087fd19878da779ccb73ecc257f',
        'daemon_cache_publication_proofs.json': '1db3ff31544f5962c6cdea7604cab30ea54d40d5b06190d42478272af6038a60'}
DEPS = ['recover_daemon_record_selection.py', 'recover_daemon_append_fields.py',
        'daemon_receive_tools.py', 'daemon_receive_fixups.txt', 'audit_daemon_environment_outputs.py',
        'daemon_cache_publication_model.py']
SPANS = {'saved_offsets': (0x10049f6e8, 0x10049f734),
         'alternate_reader': (0x100495c3c, 0x100496028),
         'mismatch_gate': (0x1004bad90, 0x1004badf8)}
KEYS = [0x473c853ae26b7ab8, 0x8f0490db2637da4e, 0x639ff74d03d39428, 0xa34408d6869aa02f,
        0x0a23823d71e7a74e, 0x6c2f97ea7411e380, 0x3d107423d6820c5f, 0x71ef41f1f2e87b90]
NORMALIZERS = [(0x100495c90, 0x100495cec, 'x16', 0), (0x100495cf8, 0x100495d0c, 'x16', 1),
 (0x100495d18, 0x100495d58, 'x16', 2), (0x100495d64, 0x100495da8, 'x16', 3),
 (0x100495db4, 0x100495dc8, 'x16', 4), (0x100495dd4, 0x100495e18, 'x16', 5),
 (0x100495e24, 0x100495e64, 'x16', 6), (0x100495e70, 0x100495e84, 'x16', 7),
 (0x100495eb8, 0x100495ecc, 'x1', 0), (0x100495ed8, 0x100495edc, 'x1', 1),
 (0x100495ee8, 0x100495efc, 'x1', 2), (0x100495f08, 0x100495f1c, 'x1', 3),
 (0x100495f28, 0x100495f68, 'x1', 4), (0x100495f74, 0x100495f88, 'x1', 5),
 (0x100495f94, 0x100495fd4, 'x1', 6), (0x100495fe0, 0x100495fe4, 'x16', 7)]


def extract():
    for name, digest in PINS.items():
        assert sha(ROOT/name) == digest
    selection = json.loads(read(ROOT/'daemon_record_selection_checks.json'))
    data = Parent.parents()
    cases, slices, totals = [], [], Counter()
    for s in selection['slices']:
        if s['kind'] != 'flag_gate':
            continue
        group, ci, ii = s['group'], s['class_index'], s['interval_index']
        packed = data[1]['prefixes'][ci]['interval_packed'] if group == 'prefix' else data[2]['classes'][ci]['intervals'][ii]['interval_packed']
        row = Parent.B.unpack(packed)
        gate, f = s['start_visit'], s['entry']
        frame = int(f['SP'], 16)
        selected = next(h for h in selection['helper_classes'] if h['group'] == group and h['class_index'] == ci)
        o = selected['selected_offset_bytes']
        j = next(j for j, visit in enumerate(row['source_visits']) if visit['pc'] == '0x10049f6e8')
        hi = j+19
        assert [v['pc'] for v in row['source_visits'][j:hi]] == [hex(pc) for pc in range(*SPANS['saved_offsets'], 4)]
        incoming = row['source_frames'][j]['registers31']
        assert incoming[16] == '0xbff7' and int(incoming[23], 16) == (o-0x89271580)&0xffffffff
        slices.append({'group': group, 'class_index': ci, 'interval_index': ii, 'start_visit': j,
                       'end_visit_exclusive': hi, 'entry': row['source_frames'][j], 'exit': row['source_frames'][hi],
                       'reads': [r for r in row['source_reads'] if j <= r['source_visit_index'] < hi],
                       'writes': [w for w in row['source_writes'] if j <= w['source_visit_index'] < hi]})
        cells, writers = [], {}
        for off, n, expected in [(0x58, 8, o+14), (0x50, 8, o+15), (0xb0, 8, 0x1010c8268),
                                  (0x6c, 4, (o+20-0x89271580)&0xffffffff)]:
            request = {'address': hex(frame+off), 'size_bytes': n, 'source_visit_index': gate}
            chain = custody(row, request)
            raw = []
            for c in chain:
                w = c['last_writer_in_this_interval']
                assert w is not None
                raw.append(bytes.fromhex(w['after_hex'])[int(c['address'], 16)-int(w['address'], 16)])
                writers[w['source_visit_index']] = w
            assert int.from_bytes(bytes(raw), 'little') == expected
            cells.append({**request, 'bytes_hex': bytes(raw).hex(), 'custody': chain})
        for j in sorted(writers):
            slices.append({'group': group, 'class_index': ci, 'interval_index': ii, 'start_visit': j,
                           'end_visit_exclusive': j+1, 'entry': row['source_frames'][j], 'exit': row['source_frames'][j+1],
                           'reads': [r for r in row['source_reads'] if r['source_visit_index'] == j],
                           'writes': [w for w in row['source_writes'] if w['source_visit_index'] == j]})
        assert f['registers31'][6] == '0x6ce1' and f['registers31'][7] == '0x1010c67d4'
        flag = int.from_bytes(bytes.fromhex(s['reads'][0]['bytes_hex']), 'little')
        assert flag & 4 == 0
        assert not any(v['pc'] == '0x100495c3c' for v in row['source_visits'])
        cases.append({'group': group, 'class_index': ci, 'helper_SP': hex(frame), 'offset_bytes': o,
                      'flag32': hex(flag), 'alternate_path_observed': False, 'saved_cells': cells})
        totals.update(helper_cases=1, saved_cells_checked=4, saved_bytes_checked=28,
                      last_writer_instructions=len(writers), preparation_slices=1)
    routes = []
    specs = [(0x6ce1, 0x1003cbb0c, 0xe0aa), (0x6ce6, 0x100495c3c, 0xe0aa),
             (0x4dc0, 0x1003209ac, 0xb299), (0x83da, 0x10048d3d0, 0xd137),
             (0x3a61, 0x1004bad90, 0xd137), (0x1bec, 0x10063b9bc, 0xcb9a),
             (0x1bc3, 0x1004aa840, 0xcb9a)]
    for index, target, modifier in specs:
        at = TABLE+8*index
        raw = IMAGE.read(at, 8)
        w = int.from_bytes(raw, 'little')
        assert FIXUPS[at]['target'] == target and (w >> 32)&65535 == modifier and (w >> 48)&7 == 0
        routes.append({'index32': hex(index), 'slot': hex(at), 'target': hex(target),
                       'IA_modifier': hex(modifier), 'word_hex': raw.hex()})
    source = []
    for name, (a, b) in SPANS.items():
        raw = IMAGE.read(a, b-a)
        instructions = [{'pc': hex(i.address), 'bytes_hex': bytes(i.bytes).hex(), 'mnemonic': i.mnemonic,
                         'operands': i.op_str} for i in DEC.disasm(raw, a)]
        assert len(instructions)*4 == len(raw)
        source.append({'kind': name, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': raw.hex(), 'instructions': instructions})
    totals.update(dispatch_routes=len(routes), source_instructions=sum(len(s['instructions']) for s in source), normalizers=len(NORMALIZERS))
    assert len(cases) == 6
    assert DECODER_CONSTANTS['x0'] == 0x1010c67d4 and DECODER_CONSTANTS['x6'] == 0x1010c8268
    comparison = {'global_mask_cell': hex(DECODER_CONSTANTS['x0']), 'global_table_pointer_cell': hex(DECODER_CONSTANTS['x6']),
                  'record_first_round_key64': hex(KEYS[0]), 'cached_consumer_first_round_key64': hex(CACHE_KEYS['x3']),
                  'record_index_at_address_zero_mask255': 0xa8, 'cached_consumer_index_at_address_zero_mask255': word_index(0),
                  'same_parameterization': False, 'native_epoch_join_established': False}
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE), 'parent_pins': PINS,
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'source_spans': source, 'cases': cases, 'slices': slices,
            'routes': routes, 'original_fixups': verify_original_fixups(int(r['slot'], 16) for r in routes),
            'keys64': [hex(k) for k in KEYS], 'cached_consumer_comparison': comparison,
            'verified_counts': dict(totals), 'prior_admissions_rerun': False,
            'new_target_intervals': 0, 'new_guest_input_bytes': 0, 'new_API_return_premises': 0,
            'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    e = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
