#!/usr/bin/env python3
"""Recover the alternative four-byte reader and saved-caller/global interfaces.
O(parent receipts + six journals + selected source) time/space. No new target
interval, guest bytes, owner/root definition or API-return premise.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE, TABLE, FIXUPS, verify_original_fixups
from audit_daemon_environment_outputs import DEC
from recover_daemon_append_fields import custody
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_storage import KEYS
import recover_daemon_record_walk as Parent

P = 'daemon_alternate_word'
PINS = {**Parent.PINS,
        'daemon_record_walk_checks.json': '0201f769d15390c7b70c2d583fd6e1356cc1b359a93b63afd044193cfce93990',
        'daemon_record_walk_audit.json': 'a67054eedfe2ebc96751c3f8292897b7fa0f62a79fbca810afe28fa4045fd836'}
DEPS = ['recover_daemon_record_walk.py', 'recover_daemon_record_selection.py', 'recover_daemon_record_storage.py',
        'recover_daemon_append_fields.py', 'daemon_receive_tools.py', 'daemon_receive_fixups.txt', 'audit_daemon_environment_outputs.py']
SPANS = {'alternative_word': (0x100357e2c, 0x1003585cc),
         'reader_setup': (0x1005320f8, 0x1005321d0),
         'caller_save': (0x10049f780, 0x10049f784),
         'return_bridge': (0x1003ec410, 0x1003ec418)}
NORMALIZERS = [
 (0x100357e80,0x100357ec0,'x22','x22'), (0x100357ecc,0x100357ee0,'x22','x22'),
 (0x100357eec,0x100357f00,'x22','x22'), (0x100357f10,0x100357f24,'x22','x22'),
 (0x100357f30,0x100357f44,'x22','x22'), (0x100357f54,0x100357f68,'x22','x22'),
 (0x100357f74,0x100357f88,'x22','x22'), (0x100357f94,0x100357fa8,'x16','x16'),
 (0x100357fec,0x10035802c,'x24','x4'), (0x100358038,0x10035807c,'x4','x4'),
 (0x100358088,0x10035808c,'x4','x4'), (0x10035809c,0x1003580dc,'x4','x4'),
 (0x1003580f0,0x1003580f4,'x23','x23'), (0x100358100,0x100358104,'x23','x23'),
 (0x10035811c,0x100358120,'x23','x23'), (0x100358130,0x100358134,'x4','x4'),
 (0x100358164,0x100358178,'x4','x4'), (0x100358184,0x100358188,'x4','x4'),
 (0x100358194,0x1003581e8,'x4','x4'), (0x1003581f4,0x100358234,'x4','x4'),
 (0x100358240,0x100358284,'x4','x4'), (0x100358290,0x1003582d0,'x23','x23'),
 (0x1003582dc,0x100358320,'x23','x23'), (0x100358330,0x100358334,'x4','x4'),
 (0x10035836c,0x100358370,'x2','x2'), (0x10035837c,0x1003583bc,'x2','x2'),
 (0x1003583c8,0x100358408,'x2','x2'), (0x100358414,0x100358454,'x2','x2'),
 (0x100358460,0x1003584a0,'x2','x2'), (0x1003584ac,0x1003584ec,'x2','x2'),
 (0x1003584f8,0x100358538,'x2','x2'), (0x100358544,0x100358558,'x1','x1')]
WHITENING = 0x7e7e7e7e7e7e7e7e


def normalizer_key(j):
    return KEYS[j%8]^(WHITENING if j == 31 else 0)


def extract():
    for name, digest in PINS.items():
        assert sha(ROOT/name) == digest
    old = json.loads(read(ROOT/'daemon_record_selection_checks.json'))
    data = Parent.Parent.parents()
    cases, slices, totals = [], [], Counter()
    for s in old['slices']:
        if s['kind'] != 'word_reader':
            continue
        group, ci, ii = s['group'], s['class_index'], s['interval_index']
        packed = data[1]['prefixes'][ci]['interval_packed'] if group == 'prefix' else data[2]['classes'][ci]['intervals'][ii]['interval_packed']
        row = Parent.Parent.B.unpack(packed)
        f, at = s['entry'], s['start_visit']
        frame = int(f['SP'], 16)
        registers = f['registers31']
        assert {j: registers[j] for j in [6, 7, 8, 9, 19, 20, 21, 27]} == {
            6: '0x602d', 7: '0x1010c67d4', 8: '0x1010c8268', 9: '0x1010a1960',
            19: '0x89271582', 20: '0x89271583', 21: '0xffff9684', 27: '0x100333948'}
        writers, cells = {}, []
        for off, value in [(0xa8, int(registers[0], 16)), (0xb0, 0x1010c8268)]:
            request = {'address': hex(frame+off), 'size_bytes': 8, 'source_visit_index': at}
            chain = custody(row, request)
            raw = []
            for c in chain:
                w = c['last_writer_in_this_interval']
                assert w is not None
                raw.append(bytes.fromhex(w['after_hex'])[int(c['address'], 16)-int(w['address'], 16)])
                writers[w['source_visit_index']] = w
            assert int.from_bytes(bytes(raw), 'little') == value
            cells.append({**request, 'bytes_hex': bytes(raw).hex(), 'custody': chain})
        def select(lo, hi):
            slices.append({'group': group, 'class_index': ci, 'interval_index': ii, 'start_visit': lo,
                           'end_visit_exclusive': hi, 'entry': row['source_frames'][lo], 'exit': row['source_frames'][hi],
                           'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
                           'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]})
        for j in sorted(writers):
            select(j, j+1)
        lo = next(j for j, v in enumerate(row['source_visits']) if v['pc'] == '0x1005320f8')
        hi = lo+(0x1005321cc-0x1005320f8)//4
        assert [v['pc'] for v in row['source_visits'][lo:hi]] == [hex(pc) for pc in range(0x1005320f8, 0x1005321cc, 4)]
        select(lo, hi)
        assert not any(v['pc'] == '0x100357e2c' for v in row['source_visits'])
        cases.append({'group': group, 'class_index': ci, 'helper_SP': hex(frame), 'reader_entry': f,
                      'saved_cells': cells, 'alternative_word_observed': False})
        totals.update(helper_cases=1, saved_cells_checked=2, saved_bytes_checked=16,
                      last_writer_instructions=len(writers), setup_source_visits=hi-lo)
    source = []
    for name, (a, b) in SPANS.items():
        raw = IMAGE.read(a, b-a)
        ins = [{'pc': hex(i.address), 'bytes_hex': bytes(i.bytes).hex(), 'mnemonic': i.mnemonic, 'operands': i.op_str}
               for i in DEC.disasm(raw, a)]
        assert len(ins)*4 == len(raw)
        source.append({'kind': name, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': raw.hex(), 'instructions': ins})
    routes = []
    for index, target, modifier in [(0xc00f, 0x100357e2c, 0x43b0), (0xbff7, 0x100405d98, 0x43b0),
                                   (0x602d, 0x1003ec410, 0x143b), (0xc4, 0x1003fb284, 0x352e)]:
        slot = TABLE+8*index
        raw = IMAGE.read(slot, 8)
        word = int.from_bytes(raw, 'little')
        assert FIXUPS[slot]['target'] == target and (word >> 32)&65535 == modifier and (word >> 48)&7 == 0
        routes.append({'index32': hex(index), 'slot': hex(slot), 'target': hex(target), 'IA_modifier': hex(modifier), 'word_hex': raw.hex()})
    totals.update(source_instructions=sum(len(s['instructions']) for s in source), normalizers=len(NORMALIZERS),
                  dispatch_routes=len(routes), replay_slices=len(slices))
    assert len(cases) == 6
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE), 'parent_pins': PINS,
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'source_spans': source, 'cases': cases, 'slices': slices,
            'routes': routes, 'original_fixups': verify_original_fixups(int(r['slot'], 16) for r in routes),
            'keys64': [hex(k) for k in KEYS], 'fourth_byte_whitening64': hex(WHITENING),
            'verified_counts': dict(totals), 'prior_admissions_rerun': False, 'new_target_intervals': 0,
            'new_guest_input_bytes': 0, 'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    e = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
