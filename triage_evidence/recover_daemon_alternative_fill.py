#!/usr/bin/env python3
"""Original-source alternative allocation and address-masked zero-fill evidence.
O(parent receipt bytes + retained state bytes + source words + 512 bank rows)
time/space. No target interval, guest input, allocation or return admission.
"""
import json
from daemon_receive_tools import ROOT, SOURCE, IMAGE, TABLE, FIXUPS, selected, verify_original_fixups
from audit_daemon_environment_outputs import DEC
from audit_daemon_network_record import state_bytes
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_storage_flag as Parent

P = 'daemon_alternative_fill'
SP = Parent.SP
unpack = Parent.unpack
PINS = {name: Parent.PINS[name] for name in [
    'daemon_state_container_construction_checks.json', 'daemon_state_container_construction_audit.json',
    'daemon_alternate_word_checks.json', 'daemon_alternate_word_audit.json']}
PINS.update({'daemon_storage_flag_checks.json': '25dde28ce42bfe2840e4cf9c8887ac969bd7a660f333e59925bf38aa553f50e0',
             'daemon_storage_flag_audit.json': 'd064264e74e129f32aef403fa8328b288500e0bdff16e5439da6de9b22b82740'})
DEPS = ['recover_daemon_storage_flag.py', 'recover_daemon_constructor_gate.py',
        'daemon_receive_tools.py', 'daemon_receive_fixups.txt', 'audit_daemon_environment_outputs.py',
        'audit_daemon_network_record.py']
SPANS = {'zero_slots': (0x10083c8f0, 0x10083c8f8),
         'alternative_allocate': (0x1008c0750, 0x1008c07d8),
         'alternative_return': (0x1008c07d8, 0x1008c07f4),
         'clear_return': (0x100934300, 0x100934318),
         'any_pointer_gate': (0x100934a2c, 0x100934a64),
         'object_allocate': (0x1008a0fa0, 0x1008a103c),
         'object_return': (0x1008a103c, 0x1008a106c),
         'mode_split': (0x10092fb3c, 0x10092fb7c),
         'fill_count': (0x10087ce80, 0x10087cf30),
         'fill_initialize': (0x1006f67d4, 0x1006f6914),
         'fill_loop': (0x1004e8b28, 0x1004e8c5c),
         'fill_complete': (0x1006e5c2c, 0x1006e5c50),
         'saved_bridge': (0x1007f39ac, 0x1007f39b4)}
NORMALIZERS = [(0x1004e8b7c, 0x1004e8b8c, 'x17', 1),
               (0x1004e8ba8, 0x1004e8bb8, 'x17', 3),
               (0x1004e8be4, 0x1004e8bf8, 'x27', 6)]
CONTEXT = {'x1': 0xb842ba42d4112c84, 'x2': 0xdc215d216a089642,
           'x3': 0x5325cdfa4c3f4c0c, 'x4': 0xd9090702c23380ae,
           'x5': 0xec8483816119c057, 'x6': 0x4fc08b57e7836078,
           'x7': 0x6c2f97ea7411e380, 'x19': 0x40ae7d1004aa901d,
           'x20': 0xbf5182effb556fe2, 'x22': 0x7dbe0933d2289c42,
           'x23': 0x71ef41f1f2e87b90, 'x24': 0xffffffff4bfe9bca,
           'w25': 13, 'x14': 0x473c853ae26b7ab8,
           'x15': 0x639ff74d03d39428, 'x16': 0x0a23823d71e7a74e}
ROUTES = [(0x4d13, 0x100934a2c, 0x62b1), (0x76bf, 0x10068ae70, 0x6d79),
          (0x76d3, 0x1008a0fa0, 0x6d79), (0x6802, 0x1008f01f8, 0x6d40),
          (0x6819, 0x10092fb3c, 0x6d40), (0x5fc1, 0x10087ce80, 0xec47),
          (0x5fd8, 0x10093c934, 0xec47), (0x12b1, 0x1007d39f0, 0x6094),
          (0xa0f6, 0x1006f67d4, 0xe8b9), (0xc68d, 0x1007f39ac, 0xe8b9),
          (0x1e73, 0x1004e8b28, 0xc336), (0x4870, 0x1004e8b28, 0x6d4e),
          (0x487d, 0x1006e5c2c, 0x6d4e), (0xbe45, 0x1007f39ac, 0xddd5)]


def extract():
    for name, digest in PINS.items():
        assert sha(ROOT/name) == digest, name
    cells = {0x9c8: 0x1010b8dc8, 0x9c0: 0x1010c4670,
             0x5f0: 0x101031da0, 0x5e0: 0x100e99900, 0x9d8: TABLE,
             0x858: 0x1010c8268, 0x878: 0x1010c67d4, 0x2338: 0, 0x3e00: 0}
    cc = json.loads(read(ROOT/'daemon_state_container_construction_checks.json'))
    snapshots, slices = [], []
    for ci, c in enumerate(cc['contexts']):
        row = unpack(c['allocation_cases'][1]['interval_packed'])
        m = state_bytes(row)
        assert row['boundary']['pc'] == '0x1009342fc'
        assert row['boundary']['registers31'][22] == '0x76d8ea81'
        assert row['boundary']['registers31'][0] == '0x15'
        for off, expected in cells.items():
            assert int.from_bytes(bytes(m[SP+off+j] for j in range(8)), 'little') == expected
        lo = next(j for j, v in enumerate(row['source_visits']) if v['pc'] == '0x10083c8f0')
        assert [v['pc'] for v in row['source_visits'][lo:lo+2]] == ['0x10083c8f0', '0x10083c8f4']
        slices.append({'group': 'constructor', 'class_index': ci, 'kind': 'zero_slots',
                       'start_visit': lo, 'end_visit_exclusive': lo+2,
                       'entry': row['source_frames'][lo], 'exit': row['source_frames'][lo+2],
                       'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < lo+2],
                       'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < lo+2]})
        snapshots.append({'parent_index': ci, 'boundary': row['boundary']['pc'],
                          'encoded_extent32': '0x76d8ea81', 'clear_pending_request_bytes': 21,
                          'cells64': {hex(off): hex(v) for off, v in cells.items()},
                          'scope': 'Existing clear-route conditional snapshot; alternative branch not executed.'})
    assert len(snapshots) == 76
    source = []
    for name, (a, b) in SPANS.items():
        ii = list(DEC.disasm(IMAGE.read(a, b-a), a))
        assert len(ii)*4 == b-a
        source.append({'name': name, 'start': hex(a), 'end_exclusive': hex(b),
                       'bytes_hex': IMAGE.read(a, b-a).hex(),
                       'instructions': [{'pc': hex(i.address), 'mnemonic': i.mnemonic, 'operands': i.op_str} for i in ii]})
    routes = []
    for idx, target, modifier in ROUTES:
        slot = TABLE+8*idx
        raw = IMAGE.read(slot, 8)
        word = int.from_bytes(raw, 'little')
        assert FIXUPS[slot]['target'] == target and (word>>32)&65535 == modifier
        assert (word>>48)&7 == 0
        routes.append({'index32': hex(idx), 'target': hex(target), 'IA_modifier': hex(modifier),
                       'slot': hex(slot), 'word_hex': raw.hex()})
    banks = []
    for key, add in [(0x0a, 0xcb23), (0x86, 0xcbb5)]:
        r = selected(cells[0x5f0], cells[0x5e0], key, add)
        assert r['index'] == '0xcc0d' and r['target'] == 'libSystem/_malloc'
        left, right = (IMAGE.read(cells[o], 256) for o in [0x5f0, 0x5e0])
        r.update({'left256_hex': left.hex(), 'right256_hex': right.hex(),
                  'outputs256': [x^right[left[x]^key] for x in range(256)]})
        assert set(r['outputs256']) == {int(r['constant'], 16)}
        banks.append(r)
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'parent_pins': PINS, 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'source_spans': source, 'routes': routes, 'allocator_banks': banks,
            'original_fixups': verify_original_fixups([int(r['slot'], 16) for r in routes]+[TABLE+8*0xcc0d]),
            'retained_clear_snapshots': snapshots, 'slices': slices,
            'verified_counts': {'source_instructions': sum((b-a)//4 for a,b in SPANS.values()),
                'source_spans': len(SPANS), 'dispatch_routes': len(routes), 'allocator_bank_rows': 512,
                'retained_clear_snapshots': len(snapshots), 'saved_cells_checked': 9*len(snapshots),
                'zero_store_replay_slices': len(slices)},
            'alternative_branch_executed': False, 'prior_admissions_rerun': False, 'new_target_intervals': 0,
            'new_guest_input_bytes': 0, 'new_API_return_premises': 0,
            'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    e = extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
