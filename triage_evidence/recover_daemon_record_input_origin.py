#!/usr/bin/env python3
"""Retained record-input serialization, middle-block transform and splice.
O(parent bytes + visits + read/write bytes + selected frames) time/space.
No new execution interval, root byte, native API, Mach operation or IDB edit.
"""
import gc
import json
from collections import Counter, defaultdict
from daemon_receive_tools import ROOT, SOURCE, IMAGE, FIXUPS
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_banks import span, instruction
import recover_daemon_record_extension as Parent

P = 'daemon_record_input_origin'
PINS = {'daemon_record_extension_checks.json': '9e89cde6b9d04019761c1f7370584e72ad85afc0aa0fd657f4cb4aa9ff0571d7',
        'daemon_record_extension_replay.json': '7ffde847a48145ad9821ab9d228a345dbd7722ab6d00179836624c202b81993d',
        'daemon_record_banks_checks.json': '50000b634bd81018868350c194f60e49992dded73a2a6996764f0af345c40f48'}
DEPS = ['daemon_receive_tools.py', 'daemon_receive_fixups.txt', 'recover_daemon_record_extension.py',
        'recover_daemon_record_banks.py', 'verify_daemon_reader_record_payloads_publication.py']
SERIAL = {0x100be048c, 0x100be04c0, 0x100be04d8, 0x100be04e0}
MAP = [0x1cc, 0x1cd] + list(range(0x1bc, 0x1cc)) + [0x1de, 0x1df]
SPANS = {'serializer': (0x100be044c, 0x100be04e4),
         'formatter': (0x100aaa324, 0x100aaa3e4),
         'table_output_loop': (0x100085b08, 0x100085c1c),
         'table_input_tail': (0x10004e950, 0x10004e9ac),
         'descriptor_transfer': (0x100427c84, 0x100427ce8),
         'result_transfer': (0x100427da8, 0x100427db0),
         'result_zero': (0x1000d4910, 0x1000d491c)}


def inside(event, a, n):
    b = int(event['address'], 16)
    return b < a+n and a < b+event['size_bytes']


def piece(row, lo, hi, kind):
    assert 0 <= lo < hi < len(row['source_frames'])
    frames = row['source_frames'][lo:hi+1]
    q = frames[0]['Q_registers32']
    assert all(f['Q_registers32'] == q for f in frames)
    visits = row['source_visits'][lo:hi]
    assert all(v['image'] == 'daemon' and v['bytes_hex'] == IMAGE.read(int(v['pc'], 16), 4).hex() for v in visits)
    return {'kind': kind, 'start_visit': lo, 'end_visit_exclusive': hi,
            'visits': visits, 'Q_registers32_preserved': q,
            'frames': [{k: v for k, v in f.items() if k != 'Q_registers32'} for f in frames],
            'reads': [x for x in row['source_reads'] if lo <= x['source_visit_index'] < hi],
            'writes': [x for x in row['source_writes'] if lo <= x['source_visit_index'] < hi],
            'edges': [x for x in row['logical_edges'] if lo <= x['source_visit_index'] < hi]}


def byte_origins(row, selected):
    """Forward last-writer fold, retaining each demanded byte's exact epoch."""
    wanted = {int(r['address'], 16)+k for r in selected for k in range(r['size_bytes'])}
    by_r, by_w = defaultdict(list), defaultdict(list)
    for r in selected: by_r[r['source_visit_index']].append(r)
    for w in row['source_writes']: by_w[w['source_visit_index']].append(w)
    last, out = {}, []
    for j in sorted(by_r.keys() | by_w.keys()):
        for r in by_r.get(j, []):
            a = int(r['address'], 16); raw = bytes.fromhex(r['bytes_hex']); origins = []
            for k, b in enumerate(raw):
                w = last.get(a+k)
                if w is not None:
                    offset = a+k-int(w['address'], 16)
                    assert bytes.fromhex(w['after_hex'])[offset] == b
                    origins.append({'reader_byte': k, 'writer': w, 'writer_byte': offset})
            out.append({'reader': r, 'origins': origins,
                        'incoming_or_image_byte_indices': [k for k in range(len(raw)) if a+k not in last]})
        for w in by_w.get(j, []):
            a = int(w['address'], 16)
            for k in range(w['size_bytes']):
                if a+k in wanted: last[a+k] = w
    return out


def extract(row, ci, ii):
    visits = row['source_visits']; by_pc = defaultdict(list)
    for j, v in enumerate(visits): by_pc[int(v['pc'], 16)].append(j)
    def one(pc):
        assert len(by_pc[pc]) == 1, (hex(pc), by_pc[pc])
        return by_pc[pc][0]
    call = one(0x100c1ce88); end = one(0x100a653cc); fmt = one(0x100aaa324)
    f = int(row['source_frames'][fmt]['SP'], 16); dst = 0x680006c5b0
    serial_reads = [r for r in row['source_reads'] if r['pc'] == '0x100be0454']
    assert len(serial_reads) == 5
    assert [int(r['address'], 16) for r in serial_reads] == [f+0x414+4*j for j in range(5)]
    assert all(row['source_frames'][r['source_visit_index']]['SP'] == hex(f) for r in serial_reads)
    serial_writes = [w for w in row['source_writes'] if int(w['pc'], 16) in SERIAL]
    assert len(serial_writes) == 20 and all(w['size_bytes'] == 1 for w in serial_writes)
    sbase = f+0x1cc; tbase = f+0x1bc
    smap = {int(w['address'], 16): bytes.fromhex(w['after_hex'])[0] for w in serial_writes}
    serialized = bytes(smap[sbase+k] for k in range(20))
    chunks = [piece(row, one(0x100a5e2d8), one(0x100a5e2d8)+1, 'saved_output_pointer')]
    for r in serial_reads:
        j = r['source_visit_index']; chunks.append(piece(row, j, j+36, 'serialize_word'))
    # Five source state words are retained with their actual last writers.
    word_origins = byte_origins(row, serial_reads)
    state_writers = {o['writer']['source_visit_index'] for x in word_origins for o in x['origins']}
    assert len(state_writers) == 5
    for j in sorted(state_writers): chunks.append(piece(row, j, j+1, 'serialized_word_last_writer'))
    chunks.append(piece(row, call, end, 'descriptor_helper_and_formatter'))
    selected_reads = sorted([r for c in chunks for r in c['reads']], key=lambda r: r['source_visit_index'])
    origins = byte_origins(row, selected_reads)
    middle_reads = [r for r in row['source_reads'] if call < r['source_visit_index'] < fmt and inside(r, sbase, 20)]
    assert len(middle_reads) == 16 and all(r['pc'] == '0x10004e954' and r['size_bytes'] == 1 for r in middle_reads)
    assert [int(r['address'], 16) for r in middle_reads] == list(range(sbase+17, sbase+1, -1))
    assert bytes.fromhex(''.join(r['bytes_hex'] for r in reversed(middle_reads))) == serialized[2:18]
    out16 = [w for w in row['source_writes'] if call < w['source_visit_index'] < fmt and inside(w, tbase, 16)]
    assert len(out16) == 16 and all(w['pc'] == '0x100085bfc' and w['size_bytes'] == 1 for w in out16)
    assert [int(w['address'], 16) for w in out16] == list(range(tbase+15, tbase-1, -1))
    transformed = bytes.fromhex(''.join(w['after_hex'] for w in reversed(out16)))
    output_writes = [w for w in row['source_writes'] if inside(w, dst, 20)]
    assert len(output_writes) == 20 and all(fmt <= w['source_visit_index'] < end and w['size_bytes'] == 1 for w in output_writes)
    output = bytearray(20)
    for w in output_writes: output[int(w['address'], 16)-dst] = bytes.fromhex(w['after_hex'])[0]
    assert bytes(output) == serialized[:2]+transformed+serialized[18:]
    pointer_read = next(r for r in chunks[-1]['reads'] if r['pc'] == '0x100aaa370')
    pointer_origins = next(x for x in origins if x['reader'] == pointer_read)
    assert len(pointer_origins['origins']) == 8
    assert {o['writer']['pc'] for o in pointer_origins['origins']} == {'0x100a5e2d8'}
    assert int.from_bytes(bytes.fromhex(pointer_read['bytes_hex']), 'little') == dst
    inputs = {r['pc']: r for r in chunks[-1]['reads'] if r['pc'] in ['0x100427c84', '0x100427c8c', '0x100427c90']}
    assert int.from_bytes(bytes.fromhex(inputs['0x100427c8c']['bytes_hex']), 'little') == sbase+2
    assert int.from_bytes(bytes.fromhex(inputs['0x100427c90']['bytes_hex']), 'little') == tbase
    calls = [c for c in row['source_calls'] if call <= c['source_visit_index'] < end]
    assert [(c['pc'], c['target'], c['modifier']) for c in calls] == [
        ('0x100c1ce88', '0x100427b0c', '0x5278'), ('0x100427da4', '0x100411480', '0x5431')]
    return {'class_index': ci, 'interval_index': ii, 'frame_F': hex(f), 'outer_frame_K': row['boundary']['SP'],
            'serialized_base': hex(sbase), 'transform_output_base': hex(tbase), 'output_base': hex(dst),
            'serialized20_hex': serialized.hex(), 'middle_input16_hex': serialized[2:18].hex(),
            'transform_output16_hex': transformed.hex(), 'record_input20_hex': bytes(output).hex(),
            'word_reads': serial_reads, 'word_origins': word_origins, 'serializer_writes': serial_writes,
            'middle_reads': middle_reads, 'transformed_writes': out16, 'output_writes': output_writes,
            'output_pointer_origins': pointer_origins, 'descriptor_input_reads': inputs,
            'calls': calls, 'chunks': chunks, 'selected_read_origins': origins,
            'state_word_later_writes': [w for w in row['source_writes'] if serial_reads[-1]['source_visit_index'] < w['source_visit_index'] < call and inside(w, f+0x414, 20)],
            'new_target_intervals': 0, 'native_execution': False}


def build():
    for p, d in PINS.items(): assert sha(ROOT/p) == d
    old = json.loads(read(ROOT/'daemon_record_extension_checks.json')); cases = []; counts = Counter()
    for ci in [2, 3]:
        ii = len(old['classes'][ci]['intervals'])-1
        row = Parent.unpack(old['classes'][ci]['intervals'][ii]['interval_packed'])
        case = extract(row, ci, ii); cases.append(case)
        counts.update(retained_classes=1, selected_chunks=len(case['chunks']),
                      source_visits=sum(len(c['visits']) for c in case['chunks']),
                      read_events=sum(len(c['reads']) for c in case['chunks']),
                      write_events=sum(len(c['writes']) for c in case['chunks']),
                      selected_read_bytes=sum(r['reader']['size_bytes'] for r in case['selected_read_origins']),
                      last_writer_byte_links=sum(len(r['origins']) for r in case['selected_read_origins']))
        del row; gc.collect()
    banks = json.loads(read(ROOT/'daemon_record_banks_checks.json'))
    assert len(banks['frontiers']) == 608
    assert all(c['record_input20_hex'] == b['input20_hex'] for c in cases for b in banks['frontiers'])
    counts.update(retained_frontier_value_matches=608, new_target_intervals=0, new_root_bytes=0)
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'parent_pins': PINS, 'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'cases': cases,
            'formatter_source_offsets': [hex(x) for x in MAP],
            'spans': {n: span(*v) for n, v in SPANS.items()}, 'verified_counts': dict(counts),
            'native_API_executed': False, 'native_daemon_kext_pairing_established': False,
            'digest_message_or_algorithm_established': False, 'transform_algorithm_established': False,
            'full_goal_complete': False}


if __name__ == '__main__':
    result = build(); (ROOT/(P+'_checks.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']), flush=True)
